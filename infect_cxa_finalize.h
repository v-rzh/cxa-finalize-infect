#ifndef INFECT_CXA_FINALIZE_H
#define INFECT_CXA_FINALIZE_H
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <stdint.h>
#include <errno.h>
#include <sys/mman.h>
#include <elf.h>

#ifdef _DEBUG
#define DBG(fmt, ...) \
    printf(fmt, ##__VA_ARGS__)
#else
#define DBG(fmt, ...)
#endif

#define ERR(fmt, ...) \
    fprintf(stderr, fmt, ##__VA_ARGS__)

#define OPT_PLT     (1 << 0)
#define OPT_DTORS   (1 << 1)

#define HIJACK_PLT(x)   ((x)&OPT_PLT)
#define HIJACK_DTORS(x) ((x)&OPT_DTORS)
#define INVALID_OPTS(x) (!((HIJACK_DTORS(x) >> 1) ^ HIJACK_PLT(x)))

struct parasite_data {
    union {
        Elf64_Ehdr *elf;
        uint8_t *bytes;
    };
    size_t size;
    Elf64_Shdr *shdrs;

    uint8_t *text_bytes;
    size_t text_size;
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
    uint8_t *do_glob_dtors;
    uint8_t *hijack_site;

    uint8_t *scratch_space;
};

#endif
