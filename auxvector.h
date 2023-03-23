#include <elf.h>

#define STACK_LIMIT     65535
#define QWORD_ALIGN     0xfffffffffffffff8

/* Naive stack scan to find the auxilliary vector.
 * This should work for kernel versions v2.6.12 (and probably eariler) through
 * at least 5.15.88 (current test version).
 * The AT_HWCAP auxilliary vector entry is placed right before the
 * AT_PAGESZ by the kernel. This allows us to anchor these and other nearby
 * values to find the beginning of the auxilliary vector. While it's unlikely
 * these values would appear elsewhere on the stack in this manner,
 * it doesn't mean this method is foolproof.
 */

#define AUX_VECTOR_ORDER            \
    X(AT_HWCAP, AT_HWCAP_ORD)       \
    X(AT_PAGESZ, AT_PAGESZ_ORD)     \
    X(AT_CLKTCK, AT_CLKTCK_ORD)     \
    X(AT_PHDR, AT_PHDR_ORD)         \
    X(AT_PHENT, AT_PHENT_ORD)       \
    X(AT_PHNUM, AT_PHNUM_ORD)       \
    X(AT_BASE, AT_BASE_ORD)         \
    X(AT_FLAGS, AT_FLAGS_ORD)       \
    X(AT_ENTRY, AT_ENTRY_ORD)       \
    X(AT_UID, AT_UID_ORD)           \
    X(AT_EUID, AT_EUID_ORD)         \
    X(AT_GID, AT_GID_ORD)           \
    X(AT_EGID, AT_EGID_ORD)         \
    X(AT_SECURE, AT_SECURE_ORD)     \
    X(0, AUXVLEN64)

uint64_t aux_order[] = {
#define X(a,b) a,
    AUX_VECTOR_ORDER
#undef X
};

enum {
#define X(a,b) b,
    AUX_VECTOR_ORDER
#undef X
};

#define SCAN_VECTOR_SIZE64  (AUXVLEN64*sizeof(Elf64_Off))

struct aux_entry_64 {
    Elf64_Off id;
    Elf64_Off val;
};


struct aux_entry_64 *get_beg_auxvector(uint64_t st_addr_int, uint64_t max_addr);
