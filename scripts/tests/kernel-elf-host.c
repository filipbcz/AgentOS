#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../../boot/kernel-elf.h"

enum { FILE_SIZE = 0x3200, IMAGE_SIZE = 0x4000, PH_OFF = 64,
       RO_OFF = 0x2000, RW_OFF = 0x3000, DYN_OFF = 0x3040 };

static void fixture(uint8_t *blob) {
    memset(blob, 0, FILE_SIZE);
    Elf64_Ehdr h = {0};
    memcpy(h.e_ident, ELFMAG, SELFMAG);
    h.e_ident[EI_CLASS] = ELFCLASS64;
    h.e_ident[EI_DATA] = ELFDATA2LSB;
    h.e_ident[EI_VERSION] = EV_CURRENT;
    h.e_version = EV_CURRENT; h.e_type = ET_DYN; h.e_machine = EM_X86_64;
    h.e_ehsize = sizeof(h); h.e_phentsize = sizeof(Elf64_Phdr);
    h.e_phnum = 4; h.e_phoff = PH_OFF; h.e_entry = 8;
    memcpy(blob, &h, sizeof(h));
    const Elf64_Phdr ph[] = {
        {PT_LOAD, PF_R|PF_X, 0x1000, 0, 0, 0x20, 0x20, 4096},
        {PT_LOAD, PF_R, RO_OFF, 0x1000, 0x1000, 0x80, 0x80, 4096},
        {PT_LOAD, PF_R|PF_W, RW_OFF, 0x2000, 0x2000, 0x100, 0x1200, 4096},
        {PT_DYNAMIC, PF_R|PF_W, DYN_OFF, 0x2040, 0x2040, 0x60, 0x60, 8}
    };
    memcpy(blob+PH_OFF, ph, sizeof(ph));
    const Elf64_Rela rela[] = {
        {0x2000, ELF64_R_INFO(0, R_X86_64_RELATIVE), 8},
        {0x2008, ELF64_R_INFO(0, R_X86_64_RELATIVE), 0x4000}
    };
    memcpy(blob+RO_OFF, rela, sizeof(rela));
    const Elf64_Dyn dyn[] = {
        {DT_RELA, {.d_ptr = 0x1000}}, {DT_RELASZ, {.d_val = sizeof(rela)}},
        {DT_RELAENT, {.d_val = sizeof(Elf64_Rela)}},
        {DT_RELACOUNT, {.d_val = 2}}, {DT_FLAGS_1, {.d_val = DF_1_PIE}},
        {DT_NULL, {.d_val = 0}}
    };
    memcpy(blob+DYN_OFF, dyn, sizeof(dyn));
    blob[0x1008] = 0xc3;
    blob[RO_OFF+0x60] = 0x34;
    blob[RW_OFF+0x20] = 0x56;
}

static void patch64(uint8_t *blob, size_t offset, uint64_t value) {
    memcpy(blob+offset, &value, sizeof(value));
}

static uint64_t read64(const uint8_t *bytes) {
    uint64_t value;
    memcpy(&value, bytes, sizeof(value));
    return value;
}

static void reject(uint8_t *blob, size_t length) {
    KernelElf elf;
    uint8_t memory[IMAGE_SIZE];
    memset(memory, 0xaa, sizeof(memory));
    uint64_t entry = 123;
    assert(!kernel_elf_parse(blob, length, &elf));
    assert(!kernel_elf_load(blob, length, memory, 0x800000, sizeof(memory), &entry));
    assert(entry == 123);
    for (size_t i = 0; i < sizeof(memory); ++i) assert(memory[i] == 0xaa);
}

static void synthetic(void) {
    uint8_t blob[FILE_SIZE], memory[IMAGE_SIZE];
    KernelElf elf;
    fixture(blob);
    assert(kernel_elf_parse(blob, sizeof(blob), &elf));
    assert(elf.entry == 8 && elf.size == IMAGE_SIZE && elf.rela_count == 2);
    const uint64_t bases[] = {0x100000, 0x80000000, KERNEL_LIMIT-IMAGE_SIZE};
    for (unsigned i = 0; i < sizeof(bases)/sizeof(*bases); ++i) {
        uint64_t entry;
        memset(memory, 0xaa, sizeof(memory));
        assert(kernel_elf_load(blob, sizeof(blob), memory, bases[i], sizeof(memory), &entry));
        assert(entry == bases[i]+8 && memory[8] == 0xc3);
        assert(memory[0x1060] == 0x34 && memory[0x2020] == 0x56);
        assert(read64(memory+0x2000) == bases[i]+8);
        assert(read64(memory+0x2008) == bases[i]+IMAGE_SIZE);
        for (size_t j = 0x2100; j < IMAGE_SIZE; ++j) assert(!memory[j]);
        assert(!memory[0x100] && !memory[0x1fff]);
    }
    uint64_t entry;
    assert(!kernel_elf_load(blob, sizeof(blob), memory, 1, sizeof(memory), &entry));
    assert(!kernel_elf_load(blob, sizeof(blob), memory, KERNEL_LIMIT-4096, sizeof(memory), &entry));
    assert(!kernel_elf_load(blob, sizeof(blob), memory, 0x800000, sizeof(memory)-1, &entry));
    reject(blob, 10);
    reject(blob, 0x3050);
    // Exact mutation of header, segment, relocation and dynamic metadata.
    struct Mutation { size_t offset; uint64_t value; };
    const struct Mutation bad[] = {
        {24, 0x2000}, {32, UINT64_MAX},
        {PH_OFF+4, PF_R|PF_W|PF_X},
        {PH_OFF+8, UINT64_MAX},
        {PH_OFF+56+16, 0}, {PH_OFF+112+40, UINT64_MAX},
        {PH_OFF+168+8, 0x3038},
        {RO_OFF, 8}, {RO_OFF+8, ELF64_R_INFO(1,R_X86_64_RELATIVE)},
        {RO_OFF+8, ELF64_R_INFO(0,R_X86_64_64)},
        {RO_OFF+16, UINT64_MAX}, {RO_OFF+16, IMAGE_SIZE+1},
        {RO_OFF+24, 0x2004}, {RO_OFF+24, 0x2040},
        {RO_OFF+24, 0x31ff}, {DYN_OFF+8, 0x2000},
        {DYN_OFF+24, 47}, {DYN_OFF+40, 16}, {DYN_OFF+56, 1},
        {DYN_OFF+64, DT_NEEDED}, {DYN_OFF+64, DT_TEXTREL},
        {DYN_OFF+80, DT_RELA}, {DYN_OFF+88, 1}
    };
    for (unsigned i = 0; i < sizeof(bad)/sizeof(*bad); ++i) {
        fixture(blob);
        patch64(blob, bad[i].offset, bad[i].value);
        reject(blob, sizeof(blob));
    }
}

// Additionally consume the actual linked kernel from each build, not just
// a synthetic fixture. Check every copied byte, relative fixup and BSS gap.
static void linked(const char *path) {
    FILE *file = fopen(path, "rb");
    assert(file && fseek(file, 0, SEEK_END) == 0);
    long length = ftell(file);
    assert(length > 0 && fseek(file, 0, SEEK_SET) == 0);
    uint8_t *blob = malloc((size_t)length);
    assert(blob && fread(blob, 1, (size_t)length, file) == (size_t)length);
    fclose(file);
    KernelElf e;
    if (!kernel_elf_parse(blob, (size_t)length, &e)) {
        fprintf(stderr, "Production loader rejected linked image: %s\n", path);
        abort();
    }
    uint8_t *memory = malloc((size_t)e.size);
    uint8_t *expected = calloc(1, (size_t)e.size);
    assert(memory && expected);
    for (unsigned i = 0; i < 3; ++i) {
        const Elf64_Phdr *p = &e.load[i];
        memcpy(expected+p->p_vaddr, blob+p->p_offset, p->p_filesz);
    }
    const uint64_t bases[] = {0x400000, UINT64_C(0x123456000), KERNEL_LIMIT-e.size};
    for (unsigned i = 0; i < sizeof(bases)/sizeof(*bases); ++i) {
        uint64_t entry;
        memset(memory, 0xaa, (size_t)e.size);
        assert(kernel_elf_load(blob, (size_t)length, memory, bases[i], (size_t)e.size, &entry));
        assert(entry == bases[i]+e.entry);
        for (uint64_t j = 0; j < e.rela_count; ++j) {
            Elf64_Rela r;
            memcpy(&r, blob+e.rela_offset+j*sizeof(r), sizeof(r));
            patch64(expected, r.r_offset, bases[i]+(uint64_t)r.r_addend);
        }
        assert(!memcmp(memory, expected, (size_t)e.size));
    }
    printf("Linked static PIE: %s, %llu relative relocations, three bases OK\n",
           path, (unsigned long long)e.rela_count);
    free(expected); free(memory); free(blob);
}

int main(int argc, char **argv) {
    synthetic();
    for (int i = 1; i < argc; ++i) linked(argv[i]);
    puts("Kernel ELF validation and relocation: OK");
    return 0;
}
