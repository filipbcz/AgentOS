#ifndef AGENTOS_KERNEL_ELF_H
#define AGENTOS_KERNEL_ELF_H

#include <elf.h>
#include <stddef.h>
#include <stdint.h>

#define KERNEL_PAGE UINT64_C(4096)
#define KERNEL_MAX_IMAGE (UINT64_C(16) * 1024 * 1024)
#define KERNEL_LIMIT (UINT64_C(1) << 39)

typedef struct {
    Elf64_Phdr load[3];
    Elf64_Phdr dynamic;
    uint64_t entry, size, rela_offset, rela_count;
} KernelElf;

static int kernel_range(uint64_t offset, uint64_t length, uint64_t limit) {
    return offset <= limit && length <= limit - offset;
}

static int kernel_inside(uint64_t offset, uint64_t length, uint64_t start, uint64_t size) {
    return offset >= start && kernel_range(offset - start, length, size);
}

static uint64_t kernel_align(uint64_t size) {
    // All callers bound size by KERNEL_MAX_IMAGE first.
    return (size + KERNEL_PAGE - 1) & ~(KERNEL_PAGE - 1);
}

// Read the signed embedded bytes without requiring the compiler to assume
// alignment or aliasing of C structs in the input file.
static void kernel_copy(void *destination, const void *source, size_t size) {
    uint8_t *out = destination;
    const uint8_t *in = source;
    for (size_t i = 0; i < size; ++i) out[i] = in[i];
}

static int kernel_rela(const uint8_t *blob, const KernelElf *elf) {
    const Elf64_Phdr *rw = &elf->load[2];
    uint64_t previous_end = rw->p_vaddr;
    for (uint64_t i = 0; i < elf->rela_count; ++i) {
        Elf64_Rela r;
        kernel_copy(&r, blob + elf->rela_offset + i * sizeof(r), sizeof(r));
        // A self-contained static PIE may only need base-relative fixups.
        // Never write instructions or read-only pages; disallow overlapping
        // targets and dynamic-table modification. One-past-image pointers
        // are allowed for linker boundary symbols such as kernel_end.
        if (r.r_info != ELF64_R_INFO(0, R_X86_64_RELATIVE) ||
            r.r_addend < 0 || (uint64_t)r.r_addend > elf->size ||
            r.r_offset < previous_end ||
            !kernel_inside(r.r_offset, sizeof(uint64_t), rw->p_vaddr, rw->p_memsz) ||
            (r.r_offset < elf->dynamic.p_vaddr + elf->dynamic.p_memsz &&
             r.r_offset + sizeof(uint64_t) > elf->dynamic.p_vaddr))
            return 0;
        previous_end = r.r_offset + sizeof(uint64_t);
    }
    return 1;
}

// This is the versioned, deliberately narrow AgentOS kernel image contract,
// not a userspace dynamic loader. All addresses in the ELF are image offsets.
// Only three page-separated PT_LOAD segments and one PT_DYNAMIC are allowed.
static int kernel_elf_parse(const uint8_t *blob, size_t length, KernelElf *out) {
    Elf64_Ehdr h;
    KernelElf e = {0};
    if (length < sizeof(h)) return 0;
    kernel_copy(&h, blob, sizeof(h));
    if (h.e_ident[0] != ELFMAG0 || h.e_ident[1] != ELFMAG1 ||
        h.e_ident[2] != ELFMAG2 || h.e_ident[3] != ELFMAG3 ||
        h.e_ident[EI_CLASS] != ELFCLASS64 || h.e_ident[EI_DATA] != ELFDATA2LSB ||
        h.e_ident[EI_VERSION] != EV_CURRENT || h.e_version != EV_CURRENT ||
        h.e_type != ET_DYN || h.e_machine != EM_X86_64 || h.e_flags != 0 ||
        h.e_ehsize != sizeof(h) || h.e_phentsize != sizeof(Elf64_Phdr) ||
        h.e_phnum != 4 || h.e_phoff < sizeof(h) ||
        !kernel_range(h.e_phoff, 4 * sizeof(Elf64_Phdr), length)) return 0;

    uint64_t next = 0, previous_file_end = h.e_phoff + 4 * sizeof(Elf64_Phdr);
    const uint32_t flags[3] = {PF_R | PF_X, PF_R, PF_R | PF_W};
    for (unsigned i = 0; i < 3; ++i) {
        Elf64_Phdr *p = &e.load[i];
        kernel_copy(p, blob + h.e_phoff + i * sizeof(*p), sizeof(*p));
        if (p->p_type != PT_LOAD || p->p_flags != flags[i] ||
            p->p_vaddr != next || p->p_paddr != p->p_vaddr ||
            p->p_align != KERNEL_PAGE || p->p_offset % KERNEL_PAGE ||
            p->p_offset < previous_file_end ||
            !p->p_filesz || p->p_filesz > p->p_memsz ||
            (i != 2 && p->p_filesz != p->p_memsz) ||
            !kernel_range(p->p_offset, p->p_filesz, length) ||
            !kernel_range(p->p_vaddr, p->p_memsz, KERNEL_MAX_IMAGE)) return 0;
        next = kernel_align(p->p_vaddr + p->p_memsz);
        previous_file_end = p->p_offset + p->p_filesz;
    }
    e.size = next;
    e.entry = h.e_entry;
    if (!kernel_inside(e.entry, 1, 0, e.load[0].p_filesz)) return 0;

    Elf64_Phdr *d = &e.dynamic;
    const Elf64_Phdr *ro = &e.load[1], *rw = &e.load[2];
    kernel_copy(d, blob + h.e_phoff + 3 * sizeof(*d), sizeof(*d));
    if (d->p_type != PT_DYNAMIC || d->p_flags != (PF_R | PF_W) ||
        d->p_paddr != d->p_vaddr || d->p_align != 8 || d->p_vaddr % 8 ||
        !d->p_filesz || d->p_filesz != d->p_memsz ||
        d->p_filesz % sizeof(Elf64_Dyn) ||
        !kernel_inside(d->p_vaddr, d->p_filesz, rw->p_vaddr, rw->p_filesz) ||
        d->p_offset != rw->p_offset + (d->p_vaddr - rw->p_vaddr)) return 0;

    uint64_t rela = 0, bytes = 0, entsize = 0, count = 0;
    unsigned seen = 0;
    int terminated = 0;
    for (uint64_t i = 0; i < d->p_filesz; i += sizeof(Elf64_Dyn)) {
        Elf64_Dyn tag;
        kernel_copy(&tag, blob + d->p_offset + i, sizeof(tag));
        uint64_t value = tag.d_un.d_val;
        unsigned bit = 0;
        if (terminated) {
            if (tag.d_tag != DT_NULL || value != 0) return 0;
            continue;
        }
        switch (tag.d_tag) {
        case DT_NULL: if (value != 0) return 0; terminated = 1; break;
        case DT_RELA: rela = value; bit = 1; break;
        case DT_RELASZ: bytes = value; bit = 2; break;
        case DT_RELAENT: entsize = value; bit = 4; break;
        case DT_RELACOUNT: count = value; bit = 8; break;
        // Metadata emitted by GNU ld; there are no external symbols or
        // dependencies. No interpreter, PLT, REL, RELR, TLS or init hooks.
        case DT_HASH: case DT_GNU_HASH: case DT_STRTAB: case DT_SYMTAB:
            if (!kernel_inside(value, 1, ro->p_vaddr, ro->p_filesz)) return 0;
            break;
        case DT_STRSZ: if (!value || value > ro->p_filesz) return 0; break;
        case DT_SYMENT: if (value != sizeof(Elf64_Sym)) return 0; break;
        case DT_DEBUG: if (value != 0) return 0; break;
        case DT_FLAGS: if (value & ~((uint64_t)DF_BIND_NOW)) return 0; break;
        case DT_FLAGS_1: if (value & ~((uint64_t)DF_1_PIE | DF_1_NOW)) return 0; break;
        default: return 0;
        }
        if (bit && (seen & bit)) return 0;
        seen |= bit;
    }
    if (!terminated) return 0;
    if (seen & 7) {
        if ((seen & 7) != 7 || entsize != sizeof(Elf64_Rela) ||
            bytes % sizeof(Elf64_Rela) || rela % 8 ||
            !kernel_inside(rela, bytes, ro->p_vaddr, ro->p_filesz)) return 0;
        e.rela_offset = ro->p_offset + rela - ro->p_vaddr;
        e.rela_count = bytes / sizeof(Elf64_Rela);
    }
    if ((seen & 8) && count != e.rela_count) return 0;
    if (!kernel_rela(blob, &e)) return 0;
    *out = e;
    return 1;
}

// The caller exclusively owns the whole page-rounded destination, separate
// from the signed source. Parse before allocation; materialize only after all
// checks. On failure no destination byte is changed.
static int kernel_elf_load(const uint8_t *blob, size_t length, void *destination,
                           uint64_t base, size_t capacity, uint64_t *entry) {
    KernelElf e;
    if (!kernel_elf_parse(blob, length, &e) || !destination ||
        base < KERNEL_PAGE || base % KERNEL_PAGE ||
        capacity < e.size || !kernel_range(base, e.size, KERNEL_LIMIT)) return 0;
    uint8_t *out = destination;
    for (uint64_t i = 0; i < e.size; ++i) out[i] = 0;
    for (unsigned i = 0; i < 3; ++i) {
        const Elf64_Phdr *p = &e.load[i];
        kernel_copy(out + p->p_vaddr, blob + p->p_offset, p->p_filesz);
    }
    for (uint64_t i = 0; i < e.rela_count; ++i) {
        Elf64_Rela r;
        kernel_copy(&r, blob + e.rela_offset + i * sizeof(r), sizeof(r));
        uint64_t value = base + (uint64_t)r.r_addend;
        kernel_copy(out + r.r_offset, &value, sizeof(value));
    }
    *entry = base + e.entry;
    return 1;
}

#endif
