// Copied into a SIPI page. Offsets 0..45 in the following (NX) page are
// populated by the BSP. No code or absolute label in this page needs patching.
.section .rodata.ap_start,"a",@progbits
.global ap_start, ap_end, ap_pm, ap_long, ap_gdt
.code16
ap_start:
    cli
    cld
    mov %cs, %ax
    mov %ax, %ds
    movzwl %ax, %ebx
    shl $4, %ebx
    lgdtl 4096+24
    mov %cr0, %eax
    or $1, %eax
    mov %eax, %cr0
    ljmpl *4096+32
.code32
ap_pm:
    mov $16, %ax
    mov %ax, %ds
    mov %ax, %es
    mov %ax, %ss
    mov $0x620, %eax         // PAE, OSFXSR, OSXMMEXCPT
    mov %eax, %cr4
    mov 4096(%ebx), %eax
    mov %eax, %cr3
    mov $0xc0000080, %ecx
    rdmsr
    or $0x900, %eax           // LME, NXE
    wrmsr
    mov %cr0, %eax
    and $~12, %eax            // clear EM, TS
    or $0x80010002, %eax      // PG, WP, MP
    mov %eax, %cr0
    ljmpl *4096+40(%ebx)
.code64
ap_long:
    mov 4096+8(%rbx), %rsp
    mov 4096+16(%rbx), %rdi
    xor %ebp, %ebp
    movabs $ap_main, %rax
    call *%rax
    ud2
.balign 8
ap_gdt:
    .quad 0, 0x00cf9b000000ffff, 0x00cf93000000ffff, 0x00af9b000000ffff
ap_end:
.section .text.memcpy,"ax",@progbits
// Freestanding SysV routines used by Rust when copying and clearing ACPI lists.
.global memcpy
memcpy:
    mov %rdi, %rax
    mov %rdx, %rcx
    rep movsb
    ret
.section .text.memset,"ax",@progbits
.global memset
memset:
    mov %rdi, %r8
    mov %esi, %eax
    mov %rdx, %rcx
    rep stosb
    mov %r8, %rax
    ret
.section .text.bcmp,"ax",@progbits
.global bcmp
bcmp:
    xor %eax, %eax
    mov %rdx, %rcx
    repe cmpsb
    setne %al
    ret
.section .note.GNU-stack,"",@progbits
