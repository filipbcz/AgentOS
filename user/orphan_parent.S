#include "abi.h"
.global _start
.text
_start:
    /* The intermediate parent starts an indefinitely yielding worker then
       exits without waiting. This must transfer the child's reaping rights
       to the CPU-local root init process; no descriptor or task may leak. */
    mov $SYS_SPAWN, %eax
    lea worker(%rip), %rdi
    mov $8, %esi
    syscall
    test %rax, %rax
    jle failed
    mov $SYS_EXIT, %eax
    xor %edi, %edi
    syscall
    ud2
failed:
    mov $SYS_EXIT, %eax
    mov $77, %edi
    syscall
    ud2
.section .rodata
worker: .ascii "svc_hang"
