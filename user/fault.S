#include "abi.h"
.global _start
.text
_start:
    movq $-1, -64(%rsp)           // same VA as parent's private value
    mov $0x02000000, %eax
    mov (%rax), %eax               // CPL3 read of present supervisor-only text
    mov $1, %edi                   // reaching here must fail the parent's test
    mov $SYS_EXIT, %eax
    syscall
    ud2
