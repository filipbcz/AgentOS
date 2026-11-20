#include "abi.h"
.global _start
.text
_start:
    call serve
    mov %eax, %edi
    mov $SYS_EXIT, %eax
    syscall
    ud2
