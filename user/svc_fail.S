#include "abi.h"
.global _start
.text
_start:
    mov $SYS_EXIT, %eax
    mov $42, %edi
    syscall
    ud2
