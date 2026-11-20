#include "abi.h"
.global _start
.text
_start:
1:
    mov $SYS_YIELD, %eax
    syscall
    jmp 1b
