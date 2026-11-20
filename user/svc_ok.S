#include "abi.h"
.global _start
.text
_start:
    mov $SYS_EXIT, %eax
    xor %edi, %edi
    syscall
    ud2
