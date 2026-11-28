#include "../../user/abi.h"
.global _start
.text
_start:
    call receive
    mov %eax, %edi
    mov $SYS_EXIT, %eax
    syscall
    ud2
