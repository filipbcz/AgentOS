#include "abi.h"
.global _start
.text
_start:
    call runServiceManager
    mov %eax,%edi
    mov $SYS_EXIT,%eax
    syscall
    ud2
