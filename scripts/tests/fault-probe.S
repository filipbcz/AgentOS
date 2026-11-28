/* Fresh native userspace ELF for the controlled isolation regression. */
#include "../../user/abi.h"
.global _start
.text
_start:
    call runFaultProbe
    mov %eax, %edi
    mov $SYS_EXIT, %eax
    syscall
    ud2
.section .note.GNU-stack,"",@progbits
