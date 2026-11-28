#include "abi.h"
.global _start
.text
_start:
    call run_orphans
    test %eax, %eax
    jne finished
    // BSP PID 1 stays resident for service supervision; AP roots exit.
    mov $SYS_GETPID, %eax
    syscall
    cmp $1, %rax
    jne ap_finished
    mov $SYS_BOOT_PAUSE, %eax
    syscall
    test %eax, %eax
    jne failed
    call runServiceManager
    jmp finished
ap_finished:
    xor %eax, %eax
finished:
    mov %eax, %edi
    jmp terminate
failed:
    mov $1, %edi
terminate:
    mov $SYS_EXIT, %eax
    syscall
    ud2
