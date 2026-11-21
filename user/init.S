#include "abi.h"
.global _start
.text
_start:
    mov $SYS_GETPID, %eax
    syscall
    test %rax, %rax
    jle failed
    mov %rax, %r12
    mov %r12, -64(%rsp)
    mov $SYS_WRITE, %eax
    mov $1, %edi
    mov $0x02000000, %esi          // supervisor-only kernel page
    mov $8, %edx
    syscall
    cmp $-14, %rax
    jne failed
    mov $SYS_WRITE, %eax
    lea 15(%rsp), %rsi             // one valid byte, then outside the stack
    mov $2, %edx
    syscall
    cmp $-14, %rax
    jne failed
    mov $-1, %rax
    syscall
    cmp $-38, %rax
    jne failed
    mov $SYS_SPAWN, %eax
    lea child(%rip), %rdi
    mov $5, %esi
    syscall
    test %rax, %rax
    jle failed
    mov %rax, %r13
    cmp %r12, %r13
    je failed
    // A faulting child must be reaped through the same blocking kernel wait
    // used by PID1 services; no userspace yield-polling or unbounded hang.
    mov $SYS_MONOTONIC_MS, %eax
    syscall
    test %rax, %rax
    js failed
    movabs $0x7fffffffffffec77, %rbx   // signed max - 5000ms
    cmp %rbx, %rax
    ja failed
    lea 5000(%rax), %rsi
    mov $SYS_WAIT_CHILD_UNTIL, %eax
    mov %r13, %rdi
    syscall
    cmp $270, %rax                 // fault status 256 + page-fault vector 14
    jne failed
    cmp %r12, -64(%rsp)
    jne failed
    mov $SYS_WRITE, %eax
    mov $1, %edi
    lea survived(%rip), %rsi
    mov $survived_len, %edx
    syscall
    cmp $survived_len, %rax
    jne failed
    call run_transfer
    test %eax, %eax
    jne finished
    call run_ipc
    test %eax, %eax
    jne finished
    call run_supervisor
    test %eax, %eax
    jne finished
    call run_orphans
    test %eax, %eax
    jne finished
    call run_forktest
    test %eax, %eax
    jne finished
    call runDemandPaging
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
    call runMigration
    test %eax, %eax
    jne finished
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
.section .rodata
child: .ascii "fault"
survived: .ascii "AGENTOS USER SURVIVED\r\n"
.set survived_len, . - survived
