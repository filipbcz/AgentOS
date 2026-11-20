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
wait_child:
    mov $SYS_TRY_WAIT, %eax
    mov %r13, %rdi
    syscall
    cmp $-11, %rax
    jne collected
    mov $SYS_YIELD, %eax
    syscall
    jmp wait_child
collected:
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
