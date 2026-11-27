/* Native, separate runtime register/preemption client. */
#include "../../user/abi.h"
.text
.global _start
.macro REPORT line, pid
    mov \pid, %rdi
    lea \line(%rip), %rsi
    mov $\line\()_end-\line, %edx
    call report
.endm
_start:
    mov $SYS_GETPID, %eax
    syscall
    test %rax,%rax
    jle failed
    REPORT root_line,%rax
    mov $SYS_MONOTONIC_MS,%eax
    syscall
    test %rax,%rax
    js failed
    lea 2000(%rax),%r12
    lea 60000(%r12),%r13
    mov $SYS_FORK,%eax
    syscall
    test %rax,%rax
    js failed
    jz worker_A
    mov %rax,%r14
    REPORT child_A,%r14
    mov $SYS_FORK,%eax
    syscall
    test %rax,%rax
    js failed
    jz worker_B
    mov %rax,%r15
    REPORT child_B,%r15
    mov %r14,%rdi
    call reap
    REPORT reap_A,%r14
    mov %r15,%rdi
    call reap
    REPORT reap_B,%r15
    mov $SYS_CHILD_AFTER,%eax
    xor %edi,%edi
    xor %esi,%esi
    xor %edx,%edx
    syscall
    cmp $-10,%rax
    jne failed
    mov $SYS_GETPID,%eax
    syscall
    REPORT complete_line,%rax
    jmp success

reap:
    mov %rdi,%rbx
    mov %r13,%rsi
    xor %edx,%edx
    mov $SYS_WAIT_CHILD_UNTIL,%eax
    syscall
    test %rax,%rax
    jne failed
    mov %rbx,%rdi
    xor %esi,%esi
    xor %edx,%edx
    mov $SYS_TRY_WAIT,%eax
    syscall
    cmp $-10,%rax
    jne failed
    ret

/* Report actual PID in the last 16 digits before CRLF. */
report:
    mov %rdi,%r8
    lea -3(%rsi,%rdx),%r9
    lea digits(%rip),%rdi
    mov $16,%ecx
1:
    mov %r8,%rax
    and $15,%eax
    mov (%rdi,%rax),%al
    mov %al,(%r9)
    shr $4,%r8
    dec %r9
    dec %ecx
    jnz 1b
    mov $SYS_WRITE,%eax
    mov $1,%edi
    syscall
    cmp %rdx,%rax
    jne failed
    ret

.macro WORKER label,a,b
worker_\label:
    mov %r12,%rdi
    xor %esi,%esi
    xor %edx,%edx
    mov $SYS_SLEEP_UNTIL,%eax
    syscall
    test %rax,%rax
    jne failed
    mov $SYS_GETPID,%eax
    syscall
    REPORT begin_\label,%rax
    movabs $\a,%r10
    movabs $\b,%r14
    movq %r10,%xmm0
    movq %r14,%xmm1
    punpcklqdq %xmm1,%xmm0
    movq %r14,%xmm15
    movq %r10,%xmm1
    punpcklqdq %xmm1,%xmm15
    mov $0x4000000,%ecx
.global window_\label\()_begin, window_\label\()_end
window_\label\()_begin:
    pause
    dec %rcx
    jnz window_\label\()_begin
window_\label\()_end:
    /* Independent literal checks, with no reinitialization after the loop. */
    movabs $\a,%rax
    cmp %rax,%r10
    jne failed
    movq %xmm0,%rcx
    cmp %rax,%rcx
    jne failed
    movq %xmm15,%r9
    psrldq $8,%xmm15
    movq %xmm15,%rcx
    cmp %rax,%rcx
    jne failed
    movabs $\b,%rax
    cmp %rax,%r14
    jne failed
    cmp %rax,%r9
    jne failed
    psrldq $8,%xmm0
    movq %xmm0,%rcx
    cmp %rax,%rcx
    jne failed
    mov $SYS_GETPID,%eax
    syscall
    REPORT ok_\label,%rax
    jmp success
.endm
WORKER A,0x1122334455667788,0x89abcdef01234567
WORKER B,0x76543210fedcba98,0x8877665544332211
success:
    xor %edi,%edi
    jmp terminate
failed:
    mov $91,%edi
terminate:
    mov $SYS_EXIT,%eax
    syscall
    ud2
.section .rodata
digits: .ascii "0123456789abcdef"
.data
.macro LINE label, text
\label: .ascii "\text PID=0000000000000000\r\n"
\label\()_end:
.endm
LINE root_line,"REG ROOT"
LINE child_A,"REG A"
LINE child_B,"REG B"
LINE begin_A,"REG A BEGIN"
LINE begin_B,"REG B BEGIN"
LINE ok_A,"REG A OK"
LINE ok_B,"REG B OK"
LINE reap_A,"REG A REAP"
LINE reap_B,"REG B REAP"
LINE complete_line,"REG COMPLETE"
.section .note.GNU-stack,"",@progbits
