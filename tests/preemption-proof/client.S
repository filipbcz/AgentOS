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
#ifdef PREEMPT_CPUS
/* Bounded normal fork/yield setup; retain runnable competitors for the
 * ordinary load balancer. No affinity or assumed worker-to-CPU mapping. */
#if PREEMPT_CPUS != 2 && PREEMPT_CPUS != 4 && PREEMPT_CPUS != 8
#error Unsupported proof profile
#endif
.macro SPAWN_WORKER label
.Lspawn_\label:
    mov $SYS_MONOTONIC_MS,%eax
    syscall
    test %rax,%rax
    js failed
    cmp %r12,%rax
    jae failed
    mov $SYS_FORK,%eax
    syscall
    cmp $-11,%rax
    je .Lretry_\label
    test %rax,%rax
    js failed
    jz worker_\label
    mov %rax,pid_\label(%rip)
    REPORT child_\label,%rax
    mov $SYS_YIELD,%eax
    syscall
    test %rax,%rax
    jne failed
    jmp .Lspawned_\label
.Lretry_\label:
    mov $SYS_YIELD,%eax
    syscall
    test %rax,%rax
    jne failed
    jmp .Lspawn_\label
.Lspawned_\label:
.endm
.macro REAP_WORKER label
    mov pid_\label(%rip),%rdi
    call reap
    mov pid_\label(%rip),%rdi
    REPORT reap_\label,%rdi
.endm
_start:
    mov $SYS_GETPID,%eax
    syscall
    test %rax,%rax
    jle failed
    REPORT root_line,%rax
    mov $SYS_MONOTONIC_MS,%eax
    syscall
    test %rax,%rax
    js failed
    lea 6000(%rax),%r12
    lea 60000(%r12),%r13
#if PREEMPT_CPUS * 2 > 0
    SPAWN_WORKER A
#endif
#if PREEMPT_CPUS * 2 > 1
    SPAWN_WORKER B
#endif
#if PREEMPT_CPUS * 2 > 2
    SPAWN_WORKER C
#endif
#if PREEMPT_CPUS * 2 > 3
    SPAWN_WORKER D
#endif
#if PREEMPT_CPUS * 2 > 4
    SPAWN_WORKER E
#endif
#if PREEMPT_CPUS * 2 > 5
    SPAWN_WORKER F
#endif
#if PREEMPT_CPUS * 2 > 6
    SPAWN_WORKER G
#endif
#if PREEMPT_CPUS * 2 > 7
    SPAWN_WORKER H
#endif
#if PREEMPT_CPUS * 2 > 8
    SPAWN_WORKER I
#endif
#if PREEMPT_CPUS * 2 > 9
    SPAWN_WORKER J
#endif
#if PREEMPT_CPUS * 2 > 10
    SPAWN_WORKER K
#endif
#if PREEMPT_CPUS * 2 > 11
    SPAWN_WORKER L
#endif
#if PREEMPT_CPUS * 2 > 12
    SPAWN_WORKER M
#endif
#if PREEMPT_CPUS * 2 > 13
    SPAWN_WORKER N
#endif
#if PREEMPT_CPUS * 2 > 14
    SPAWN_WORKER O
#endif
#if PREEMPT_CPUS * 2 > 15
    SPAWN_WORKER P
#endif
    mov $SYS_MONOTONIC_MS,%eax
    syscall
    test %rax,%rax
    js failed
    cmp %r12,%rax
    jae failed
#if PREEMPT_CPUS * 2 > 0
    REAP_WORKER A
#endif
#if PREEMPT_CPUS * 2 > 1
    REAP_WORKER B
#endif
#if PREEMPT_CPUS * 2 > 2
    REAP_WORKER C
#endif
#if PREEMPT_CPUS * 2 > 3
    REAP_WORKER D
#endif
#if PREEMPT_CPUS * 2 > 4
    REAP_WORKER E
#endif
#if PREEMPT_CPUS * 2 > 5
    REAP_WORKER F
#endif
#if PREEMPT_CPUS * 2 > 6
    REAP_WORKER G
#endif
#if PREEMPT_CPUS * 2 > 7
    REAP_WORKER H
#endif
#if PREEMPT_CPUS * 2 > 8
    REAP_WORKER I
#endif
#if PREEMPT_CPUS * 2 > 9
    REAP_WORKER J
#endif
#if PREEMPT_CPUS * 2 > 10
    REAP_WORKER K
#endif
#if PREEMPT_CPUS * 2 > 11
    REAP_WORKER L
#endif
#if PREEMPT_CPUS * 2 > 12
    REAP_WORKER M
#endif
#if PREEMPT_CPUS * 2 > 13
    REAP_WORKER N
#endif
#if PREEMPT_CPUS * 2 > 14
    REAP_WORKER O
#endif
#if PREEMPT_CPUS * 2 > 15
    REAP_WORKER P
#endif
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
#else
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
#endif

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
#ifdef PREEMPT_CPUS
.Lready_\label:
    mov $SYS_MONOTONIC_MS,%eax
    syscall
    test %rax,%rax
    js failed
    cmp %r12,%rax
    jae .Lbegin_\label
    mov $SYS_YIELD,%eax
    syscall
    test %rax,%rax
    jne failed
    jmp .Lready_\label
.Lbegin_\label:
#else
    mov %r12,%rdi
    xor %esi,%esi
    xor %edx,%edx
    mov $SYS_SLEEP_UNTIL,%eax
    syscall
    test %rax,%rax
    jne failed
#endif
    mov $SYS_GETPID,%eax
    syscall
    REPORT begin_\label,%rax
#ifdef PREEMPT_CPUS
    .p2align 4
#endif
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
#ifdef PREEMPT_CPUS
#if PREEMPT_CPUS * 2 > 0
WORKER A,0x1122334455667788,0x89abcdef01234567
#endif
#if PREEMPT_CPUS * 2 > 1
WORKER B,0x76543210fedcba98,0x8877665544332211
#endif
#if PREEMPT_CPUS * 2 > 2
WORKER C,0x132031465764758a,0x89a9cded01214565
#endif
#if PREEMPT_CPUS * 2 > 3
WORKER D,0x122130475665748b,0x89a8cdec01204564
#endif
#if PREEMPT_CPUS * 2 > 4
WORKER E,0x152637405162738c,0x89afcdeb01274563
#endif
#if PREEMPT_CPUS * 2 > 5
WORKER F,0x142736415063728d,0x89aecdea01264562
#endif
#if PREEMPT_CPUS * 2 > 6
WORKER G,0x172435425360718e,0x89adcde901254561
#endif
#if PREEMPT_CPUS * 2 > 7
WORKER H,0x162534435261708f,0x89accde801244560
#endif
#if PREEMPT_CPUS * 2 > 8
WORKER I,0x192a3b4c5d6e7f80,0x89a3cde7012b456f
#endif
#if PREEMPT_CPUS * 2 > 9
WORKER J,0x182b3a4d5c6f7e81,0x89a2cde6012a456e
#endif
#if PREEMPT_CPUS * 2 > 10
WORKER K,0x1b28394e5f6c7d82,0x89a1cde50129456d
#endif
#if PREEMPT_CPUS * 2 > 11
WORKER L,0x1a29384f5e6d7c83,0x89a0cde40128456c
#endif
#if PREEMPT_CPUS * 2 > 12
WORKER M,0x1d2e3f48596a7b84,0x89a7cde3012f456b
#endif
#if PREEMPT_CPUS * 2 > 13
WORKER N,0x1c2f3e49586b7a85,0x89a6cde2012e456a
#endif
#if PREEMPT_CPUS * 2 > 14
WORKER O,0x1f2c3d4a5b687986,0x89a5cde1012d4569
#endif
#if PREEMPT_CPUS * 2 > 15
WORKER P,0x1e2d3c4b5a697887,0x89a4cde0012c4568
#endif
#else
WORKER A,0x1122334455667788,0x89abcdef01234567
WORKER B,0x76543210fedcba98,0x8877665544332211
#endif
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
#ifdef PREEMPT_CPUS
#if PREEMPT_CPUS * 2 > 0
LINE child_A,"REG A"
LINE begin_A,"REG A BEGIN"
LINE ok_A,"REG A OK"
LINE reap_A,"REG A REAP"
.balign 8
pid_A: .quad 0
#endif
#if PREEMPT_CPUS * 2 > 1
LINE child_B,"REG B"
LINE begin_B,"REG B BEGIN"
LINE ok_B,"REG B OK"
LINE reap_B,"REG B REAP"
.balign 8
pid_B: .quad 0
#endif
#if PREEMPT_CPUS * 2 > 2
LINE child_C,"REG C"
LINE begin_C,"REG C BEGIN"
LINE ok_C,"REG C OK"
LINE reap_C,"REG C REAP"
.balign 8
pid_C: .quad 0
#endif
#if PREEMPT_CPUS * 2 > 3
LINE child_D,"REG D"
LINE begin_D,"REG D BEGIN"
LINE ok_D,"REG D OK"
LINE reap_D,"REG D REAP"
.balign 8
pid_D: .quad 0
#endif
#if PREEMPT_CPUS * 2 > 4
LINE child_E,"REG E"
LINE begin_E,"REG E BEGIN"
LINE ok_E,"REG E OK"
LINE reap_E,"REG E REAP"
.balign 8
pid_E: .quad 0
#endif
#if PREEMPT_CPUS * 2 > 5
LINE child_F,"REG F"
LINE begin_F,"REG F BEGIN"
LINE ok_F,"REG F OK"
LINE reap_F,"REG F REAP"
.balign 8
pid_F: .quad 0
#endif
#if PREEMPT_CPUS * 2 > 6
LINE child_G,"REG G"
LINE begin_G,"REG G BEGIN"
LINE ok_G,"REG G OK"
LINE reap_G,"REG G REAP"
.balign 8
pid_G: .quad 0
#endif
#if PREEMPT_CPUS * 2 > 7
LINE child_H,"REG H"
LINE begin_H,"REG H BEGIN"
LINE ok_H,"REG H OK"
LINE reap_H,"REG H REAP"
.balign 8
pid_H: .quad 0
#endif
#if PREEMPT_CPUS * 2 > 8
LINE child_I,"REG I"
LINE begin_I,"REG I BEGIN"
LINE ok_I,"REG I OK"
LINE reap_I,"REG I REAP"
.balign 8
pid_I: .quad 0
#endif
#if PREEMPT_CPUS * 2 > 9
LINE child_J,"REG J"
LINE begin_J,"REG J BEGIN"
LINE ok_J,"REG J OK"
LINE reap_J,"REG J REAP"
.balign 8
pid_J: .quad 0
#endif
#if PREEMPT_CPUS * 2 > 10
LINE child_K,"REG K"
LINE begin_K,"REG K BEGIN"
LINE ok_K,"REG K OK"
LINE reap_K,"REG K REAP"
.balign 8
pid_K: .quad 0
#endif
#if PREEMPT_CPUS * 2 > 11
LINE child_L,"REG L"
LINE begin_L,"REG L BEGIN"
LINE ok_L,"REG L OK"
LINE reap_L,"REG L REAP"
.balign 8
pid_L: .quad 0
#endif
#if PREEMPT_CPUS * 2 > 12
LINE child_M,"REG M"
LINE begin_M,"REG M BEGIN"
LINE ok_M,"REG M OK"
LINE reap_M,"REG M REAP"
.balign 8
pid_M: .quad 0
#endif
#if PREEMPT_CPUS * 2 > 13
LINE child_N,"REG N"
LINE begin_N,"REG N BEGIN"
LINE ok_N,"REG N OK"
LINE reap_N,"REG N REAP"
.balign 8
pid_N: .quad 0
#endif
#if PREEMPT_CPUS * 2 > 14
LINE child_O,"REG O"
LINE begin_O,"REG O BEGIN"
LINE ok_O,"REG O OK"
LINE reap_O,"REG O REAP"
.balign 8
pid_O: .quad 0
#endif
#if PREEMPT_CPUS * 2 > 15
LINE child_P,"REG P"
LINE begin_P,"REG P BEGIN"
LINE ok_P,"REG P OK"
LINE reap_P,"REG P REAP"
.balign 8
pid_P: .quad 0
#endif
#else
LINE child_A,"REG A"
LINE child_B,"REG B"
LINE begin_A,"REG A BEGIN"
LINE begin_B,"REG B BEGIN"
LINE ok_A,"REG A OK"
LINE ok_B,"REG B OK"
LINE reap_A,"REG A REAP"
LINE reap_B,"REG B REAP"
#endif
LINE complete_line,"REG COMPLETE"
.section .note.GNU-stack,"",@progbits
