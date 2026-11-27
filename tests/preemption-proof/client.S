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
/* Every diagnostic stub is outside the successful instruction path. RAX is
 * captured before any other syscall; the stage-specific exit survives even
 * a failed/short diagnostic write. Zero slot/child denotes not applicable. */
.macro DIAG name,code,slot=0,child=none,early=0
.pushsection .text.diag,"ax"
\name:
    mov %rax,%r15
    mov $\code,%r14d
    mov $\slot,%ebp
    .ifc \child,none
    xor %ebx,%ebx
    .else
    mov pid_\child(%rip),%rbx
    .endif
    .if \early
    xor %r12d,%r12d
    xor %r13d,%r13d
    .endif
    xor %r10d,%r10d
    jmp diag_emit
.popsection
.endm
.macro SENTINEL name,code,slot,actual
.pushsection .text.diag,"ax"
\name:
    mov %rax,%r11
    mov \actual,%r15
    mov %r11,%r10
    mov $\code,%r14d
    mov $\slot,%ebp
    xor %ebx,%ebx
    jmp diag_emit
.popsection
.endm
.macro SPAWN_WORKER label,slot
.Lspawn_\label:
    mov $SYS_MONOTONIC_MS,%eax
    syscall
    test %rax,%rax
    js diag_spawn_clock_\label
    cmp %r12,%rax
    jae diag_spawn_limit_\label
    mov $SYS_FORK,%eax
    syscall
    cmp $-11,%rax
    je .Lretry_\label
    test %rax,%rax
    js diag_fork_\label
    jz worker_\label
    mov %rax,pid_\label(%rip)
    REPORT child_\label,%rax
    mov $SYS_YIELD,%eax
    syscall
    test %rax,%rax
    jne diag_yield_\label
    jmp .Lspawned_\label
.Lretry_\label:
    mov $SYS_YIELD,%eax
    syscall
    test %rax,%rax
    jne diag_retry_yield_\label
    jmp .Lspawn_\label
.Lspawned_\label:
    DIAG diag_spawn_clock_\label,103,\slot,\label
    DIAG diag_spawn_limit_\label,104,\slot,\label
    DIAG diag_fork_\label,105,\slot,\label
    DIAG diag_yield_\label,106,\slot,\label
    DIAG diag_retry_yield_\label,107,\slot,\label
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
    jle diag_root_pid
    REPORT root_line,%rax
    mov $SYS_MONOTONIC_MS,%eax
    syscall
    test %rax,%rax
    js diag_root_clock
    lea 6000(%rax),%r12
    lea 60000(%r12),%r13
#if PREEMPT_CPUS * 2 > 0
    SPAWN_WORKER A,1
#endif
#if PREEMPT_CPUS * 2 > 1
    SPAWN_WORKER B,2
#endif
#if PREEMPT_CPUS * 2 > 2
    SPAWN_WORKER C,3
#endif
#if PREEMPT_CPUS * 2 > 3
    SPAWN_WORKER D,4
#endif
#if PREEMPT_CPUS * 2 > 4
    SPAWN_WORKER E,5
#endif
#if PREEMPT_CPUS * 2 > 5
    SPAWN_WORKER F,6
#endif
#if PREEMPT_CPUS * 2 > 6
    SPAWN_WORKER G,7
#endif
#if PREEMPT_CPUS * 2 > 7
    SPAWN_WORKER H,8
#endif
#if PREEMPT_CPUS * 2 > 8
    SPAWN_WORKER I,9
#endif
#if PREEMPT_CPUS * 2 > 9
    SPAWN_WORKER J,10
#endif
#if PREEMPT_CPUS * 2 > 10
    SPAWN_WORKER K,11
#endif
#if PREEMPT_CPUS * 2 > 11
    SPAWN_WORKER L,12
#endif
#if PREEMPT_CPUS * 2 > 12
    SPAWN_WORKER M,13
#endif
#if PREEMPT_CPUS * 2 > 13
    SPAWN_WORKER N,14
#endif
#if PREEMPT_CPUS * 2 > 14
    SPAWN_WORKER O,15
#endif
#if PREEMPT_CPUS * 2 > 15
    SPAWN_WORKER P,16
#endif
    mov $SYS_MONOTONIC_MS,%eax
    syscall
    test %rax,%rax
    js diag_post_clock
    cmp %r12,%rax
    jae diag_post_limit
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
    jne diag_child_check
    mov $SYS_GETPID,%eax
    syscall
    REPORT complete_line,%rax
    jmp success
    DIAG diag_root_pid,101,0,none,1
    DIAG diag_root_clock,102,0,none,1
    DIAG diag_post_clock,108
    DIAG diag_post_limit,109
    DIAG diag_child_check,112
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
#ifdef PREEMPT_CPUS
    jne diag_wait
#else
    jne failed
#endif
    mov %rbx,%rdi
    xor %esi,%esi
    xor %edx,%edx
    mov $SYS_TRY_WAIT,%eax
    syscall
    cmp $-10,%rax
#ifdef PREEMPT_CPUS
    jne diag_try_wait
#else
    jne failed
#endif
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
#ifdef PREEMPT_CPUS
    jne diag_report
#else
    jne failed
#endif
    ret

.macro WORKER label,a,b,slot=0
worker_\label:
#ifdef PREEMPT_CPUS
.Lready_\label:
    mov $SYS_MONOTONIC_MS,%eax
    syscall
    test %rax,%rax
    js diag_worker_clock_\label
    cmp %r12,%rax
    jae .Lbegin_\label
    mov $SYS_YIELD,%eax
    syscall
    test %rax,%rax
    jne diag_worker_yield_\label
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
#if defined(PREEMPT_CPUS) && (PREEMPT_CPUS == 4 || PREEMPT_CPUS == 8)
    /* A fixed bounded window, not a soak. The observer must still prove
     * all six real local IRQ switches and normal completion independently. */
    mov $0x100000,%ecx
#else
    mov $0x4000000,%ecx
#endif
.global window_\label\()_begin, window_\label\()_end
window_\label\()_begin:
    pause
    dec %rcx
    jnz window_\label\()_begin
window_\label\()_end:
    /* Independent literal checks, with no reinitialization after the loop. */
    movabs $\a,%rax
    cmp %rax,%r10
#ifdef PREEMPT_CPUS
    jne diag_bad_r10_\label
#else
    jne failed
#endif
    movq %xmm0,%rcx
    cmp %rax,%rcx
#ifdef PREEMPT_CPUS
    jne diag_bad_xmm0lo_\label
#else
    jne failed
#endif
    movq %xmm15,%r9
    psrldq $8,%xmm15
    movq %xmm15,%rcx
    cmp %rax,%rcx
#ifdef PREEMPT_CPUS
    jne diag_bad_xmm15hi_\label
#else
    jne failed
#endif
    movabs $\b,%rax
    cmp %rax,%r14
#ifdef PREEMPT_CPUS
    jne diag_bad_r14_\label
#else
    jne failed
#endif
    cmp %rax,%r9
#ifdef PREEMPT_CPUS
    jne diag_bad_xmm15lo_\label
#else
    jne failed
#endif
    psrldq $8,%xmm0
    movq %xmm0,%rcx
    cmp %rax,%rcx
#ifdef PREEMPT_CPUS
    jne diag_bad_xmm0hi_\label
#else
    jne failed
#endif
    mov $SYS_GETPID,%eax
    syscall
    REPORT ok_\label,%rax
    jmp success
#ifdef PREEMPT_CPUS
    DIAG diag_worker_clock_\label,113,\slot
    DIAG diag_worker_yield_\label,114,\slot
    SENTINEL diag_bad_r10_\label,115,\slot,%r10
    SENTINEL diag_bad_xmm0lo_\label,116,\slot,%rcx
    SENTINEL diag_bad_xmm15hi_\label,117,\slot,%rcx
    SENTINEL diag_bad_r14_\label,118,\slot,%r14
    SENTINEL diag_bad_xmm15lo_\label,119,\slot,%r9
    SENTINEL diag_bad_xmm0hi_\label,120,\slot,%rcx
#endif
.endm
#ifdef PREEMPT_CPUS
#if PREEMPT_CPUS * 2 > 0
WORKER A,0x1122334455667788,0x89abcdef01234567,1
#endif
#if PREEMPT_CPUS * 2 > 1
WORKER B,0x76543210fedcba98,0x8877665544332211,2
#endif
#if PREEMPT_CPUS * 2 > 2
WORKER C,0x132031465764758a,0x89a9cded01214565,3
#endif
#if PREEMPT_CPUS * 2 > 3
WORKER D,0x122130475665748b,0x89a8cdec01204564,4
#endif
#if PREEMPT_CPUS * 2 > 4
WORKER E,0x152637405162738c,0x89afcdeb01274563,5
#endif
#if PREEMPT_CPUS * 2 > 5
WORKER F,0x142736415063728d,0x89aecdea01264562,6
#endif
#if PREEMPT_CPUS * 2 > 6
WORKER G,0x172435425360718e,0x89adcde901254561,7
#endif
#if PREEMPT_CPUS * 2 > 7
WORKER H,0x162534435261708f,0x89accde801244560,8
#endif
#if PREEMPT_CPUS * 2 > 8
WORKER I,0x192a3b4c5d6e7f80,0x89a3cde7012b456f,9
#endif
#if PREEMPT_CPUS * 2 > 9
WORKER J,0x182b3a4d5c6f7e81,0x89a2cde6012a456e,10
#endif
#if PREEMPT_CPUS * 2 > 10
WORKER K,0x1b28394e5f6c7d82,0x89a1cde50129456d,11
#endif
#if PREEMPT_CPUS * 2 > 11
WORKER L,0x1a29384f5e6d7c83,0x89a0cde40128456c,12
#endif
#if PREEMPT_CPUS * 2 > 12
WORKER M,0x1d2e3f48596a7b84,0x89a7cde3012f456b,13
#endif
#if PREEMPT_CPUS * 2 > 13
WORKER N,0x1c2f3e49586b7a85,0x89a6cde2012e456a,14
#endif
#if PREEMPT_CPUS * 2 > 14
WORKER O,0x1f2c3d4a5b687986,0x89a5cde1012d4569,15
#endif
#if PREEMPT_CPUS * 2 > 15
WORKER P,0x1e2d3c4b5a697887,0x89a4cde0012c4568,16
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
#ifdef PREEMPT_CPUS
/* Codes 101..127 are stable failure causes, not a successful test marker.
 * For 103/104/108/109 RAW is the original clock sample/errno; NOW is an
 * independent post-failure sample. 115..120 RAW is the compared register
 * value and DETAIL its expected sentinel, rather than a syscall result.
 * WRITE failures retain the byte count in DETAIL and the actual return RAW. */
.pushsection .text.diag,"ax"
diag_wait:
    mov %rax,%r15
    mov $110,%r14d
    jmp diag_reap_slot
diag_try_wait:
    mov %rax,%r15
    mov $111,%r14d
diag_reap_slot:
    xor %r10d,%r10d
    xor %ebp,%ebp
    lea diag_pid_table(%rip),%r8
    mov $(2*PREEMPT_CPUS),%ecx
1:
    inc %ebp
    mov (%r8),%r9
    cmp (%r9),%rbx
    je diag_emit
    add $8,%r8
    dec %ecx
    jnz 1b
    xor %ebp,%ebp
    jmp diag_emit

diag_report:
    mov %rax,%r15
    mov %rdx,%r10
    mov $127,%r14d
    xor %ebp,%ebp
    xor %ebx,%ebx
    lea diag_report_table(%rip),%r8
    lea diag_report_end(%rip),%r9
1:
    cmp %r9,%r8
    jae diag_emit
    cmp (%r8),%rsi
    je 2f
    add $24,%r8
    jmp 1b
2:
    mov 8(%r8),%r14
    mov 16(%r8),%rbp
    cmp $121,%r14
    jne 3f
    xor %r12d,%r12d
    xor %r13d,%r13d
3:
    cmp $122,%r14
    je 4f
    cmp $125,%r14
    jne diag_emit
4:
    lea diag_pid_table(%rip),%r8
    mov -8(%r8,%rbp,8),%r8
    mov (%r8),%rbx
    jmp diag_emit

/* Error-only formatter. R14/R15/R12/R13/RBP/RBX/R10 hold the original
 * metadata; hex formatting only uses RAX/RCX/RDI/RSI/R8. R9 and RDX retain
 * the independently sampled PID/time. Nothing returns to the caller. */
.macro PUT_FIELD field,value
    mov \value,%rax
    lea diag_\field+16(%rip),%rdi
    call diag_hex
.endm
diag_emit:
    mov $SYS_GETPID,%eax
    syscall
    mov %rax,%r9
    mov $SYS_MONOTONIC_MS,%eax
    syscall
    mov %rax,%rdx
    PUT_FIELD step,%r14
    PUT_FIELD pid,%r9
    PUT_FIELD slot,%rbp
    PUT_FIELD child,%rbx
    PUT_FIELD raw,%r15
    PUT_FIELD now,%rdx
    PUT_FIELD setup,%r12
    PUT_FIELD wait_field,%r13
    PUT_FIELD detail,%r10
    mov $SYS_WRITE,%eax
    mov $1,%edi
    lea diag_line(%rip),%rsi
    mov $diag_line_end-diag_line,%edx
    syscall
    /* Ignore diagnostic write result, including short writes and errno. */
    mov %r14d,%edi
    jmp terminate
diag_hex:
    lea digits(%rip),%rsi
    mov $16,%ecx
1:
    mov %rax,%r8
    and $15,%r8d
    mov (%rsi,%r8),%r8b
    dec %rdi
    mov %r8b,(%rdi)
    shr $4,%rax
    dec %ecx
    jnz 1b
    ret
.popsection
.pushsection .rodata.diag_reports,"a"
.balign 8
diag_report_table:
.popsection
.pushsection .rodata.diag_pids,"a"
.balign 8
diag_pid_table:
.popsection
#endif
.section .rodata
digits: .ascii "0123456789abcdef"
.data
.macro LINE label, text, step=0,slot=0
\label: .ascii "\text PID=0000000000000000\r\n"
\label\()_end:
#ifdef PREEMPT_CPUS
    .if \step
    .pushsection .rodata.diag_reports,"a"
    .quad \label,\step,\slot
    .popsection
    .endif
#endif
.endm
LINE root_line,"REG ROOT",121,0
#ifdef PREEMPT_CPUS
#if PREEMPT_CPUS * 2 > 0
LINE child_A,"REG A",122,1
LINE begin_A,"REG A BEGIN",123,1
LINE ok_A,"REG A OK",124,1
LINE reap_A,"REG A REAP",125,1
.balign 8
pid_A: .quad 0
.pushsection .rodata.diag_pids,"a"
.quad pid_A
.popsection
#endif
#if PREEMPT_CPUS * 2 > 1
LINE child_B,"REG B",122,2
LINE begin_B,"REG B BEGIN",123,2
LINE ok_B,"REG B OK",124,2
LINE reap_B,"REG B REAP",125,2
.balign 8
pid_B: .quad 0
.pushsection .rodata.diag_pids,"a"
.quad pid_B
.popsection
#endif
#if PREEMPT_CPUS * 2 > 2
LINE child_C,"REG C",122,3
LINE begin_C,"REG C BEGIN",123,3
LINE ok_C,"REG C OK",124,3
LINE reap_C,"REG C REAP",125,3
.balign 8
pid_C: .quad 0
.pushsection .rodata.diag_pids,"a"
.quad pid_C
.popsection
#endif
#if PREEMPT_CPUS * 2 > 3
LINE child_D,"REG D",122,4
LINE begin_D,"REG D BEGIN",123,4
LINE ok_D,"REG D OK",124,4
LINE reap_D,"REG D REAP",125,4
.balign 8
pid_D: .quad 0
.pushsection .rodata.diag_pids,"a"
.quad pid_D
.popsection
#endif
#if PREEMPT_CPUS * 2 > 4
LINE child_E,"REG E",122,5
LINE begin_E,"REG E BEGIN",123,5
LINE ok_E,"REG E OK",124,5
LINE reap_E,"REG E REAP",125,5
.balign 8
pid_E: .quad 0
.pushsection .rodata.diag_pids,"a"
.quad pid_E
.popsection
#endif
#if PREEMPT_CPUS * 2 > 5
LINE child_F,"REG F",122,6
LINE begin_F,"REG F BEGIN",123,6
LINE ok_F,"REG F OK",124,6
LINE reap_F,"REG F REAP",125,6
.balign 8
pid_F: .quad 0
.pushsection .rodata.diag_pids,"a"
.quad pid_F
.popsection
#endif
#if PREEMPT_CPUS * 2 > 6
LINE child_G,"REG G",122,7
LINE begin_G,"REG G BEGIN",123,7
LINE ok_G,"REG G OK",124,7
LINE reap_G,"REG G REAP",125,7
.balign 8
pid_G: .quad 0
.pushsection .rodata.diag_pids,"a"
.quad pid_G
.popsection
#endif
#if PREEMPT_CPUS * 2 > 7
LINE child_H,"REG H",122,8
LINE begin_H,"REG H BEGIN",123,8
LINE ok_H,"REG H OK",124,8
LINE reap_H,"REG H REAP",125,8
.balign 8
pid_H: .quad 0
.pushsection .rodata.diag_pids,"a"
.quad pid_H
.popsection
#endif
#if PREEMPT_CPUS * 2 > 8
LINE child_I,"REG I",122,9
LINE begin_I,"REG I BEGIN",123,9
LINE ok_I,"REG I OK",124,9
LINE reap_I,"REG I REAP",125,9
.balign 8
pid_I: .quad 0
.pushsection .rodata.diag_pids,"a"
.quad pid_I
.popsection
#endif
#if PREEMPT_CPUS * 2 > 9
LINE child_J,"REG J",122,10
LINE begin_J,"REG J BEGIN",123,10
LINE ok_J,"REG J OK",124,10
LINE reap_J,"REG J REAP",125,10
.balign 8
pid_J: .quad 0
.pushsection .rodata.diag_pids,"a"
.quad pid_J
.popsection
#endif
#if PREEMPT_CPUS * 2 > 10
LINE child_K,"REG K",122,11
LINE begin_K,"REG K BEGIN",123,11
LINE ok_K,"REG K OK",124,11
LINE reap_K,"REG K REAP",125,11
.balign 8
pid_K: .quad 0
.pushsection .rodata.diag_pids,"a"
.quad pid_K
.popsection
#endif
#if PREEMPT_CPUS * 2 > 11
LINE child_L,"REG L",122,12
LINE begin_L,"REG L BEGIN",123,12
LINE ok_L,"REG L OK",124,12
LINE reap_L,"REG L REAP",125,12
.balign 8
pid_L: .quad 0
.pushsection .rodata.diag_pids,"a"
.quad pid_L
.popsection
#endif
#if PREEMPT_CPUS * 2 > 12
LINE child_M,"REG M",122,13
LINE begin_M,"REG M BEGIN",123,13
LINE ok_M,"REG M OK",124,13
LINE reap_M,"REG M REAP",125,13
.balign 8
pid_M: .quad 0
.pushsection .rodata.diag_pids,"a"
.quad pid_M
.popsection
#endif
#if PREEMPT_CPUS * 2 > 13
LINE child_N,"REG N",122,14
LINE begin_N,"REG N BEGIN",123,14
LINE ok_N,"REG N OK",124,14
LINE reap_N,"REG N REAP",125,14
.balign 8
pid_N: .quad 0
.pushsection .rodata.diag_pids,"a"
.quad pid_N
.popsection
#endif
#if PREEMPT_CPUS * 2 > 14
LINE child_O,"REG O",122,15
LINE begin_O,"REG O BEGIN",123,15
LINE ok_O,"REG O OK",124,15
LINE reap_O,"REG O REAP",125,15
.balign 8
pid_O: .quad 0
.pushsection .rodata.diag_pids,"a"
.quad pid_O
.popsection
#endif
#if PREEMPT_CPUS * 2 > 15
LINE child_P,"REG P",122,16
LINE begin_P,"REG P BEGIN",123,16
LINE ok_P,"REG P OK",124,16
LINE reap_P,"REG P REAP",125,16
.balign 8
pid_P: .quad 0
.pushsection .rodata.diag_pids,"a"
.quad pid_P
.popsection
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
LINE complete_line,"REG COMPLETE",126,0
#ifdef PREEMPT_CPUS
.pushsection .rodata.diag_reports,"a"
diag_report_end:
.popsection
diag_line: .ascii "REG FAIL STEP="
diag_step: .ascii "0000000000000000 PID="
diag_pid: .ascii "0000000000000000 SLOT="
diag_slot: .ascii "0000000000000000 CHILD="
diag_child: .ascii "0000000000000000 RAW="
diag_raw: .ascii "0000000000000000 NOW="
diag_now: .ascii "0000000000000000 SETUP="
diag_setup: .ascii "0000000000000000 WAIT="
diag_wait_field: .ascii "0000000000000000 DETAIL="
diag_detail: .ascii "0000000000000000\r\n"
diag_line_end:
#endif
.section .note.GNU-stack,"",@progbits
