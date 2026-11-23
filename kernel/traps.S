// x86-64, Intel syntax (included via global_asm). All gates enter at CPL0.
.section .text.traps,"ax"
.macro vector n
isr_\n:
    .if !( (\n==8)||(\n==10)||(\n==11)||(\n==12)||(\n==13)||(\n==14)||(\n==17)||(\n==21)||(\n==29)||(\n==30) )
        push 0
    .endif
    push \n
    jmp isr_common
.endm
.irp n,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31
    vector \n
.endr
isr_common:
    test byte ptr [rsp+24], 3
    jz 1f
    swapgs
1:
    cld
    .irp reg,rax,rcx,rdx,rsi,rdi,r8,r9,r10,r11,rbx
        push \reg
    .endr
    mov rbx, rsp
    lea rdi, [rbx+80]       // vector, error, saved RIP, CS and RFLAGS
    mov rsi, cr2
    mov rdx, [rbx+40]       // interrupted RDI: probe operand
    and rsp, -16
    sub rsp, 512
    fxsave64 [rsp]
    call dispatch_exception
    test rax, rax
    jnz restore_context
    fxrstor64 [rsp]
    mov rsp, rbx
    .irp reg,rbx,r11,r10,r9,r8,rdi,rsi,rdx,rcx,rax
        pop \reg
    .endr
    add rsp, 16
    // Successful user #PF/COW retry takes this direct IRETQ path rather
    // than restore_context. Undo the entry SWAPGS using saved CS at RSP+8.
    // Without it, the next user SYSCALL swaps to GS base 0 and crashes at
    // native_syscall's first gs:[8] access (observed CR2=0x8).
    test byte ptr [rsp+8], 3
    jz 9f
    swapgs
9:  iretq

.global timer_gate, serial_gate, keyboard_gate, reschedule_gate, spurious_gate, wait_for_irq, after_hlt
// Only the measured HLT path leaves RDI pointing at a pair of timestamps.
// Timestamp before saving SIMD state or acknowledging the interrupt, so its
// handler and return path are charged to active time.
.macro timestamp_idle_irq
    test byte ptr [rsp+8], 3
    jnz 8f
    push rax
    lea rax, [rip + idle_after_hlt]
    cmp [rsp+8], rax
    jne 9f
    push rdx
    lfence
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov [rdi+8], rax
    pop rdx
9:  pop rax
8:
.endm
timer_gate:
    timestamp_idle_irq
    test byte ptr [rsp+8], 3
    jz 1f
    swapgs
1:
    cld
    .macro save_context
    .irp reg,rax,rcx,rdx,rsi,rdi,r8,r9,r10,r11,rbx,rbp,r12,r13,r14,r15
        push \reg
    .endr
    // The CPU aligned the stack before its five pushes. Fifteen GPRs
    // complete the alignment needed by FXSAVE and the SysV call.
    sub rsp, 512
    fxsave64 [rsp]
    mov rdi, rsp
    .endm
    save_context
    call timer_interrupt
    jmp restore_context
serial_gate:
    test byte ptr [rsp+8], 3
    jz 1f
    swapgs
1:
    cld
    save_context
    call serial_interrupt
    jmp restore_context
keyboard_gate:
    test byte ptr [rsp+8], 3
    jz 1f
    swapgs
1:
    cld
    save_context
    call keyboard_interrupt
    jmp restore_context
.macro device_gate name, vector
    .global \name
\name:
    test byte ptr [rsp+8], 3
    jz 1f
    swapgs
1:
    cld
    save_context
    mov esi, \vector
    call pci_interrupt
    jmp restore_context
.endm
device_gate msi_gate, 0xe4
device_gate msix_gate, 0xe5
reschedule_gate:
    test byte ptr [rsp+8], 3
    jz 1f
    swapgs
1:
    cld
    save_context
    call reschedule_interrupt
restore_context:
    mov rsp, rax
    // A queue may publish the outgoing stack only after RSP has actually
    // left it. FXSAVE/GPR state remains intact above this callback's stack.
    call finish_context_switch
    fxrstor64 [rsp]
    add rsp, 512
    .irp reg,r15,r14,r13,r12,rbp,rbx,r11,r10,r9,r8,rdi,rsi,rdx,rcx,rax
        pop \reg
    .endr
    test byte ptr [rsp+8], 3
    jz 1f
    swapgs
1:
    iretq
.global native_syscall
native_syscall:
    // SYSCALL saves RIP/RFLAGS in RCX/R11 but does not switch RSP.
    // FMASK disabled interrupts before this first instruction.
    swapgs
    mov gs:[8], rsp
    mov rsp, gs:[16]
    push 0x2b
    push qword ptr gs:[8]
    push r11
    push 0x33
    push rcx
    save_context
    call dispatch_syscall
    jmp restore_context
.global task_return
task_return:
    call finish_task
    ud2

.global check_preempted_registers
check_preempted_registers:
    mov r10, rsi
    movq xmm0, rsi
    mov ecx, [rdi]
1:
    pause
    mov eax, [rdi]
    sub eax, ecx
    cmp eax, 8
    jb 1b
    movq rax, xmm0
    cmp rax, r10
    je 2f
    xor eax, eax
2:
    ret
spurious_gate:
    timestamp_idle_irq
    // IRETQ must not consume a noncanonical user RSP in kernel mode.
    test byte ptr [rsp+8], 3
    jz 1f
    cmp dword ptr [rsp+28], 0x7fff
    jbe 1f
    push 0
    jmp isr_13
1:
    iretq
.global idle_wait
idle_wait:
    lfence
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov [rdi], rax
    sti
    hlt
idle_after_hlt:
    cli
    ret
wait_for_irq:
    sti
    hlt
after_hlt:
    cli
    ret

.global load_descriptors
load_descriptors:
    lgdt [rdi]
    push 8
    lea rax, [rip + reload_cs]
    push rax
    retfq
reload_cs:
    mov ax, 16
    mov ss, ax
    mov ds, ax
    mov es, ax
    mov ax, 24
    ltr ax
    lidt [rsi]
    ret

// A successful recovery redirects to probe_pass; the ordinary path returns 0.
.global probe_break, after_break, probe_read, read_site, probe_ro, write_site
.global probe_nx, nx_target, probe_pass
probe_break:
    int3
after_break:
    xor eax, eax
    ret
probe_read:
read_site:
    mov rax, [rdi]
    xor eax, eax
    ret
probe_ro:
write_site:
    mov byte ptr [rdi], 0xc3
    xor eax, eax
    ret
probe_nx:
    xor eax, eax
    jmp rdi
probe_pass:
    mov eax, 1
    ret
.section .rodata.traps,"a"
nx_target:
    .byte 0xc3
.balign 8
.global vectors
vectors:
    .irp n,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31
        .quad isr_\n
    .endr
