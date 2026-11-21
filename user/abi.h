#ifndef AGENTOS_ABI_H
#define AGENTOS_ABI_H

#define SYS_GETPID   0x10001
#define SYS_WRITE    0x10002
#define SYS_EXIT     0x10003
#define SYS_SPAWN    0x10004
#define SYS_TRY_WAIT 0x10005
#define SYS_YIELD    0x10006
#define SYS_OPEN     0x10007
#define SYS_READ     0x10008
#define SYS_CLOSE    0x10009
#define SYS_PIPE     0x1000a
#define SYS_DUP2     0x1000b
#define SYS_IPC_PAIR 0x1000c
#define SYS_IPC_SEND 0x1000d
#define SYS_IPC_RECV 0x1000e
#define SYS_KILL     0x1000f
#define SYS_MONOTONIC_MS 0x10010

/* SYS_MONOTONIC_MS: nonnegative milliseconds since owning CPU's epoch.
 * Per-CPU only; a process is currently pinned to its CPU. Not UTC and not
 * synchronized between CPUs. Returns -5 if the calibrated source is absent.
 */
/* SYS_KILL(pid): a process may terminate only its direct child.
 * The child becomes a reapable zombie with exit status 137.
 * Returns 0 when newly terminated and 1 if already a zombie; unknown PID -3,
 * unrelated PID -1, zero/self -22. This is not a general signal ABI. */
#define IPC_MAX_MESSAGE 1024

#ifndef __ASSEMBLER__
/* IPC_PAIR stores two 32-bit descriptors. Each endpoint can send and receive.
 * IPC_SEND accepts 1..IPC_MAX_MESSAGE payload bytes and returns their count.
 * IPC_RECV's capacity and return value count only payload bytes. Its destination
 * must reserve sizeof(struct ipc_peer) + capacity bytes: kernel-derived identity
 * first, then one complete payload. A short capacity (-90) or invalid destination
 * (-14) leaves the message queued. A drained, closed peer returns 0; send returns
 * -32 after the peer's last descriptor closes. dup2/spawn retain endpoint refs.
 */
struct ipc_peer { unsigned long pid; unsigned uid, gid; };
_Static_assert(sizeof(struct ipc_peer) == 16, "IPC peer layout");
static inline long os_call(long op, long a, long b, long c) {
    __asm__ volatile ("syscall" : "+a"(op) : "D"(a), "S"(b), "d"(c) : "rcx","r11","cc","memory");
    return op;
}
static inline void format_hex(char *out, unsigned long value, unsigned digits) {
    while (digits) {
        out[--digits] = "0123456789abcdef"[value & 15];
        value >>= 4;
    }
}
#endif
#endif
