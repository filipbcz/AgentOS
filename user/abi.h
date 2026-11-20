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

#ifndef __ASSEMBLER__
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
