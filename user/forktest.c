#include "abi.h"

/* Real in-guest fork/COW acceptance: both sides continue from one instruction.
 * Parent data and a previously loaded writable segment remain unchanged
 * after child writes. SYS_READ exercises kernel copy_to_user into COW .bss.
 */
static volatile unsigned long private_value = 0x19f6b5a40d73c258UL;
static unsigned char shared_buffer[64];
static const char data_file[] = "/data/transfer.bin";

static int phase(const char *event, unsigned long root, unsigned long child) {
    char line[]="AGENTOS COW BEGIN ROOT=0000000000000000 CHILD=0000000000000000\r\n";
    enum {
        ROOT_AT=sizeof("AGENTOS COW BEGIN ROOT=")-1,
        CHILD_AT=ROOT_AT+16+sizeof(" CHILD=")-1
    };
    for (unsigned i=0;i<5;i++) line[sizeof("AGENTOS COW ")-1+i]=event[i];
    format_hex(line+ROOT_AT,root,16);
    format_hex(line+CHILD_AT,child,16);
    return os_call(SYS_WRITE,1,(long)line,sizeof(line)-1)==sizeof(line)-1;
}

static void child_done(unsigned status) {
    (void)os_call(SYS_EXIT,status,0,0);
    for (;;) (void)os_call(SYS_YIELD,0,0,0);
}

int run_forktest(void) {
    long root=os_call(SYS_GETPID,0,0,0);
    if (root<=0 || private_value!=0x19f6b5a40d73c258UL) return 91;
    for (unsigned i=0;i<sizeof(shared_buffer);i++) shared_buffer[i]=0xa5;
    if (!phase("BEGIN",root,0)) return 92;
    // Both processes share a writable data page and an active user stack at
    // this point. Child starts with the same registers and return address.
    long child=os_call(SYS_FORK,0,0,0);
    if (child<0) return 93;
    if (child==0) {
        volatile unsigned long on_stack=0x07ad52c1b843e06fUL;
        if (os_call(SYS_GETPID,0,0,0)==root ||
            private_value!=0x19f6b5a40d73c258UL ||
            shared_buffer[0]!=0xa5) child_done(94);
        private_value=0x90e8a165cd270f4bUL;
        on_stack^=0x22ac19f0807d43beUL;
        if (private_value!=0x90e8a165cd270f4bUL ||
            on_stack!=0x25014b31383ea3d1UL) child_done(95);
        // Kernel writes sixteen bytes into a COW .bss page. A direct write
        // by the kernel must not corrupt the corresponding parent page.
        long fd=os_call(SYS_OPEN,(long)data_file,sizeof(data_file)-1,0);
        if (fd<0) child_done(96);
        long count=os_call(SYS_READ,fd,(long)shared_buffer,16);
        if (count!=16) child_done(97);
        for (unsigned i=0;i<16;i++) {
            if (shared_buffer[i]!=(unsigned char)((i*73)%256)) child_done(98);
        }
        if (os_call(SYS_CLOSE,fd,0,0)!=0) child_done(99);
        if (!phase("CHILD",root,(unsigned long)os_call(SYS_GETPID,0,0,0))) child_done(100);
        child_done(0);
    }
    if (child==root) return 101;
    long now=os_call(SYS_MONOTONIC_MS,0,0,0);
    if (now<0 || (unsigned long)now>0x7fffffffffffffffUL-2000) return 102;
    if (os_call(SYS_WAIT_CHILD_UNTIL,child,now+2000,0)!=0) return 103;
    if (private_value!=0x19f6b5a40d73c258UL) return 104;
    for (unsigned i=0;i<sizeof(shared_buffer);i++)
        if (shared_buffer[i]!=0xa5) return 105;
    // Last-owner promotion must be writable and must not allocate a new
    // frame after the child was reaped.
    private_value=0x74ed02b6c8a5913fUL;
    shared_buffer[0]=0x5c;
    if (private_value!=0x74ed02b6c8a5913fUL ||
        shared_buffer[0]!=0x5c) return 106;
    if (!phase("REAPS",root,(unsigned long)child) ||
        !phase("ENDED",root,(unsigned long)child)) return 107;
    return 0;
}
