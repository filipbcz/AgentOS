#ifndef AGENTOS_IPC_TEST_H
#define AGENTOS_IPC_TEST_H
#include "../../user/abi.h"

enum { fdCount=32, childEndpoint=31 };
struct request { unsigned long challenge; struct ipc_peer claimed; };
struct response { unsigned long answer; struct ipc_peer observed; };
static inline unsigned long answer(unsigned long challenge) {
    return (challenge << 9 | challenge >> 55) ^ 0x6d97341bUL;
}
/* DUP2(fd,fd) validates without changing the descriptor or its references. */
static inline long fdMask(void) {
    unsigned long mask=0;
    for (long fd=0;fd<fdCount;fd++) {
        long r=os_call(SYS_DUP2,fd,fd,0);
        if (r==fd) mask|=1UL<<fd;
        else if (r!=-9) return -1;
    }
    return (long)mask;
}
static inline int firstFree(unsigned long mask) {
    for (int fd=0;fd<fdCount;fd++) if (!(mask&(1UL<<fd))) return fd;
    return -1;
}
static inline int peerMatches(struct ipc_peer peer,unsigned long pid) {
    return peer.pid==pid && pid>0 && peer.uid==1000 && peer.gid==1000;
}
static inline int ipcRecord(const char *kind,const char *const names[],
                            const unsigned long values[],unsigned count) {
    char line[256]; unsigned n=0;
    const char *prefix="AGENTOS IPC TEST ";
    while (*prefix) line[n++]=*prefix++;
    while (*kind) line[n++]=*kind++;
    for (unsigned i=0;i<count;i++) {
        const char *s=names[i];
        while (*s) {
            if (n>=sizeof(line)-18) return 0;
            line[n++]=*s++;
        }
        if (n+18>sizeof(line)) return 0;
        format_hex(line+n,values[i],16); n+=16;
    }
    line[n++]='\r';line[n++]='\n';
    return os_call(SYS_WRITE,1,(long)line,n)==(long)n;
}
#endif
