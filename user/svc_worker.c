#include "abi.h"
#include "service_protocol.h"

#define MAX_MS 0x7fffffffffffffffUL
static void close_unrelated(void) {
    for (long fd=3;fd<32;fd++) {
        if (fd!=SVC_CHANNEL_FD) (void)os_call(SYS_CLOSE,fd,0,0);
    }
}
int runServiceWorker(void) {
#ifdef AGENTOS_FLAKY
    const unsigned id=SVC_FLAKY;
#else
    const unsigned id=SVC_CORE;
#endif
    close_unrelated();
    /* READY means that the service has exercised its own required kernel
     * time source and an actual scheduler-backed delay. Merely starting an
     * ELF is not sufficient to claim operational readiness. No READY packet
     * must escape on clock failure, premature wakeup or overflow.
     * Real storage/accounts/login health checks are separate future work.
     */
    long checked_at=os_call(SYS_MONOTONIC_MS,0,0,0);
    if (checked_at<0 || (unsigned long)checked_at>MAX_MS-20) return 126;
    if (os_call(SYS_SLEEP_UNTIL,checked_at+20,0,0)!=0) return 127;
    long after_check=os_call(SYS_MONOTONIC_MS,0,0,0);
    if (after_check<checked_at+20) return 128;
    struct svc_request ready={SVC_MAGIC,SVC_VERSION,SVC_OP_READY,
                              (unsigned short)id,0};
    if (os_call(SYS_IPC_SEND,SVC_CHANNEL_FD,(long)&ready,sizeof(ready))!=
        sizeof(ready)) return 121;
    struct svc_received_response reply;
    if (os_call(SYS_IPC_RECV,SVC_CHANNEL_FD,(long)&reply,
                sizeof(reply.data))!=sizeof(reply.data) ||
        reply.peer.pid==0 || reply.peer.uid!=1000 || reply.peer.gid!=1000 ||
        reply.data.magic!=SVC_MAGIC || reply.data.version!=SVC_VERSION ||
        reply.data.result!=SVC_OK || reply.data.reserved ||
        reply.data.states[id]!=SVC_RUNNING) return 122;
#ifdef AGENTOS_FLAKY
    if (os_call(SYS_CLOSE,SVC_CHANNEL_FD,0,0)!=0) return 123;
#endif
    (void)os_call(SYS_CLOSE,0,0,0);
    (void)os_call(SYS_CLOSE,1,0,0);
    (void)os_call(SYS_CLOSE,2,0,0);
#ifdef AGENTOS_FLAKY
        long now=os_call(SYS_MONOTONIC_MS,0,0,0);
        if (now<0 || (unsigned long)now>MAX_MS-100) return 124;
        if (os_call(SYS_SLEEP_UNTIL,now+100,0,0)!=0) return 125;
        // Deliberately crash after a successful IPC READY handshake.
        // The persistent supervisor must reap, back off and enforce limits.
        return 42;
#else
    // A ready stable service has no periodic work. Its manager keeps this
    // lifetime endpoint open; closure is an orderly end of ownership. A
    // protocol violation is a service failure, never a busy receive loop.
    unsigned char pPacket[sizeof(struct ipc_peer)+IPC_MAX_MESSAGE];
    long pReceived=os_call(SYS_IPC_RECV,SVC_CHANNEL_FD,(long)pPacket,IPC_MAX_MESSAGE);
    return pReceived==0 ? 0 : 129;
#endif
}
