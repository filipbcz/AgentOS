/* The sole counterpart of the staged IPC workload, not a system service. */
#include "ipc-test.h"

int serve(void) {
    long inherited=fdMask();
    if (inherited!=(7L|(1L<<3)|(1L<<childEndpoint))) return 31;
    for (int fd=3;fd<fdCount;fd++)
        if (fd!=childEndpoint && (inherited&(1L<<fd)) && os_call(SYS_CLOSE,fd,0,0)) return 31;
    long remaining=fdMask();
    if (remaining!=(7L|(1L<<childEndpoint))) return 31;
    struct { struct ipc_peer sender; struct request data; } incoming;
    long shortBuffer=os_call(SYS_IPC_RECV,childEndpoint,(long)&incoming,1);
    long null=os_call(SYS_IPC_RECV,childEndpoint,0,sizeof(incoming.data));
    if (shortBuffer!=-90 || null!=-14 ||
        os_call(SYS_IPC_RECV,childEndpoint,(long)&incoming,sizeof(incoming.data))!=sizeof(incoming.data)) return 32;
    long self=os_call(SYS_GETPID,0,0,0);
    unsigned long stats[8];
    long ms=os_call(SYS_MONOTONIC_MS,0,0,0);
    struct ipc_peer peer=incoming.sender;
    if (self<=0 || ms<0 || os_call(SYS_SCHED_STATS,(long)stats,sizeof(stats),0) ||
        stats[0]!=1 || stats[6]!=(unsigned long)self || !peerMatches(peer,stats[7]) ||
        peer.pid==(unsigned long)self || incoming.data.claimed.pid || incoming.data.claimed.uid ||
        incoming.data.claimed.gid ||
        incoming.data.challenge!=peer.pid*0x9e3779b97f4a7c15UL+(unsigned long)self) return 33;
    long denied=os_call(SYS_KILL,peer.pid,0,0);
    if (denied!=-1) return 36;
    const char *const cpuNames[]={" PID="," PARENT="," APIC="," CPUS="," MOVES="," TOTAL="," MS="};
    const unsigned long cpuValues[]={stats[6],stats[7],stats[1],stats[2],stats[3],stats[4],(unsigned long)ms};
    const char *const peerNames[]={" PID="," PEER="," UID="," GID="," CHALLENGE="," ANSWER="," DENIED="};
    struct response reply={answer(incoming.data.challenge),peer};
    const unsigned long peerValues[]={(unsigned long)self,peer.pid,peer.uid,peer.gid,incoming.data.challenge,
                                      reply.answer,(unsigned long)denied};
    const char *const fdNames[]={" PID="," INHERITED="," REMAINING="," SHORT="," NULL="};
    const unsigned long fdValues[]={(unsigned long)self,(unsigned long)inherited,(unsigned long)remaining,
                                    (unsigned long)shortBuffer,(unsigned long)null};
    if (!ipcRecord("SERVICE_CPU",cpuNames,cpuValues,7) ||
        !ipcRecord("SERVICE_FDS",fdNames,fdValues,5) ||
        !ipcRecord("SERVICE",peerNames,peerValues,7)) return 34;
    if (os_call(SYS_IPC_SEND,childEndpoint,(long)&reply,sizeof(reply))!=sizeof(reply) ||
        os_call(SYS_CLOSE,childEndpoint,0,0) || fdMask()!=7) return 35;
    return 0;
}
