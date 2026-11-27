/* Relocated native IPC/timer regression. Uses only the normal ABI and
 * preserves the foreground process's inherited standard descriptors.
 */
#include "ipc-test.h"

struct test_message { struct ipc_peer sender; unsigned char data[IPC_MAX_MESSAGE]; };

static int timerRecord(const char *kind,unsigned long self,const unsigned long stats[4]) {
    const char *const names[]={" PID="," VERSION="," MS="," TIMERS="," IDLE="};
    const unsigned long values[]={self,stats[0],stats[1],stats[2],stats[3]};
    return ipcRecord(kind,names,values,5);
}
static int checkTimerStats(unsigned long self) {
    unsigned long before[4],after[4];
    if (os_call(SYS_TIMER_STATS,(long)before,sizeof(before),0) ||
        before[0]!=2 || before[3]>before[2] || !timerRecord("TIMER_BEFORE",self,before)) return 0;
    long null=os_call(SYS_TIMER_STATS,0,sizeof(before),0);
    long wrap=os_call(SYS_TIMER_STATS,-8,sizeof(before),0);
    long ro=os_call(SYS_TIMER_STATS,(long)&checkTimerStats,sizeof(before),0);
    long size=os_call(SYS_TIMER_STATS,(long)before,sizeof(before)-1,0);
    long flags=os_call(SYS_TIMER_STATS,(long)before,sizeof(before),1);
    const char *const names[]={" PID="," NULL="," WRAP="," RO="," SIZE="," FLAGS="};
    const unsigned long values[]={self,(unsigned long)null,(unsigned long)wrap,(unsigned long)ro,
                                   (unsigned long)size,(unsigned long)flags};
    return null==-14 && wrap==-14 && ro==-14 && size==-22 && flags==-22 &&
        ipcRecord("TIMER_ERRORS",names,values,6) &&
        os_call(SYS_TIMER_STATS,(long)after,sizeof(after),0)==0 &&
        after[0]==2 && after[1]>=before[1] && after[2]>=before[2] &&
        after[3]>=before[3] && after[3]<=after[2] && timerRecord("TIMER_AFTER",self,after);
}
static int receiveMatch(int fd,unsigned long self,unsigned length,unsigned seq) {
    struct test_message incoming;
    long n=os_call(SYS_IPC_RECV,fd,(long)&incoming,IPC_MAX_MESSAGE);
    if (n!=(long)length || !peerMatches(incoming.sender,self)) return 0;
    unsigned fnv=2166136261U;
    for (unsigned i=0;i<length;i++) {
        if (incoming.data[i]!=(unsigned char)(i*73+i/251)) return 0;
        fnv=(fnv^incoming.data[i])*16777619U;
    }
    const char *const names[]={" PID="," SEQ="," PEER="," UID="," GID="," FD="," BYTES="," FNV="};
    const unsigned long values[]={self,seq,incoming.sender.pid,incoming.sender.uid,incoming.sender.gid,
                                  (unsigned long)fd,(unsigned long)n,fnv};
    return ipcRecord("MESSAGE",names,values,8);
}
static int check_channel(unsigned long self) {
    int fds[2]; unsigned char payload[IPC_MAX_MESSAGE]; struct test_message incoming;
    long initial=fdMask();
    // Create a real hole in the otherwise stdio-only table, without replacing
    // a live handle. A failed pair must leave the exact occupied set unchanged.
    if (initial!=7) return 0;
    int held=firstFree((unsigned long)initial)+1;
    if (held>=fdCount || os_call(SYS_DUP2,1,held,0)!=held) return 0;
    long occupied=fdMask();
    if (occupied!=(initial|(1L<<held))) return 0;
    int first=firstFree((unsigned long)occupied);
    int second=firstFree((unsigned long)occupied|(1UL<<first));
    if (os_call(SYS_IPC_PAIR,0,0,0)!=-14 || fdMask()!=occupied ||
        os_call(SYS_IPC_SEND,32,0,1)!=-9 || os_call(SYS_IPC_RECV,32,0,1)!=-9 ||
        os_call(SYS_IPC_TRY_SEND,32,0,1)!=-9 ||
        os_call(SYS_IPC_SEND,1,0,1)!=-88 || os_call(SYS_IPC_RECV,1,0,1)!=-88 ||
        os_call(SYS_IPC_TRY_SEND,1,0,1)!=-88 ||
        os_call(SYS_IPC_PAIR,(long)fds,0,0) || fds[0]!=first || fds[1]!=second ||
        fdMask()!=(occupied|(1L<<first)|(1L<<second))) return 0;
    for (unsigned i=0;i<sizeof(payload);i++) payload[i]=(unsigned char)(i*73+i/251);
    // Preserve every historical invalid send, mailbox capacity and direction.
    if (os_call(SYS_IPC_SEND,fds[0],(long)payload,0)!=-90 ||
        os_call(SYS_IPC_SEND,fds[0],(long)payload,IPC_MAX_MESSAGE+1)!=-90 ||
        os_call(SYS_IPC_SEND,fds[0],0,1)!=-14 ||
        os_call(SYS_IPC_SEND,fds[0],(long)payload,sizeof(payload))!=sizeof(payload)) return 0;
    long full=os_call(SYS_IPC_TRY_SEND,fds[0],(long)payload,1);
    if (full!=-11 || os_call(SYS_IPC_SEND,fds[1],(long)payload,1)!=1) return 0;
    long shortBuffer=os_call(SYS_IPC_RECV,fds[1],(long)&incoming,IPC_MAX_MESSAGE-1);
    long null=os_call(SYS_IPC_RECV,fds[1],0,IPC_MAX_MESSAGE);
    long ro=os_call(SYS_IPC_RECV,fds[1],(long)&check_channel,IPC_MAX_MESSAGE);
    long wrap=os_call(SYS_IPC_RECV,fds[1],-8,IPC_MAX_MESSAGE);
    const char *const errNames[]={" PID="," FULL="," SHORT="," NULL="," RO="," WRAP="};
    const unsigned long errValues[]={self,(unsigned long)full,(unsigned long)shortBuffer,
                                     (unsigned long)null,(unsigned long)ro,(unsigned long)wrap};
    if (shortBuffer!=-90 || null!=-14 || ro!=-14 || wrap!=-14 ||
        !ipcRecord("CHANNEL_ERRORS",errNames,errValues,6) ||
        !receiveMatch(fds[1],self,IPC_MAX_MESSAGE,1) || !receiveMatch(fds[0],self,1,2)) return 0;
    long empty=os_call(SYS_IPC_TRY_RECV,fds[1],(long)&incoming,IPC_MAX_MESSAGE);
    if (empty!=-11 || os_call(SYS_IPC_TRY_SEND,fds[0],(long)payload,7)!=7 ||
        !receiveMatch(fds[1],self,7,3)) return 0;
    // Duplicate into an independently observed free slot; closing the original
    // does not close the duplicate. Drain the full message after sender close.
    int duplicate=firstFree((unsigned long)occupied|(1UL<<first)|(1UL<<second));
    if (duplicate<0 || os_call(SYS_DUP2,fds[1],duplicate,0)!=duplicate ||
        os_call(SYS_CLOSE,fds[1],0,0) ||
        os_call(SYS_IPC_SEND,fds[0],(long)payload,sizeof(payload))!=sizeof(payload) ||
        os_call(SYS_CLOSE,fds[0],0,0) ||
        !receiveMatch(duplicate,self,IPC_MAX_MESSAGE,4)) return 0;
    long eof=os_call(SYS_IPC_RECV,duplicate,(long)&incoming,IPC_MAX_MESSAGE);
    long tryPipe=os_call(SYS_IPC_TRY_SEND,duplicate,(long)payload,1);
    long pipe=os_call(SYS_IPC_SEND,duplicate,(long)payload,1);
    if (eof!=0 || tryPipe!=-32 || pipe!=-32 || os_call(SYS_CLOSE,duplicate,0,0) ||
        os_call(SYS_CLOSE,held,0,0)) return 0;
    long restored=fdMask();
    const char *const endNames[]={" PID="," EMPTY="," EOF="," TRYPIPE="," PIPE="};
    const unsigned long endValues[]={self,(unsigned long)empty,(unsigned long)eof,
                                     (unsigned long)tryPipe,(unsigned long)pipe};
    const char *const fdNames[]={" PID="," INITIAL="," OCCUPIED="," HELD="," FIRST="," SECOND="," DUP="," RESTORED="};
    const unsigned long fdValues[]={self,(unsigned long)initial,(unsigned long)occupied,(unsigned long)held,
        (unsigned long)first,(unsigned long)second,(unsigned long)duplicate,(unsigned long)restored};
    return restored==initial && ipcRecord("CHANNEL_END",endNames,endValues,5) &&
           ipcRecord("FDS",fdNames,fdValues,8);
}
static long childDeadline(long deadline) {
    long now=os_call(SYS_MONOTONIC_MS,0,0,0);
    if (now<0 || now>deadline) return -1;
    return deadline-now<5000?deadline:now+5000;
}
int run_ipc(long deadline) {
    long pid=os_call(SYS_GETPID,0,0,0);
    if (pid<=0 || !checkTimerStats((unsigned long)pid) || !check_channel((unsigned long)pid)) return 28;
    int fds[2];
    long before=fdMask();
    if (before!=7 || (before&(1L<<childEndpoint)) ||
        os_call(SYS_IPC_PAIR,(long)fds,0,0)) return 21;
    if (fds[0]!=firstFree((unsigned long)before) ||
        fds[1]!=firstFree((unsigned long)before|(1UL<<fds[0])) ||
        fds[1]==childEndpoint || os_call(SYS_DUP2,fds[1],childEndpoint,0)!=childEndpoint ||
        os_call(SYS_CLOSE,fds[1],0,0)) return 22;
    // Legacy SPAWN intentionally inherits the endpoint. The counterpart
    // independently checks the inherited set and closes every private handle
    // except its endpoint. Neither side repurposes fd 0, 1, or 2.
    long inherited=fdMask();
    if (inherited!=(before|(1L<<fds[0])|(1L<<childEndpoint))) return 22;
    long service=os_call(SYS_SPAWN,(long)"ipc-service",11,0);
    if (service<=0) return 23;
    int result=23, collected=0;
    if (os_call(SYS_CLOSE,childEndpoint,0,0)) goto cleanup;
    struct request request={(unsigned long)pid*0x9e3779b97f4a7c15UL+(unsigned long)service,{0,0,0}};
    if (os_call(SYS_IPC_SEND,fds[0],(long)&request,sizeof(request))!=sizeof(request)) {
        result=24;goto cleanup;
    }
    struct { struct ipc_peer sender; struct response data; } reply;
    if (os_call(SYS_IPC_RECV,fds[0],(long)&reply,sizeof(reply.data))!=sizeof(reply.data) ||
        !peerMatches(reply.sender,(unsigned long)service) ||
        !peerMatches(reply.data.observed,(unsigned long)pid) ||
        reply.data.answer!=answer(request.challenge)) {result=25;goto cleanup;}
    long end=childDeadline(deadline);
    long status=end<0?-5:os_call(SYS_WAIT_CHILD_UNTIL,service,end,0);
    if (status>=0) collected=1;
    if (status!=0) {result=26;goto cleanup;}
    long again=os_call(SYS_TRY_WAIT,service,0,0);
    long eof=os_call(SYS_IPC_RECV,fds[0],(long)&reply,sizeof(reply.data));
    long broken=os_call(SYS_IPC_SEND,fds[0],(long)&request,sizeof(request));
    if (again!=-10 || eof!=0 || broken!=-32 || os_call(SYS_CLOSE,fds[0],0,0)) {
        result=26;goto cleanup;
    }
    fds[0]=-1;
    long restored=fdMask();
    const char *const replyNames[]={" PID="," PEER="," UID="," GID="," OBSERVED="," CHALLENGE="," ANSWER="};
    const unsigned long replyValues[]={(unsigned long)pid,reply.sender.pid,reply.sender.uid,reply.sender.gid,
        reply.data.observed.pid,request.challenge,reply.data.answer};
    const char *const reapNames[]={" PID="," CHILD="," STATUS="," AGAIN="," EOF="," PIPE="," INHERITED="," RESTORED="};
    const unsigned long reapValues[]={(unsigned long)pid,(unsigned long)service,(unsigned long)status,
        (unsigned long)again,(unsigned long)eof,(unsigned long)broken,(unsigned long)inherited,(unsigned long)restored};
    result=restored==before && os_call(SYS_CHILD_AFTER,0,0,0)==-10 &&
        ipcRecord("REPLY",replyNames,replyValues,7) && ipcRecord("REAP",reapNames,reapValues,8)?0:27;
cleanup:
    if (fds[0]>=0) (void)os_call(SYS_CLOSE,fds[0],0,0);
    if (!collected) {
        (void)os_call(SYS_KILL,service,0,0);
        long until=childDeadline(deadline);
        if (until>=0) (void)os_call(SYS_WAIT_CHILD_UNTIL,service,until,0);
    }
    return result;
}
