/* Real foreground IPC-driven adoption regression. The host advances only
 * after PID1's ordinary collection records, not after a guessed delay.
 * No service-control endpoint, special kernel operation or CPU affinity.
 */
#include "../../user/abi.h"

enum { parentRole=0, liveRole=1, pulseRole=2, shutdownRole=3, roleCount=4 };
enum { zombieStatus=57, pulseStatus=58, liveStatus=59, waitMs=5000, shutdownHoldMs=60000 };
struct Report {
    unsigned long role, step, token, aux;
    unsigned long stats[8];
};
struct Incoming { struct ipc_peer peer; struct Report report; };
struct Command { struct ipc_peer peer; unsigned long token; };
static int gChannel[roleCount][2];
static long gController, gParent;
static long gWorkers[roleCount];

static long deadline(unsigned delay) {
    long pNow=os_call(SYS_MONOTONIC_MS,0,0,0);
    return pNow>=0 && (unsigned long)pNow<=0x7fffffffffffffffUL-delay ? pNow+delay : -1;
}
static unsigned long token(unsigned role,unsigned step) {
    return 0x9b1735ac82000000UL | ((unsigned long)role<<8) | step;
}
static int closeFd(int *fd) {
    if (*fd<0) return 1;
    long pResult=os_call(SYS_CLOSE,*fd,0,0);
    *fd=-1;
    return pResult==0;
}
static int peer(const struct ipc_peer *p,long expected) {
    return p->pid>0 && (expected<=0 || p->pid==(unsigned long)expected) &&
           p->uid==1000 && p->gid==1000;
}
static int sample(struct Report *r,unsigned role,unsigned step,unsigned long value,unsigned long aux,long parent) {
    r->role=role;r->step=step;r->token=value;r->aux=aux;
    long pPid=os_call(SYS_GETPID,0,0,0);
    return pPid>0 && os_call(SYS_SCHED_STATS,(long)r->stats,64,0)==0 &&
           r->stats[0]==1 && r->stats[6]==(unsigned long)pPid &&
           (parent<0 || r->stats[7]==(unsigned long)parent) &&
           r->stats[2]>0 && r->stats[3]<=r->stats[4];
}
static void append(char *line,unsigned *n,const char *text) {
    while (*text) line[(*n)++]=*text++;
}
static int record(const char *kind,const char *const names[],const unsigned long values[],unsigned count) {
    char line[320];unsigned n=0;
    append(line,&n,"AGENTOS ADOPTION TEST ");append(line,&n,kind);
    for(unsigned i=0;i<count;i++) {
        append(line,&n,names[i]);format_hex(line+n,values[i],16);n+=16;
    }
    append(line,&n,"\r\n");
    return n<=sizeof(line) && os_call(SYS_WRITE,1,(long)line,n)==(long)n;
}
static int show(const struct Report *r) {
    const char *const names[]={" ROLE="," STEP="," PID="," PARENT="," APIC="," CPUS=",
                              " MOVES="," TOTAL="," TOKEN="," AUX="};
    const unsigned long v[]={r->role,r->step,r->stats[6],r->stats[7],r->stats[1],r->stats[2],
                             r->stats[3],r->stats[4],r->token,r->aux};
    return record("SNAP",names,v,10);
}
static int pairRecord(const char *kind,unsigned long a,unsigned long b) {
    const char *const names[]={" STEP="," PID="};
    const unsigned long v[]={a,b};
    return record(kind,names,v,2);
}
static int sendReport(unsigned role,unsigned step,unsigned long value,unsigned long aux,long parent) {
    struct Report r;
    return sample(&r,role,step,value,aux,parent) &&
           os_call(SYS_IPC_SEND,gChannel[role][1],(long)&r,sizeof(r))==(long)sizeof(r);
}
static int receiveReport(unsigned role,unsigned step,unsigned long value,long parent,struct Report *out) {
    struct Incoming p;
    if (os_call(SYS_IPC_RECV,gChannel[role][0],(long)&p,sizeof(p.report))!=(long)sizeof(p.report) ||
        !peer(&p.peer,gWorkers[role]) || p.report.role!=role || p.report.step!=step ||
        p.report.token!=value || p.report.stats[0]!=1 ||
        p.report.stats[6]!=p.peer.pid || p.report.stats[7]!=(unsigned long)parent ||
        (role!=parentRole && p.report.aux!=0)) return 0;
    gWorkers[role]=(long)p.peer.pid;
    *out=p.report;
    return show(&p.report);
}
static int sendCommand(unsigned role,unsigned step) {
    unsigned long pToken=token(role,step);
    return os_call(SYS_IPC_SEND,gChannel[role][0],(long)&pToken,sizeof(pToken))==(long)sizeof(pToken);
}
static int receiveCommand(unsigned role,unsigned step) {
    struct Command p;
    return os_call(SYS_IPC_RECV,gChannel[role][1],(long)&p,sizeof(p.token))==(long)sizeof(p.token) &&
           peer(&p.peer,gController) && p.token==token(role,step);
}
static void done(unsigned status) {
    (void)os_call(SYS_EXIT,status,0,0);
    for (;;) (void)os_call(SYS_YIELD,0,0,0);
}
static int worker(unsigned role) {
    for (unsigned i=0;i<roleCount;i++)
        if (i!=role && !closeFd(&gChannel[i][1])) return 151;
    if (!sendReport(role,0,token(role,0),0,gParent)) return 152;
    unsigned count=role==liveRole?2:1;
    for (unsigned step=1;step<=count;step++) {
        if (!receiveCommand(role,step) || !sendReport(role,step,token(role,step),0,1)) return 153;
    }
    if (role==pulseRole) return pulseStatus;
    if (role==liveRole) return liveStatus;
    // The controller will close the peer after its last authenticated reply.
    // Stay alive without polling or owning the foreground terminal; normal
    // shell shutdown must explicitly kill and collect this adopted child.
    struct Command p;
    if (os_call(SYS_IPC_RECV,gChannel[role][1],(long)&p,sizeof(p.token))!=0 ||
        !closeFd(&gChannel[role][1])) return 154;
    long pEnd=deadline(shutdownHoldMs);
    if (pEnd<0 || os_call(SYS_SLEEP_UNTIL,pEnd,0,0)!=0) return 155;
    return 156; // the host must observe real shutdown before this fallback
}
static int intermediate(void) {
    gParent=os_call(SYS_GETPID,0,0,0);
    for(unsigned i=0;i<roleCount;i++) if (!closeFd(&gChannel[i][0])) return 157;
    long zombie=os_call(SYS_FORK,0,0,0);
    if (zombie<0) return 158;
    if (!zombie) done(zombieStatus);
    // Only this one child exists here. The non-consuming child-exit event
    // proves publication of status before its parent exits and adopts it.
    long pEnd=deadline(waitMs);
    if (pEnd<0 || os_call(SYS_WAIT_EVENTS_UNTIL,0,pEnd,0)!=(1L<<32) ||
        !sendReport(parentRole,0,1UL<<32,(unsigned long)zombie,gController)) return 159;
    for(unsigned i=liveRole;i<shutdownRole;i++) {
        long pid=os_call(SYS_FORK,0,0,0);
        if (pid<0) return 160;
        if (!pid) done(worker(i));
        if (!closeFd(&gChannel[i][1])) return 161;
    }
    // The controller has authenticated the original parent of every live
    // child before granting this release. No child is collected here.
    return receiveCommand(parentRole,1)?0:162;
}
/* Start the shutdown case only after the earlier children are collected.
 * This keeps the entire test within the ordinary eight-slot UP capacity.
 */
static int shutdownIntermediate(void) {
    gParent=os_call(SYS_GETPID,0,0,0);
    for(unsigned i=0;i<roleCount;i++) if (!closeFd(&gChannel[i][0])) return 174;
    if (!sendReport(parentRole,4,token(parentRole,4),0,gController)) return 175;
    long pid=os_call(SYS_FORK,0,0,0);
    if (pid<0) return 176;
    if (!pid) done(worker(shutdownRole));
    if (!closeFd(&gChannel[shutdownRole][1])) return 177;
    return receiveCommand(parentRole,4)?0:178;
}
static int collectParent(long parent) {
    long pEnd=deadline(waitMs);
    return pEnd>=0 && os_call(SYS_WAIT_CHILD_UNTIL,parent,pEnd,0)==0 &&
           os_call(SYS_TRY_WAIT,parent,0,0)==-10 && closeFd(&gChannel[parentRole][0]) &&
           os_call(SYS_CHILD_AFTER,0,0,0)==-10;
}
static int gate(unsigned step,long pid) {
    // Ordinary canonical TTY input is delivered only after Enter.
    // Read the complete two-byte record, including its LF.
    char pLine[3];
    return pairRecord("WAIT",step,(unsigned long)pid) &&
           os_call(SYS_READ,0,(long)pLine,sizeof(pLine))==2 &&
           pLine[0]==(char)('A'+step-1) && pLine[1]=='\n' &&
           pairRecord("GO",step,(unsigned long)pid);
}
static int exchange(unsigned role,unsigned step) {
    struct Report r;
    return sendCommand(role,step) && receiveReport(role,step,token(role,step),1,&r);
}
int runAdoption(void) {
    struct Report r;
    gController=os_call(SYS_GETPID,0,0,0);
    if (gController<=1 || !sample(&r,4,0,token(4,0),0,-1) || !show(&r)) return 150;
    for(unsigned i=0;i<roleCount;i++) gChannel[i][0]=gChannel[i][1]=-1;
    for(unsigned i=0;i<shutdownRole;i++)
        if (os_call(SYS_IPC_PAIR,(long)gChannel[i],0,0)!=0) return 163;
    long parent=os_call(SYS_FORK,0,0,0);
    if (parent<0) return 164;
    if (!parent) done(intermediate());
    gParent=parent;gWorkers[parentRole]=parent;
    for(unsigned i=0;i<roleCount;i++) if (!closeFd(&gChannel[i][1])) return 165;
    if (!receiveReport(parentRole,0,1UL<<32,gController,&r) ||
        r.aux<=(unsigned long)parent) return 166;
    long zombie=(long)r.aux;
    for(unsigned i=liveRole;i<shutdownRole;i++)
        if (!receiveReport(i,0,token(i,0),parent,&r) || gWorkers[i]<=zombie) return 167;
    if (!sendCommand(parentRole,1)) return 168;
    if (!collectParent(parent)) return 169;
    for(unsigned i=liveRole;i<shutdownRole;i++)
        if (os_call(SYS_TRY_WAIT,gWorkers[i],0,0)!=-10 ||
            os_call(SYS_KILL,gWorkers[i],0,0)!=-1) return 170;
    if (!pairRecord("PARENT_REAP",0,(unsigned long)parent) ||
        !gate(1,zombie) || !exchange(liveRole,1) ||
        !exchange(pulseRole,1) || !closeFd(&gChannel[pulseRole][0])) return 171;
    if (!gate(2,gWorkers[pulseRole]) ||
        !exchange(liveRole,2) || !closeFd(&gChannel[liveRole][0])) return 172;
    if (!gate(3,gWorkers[liveRole])) return 173;
    if (os_call(SYS_IPC_PAIR,(long)gChannel[parentRole],0,0)!=0 ||
        os_call(SYS_IPC_PAIR,(long)gChannel[shutdownRole],0,0)!=0) return 179;
    parent=os_call(SYS_FORK,0,0,0);
    if (parent<0) return 180;
    if (!parent) done(shutdownIntermediate());
    gWorkers[parentRole]=parent;
    if (!closeFd(&gChannel[parentRole][1]) || !closeFd(&gChannel[shutdownRole][1]) ||
        !receiveReport(parentRole,4,token(parentRole,4),gController,&r) || r.aux ||
        !receiveReport(shutdownRole,0,token(shutdownRole,0),parent,&r) ||
        !sendCommand(parentRole,4) || !collectParent(parent) ||
        os_call(SYS_TRY_WAIT,gWorkers[shutdownRole],0,0)!=-10 ||
        os_call(SYS_KILL,gWorkers[shutdownRole],0,0)!=-1 ||
        !pairRecord("PARENT_REAP",4,(unsigned long)parent) ||
        !exchange(shutdownRole,1) || !closeFd(&gChannel[shutdownRole][0]) ||
        !pairRecord("DONE",3,(unsigned long)gWorkers[shutdownRole])) return 181;
    return 0;
}
