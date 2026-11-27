/* Test-only workload, invoked by the ordinary shell. */
#include "../../user/abi.h"

#if defined(PIPE_WORKLOAD)
int run_pipe_transfer(long deadline);
#elif defined(IPC_WORKLOAD)
int run_ipc(long deadline);
#elif defined(COW_WORKLOAD)
int run_forktest(void);
#elif defined(DEMAND_WORKLOAD)
int runDemandPaging(void);
#else
int run_supervisor(void);
#endif
enum { maxPool=8, maxRounds=4, budgetMs=15000, workMs=100,
       runReserveMs=3000, skipStatus=75, movedStatus=76 };
enum { workCommand=1, runCommand=2, stopCommand=3, peerCommand=4, peerStop=5, peerIterations=2000000 };
struct Sample { unsigned long stats[8], ms; };
struct Command { unsigned long kind, round, apic; };
struct Report { unsigned long round, slot; struct Sample sample; };
struct IncomingCommand { struct ipc_peer peer; struct Command body; };
struct IncomingReport { struct ipc_peer peer; struct Report body; };
struct PeerReport { struct Report report; unsigned long work; };
struct IncomingPeer { struct ipc_peer peer; struct PeerReport body; };
static int gChannels[maxPool][2];
static long gPids[maxPool], gDeadline;
static unsigned long gRoot, gCpus;
static unsigned gCount, gCovered;
static unsigned long gApics[maxPool];
_Static_assert(sizeof(struct Sample)==72,"scheduler sample layout");

static long now(void) { return os_call(SYS_MONOTONIC_MS,0,0,0); }
static int sample(struct Sample *s) {
    long pid=os_call(SYS_GETPID,0,0,0);
    if (pid<=0 || os_call(SYS_SCHED_STATS,(long)s->stats,64,0)!=0) return 0;
    long ms=now();
    s->ms=(unsigned long)ms;
    return ms>=0 && (!gDeadline || ms<=gDeadline) && s->stats[0]==1 &&
        s->stats[1]<=0xffffffffUL && s->stats[2]>0 &&
        (!gCpus || s->stats[2]==gCpus) && s->stats[6]==(unsigned long)pid &&
        s->stats[3]<=s->stats[4] && s->stats[4]<0x7fffffffffffffffUL &&
        (s->stats[2]!=1 || (!s->stats[3] && !s->stats[4] && !s->stats[5]));
}
static void append(char *line,unsigned *n,const char *text) {
    while (*text) line[(*n)++]=*text++;
}
static int record(const char *kind,const char *const names[],const unsigned long values[],unsigned count) {
    char line[256]; unsigned n=0;
    append(line,&n,"AGENTOS TEST "); append(line,&n,kind);
    for (unsigned i=0;i<count;++i) {
        append(line,&n,names[i]); format_hex(line+n,values[i],16); n+=16;
    }
    append(line,&n,"\r\n");
    return n<=sizeof(line) && os_call(SYS_WRITE,1,(long)line,n)==n;
}
static int snapshot(const char *kind,const struct Sample *s) {
    const char *const names[]={" PID="," PARENT="," APIC="," CPUS="," MOVES="," TOTAL="," MS="};
    const unsigned long v[]={s->stats[6],s->stats[7],s->stats[1],s->stats[2],s->stats[3],s->stats[4],s->ms};
    return record(kind,names,v,7);
}
static int peerSnapshot(const char *kind,const struct PeerReport *p) {
    const struct Sample *s=&p->report.sample;
    const char *const names[]={" PID="," PARENT="," APIC="," CPUS="," MOVES="," TOTAL="," MS="," WORK="};
    const unsigned long v[]={s->stats[6],s->stats[7],s->stats[1],s->stats[2],s->stats[3],s->stats[4],s->ms,p->work};
    return record(kind,names,v,8);
}
static int activatePeer(long peer,unsigned round) {
    const char *const names[]={" ROOT="," ROUND="," PEER="};
    const unsigned long v[]={gRoot,round,(unsigned long)peer};
    return record("PEER_ACTIVATE",names,v,3);
}
static int unpaired(long peer) {
    const char *const names[]={" ROOT="," PEER="};
    const unsigned long v[]={gRoot,(unsigned long)peer};
    return record("UNPAIRED",names,v,2);
}
static int pairRecord(long pid,long peer) {
    const char *const names[]={" ROOT="," PID="," PEER="};
    const unsigned long v[]={gRoot,(unsigned long)pid,(unsigned long)peer};
    return record("PAIR",names,v,3);
}
static int wave(unsigned round) {
    const char *const names[]={" ROOT="," ROUND="," COUNT="};
    const unsigned long v[]={gRoot,round,gCount};
    return record("WAVE",names,v,3);
}
static int candidate(unsigned round,unsigned slot,long pid) {
    const char *const names[]={" ROOT="," ROUND="," SLOT="," PID="};
    const unsigned long v[]={gRoot,round,slot,(unsigned long)pid};
    return record("CANDIDATE",names,v,4);
}
static int selectCandidate(long pid,unsigned long apic,int run) {
    const char *const names[]={" ROOT="," PID="," APIC="," RUN="};
    const unsigned long v[]={gRoot,(unsigned long)pid,apic,(unsigned long)run};
    return record("SELECT",names,v,4);
}
static int reaped(long pid,long status) {
    const char *const names[]={" ROOT="," PID="," STATUS="};
    const unsigned long v[]={gRoot,(unsigned long)pid,(unsigned long)status};
    return record("REAP",names,v,3);
}
static int closeFd(int *fd) {
    if (*fd<0) return 1;
    int ok=os_call(SYS_CLOSE,*fd,0,0)==0;
    *fd=-1; return ok;
}
static int send(int fd,const void *body,unsigned size) {
    return os_call(SYS_IPC_TRY_SEND,fd,(long)body,size)==size;
}
static int receive(int fd,unsigned long pid,void *incoming,unsigned size) {
    if (fd<0 || fd>=32) return 0;
    unsigned long mask=1UL<<fd;
    long events=os_call(SYS_WAIT_EVENTS_UNTIL,mask,gDeadline,0);
    return events==(long)mask && os_call(SYS_IPC_TRY_RECV,fd,(long)incoming,size)==size &&
        ((struct ipc_peer *)incoming)->pid==pid;
}
static int receiveCommand(int fd,unsigned round,struct Command *command) {
    struct IncomingCommand in;
    if (!receive(fd,gRoot,&in,sizeof(in.body)) || in.body.round!=round) return 0;
    *command=in.body; return 1;
}
static int command(unsigned slot,unsigned round,unsigned kind,unsigned long apic) {
    const struct Command c={kind,round,apic};
    return send(gChannels[slot][0],&c,sizeof(c));
}
/* Keep the existing test pool runnable after READY, using only ordinary
 * authenticated nonblocking IPC. The original runner deadline and finite
 * peer iteration cap bound the wait. Record actual boundaries after receipt;
 * never fall back to blocking or count an incomplete interval. */
static int probeAbort(const struct Sample *entry,unsigned reason,unsigned polls,long result) {
    const char *const names[]={" PID="," PARENT="," MODE="," REASON="," POLLS="," RESULT="," NOW="};
    long ms=now();
    const unsigned long v[]={entry->stats[6],gRoot,2,reason,polls,(unsigned long)result,(unsigned long)ms};
    (void)snapshot("WAIT_ENTER",entry);
    (void)record("WAIT_ABORT",names,v,7);
    return 0;
}
static int postReadyCommand(int fd,unsigned round,struct Command *c) {
    struct Sample entry,wake,received;
    struct IncomingCommand in;
    long events=0,n=-11;
    unsigned polls=0;
    if (!sample(&entry) || entry.stats[7]!=gRoot || fd<0 || fd>=32) return 0;
    for (;polls<peerIterations;) {
        long ms=now();
        if (ms<0 || ms>gDeadline) return probeAbort(&entry,3,polls,ms);
        ++polls;
        n=os_call(SYS_IPC_TRY_RECV,fd,(long)&in,sizeof(in.body));
        if (n!=-11) break;
    }
    if (n==-11) return probeAbort(&entry,4,polls,n);
    if (!sample(&wake)) return probeAbort(&entry,2,polls,n);
    if (n!=sizeof(in.body) || in.peer.pid!=gRoot || in.body.round!=round ||
        (in.body.kind!=peerCommand && in.body.kind!=runCommand && in.body.kind!=stopCommand))
        return probeAbort(&entry,5,polls,n);
    if (!sample(&received)) return probeAbort(&entry,6,polls,n);
    const char *const names[]={" PID="," MODE="," KIND="," POLLS="," EVENTS="," BYTES="};
    const unsigned long v[]={received.stats[6],2,in.body.kind,polls,(unsigned long)events,(unsigned long)n};
    if (!snapshot("WAIT_ENTER",&entry) || !snapshot("WAIT_RETURN",&wake) ||
        !snapshot("WAIT_RECEIVED",&received) || !record("WAIT_RESULT",names,v,6)) return 0;
    *c=in.body;
    return 1;
}
static int postReadySend(unsigned slot,unsigned round,unsigned kind,unsigned long apic) {
    struct Sample s;
    if (!sample(&s) || s.stats[6]!=gRoot) return 0;
    const char *const names[]={" ROOT="," ROUND="," TARGET="," KIND="," APIC="," MS="," TOTAL="};
    const unsigned long v[]={gRoot,round,(unsigned long)gPids[slot],kind,s.stats[1],s.ms,s.stats[4]};
    return record("WAIT_SEND",names,v,7) && command(slot,round,kind,apic);
}


static int placementWork(void) {
    long start=now();
    if (start<0 || start>gDeadline-workMs) return 0;
    unsigned long value=1;
    /* Ordinary runnable CPU work, never a forced move. Both wall-clock and
     * iteration limits apply, even if the guest clock ceases advancing. */
    for (unsigned i=0;i<200000;++i) {
        long ms=now();
        if (ms<start || ms>gDeadline) return 0;
        if (ms>=start+workMs) return 1;
        for (unsigned j=0;j<256;++j) {
            value=value*33+1;
            __asm__ volatile ("" : "+r"(value) :: "memory");
        }
        if (os_call(SYS_YIELD,0,0,0)!=0) return 0;
    }
    return 0;
}
/* Exit 81 remains a failure. Record the exact branch and real observations
 * before exiting, without changing the successful peer protocol or its bounds.
 * A negative OBSERVED value is encoded as its signed syscall result in hex. */
enum { peerClockError=1, peerDeadline=2, peerWorkLimit=3 };
static int peerAbort(const struct PeerReport *p,unsigned reason,long last,long observed) {
    const char *const names[]={" PID="," PARENT="," REASON="," START="," LAST="," OBSERVED="," DEADLINE="," WORK="};
    const unsigned long v[]={p->report.sample.stats[6],gRoot,reason,p->report.sample.ms,
                             (unsigned long)last,(unsigned long)observed,(unsigned long)gDeadline,p->work};
    (void)record("PEER_ABORT",names,v,8);
    return 81;
}
/* Only this ordinary fork child remains runnable. After the authenticated
 * start report, there are no blocking syscalls until STOP has been received.
 * The controller sends STOP only after collecting the supervisor candidate.
 * Both the original guest deadline and a finite iteration cap apply. */
static int peerWork(int fd,unsigned slot,unsigned round,unsigned long apic) {
    struct PeerReport p={.report={.round=round,.slot=slot},.work=0};
    if (!sample(&p.report.sample) || p.report.sample.stats[7]!=gRoot ||
        !send(fd,&p,sizeof(p))) return 80;
    unsigned long value=1;
    long last=(long)p.report.sample.ms;
    for (unsigned i=0;i<peerIterations;++i) {
        long ms=now();
        if (ms<0) return peerAbort(&p,peerClockError,last,ms);
        if (ms>gDeadline) return peerAbort(&p,peerDeadline,last,ms);
        last=ms;
        for (unsigned j=0;j<256;++j) {
            value=value*33+1;
            __asm__ volatile ("" : "+r"(value) :: "memory");
        }
        ++p.work;
        struct IncomingCommand in;
        long n=os_call(SYS_IPC_TRY_RECV,fd,(long)&in,sizeof(in.body));
        if (n==-11) continue;
        if (n!=sizeof(in.body) || in.peer.pid!=gRoot || in.body.round!=round ||
            in.body.kind!=peerStop || in.body.apic!=apic) return 82;
        struct Command finish;
        if (!sample(&p.report.sample) || p.report.sample.stats[7]!=gRoot ||
            !send(fd,&p,sizeof(p)) || !receiveCommand(fd,round,&finish) ||
            finish.kind!=stopCommand || finish.apic!=apic ||
            !closeFd(&gChannels[slot][1]) || os_call(SYS_CHILD_AFTER,0,0,0)!=-10) return 83;
        return 0;
    }
    return peerAbort(&p,peerWorkLimit,last,now());
}
static int worker(unsigned slot,unsigned round) {
    for (unsigned i=0;i<gCount;++i)
        if (!closeFd(&gChannels[i][0]) || (i!=slot && !closeFd(&gChannels[i][1]))) return 70;
    int fd=gChannels[slot][1]; struct Command c;
    struct Report report={.round=round,.slot=slot};
    if (!receiveCommand(fd,round,&c) || c.kind!=workCommand || !placementWork() ||
        !sample(&report.sample) || report.sample.stats[7]!=gRoot ||
        !send(fd,&report,sizeof(report)) || !postReadyCommand(fd,round,&c) ||
        os_call(SYS_CHILD_AFTER,0,0,0)!=-10) return 71;
    if (c.kind==peerCommand) return peerWork(fd,slot,round,c.apic);
    if (!closeFd(&gChannels[slot][1])) return 71;
    if (c.kind==stopCommand) return 0;
    if (c.kind!=runCommand) return 72;
    struct Sample before,after;
    if (!sample(&before) || before.stats[7]!=gRoot || before.ms>(unsigned long)(gDeadline-runReserveMs)) return 73;
    if (before.stats[1]!=c.apic) return snapshot("SKIP",&before)?skipStatus:74;
    if (!snapshot("BEGIN",&before)) return 74;
#if defined(PIPE_WORKLOAD)
    int result=run_pipe_transfer(gDeadline);
#elif defined(IPC_WORKLOAD)
    int result=run_ipc(gDeadline);
#elif defined(COW_WORKLOAD)
    int result=run_forktest();
#elif defined(DEMAND_WORKLOAD)
    int result=runDemandPaging();
#else
    int result=run_supervisor();
#endif
    if (result) return result;
    if (os_call(SYS_CHILD_AFTER,0,0,0)!=-10 || !sample(&after) || after.stats[7]!=gRoot ||
        after.stats[6]!=before.stats[6] || !snapshot("ENDED",&after)) return 68;
    /* Spawn is local to the owning queue. No published migration anywhere
     * in this complete bracket implies locality of every direct child too. */
    return after.stats[1]==before.stats[1] && after.stats[3]==before.stats[3] &&
        after.stats[4]==before.stats[4] ? 0 : movedStatus;
}
static int covered(unsigned long apic) {
    for (unsigned i=0;i<gCovered;++i) if (gApics[i]==apic) return 1;
    return 0;
}
static void cleanup(void) {
    long ms=now(), until=ms>=0 && ms<0x7fffffffffffffffL-1000 ? ms+1000 : -1;
    for (unsigned i=0;i<gCount;++i) if (gPids[i]>0) (void)os_call(SYS_KILL,gPids[i],0,0);
    for (unsigned i=0;i<gCount;++i) {
        if (gPids[i]>0 && until>=0) (void)os_call(SYS_WAIT_CHILD_UNTIL,gPids[i],until,0);
        (void)closeFd(&gChannels[i][0]); (void)closeFd(&gChannels[i][1]);
    }
}
static long collect(unsigned slot) {
    long pid=gPids[slot];
    long status=os_call(SYS_WAIT_CHILD_UNTIL,pid,gDeadline,0);
    if (status<0) return status;
    gPids[slot]=0;
    return closeFd(&gChannels[slot][0]) && reaped(pid,status) ? status : -1;
}
static long selectAndCollect(unsigned slot,unsigned round,unsigned long apic,int run) {
    long ms=now();
    if (ms<0 || ms>gDeadline-(run?runReserveMs:0) ||
        !selectCandidate(gPids[slot],apic,run) || !postReadySend(slot,round,run?runCommand:stopCommand,apic)) return -1;
    return collect(slot);
}
static int readPeer(unsigned slot,unsigned round,struct PeerReport *report,const char *kind) {
    struct IncomingPeer in;
    if (!receive(gChannels[slot][0],gPids[slot],&in,sizeof(in.body)) ||
        in.body.report.round!=round || in.body.report.slot!=slot ||
        in.body.report.sample.stats[6]!=(unsigned long)gPids[slot] ||
        in.body.report.sample.stats[7]!=gRoot || !peerSnapshot(kind,&in.body)) return 0;
    *report=in.body; return 1;
}
/* READY is only a placement hint for a sleeping child. Select the peer
 * first, then choose an unused candidate using the authenticated live
 * PEER_BEGIN. A miss consumes only the peer, never an unrelated candidate.
 * Prefer the former opposite-CPU hint; if none exists, a peer may still
 * migrate upon wake. Each activation consumes one existing pool member. */
static unsigned choosePeer(const struct Sample ready[]) {
    for (unsigned pass=0;pass<2;++pass)
        for (unsigned i=0;i<gCount;++i)
            if (gPids[i]>0 && !covered(ready[i].stats[1]))
                for (unsigned j=0;j<gCount;++j)
                    if (j!=i && gPids[j]>0 &&
                        (pass || ready[j].stats[1]!=ready[i].stats[1])) return j;
    return gCount;
}
static unsigned choosePartner(unsigned peer,unsigned long liveApic,const struct Sample ready[]) {
    for (unsigned i=0;i<gCount;++i)
        if (i!=peer && gPids[i]>0 && ready[i].stats[1]!=liveApic &&
            !covered(ready[i].stats[1])) return i;
    return gCount;
}
static int advances(const struct Sample *a,const struct Sample *b) {
    return a->stats[6]==b->stats[6] && a->stats[7]==b->stats[7] &&
        a->stats[2]==b->stats[2] && a->ms<=b->ms && b->ms<=(unsigned long)gDeadline &&
        a->stats[3]<=b->stats[3] && a->stats[4]<=b->stats[4] &&
        b->stats[3]-a->stats[3]<=b->stats[4]-a->stats[4] &&
        (a->stats[1]==b->stats[1] || a->stats[3]<b->stats[3]);
}
static int runPair(unsigned peer,unsigned round,const struct Sample ready[]) {
    /* The command token remains the original hint for authenticated STOP.
     * Actual locality is based solely on the live start/end snapshots. */
    unsigned long token=ready[peer].stats[1];
    struct PeerReport before,after;
    if (!activatePeer(gPids[peer],round) || !postReadySend(peer,round,peerCommand,token) ||
        !readPeer(peer,round,&before,"PEER_BEGIN") || before.work!=0 ||
        !advances(&ready[peer],&before.report.sample)) return 0;
    unsigned long peerApic=before.report.sample.stats[1];
    unsigned slot=choosePartner(peer,peerApic,ready);
    unsigned long apic=0;
    long status=-1;
    if (slot<gCount) {
        apic=ready[slot].stats[1];
        if (!pairRecord(gPids[slot],gPids[peer])) return 0;
        /* worker() rechecks its actual APIC immediately before BEGIN. */
        status=selectAndCollect(slot,round,apic,1);
        if (status!=0 && status!=skipStatus && status!=movedStatus) return 0;
    } else if (!unpaired(gPids[peer])) return 0;
    if (!command(peer,round,peerStop,token) || !readPeer(peer,round,&after,"PEER_END") ||
        !command(peer,round,stopCommand,token) || collect(peer)!=0) return 0;
    if (after.work==0 || after.work>peerIterations ||
        !advances(&before.report.sample,&after.report.sample)) return 0;
    if (slot<gCount && status==0 && after.report.sample.stats[1]==peerApic &&
        after.report.sample.stats[3]==before.report.sample.stats[3]) gApics[gCovered++]=apic;
    return 1;
}
static int runWave(unsigned round) {
    struct Sample ready[maxPool];
    for (unsigned i=0;i<gCount;++i) {
        gChannels[i][0]=gChannels[i][1]=-1; gPids[i]=0;
    }
    if (!wave(round)) return 0;
    for (unsigned i=0;i<gCount;++i)
        if (os_call(SYS_IPC_PAIR,(long)gChannels[i],0,0)!=0) return 0;
    for (unsigned i=0;i<gCount;++i) {
        long pid=os_call(SYS_FORK,0,0,0);
        if (pid==0) { (void)os_call(SYS_EXIT,worker(i,round),0,0); __builtin_trap(); }
        if (pid<0) return 0;
        gPids[i]=pid;
        if (!candidate(round,i,pid)) return 0;
    }
    for (unsigned i=0;i<gCount;++i)
        if (!closeFd(&gChannels[i][1]) || !command(i,round,workCommand,0)) return 0;
    for (unsigned i=0;i<gCount;++i) {
        struct IncomingReport in;
        if (!receive(gChannels[i][0],gPids[i],&in,sizeof(in.body)) ||
            in.body.round!=round || in.body.slot!=i || in.body.sample.stats[6]!=(unsigned long)gPids[i] ||
            in.body.sample.stats[7]!=gRoot || !snapshot("READY",&in.body.sample)) return 0;
        ready[i]=in.body.sample;
    }
    if (gCpus==2) {
        while (gCovered<gCpus) {
            unsigned peer=choosePeer(ready);
            if (peer==gCount) break;
            if (!runPair(peer,round,ready)) return 0;
        }
        for (unsigned i=0;i<gCount;++i)
            if (gPids[i]>0 && selectAndCollect(i,round,ready[i].stats[1],0)!=0) return 0;
    } else {
        for (unsigned i=0;i<gCount;++i) {
            unsigned long apic=ready[i].stats[1];
            int run=!covered(apic) && gCovered<gCpus;
            long status=selectAndCollect(i,round,apic,run);
            if (status<0) return 0;
            if (run && status==0) gApics[gCovered++]=apic;
            else if ((!run && status!=0) || (run && status!=skipStatus && status!=movedStatus)) return 0;
        }
    }
    return os_call(SYS_CHILD_AFTER,0,0,0)==-10;
}
int runSupervisorWorkload(void) {
    struct Sample before,after;
    if (!sample(&before) || before.stats[7]<=1 || before.stats[7]>=before.stats[6] ||
        before.stats[2]>2 || before.ms>0x7fffffffffffffffUL-budgetMs ||
        os_call(SYS_CHILD_AFTER,0,0,0)!=-10) return 66;
    gRoot=before.stats[6]; gCpus=before.stats[2]; gDeadline=(long)before.ms+budgetMs;
    gCount=gCpus==1?1:2*(unsigned)gCpus;
    if (!snapshot("RUNNER",&before)) return 67;
    for (unsigned round=1;round<=maxRounds && gCovered<gCpus;++round)
        if (!runWave(round)) { cleanup(); return 77; }
    if (gCovered!=gCpus || !sample(&after) || after.stats[6]!=gRoot ||
        after.stats[7]!=before.stats[7] || os_call(SYS_CHILD_AFTER,0,0,0)!=-10) return 78;
    return snapshot("COMPLETE",&after)?0:79;
}
