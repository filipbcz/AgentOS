/* Bounded, separate runtime workload. No CPU affinity or production hooks.
 * All data and CPU identities are checked by the IPC receiver, not stdout
 * from the individual workers. The host independently checks the trace. */
#include "../../user/abi.h"

enum { maxWorkers=10, epochs=30, epochMs=2000, durationMs=60000,
       setupMs=20000, startDelayMs=2000, finishGraceMs=15000, payloadBytes=128,
       readyKind=1, sampleKind=2, doneKind=3, goKind=4, stopKind=5 };
typedef unsigned long U;
struct Stats { U version,apic,cpus,moves,total,wakeups,pid,parent; };
struct Message {
    U kind,slot,pid,parent,cpus,epoch,start,mid,end,before,middle,after;
    U apic0,apic1,moves0,moves1,hash;
    unsigned char payload[payloadBytes];
};
struct Incoming { struct ipc_peer peer; struct Message body; };
struct Gate { U kind,start,end,deadline; };
struct GateIn { struct ipc_peer peer; struct Gate body; };
_Static_assert(sizeof(struct Stats)==64 && sizeof(struct Message)<=IPC_MAX_MESSAGE,"ABI sizes");
_Static_assert(3+2*maxWorkers<=32,"descriptor capacity");

static int gChannels[maxWorkers][2];
static long gChildren[maxWorkers];
static unsigned gWorkers,gCpus;
static U gRoot,gSetupLimit,gGateLimit;
static volatile unsigned char gScratch[payloadBytes];

static long now(void) { return os_call(SYS_MONOTONIC_MS,0,0,0); }
static int stats(struct Stats *a, U pid, U parent) {
    return os_call(SYS_SCHED_STATS,(long)a,sizeof(*a),0)==0 &&
        a->version==1 && a->cpus==gCpus && a->pid==pid && a->parent==parent &&
        a->apic<255;
}
static void terminate(unsigned status) {
    (void)os_call(SYS_EXIT,status,0,0);
    __builtin_unreachable();
}
static int closeFd(int fd) { return os_call(SYS_CLOSE,fd,0,0)==0; }
static int peer(const struct ipc_peer *p,U pid) {
    return p->pid==pid && p->uid==1000 && p->gid==1000;
}

/* All report values use fixed-width hex; one report is one ordinary write. */
static int report(const char *kind,const char *names,const U *values,unsigned n) {
    char line[256];
    unsigned at=0;
    const char *prefix="AGENTOS TEST SMP SOAK ";
    while (*prefix) line[at++]=*prefix++;
    while (*kind) line[at++]=*kind++;
    for (unsigned i=0;i<n;++i) {
        if (at+2>=sizeof(line)) return 0;
        line[at++]=' ';
        while (*names && *names!=' ') {
            if (at+19>=sizeof(line)) return 0;
            line[at++]=*names++;
        }
        if (*names==' ') ++names;
        line[at++]='=';
        for (unsigned j=0;j<16;++j)
            line[at++]="0123456789abcdef"[(values[i]>>(60-4*j))&15];
    }
    if (*names || at+2>sizeof(line)) return 0;
    line[at++]='\r'; line[at++]='\n';
    return os_call(SYS_WRITE,1,(long)line,at)==(long)at;
}
#define REPORT(kind,names,...) report(kind,names,(const U[]){__VA_ARGS__},sizeof((const U[]){__VA_ARGS__})/sizeof(U))

/* Actual repeated private writes, with a different payload for each completed
 * block. The receiver computes the expected bytes independently of scratch. */
static unsigned char expectedByte(U pid,U epoch,U sequence,unsigned i) {
    return (unsigned char)(pid*73+epoch*29+sequence*19+i*37+(i>>3)*11+
                           ((sequence>>8)^(pid>>3)^(epoch*7)));
}
static U hashBytes(const unsigned char *a) {
    U h=14695981039346656037UL;
    for (unsigned i=0;i<payloadBytes;++i) h=(h^a[i])*1099511628211UL;
    return h;
}
static void batch(U pid,U epoch,U *work) {
    for (unsigned block=0;block<64;++block) {
        ++*work;
        for (unsigned i=0;i<payloadBytes;++i)
            gScratch[i]=expectedByte(pid,epoch,*work,i);
    }
}
static int workUntil(U pid,U epoch,U *work,U target,U deadline,U *stamp) {
    long t=now();
    if (t<0 || (U)t>deadline) return 0;
    U previous=(U)t;
    while ((U)t<target) {
        batch(pid,epoch,work);
        t=now();
        if (t<0 || (U)t<previous || (U)t>deadline) return 0;
        previous=(U)t;
    }
    *stamp=(U)t;
    return 1;
}
static int sendBounded(int fd,const void *body,U length,U limit) {
    for (;;) {
        long t=now();
        if (t<0 || (U)t>=limit) return 0;
        long result=os_call(SYS_IPC_TRY_SEND,fd,(long)body,length);
        if (result==(long)length) return 1;
        if (result!=-11 || os_call(SYS_YIELD,0,0,0)!=0) return 0;
    }
}
/* Before GO, keep doing real work so that ordinary runnable-queue balancing
 * can distribute the newly forked tasks. After DONE use a bounded event wait. */
static int receiveGate(unsigned slot,U pid,U *work,U kind,U limit,struct Gate *out) {
    int fd=gChannels[slot][1];
    for (;;) {
        long t=now();
        if (t<0 || (U)t>=limit) return 0;
        struct GateIn input;
        long result=os_call(SYS_IPC_TRY_RECV,fd,(long)&input,sizeof(input.body));
        if (result==(long)sizeof(input.body)) {
            if (!peer(&input.peer,gRoot) || input.body.kind!=kind) return 0;
            *out=input.body;
            return 1;
        }
        if (result!=-11) return 0;
        if (kind==goKind) batch(pid,epochs,work);
        else {
            long events=os_call(SYS_WAIT_EVENTS_UNTIL,1UL<<fd,limit,0);
            if (events!=(long)(1UL<<fd)) return 0;
        }
    }
}
static void worker(unsigned slot) {
    for (unsigned i=0;i<gWorkers;++i)
        if (!closeFd(gChannels[i][0]) || (i!=slot && !closeFd(gChannels[i][1]))) terminate(101);
    U pid=(U)os_call(SYS_GETPID,0,0,0), work=0;
    struct Stats a,b;
    struct Message m={0};
    long t=now();
    if (!pid || t<0 || !stats(&a,pid,gRoot)) terminate(102);
    m.kind=readyKind; m.slot=slot; m.pid=pid; m.parent=gRoot; m.cpus=gCpus;
    m.apic0=a.apic; m.moves0=a.moves; m.end=(U)t;
    if (!sendBounded(gChannels[slot][1],&m,sizeof(m),gSetupLimit)) terminate(103);
    struct Gate gate;
    if (!receiveGate(slot,pid,&work,goKind,gSetupLimit,&gate) ||
        gate.end!=gate.start+durationMs || gate.deadline!=gate.end+finishGraceMs) terminate(104);
    for (unsigned e=0;e<epochs;++e) {
        U base=gate.start+(U)e*epochMs, stamp;
        /* Busy computation in the gaps is intentional test load. Neither
         * affinity nor repeated spawning is used to select a CPU. */
        if (!workUntil(pid,e,&work,base,base+500,&stamp) || !stats(&a,pid,gRoot)) terminate(105);
        t=now();
        if (t<0 || (U)t<base || (U)t>base+500) terminate(106);
        m.kind=sampleKind; m.epoch=e; m.start=(U)t; m.before=work;
        m.apic0=a.apic; m.moves0=a.moves;
        if (!workUntil(pid,e,&work,base+750,base+1100,&m.mid)) terminate(107);
        m.middle=work;
        if (!workUntil(pid,e,&work,base+1500,base+epochMs,&m.end)) terminate(108);
        m.after=work;
        if (m.middle<=m.before || m.after<=m.middle || !stats(&b,pid,gRoot) ||
            b.moves<a.moves || (a.apic!=b.apic && a.moves==b.moves)) terminate(109);
        m.apic1=b.apic; m.moves1=b.moves;
        for (unsigned i=0;i<payloadBytes;++i) m.payload[i]=gScratch[i];
        m.hash=hashBytes(m.payload);
        if (!sendBounded(gChannels[slot][1],&m,sizeof(m),base+epochMs+1000)) terminate(110);
    }
    U stamp;
    if (!workUntil(pid,epochs,&work,gate.end,gate.end+2000,&stamp) ||
        !stats(&a,pid,gRoot)) terminate(111);
    m.kind=doneKind; m.end=stamp; m.after=work; m.apic0=a.apic; m.moves0=a.moves;
    if (!sendBounded(gChannels[slot][1],&m,sizeof(m),gate.deadline)) terminate(112);
    struct Gate stop;
    if (!receiveGate(slot,pid,&work,stopKind,gate.deadline,&stop) ||
        stop.start!=gate.start || stop.end!=gate.end || stop.deadline!=gate.deadline ||
        !closeFd(gChannels[slot][1])) terminate(113);
    terminate(0);
}

static int receiveAny(U mask,U deadline,struct Incoming *input,unsigned *slot) {
    for (;;) {
        long t=now();
        if (t<0 || (U)t>=deadline) return 0;
        long events=os_call(SYS_WAIT_EVENTS_UNTIL,mask,deadline,0);
        if (events<=0 || ((U)events&~mask)) return 0;
        for (unsigned i=0;i<gWorkers;++i) {
            int fd=gChannels[i][0];
            if (!((U)events&(1UL<<fd))) continue;
            long n=os_call(SYS_IPC_TRY_RECV,fd,(long)input,sizeof(input->body));
            if (n==-11) continue;
            if (n!=(long)sizeof(input->body) || !peer(&input->peer,(U)gChildren[i]) ||
                input->body.pid!=input->peer.pid || input->body.slot!=i ||
                input->body.parent!=gRoot || input->body.cpus!=gCpus) return 0;
            *slot=i;
            return 1;
        }
    }
}
static int scenario(void) {
    struct Stats root;
    long t=now();
    gRoot=(U)os_call(SYS_GETPID,0,0,0);
    if (t<0 || !gRoot || os_call(SYS_SCHED_STATS,(long)&root,sizeof(root),0)!=0 ||
        root.version!=1 || root.pid!=gRoot || root.parent<=1 || root.apic>=255 ||
        (root.cpus!=4 && root.cpus!=8) || os_call(SYS_CHILD_AFTER,0,0,0)!=-10) return 120;
    gCpus=(unsigned)root.cpus; gWorkers=gCpus+2;
    gSetupLimit=(U)t+setupMs;
    if (!REPORT("ROOT","PID PARENT CPUS WORKERS APIC MS LIMIT",gRoot,root.parent,root.cpus,
        gWorkers,root.apic,(U)t,gSetupLimit)) return 121;
    U mask=0;
    for (unsigned i=0;i<gWorkers;++i) {
        if (os_call(SYS_IPC_PAIR,(long)gChannels[i],0,0)!=0 ||
            gChannels[i][0]<3 || gChannels[i][0]>=32 || gChannels[i][1]<3 ||
            gChannels[i][1]>=32) return 122;
        mask|=1UL<<gChannels[i][0];
    }
    for (unsigned i=0;i<gWorkers;++i) {
        long child;
        do {
            t=now();
            if (t<0 || (U)t>=gSetupLimit) return 123;
            child=os_call(SYS_FORK,0,0,0);
            if (child==0) worker(i);
            if (child==-11 && os_call(SYS_YIELD,0,0,0)!=0) return 124;
        } while (child==-11);
        if (child<0) return 125;
        gChildren[i]=child;
        if (!REPORT("SPAWN","PID SLOT CHILD",gRoot,i,(U)child) ||
            os_call(SYS_YIELD,0,0,0)!=0) return 126;
    }
    for (unsigned i=0;i<gWorkers;++i)
        if (!closeFd(gChannels[i][1])) return 127;
    U pending=mask, lastMoves[maxWorkers]={0}, lastWork[maxWorkers]={0},lastCpu[maxWorkers]={0};
    U lastTime[maxWorkers]={0};
    unsigned nextEpoch[maxWorkers]={0};
    while (pending) {
        struct Incoming incoming; unsigned i;
        if (!receiveAny(pending,gSetupLimit,&incoming,&i)) return 128;
        struct Message *m=&incoming.body;
        t=now();
        if (m->kind!=readyKind || m->apic0>=255 || t<0 || m->end>(U)t ||
            m->end>=gSetupLimit) return 129;
        lastMoves[i]=m->moves0; lastCpu[i]=m->apic0; lastTime[i]=m->end;
        if (!REPORT("READY","PID PARENT SLOT APIC CPUS MOVES MS UID GID",
            incoming.peer.pid,m->parent,i,m->apic0,m->cpus,m->moves0,m->end,
            incoming.peer.uid,incoming.peer.gid)) return 130;
        pending&=~(1UL<<gChannels[i][0]);
    }
    t=now();
    if (t<0 || (U)t>=gSetupLimit) return 131;
    struct Gate gate={goKind,(U)t+startDelayMs,(U)t+startDelayMs+durationMs,
                      (U)t+startDelayMs+durationMs+finishGraceMs};
    gGateLimit=gate.deadline;
    if (!REPORT("GO","PID MS START END DEADLINE",gRoot,(U)t,gate.start,gate.end,gate.deadline)) return 132;
    for (unsigned i=0;i<gWorkers;++i)
        if (!sendBounded(gChannels[i][0],&gate,sizeof(gate),gSetupLimit)) return 133;

    pending=mask;
    while (pending) {
        struct Incoming incoming; unsigned i;
        if (!receiveAny(pending,gate.deadline,&incoming,&i)) return 134;
        struct Message *m=&incoming.body;
        t=now();
        if (t<0 || m->end>(U)t || (U)t>gate.deadline) return 135;
        if (m->kind==sampleKind) {
            U e=nextEpoch[i], base=gate.start+e*epochMs;
            if (e>=epochs || m->epoch!=e || m->start<base || m->start>base+500 ||
                m->mid<base+750 || m->mid>base+1100 || m->end<base+1500 ||
                m->end>base+epochMs || m->start>=m->mid || m->mid>=m->end ||
                m->start<lastTime[i] || m->before<lastWork[i] ||
                m->middle<=m->before || m->after<=m->middle ||
                m->apic0>=255 || m->apic1>=255 || m->moves0<lastMoves[i] ||
                m->moves1<m->moves0 || (m->apic0!=lastCpu[i] && m->moves0==lastMoves[i]) ||
                (m->apic0!=m->apic1 && m->moves0==m->moves1) ||
                (U)t>base+epochMs+3000) return 136;
            for (unsigned j=0;j<payloadBytes;++j)
                if (m->payload[j]!=expectedByte(incoming.peer.pid,e,m->after,j)) return 137;
            U digest=hashBytes(m->payload);
            if (digest!=m->hash) return 138;
            if (!REPORT("SAMPLE","PID EPOCH START MID END BEFORE MIDDLE AFTER",
                    incoming.peer.pid,e,m->start,m->mid,m->end,m->before,m->middle,m->after) ||
                !REPORT("DATA","PID EPOCH APIC0 APIC1 MOVE0 MOVE1 HASH RX",
                    incoming.peer.pid,e,m->apic0,m->apic1,m->moves0,m->moves1,digest,(U)t)) return 139;
            ++nextEpoch[i]; lastMoves[i]=m->moves1; lastCpu[i]=m->apic1;
            lastTime[i]=m->end; lastWork[i]=m->after;
        } else if (m->kind==doneKind) {
            if (nextEpoch[i]!=epochs || m->end<gate.end || m->end>gate.end+2000 ||
                m->after<=lastWork[i] || m->moves0<lastMoves[i] || m->apic0>=255 ||
                (m->apic0!=lastCpu[i] && m->moves0==lastMoves[i]) ||
                os_call(SYS_TRY_WAIT,gChildren[i],0,0)!=-11) return 140;
            if (!REPORT("DONE","PID APIC MOVES MS WORK TRY",
                    incoming.peer.pid,m->apic0,m->moves0,m->end,m->after,(U)-11L)) return 141;
            pending&=~(1UL<<gChannels[i][0]);
        } else return 142;
    }
    long cursor=0;
    for (unsigned i=0;i<gWorkers;++i) {
        if (os_call(SYS_CHILD_AFTER,cursor,0,0)!=gChildren[i] ||
            os_call(SYS_TRY_WAIT,gChildren[i],0,0)!=-11) return 143;
        cursor=gChildren[i];
    }
    if (os_call(SYS_CHILD_AFTER,cursor,0,0)!=-10) return 144;
    t=now();
    if (t<0 || (U)t<gate.end || (U)t>=gate.deadline ||
        !REPORT("RELEASE","PID MS COUNT DEADLINE",gRoot,(U)t,gWorkers,gate.deadline)) return 145;
    gate.kind=stopKind;
    for (unsigned i=0;i<gWorkers;++i)
        if (!sendBounded(gChannels[i][0],&gate,sizeof(gate),gate.deadline)) return 146;
    for (unsigned i=0;i<gWorkers;++i) {
        long child=gChildren[i];
        long status=os_call(SYS_WAIT_CHILD_UNTIL,child,gate.deadline,0);
        if (status!=0) return 147;
        long again=os_call(SYS_TRY_WAIT,child,0,0);
        if (again!=-10 || !closeFd(gChannels[i][0]) ||
            !REPORT("REAP","PID CHILD STATUS AGAIN",gRoot,(U)child,(U)status,(U)again)) return 148;
        gChildren[i]=0;
    }
    t=now();
    if (t<0 || (U)t>=gate.deadline || os_call(SYS_CHILD_AFTER,0,0,0)!=-10 ||
        !REPORT("FINAL","PID EMPTY MS",gRoot,(U)-10L,(U)t)) return 149;
    return 0;
}
int runSoak(void) {
    int status=scenario();
    if (status!=0) {
        (void)REPORT("FAIL","PID CODE",gRoot,(U)status);
        long t=now();
        U limit=t<0?gGateLimit:(U)t+5000;
        for (unsigned i=0;i<gWorkers;++i) if (gChildren[i]>0) {
            (void)os_call(SYS_KILL,gChildren[i],0,0);
            if (limit) (void)os_call(SYS_WAIT_CHILD_UNTIL,gChildren[i],limit,0);
        }
    }
    return status;
}
