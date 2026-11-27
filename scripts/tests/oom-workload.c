/* Test-only bounded memory pressure in an isolated 256 MiB guest. */
#include "../../user/abi.h"
#define PAGE 4096UL
#define PRESSURE_PAGES 81920UL
#define STEP 4096UL
#define KEEP 0x7355525649564531UL
#define MAX_TIME 0x7fffffffffffffffL
enum { endpoint=15, limitMs=20000, childLimitMs=25000, delayMs=250, recoveryPages=16 };
struct identity { unsigned long pid,parent,apic,cpus; };
struct packet { unsigned long kind,value,inverse,when,until; };

static int report(const char *kind,const char *names,const unsigned long *values) {
    char line[512];
    unsigned n=0;
    const char *prefix="AGENTOS TEST OOM ";
    while (*prefix) line[n++]=*prefix++;
    while (*kind) line[n++]=*kind++;
    while (*names) {
        line[n++]=' ';
        while (*names && *names!=' ') line[n++]=*names++;
        line[n++]='=';
        format_hex(line+n,*values++,16); n+=16;
        if (*names) ++names;
    }
    line[n++]='\r'; line[n++]='\n';
    return n<=sizeof(line) && os_call(SYS_WRITE,1,(long)line,n)==(long)n;
}
#define REPORT(kind,names,...) report(kind,names,(const unsigned long[]){__VA_ARGS__})

static int identity(struct identity *id) {
    unsigned long s[8];
    long pid=os_call(SYS_GETPID,0,0,0);
    if (pid<=0 || os_call(SYS_SCHED_STATS,(long)s,sizeof(s),0) || s[0]!=1 ||
        s[6]!=(unsigned long)pid || s[7]==0 || s[7]>=s[6] ||
        s[1]>=255 || (s[2]!=1 && s[2]!=2)) return 0;
    *id=(struct identity){s[6],s[7],s[1],s[2]};
    return 1;
}
static long now(void) { return os_call(SYS_MONOTONIC_MS,0,0,0); }
static long deadline(long t,unsigned ms) {
    return t>=0 && t<=MAX_TIME-(long)ms ? t+(long)ms : -1;
}
static int sendPacket(int fd,struct packet p) {
    return os_call(SYS_IPC_TRY_SEND,fd,(long)&p,sizeof(p))==(long)sizeof(p);
}
static int receivePacket(int fd,unsigned long peer,long until,struct packet *p) {
    struct { struct ipc_peer sender; struct packet data; } in;
    if (fd<0 || fd>=32 || until<0) return 0;
    long events=os_call(SYS_WAIT_EVENTS_UNTIL,1UL<<fd,until,0);
    if (events<0 || !(events&(1UL<<fd)) ||
        os_call(SYS_IPC_TRY_RECV,fd,(long)&in,sizeof(in.data))!=(long)sizeof(in.data) ||
        in.sender.pid!=peer || in.sender.uid!=1000 || in.sender.gid!=1000) return 0;
    *p=in.data;
    return 1;
}

#if defined(OOM_PRESSURE) || defined(OOM_SURVIVOR)
static int childHandles(void) {
    for (int fd=3;fd<32;++fd) {
        if (fd==endpoint) continue;
        long r=os_call(SYS_CLOSE,fd,0,0);
        if (r!=0 && r!=-9) return 0;
    }
    return os_call(SYS_DUP2,endpoint,endpoint,0)==endpoint;
}
#endif
#if !defined(OOM_SURVIVOR)
static int vmStats(unsigned long s[8]) {
    return os_call(SYS_VM_STATS,(long)s,8*sizeof(*s),0)==0 && s[0]==1;
}
#endif
#if !defined(OOM_PRESSURE)
static volatile unsigned long gKeep[PAGE/sizeof(unsigned long)] __attribute__((aligned(4096)));
static unsigned long seed(unsigned long pid) { return KEEP^pid; }
static void prepareKeep(unsigned long pid) {
    gKeep[0]=seed(pid);
    gKeep[PAGE/sizeof(unsigned long)-1]=~seed(pid);
}
static int keepOk(unsigned long pid) {
    return gKeep[0]==seed(pid) && gKeep[PAGE/sizeof(unsigned long)-1]==~seed(pid);
}
static unsigned long inverse(void) { return gKeep[PAGE/sizeof(unsigned long)-1]; }
#endif

#if defined(OOM_PRESSURE)
/* Exactly 320 MiB NOBITS in a private, writable PT_LOAD. */
static volatile unsigned long gPressure[PRESSURE_PAGES*(PAGE/sizeof(unsigned long))]
    __attribute__((aligned(4096)));
int runOom(void) {
    struct identity id;
    unsigned long stats[8];
    struct packet go;
    unsigned long base=(unsigned long)gPressure,end=base+sizeof(gPressure);
    if (!childHandles() || !identity(&id) || !vmStats(stats) ||
        stats[1]<PRESSURE_PAGES || stats[2]>32 ||
        !REPORT("RESERVE","PID PARENT APIC CPUS BASE END RESERVED RESIDENT DEMAND",
                id.pid,id.parent,id.apic,id.cpus,base,end,stats[1],stats[2],stats[5]) ||
        !sendPacket(endpoint,(struct packet){1,base,end,0,0}) ||
        !receivePacket(endpoint,id.parent,deadline(now(),childLimitMs),&go)) return 60;
    long t=now();
    if (t<0 || go.kind!=2 || go.value!=base || go.inverse!=end ||
        go.until>(unsigned long)deadline(t,limitMs) || go.when>=go.until ||
        go.when<=(unsigned long)t ||
        os_call(SYS_SLEEP_UNTIL,(long)go.when,0,0)!=0) return 61;
    t=now();
    if (t<0 || (unsigned long)t<go.when || (unsigned long)t>=go.until ||
        !REPORT("BEGIN","PID MS",id.pid,t)) return 62;
    for (unsigned long i=0;i<PRESSURE_PAGES;++i) {
        gPressure[i*(PAGE/sizeof(unsigned long))]=i+1;
        if ((i+1)%STEP==0) {
            t=now();
            if (t<0 || (unsigned long)t>=go.until || !vmStats(stats) ||
                gPressure[i*(PAGE/sizeof(unsigned long))]!=i+1 ||
                !REPORT("PROGRESS","PID PAGES RESIDENT DEMAND MS",id.pid,i+1,stats[2],stats[5],t))
                return 63;
        }
    }
    return 64; /* No genuine PAGE OOM means failure. */
}
#elif defined(OOM_SURVIVOR)
int runOom(void) {
    struct identity id;
    struct packet resume;
    if (!childHandles() || !identity(&id)) return 65;
    prepareKeep(id.pid);
    if (!keepOk(id.pid) ||
        !REPORT("SURVIVOR_BEFORE","PID PARENT APIC CPUS VALUE INVERSE",
                id.pid,id.parent,id.apic,id.cpus,gKeep[0],inverse()) ||
        !sendPacket(endpoint,(struct packet){1,gKeep[0],inverse(),0,0}) ||
        !receivePacket(endpoint,id.parent,deadline(now(),childLimitMs),&resume) ||
        resume.kind!=3 || resume.value!=seed(id.pid) || resume.inverse!=~seed(id.pid) ||
        !keepOk(id.pid) || !identity(&id) ||
        !REPORT("SURVIVOR_AFTER","PID PARENT APIC CPUS VALUE INVERSE",
                id.pid,id.parent,id.apic,id.cpus,gKeep[0],inverse()) ||
        !sendPacket(endpoint,(struct packet){4,gKeep[0],inverse(),0,0})) return 66;
    return 0;
}
#else
static volatile unsigned long gRecovery[recoveryPages*(PAGE/sizeof(unsigned long))]
    __attribute__((aligned(4096)));
static int spawnPeer(const char *name,unsigned len,long *pid,int *fd) {
    int pair[2];
    if (os_call(SYS_IPC_PAIR,(long)pair,0,0)!=0) return 0;
    *fd=pair[0];
    if (pair[0]==endpoint || pair[1]==endpoint ||
        os_call(SYS_DUP2,pair[1],endpoint,0)!=endpoint) {
        (void)os_call(SYS_CLOSE,pair[1],0,0);
        return 0;
    }
    if (os_call(SYS_CLOSE,pair[1],0,0)!=0) {
        (void)os_call(SYS_CLOSE,endpoint,0,0);
        return 0;
    }
    *pid=os_call(SYS_SPAWN,(long)name,len,0);
    long closed=os_call(SYS_CLOSE,endpoint,0,0);
    return *pid>0 && closed==0;
}
static void cleanupChild(long child) {
    if (child>0) {
        (void)os_call(SYS_KILL,child,0,0);
        long until=deadline(now(),1000);
        if (until>=0) (void)os_call(SYS_WAIT_CHILD_UNTIL,child,until,0);
    }
}
int runOom(void) {
    struct identity id;
    struct packet survivorReady,pressureReady,survivorDone;
    unsigned long before[8],after[8];
    long survivor=-1,child=-1,start,go,until,waitStatus,again,t;
    int sfd=-1,cfd=-1,result=67;
    if (!identity(&id) || os_call(SYS_CHILD_AFTER,0,0,0)!=-10) return result;
    prepareKeep(id.pid);
    long rootStart=now();
    until=deadline(rootStart,limitMs);
    if (until<0 || !keepOk(id.pid) ||
        !REPORT("ROOT","PID PARENT APIC CPUS VALUE INVERSE MS",
                id.pid,id.parent,id.apic,id.cpus,gKeep[0],inverse(),rootStart)) return result;
    if (!spawnPeer("oom-survivor",12,&survivor,&sfd) ||
        !receivePacket(sfd,(unsigned long)survivor,until,&survivorReady) ||
        survivorReady.kind!=1 || survivorReady.value!=seed((unsigned long)survivor) ||
        survivorReady.inverse!=~seed((unsigned long)survivor)) goto cleanup;
    result=68;
    if (!spawnPeer("oom-pressure",12,&child,&cfd) ||
        !receivePacket(cfd,(unsigned long)child,until,&pressureReady) ||
        pressureReady.kind!=1 || pressureReady.value%PAGE ||
        pressureReady.inverse-pressureReady.value!=PRESSURE_PAGES*PAGE ||
        !keepOk(id.pid)) goto cleanup;
    start=now(); go=deadline(start,delayMs);
    waitStatus=os_call(SYS_TRY_WAIT,child,0,0);
    if (start<rootStart || go<0 || go>=until || waitStatus!=-11 ||
        !REPORT("WAIT","PID SURVIVOR CHILD START GO UNTIL TRY VALUE INVERSE",
                id.pid,survivor,child,start,go,until,waitStatus,gKeep[0],inverse()) ||
        !sendPacket(cfd,(struct packet){2,pressureReady.value,pressureReady.inverse,
                                        (unsigned long)go,(unsigned long)until})) goto cleanup;
    /* Child waits for GO time; parent enters ordinary bounded child wait. */
    result=69;
    waitStatus=os_call(SYS_WAIT_CHILD_UNTIL,child,until,0);
    t=now();
    if (waitStatus<0) goto cleanup;
    long dead=child;
    child=-1;
    again=os_call(SYS_TRY_WAIT,dead,0,0);
    if (waitStatus!=270 || again!=-10 || t<go || t>until || !keepOk(id.pid) ||
        !REPORT("COLLECT","PID CHILD STATUS AGAIN END VALUE INVERSE",
                id.pid,dead,waitStatus,again,t,gKeep[0],inverse())) goto cleanup;
    if (os_call(SYS_CLOSE,cfd,0,0)!=0) goto cleanup;
    cfd=-1;
    result=70;
    if (os_call(SYS_TRY_WAIT,survivor,0,0)!=-11 ||
        !sendPacket(sfd,(struct packet){3,survivorReady.value,survivorReady.inverse,0,0}) ||
        !receivePacket(sfd,(unsigned long)survivor,until,&survivorDone) ||
        survivorDone.kind!=4 || survivorDone.value!=survivorReady.value ||
        survivorDone.inverse!=survivorReady.inverse) goto cleanup;
    waitStatus=os_call(SYS_WAIT_CHILD_UNTIL,survivor,until,0);
    if (waitStatus<0) goto cleanup;
    long survived=survivor;
    survivor=-1;
    again=os_call(SYS_TRY_WAIT,survived,0,0);
    long empty=os_call(SYS_CHILD_AFTER,0,0,0);
    if (waitStatus!=0 || again!=-10 || empty!=-10 ||
        !REPORT("SURVIVOR_COLLECT","PID CHILD STATUS AGAIN EMPTY",
                id.pid,survived,waitStatus,again,empty)) goto cleanup;
    if (os_call(SYS_CLOSE,sfd,0,0)!=0) goto cleanup;
    sfd=-1;
    result=71;
    if (!vmStats(before) || !keepOk(id.pid)) goto cleanup;
    for (unsigned long i=0;i<recoveryPages;++i)
        gRecovery[i*(PAGE/sizeof(unsigned long))]=i+1;
    unsigned long sum=0;
    for (unsigned long i=0;i<recoveryPages;++i) {
        unsigned long value=gRecovery[i*(PAGE/sizeof(unsigned long))];
        if (value!=i+1) goto cleanup;
        sum+=value;
    }
    t=now();
    if (!vmStats(after) || after[2]<before[2]+recoveryPages ||
        after[5]<before[5]+recoveryPages || !keepOk(id.pid) || t<0 || t>until ||
        /* Each record fits one ordinary terminal write (including CRLF). */
        !REPORT("RECOVERY_1","PID BASE PAGES BEFORE AFTER DEMAND_BEFORE DEMAND_AFTER",
                id.pid,(unsigned long)gRecovery,recoveryPages,before[2],after[2],
                before[5],after[5]) ||
        !REPORT("RECOVERY_2","PID SUM VALUE INVERSE MS",id.pid,sum,gKeep[0],inverse(),t)) goto cleanup;
    result=0;
cleanup:
    if (cfd>=0) (void)os_call(SYS_CLOSE,cfd,0,0);
    if (sfd>=0) (void)os_call(SYS_CLOSE,sfd,0,0);
    cleanupChild(child);
    cleanupChild(survivor);
    return result;
}
#endif
