/* Run the REAL persistent service_manager.c through deterministic native
 * syscalls, including boot dependency ordering, timed worker failures,
 * multi-service READY IPC, bounded retries and graceful shell/root cleanup.
 * No real kernel instructions or VirtualBox are executed in this host test.
 */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../../user/abi.h"
#include "../../user/service_protocol.h"
static long mock_call(long,long,long,long);
#define os_call mock_call
#include "../../user/service_manager.c"
#undef os_call

enum { MAX_CHILDREN=20, LOG_SIZE=16384 };
struct worker {
    long pid,start; int kind,channel,ready_sent,ack,reaped,killed;
};
static struct worker workers[MAX_CHILDREN];
static unsigned count, channel_count, sleeps, total_exits, total_kills;
static long ticks, next_pid, times[3];
static unsigned openfds[32], fdchannel[32], chars;
static char log_text[LOG_SIZE];
static int failure_mode, clock_failure_at, spoof_ready, never_ready;
static int spoof_control, spoof_control_sent;
static long core_crash_at;
static unsigned core_crashes;
static long kill_order[MAX_CHILDREN];

static void reset(void) {
    memset(workers,0,sizeof(workers));
    memset(openfds,0,sizeof(openfds));memset(fdchannel,0,sizeof(fdchannel));
    memset(log_text,0,sizeof(log_text));memset(times,0,sizeof(times));
    memset(kill_order,0,sizeof(kill_order));
    count=channel_count=sleeps=total_exits=total_kills=chars=0;
    ticks=0;next_pid=101;
    failure_mode=clock_failure_at=spoof_ready=never_ready=0;
    spoof_control=spoof_control_sent=0;
    core_crash_at=0;core_crashes=0;
    owner_pid=0;shell_active=shutdown_requested=fatal_error=online_announced=0;
    registry[SVC_CORE]=(struct record){
        "core","svc_alive",4,9,SVC_COUNT,1,SVC_DOWN,0,MAX_ATTEMPTS,0,
        0,-1,0,0,0,-1};
    registry[SVC_FLAKY]=(struct record){
        "flaky","svc_flaky",5,9,SVC_CORE,1,SVC_DOWN,0,MAX_ATTEMPTS,0,
        0,-1,0,0,0,-1};
    registry[SVC_SHELL]=(struct record){
        "shell","shell",5,5,SVC_CORE,1,SVC_DOWN,0,MAX_ATTEMPTS,0,
        0,-1,0,0,0,-1};
}
static struct worker *from_pid(long pid) {
    for(unsigned i=0;i<count;i++) if(workers[i].pid==pid) return &workers[i];
    return NULL;
}
static struct worker *from_channel(unsigned channel) {
    for(unsigned i=0;i<count;i++) if((unsigned)workers[i].channel==channel && !workers[i].reaped)
        return &workers[i];
    return NULL;
}
static long mock_call(long op,long a,long b,long c) {
    switch(op) {
        case SYS_GETPID: return 100;
        case SYS_MONOTONIC_MS: return ticks;
        case SYS_WRITE:
            assert(a==1 && b && c>0 && c<=256 && chars+(unsigned)c<LOG_SIZE);
            memcpy(log_text+chars,(const char *)b,(unsigned)c);chars+=(unsigned)c;
            return c;
        case SYS_IPC_PAIR: {
            int first=-1,second=-1;
            for(int fd=3;fd<32;fd++) {
                if(openfds[fd]) continue;
                if(first<0)first=fd;else{second=fd;break;}
            }
            assert(first>0 && second>0 && channel_count<MAX_CHILDREN);
            unsigned channel=++channel_count;
            openfds[first]=openfds[second]=1;
            fdchannel[first]=fdchannel[second]=channel;
            *(unsigned long *)a=(unsigned)first|((unsigned long)(unsigned)second<<32);
            return 0;
        }
        case SYS_DUP2:
            assert(a>=3 && a<32 && b==SVC_CHANNEL_FD && openfds[a]);
            openfds[b]=1;fdchannel[b]=fdchannel[a];return b;
        case SYS_CLOSE:
            if(a>=3 && a<32) {openfds[a]=0;fdchannel[a]=0;}
            return 0;
        case SYS_SPAWN: {
            if(failure_mode) return -12;
            assert(count<MAX_CHILDREN && openfds[SVC_CHANNEL_FD]);
            int kind=-1;
            if(b==9 && !memcmp((const void *)a,"svc_alive",9))kind=SVC_CORE;
            if(b==9 && !memcmp((const void *)a,"svc_flaky",9))kind=SVC_FLAKY;
            if(b==5 && !memcmp((const void *)a,"shell",5))kind=SVC_SHELL;
            assert(kind>=0);
            if(kind==SVC_FLAKY) {
                assert(registry[SVC_CORE].state==SVC_RUNNING);
                if(registry[SVC_FLAKY].attempts>0) {
                    long previous=times[registry[SVC_FLAKY].attempts-1];
                    long required=RESTART_BASE_MS<<(registry[SVC_FLAKY].attempts-1);
                    assert(ticks-previous>=required);
                }
                times[registry[SVC_FLAKY].attempts]=ticks;
            }
            if(kind==SVC_SHELL)
                assert(registry[SVC_FLAKY].state==SVC_FAILED &&
                       registry[SVC_CORE].state==SVC_RUNNING);
            struct worker *w=&workers[count++];
            *w=(struct worker){next_pid++,ticks,kind,(int)fdchannel[SVC_CHANNEL_FD],0,0,0,0};
            return w->pid;
        }
        case SYS_IPC_TRY_RECV: {
            assert(a>=3 && a<32 && openfds[a] && b && c==sizeof(struct svc_request));
            struct worker *w=from_channel(fdchannel[a]);
            if(!w)return -11;
            struct svc_received_request *packet=(struct svc_received_request *)b;
            if(w->ready_sent && w->kind==SVC_SHELL &&
               spoof_control && !spoof_control_sent && ticks>=w->start+80) {
                spoof_control_sent=1;
                memset(packet,0,sizeof(*packet));
                packet->peer=(struct ipc_peer){(unsigned long)w->pid+1,1000,1000};
                packet->data=(struct svc_request){SVC_MAGIC,SVC_VERSION,
                    SVC_OP_STOP,SVC_CORE,0};
                return sizeof(packet->data);
            }
            if(w->ready_sent || never_ready || ticks<w->start+20)return -11;
            memset(packet,0,sizeof(*packet));
            packet->peer=(struct ipc_peer){(unsigned long)w->pid,1000,1000};
            if(spoof_ready && w->kind==SVC_CORE)packet->peer.pid++;
            packet->data=(struct svc_request){SVC_MAGIC,SVC_VERSION,SVC_OP_READY,
                                              (unsigned short)w->kind,0};
            w->ready_sent=1;
            return sizeof(packet->data);
        }
        case SYS_IPC_SEND: {
            assert(a>=3 && a<32 && openfds[a] && c==sizeof(struct svc_response));
            struct worker *w=from_channel(fdchannel[a]);
            assert(w && w->ready_sent && !w->ack);
            const struct svc_response *response=(const struct svc_response *)b;
            assert(response->magic==SVC_MAGIC && response->version==SVC_VERSION &&
                   response->result==SVC_OK &&
                   response->states[w->kind]==SVC_RUNNING);
            w->ack=1;
            return c;
        }
        case SYS_TRY_WAIT: {
            struct worker *w=from_pid(a);
            assert(w && !w->reaped);
            if(w->killed) {
                w->reaped=1;total_exits++;return 137;
            }
            if(w->kind==SVC_CORE && w->ack && core_crash_at>0 &&
               ticks>=core_crash_at) {
                core_crash_at=0;
                core_crashes++;
                w->reaped=1;total_exits++;
                return 73;
            }
            if(w->kind==SVC_FLAKY && w->ack && ticks>=w->start+100) {
                w->reaped=1;total_exits++;return 42;
            }
            if(w->kind==SVC_SHELL && w->ack && ticks>=1000) {
                w->reaped=1;total_exits++;return 0;
            }
            return -11;
        }
        case SYS_KILL: {
            struct worker *w=from_pid(a);
            assert(w && !w->reaped && !w->killed);
            w->killed=1;kill_order[total_kills++]=a;return 0;
        }
        case SYS_WAIT_EVENTS_UNTIL: {
            assert(a>=0 && (unsigned long)a<=0xffffffffUL && b>ticks && c==0);
            sleeps++;
            if(clock_failure_at && sleeps==(unsigned)clock_failure_at)return -5;
            long next=b;
            for(unsigned i=0;i<count;i++) {
                const struct worker *w=&workers[i];
                if(w->reaped || w->killed)continue;
                long candidate=0;
                if(!w->ready_sent && !never_ready)candidate=w->start+20;
                else if(w->ack && w->kind==SVC_FLAKY)candidate=w->start+100;
                else if(w->ack && w->kind==SVC_SHELL)candidate=1000;
                if(candidate>ticks && candidate<next)next=candidate;
                if(w->ack && w->kind==SVC_CORE && core_crash_at>ticks &&
                   core_crash_at<next)next=core_crash_at;
                if(w->ack && w->kind==SVC_SHELL && spoof_control &&
                   !spoof_control_sent && w->start+80>ticks &&
                   w->start+80<next)next=w->start+80;
            }
            ticks=next;
            unsigned long events=0;
            for(unsigned fd=0;fd<32;fd++)if(((unsigned long)a&(1UL<<fd))!=0) {
                assert(openfds[fd]);
                struct worker *w=from_channel(fdchannel[fd]);
                if(w && !w->reaped &&
                   ((!w->ready_sent && !never_ready && ticks>=w->start+20) ||
                    (w->ack && w->kind==SVC_SHELL && spoof_control &&
                     !spoof_control_sent && ticks>=w->start+80)))
                    events|=1UL<<fd;
            }
            for(unsigned i=0;i<count;i++) {
                const struct worker *w=&workers[i];
                if(w->reaped || w->killed || !w->ack)continue;
                if((w->kind==SVC_FLAKY && ticks>=w->start+100) ||
                   (w->kind==SVC_SHELL && ticks>=1000) ||
                   (w->kind==SVC_CORE && core_crash_at>0 && ticks>=core_crash_at))
                    events|=1UL<<32;
            }
            assert(sleeps<1000);
            return (long)events;
        }
    }
    fprintf(stderr,"Unexpected manager syscall %ld(%ld,%ld,%ld)\n",op,a,b,c);
    abort();
}
static void normal_session(void) {
    reset();
    assert(runServiceManager()==0);
    assert(count==5 && total_exits==5 && total_kills==1);
    assert(ticks>=1000 && sleeps>0 && sleeps<50);
    assert(registry[SVC_CORE].state==SVC_STOPPED &&
           registry[SVC_FLAKY].state==SVC_STOPPED &&
           registry[SVC_SHELL].state==SVC_STOPPED);
    assert(registry[SVC_CORE].attempts==1 && registry[SVC_FLAKY].attempts==3 &&
           registry[SVC_SHELL].attempts==1);
    assert(strstr(log_text,"AGENTOS MANAGER BEGIN ROOT=0000000000000064"));
    assert(strstr(log_text,"AGENTOS MANAGER ONLIN ROOT=0000000000000064"));
    assert(strstr(log_text,"AGENTOS SHELL START PID=0000000000000069"));
    assert(strstr(log_text,"AGENTOS MANAGER SHUTD ROOT=0000000000000064"));
    assert(strstr(log_text,"AGENTOS MANAGER ENDED ROOT=0000000000000064"));
    unsigned ready_count=0;
    const char *scan=log_text;
    while((scan=strstr(scan,"AGENTOS MANAGER READY"))){ready_count++;scan++;}
    assert(ready_count==4); // core once, flaky three times; shell handshake separate
    reset();spoof_control=1;
    assert(runServiceManager()==0 && spoof_control_sent &&
           total_kills==1 && registry[SVC_CORE].state==SVC_STOPPED);
}
static void failure_injection(void) {
    reset();failure_mode=1;
    assert(runServiceManager()==81 && !count && !total_kills);
    reset();clock_failure_at=2;
    assert(runServiceManager()==81 && total_kills==2); // both newly live services must be stopped
    reset();spoof_ready=1;
    assert(runServiceManager()==81 && registry[SVC_CORE].attempts==3 &&
           total_kills==3 && !registry[SVC_SHELL].pid);
    reset();never_ready=1;
    assert(runServiceManager()==81 && registry[SVC_CORE].attempts==3 &&
           total_kills==3 && !registry[SVC_SHELL].pid);
}
static void dependency_failure_and_restart_window(void) {
    /* The operational shell must be stopped when its core dependency dies.
     * Its replacement must be a new child, with the same stable kernel-owned
     * registry; the failed optional worker must not be silently rearmed.
     */
    reset();
    core_crash_at=700;
    assert(runServiceManager()==0);
    unsigned core_starts=0,shell_starts=0,flaky_starts=0;
    for (unsigned i=0;i<count;i++) {
        if (workers[i].kind==SVC_CORE) core_starts++;
        if (workers[i].kind==SVC_SHELL) shell_starts++;
        if (workers[i].kind==SVC_FLAKY) flaky_starts++;
    }
    assert(core_crashes==1 && core_starts==2 && shell_starts==2);
    assert(flaky_starts==3 && total_exits==count && total_kills==2);
    assert(registry[SVC_CORE].state==SVC_STOPPED &&
           registry[SVC_FLAKY].attempts==3 &&
           registry[SVC_SHELL].state==SVC_STOPPED);

    /* Long healthy uptime replenishes the bounded restart budget, whereas
     * three quick crashes in the same window remain terminal until START.
     */
    reset();
    owner_pid=100;
    registry[SVC_CORE].state=SVC_RUNNING;
    struct record *flaky=&registry[SVC_FLAKY];
    flaky->state=SVC_RUNNING;
    flaky->attempts=3;
    flaky->window_started=10;
    assert(failed(SVC_FLAKY,RESTART_WINDOW_MS+10,42)==0);
    assert(flaky->attempts==0 && flaky->state==SVC_BACKOFF &&
           flaky->retry_at==RESTART_WINDOW_MS+10+RESTART_BASE_MS);
    assert(start_entry(SVC_FLAKY,flaky->retry_at)==1);
    assert(flaky->attempts==1 && flaky->window_started==RESTART_WINDOW_MS+10);
    assert(flaky->pid>0);
    assert(kill_and_reap(flaky));
    reset();
    owner_pid=100;
    registry[SVC_CORE].state=SVC_RUNNING;
    flaky=&registry[SVC_FLAKY];
    flaky->state=SVC_RUNNING;
    flaky->attempts=3;
    flaky->window_started=10;
    assert(failed(SVC_FLAKY,RESTART_WINDOW_MS+9,42)==0);
    assert(flaky->state==SVC_FAILED && flaky->attempts==3);
}

static void dependency_graph_and_leaf_first_shutdown(void) {
    reset();
    assert(registry_valid());
    registry[SVC_CORE].dependency=SVC_FLAKY;
    assert(!registry_valid()); // cycle core -> flaky -> core
    registry[SVC_CORE].dependency=SVC_COUNT;
    registry[SVC_FLAKY].dependency=SVC_COUNT+1;
    assert(!registry_valid()); // invalid index, not an arbitrary pointer
    registry[SVC_FLAKY].dependency=SVC_SHELL;
    assert(registry_valid()); // nested core -> shell -> flaky
    assert(reaches(SVC_FLAKY,SVC_CORE)==1);
    assert(reaches(SVC_CORE,SVC_FLAKY)==0);
    owner_pid=100;
    workers[0]=(struct worker){101,0,SVC_SHELL,0,1,1,0,0};
    workers[1]=(struct worker){102,0,SVC_FLAKY,0,1,1,0,0};
    count=2;
    registry[SVC_CORE].state=SVC_RUNNING;
    registry[SVC_SHELL].state=SVC_RUNNING;
    registry[SVC_SHELL].pid=101;
    registry[SVC_FLAKY].state=SVC_RUNNING;
    registry[SVC_FLAKY].pid=102;
    shell_active=1;
    assert(suspend_dependents(SVC_CORE));
    assert(total_kills==2 && kill_order[0]==102 && kill_order[1]==101);
    assert(shell_active==0 && registry[SVC_SHELL].state==SVC_DOWN &&
           registry[SVC_FLAKY].state==SVC_DOWN);
    assert(workers[0].reaped && workers[1].reaped);
    reset();
    registry[SVC_FLAKY].dependency=SVC_SHELL;
    registry[SVC_CORE].state=SVC_RUNNING;
    registry[SVC_SHELL].desired=0;
    registry[SVC_FLAKY].desired=1;
    struct svc_request req={SVC_MAGIC,SVC_VERSION,SVC_OP_STOP,SVC_CORE,0};
    assert(apply_command(&req,100)==SVC_BAD_DEPENDENCY);
    reset();
    registry[SVC_FLAKY].dependency=SVC_SHELL;
    owner_pid=100;
    workers[0]=(struct worker){201,0,SVC_CORE,0,1,1,0,0};
    workers[1]=(struct worker){202,0,SVC_SHELL,0,1,1,0,0};
    workers[2]=(struct worker){203,0,SVC_FLAKY,0,1,1,0,0};
    count=3;
    registry[SVC_CORE].pid=201;
    registry[SVC_SHELL].pid=202;
    registry[SVC_FLAKY].pid=203;
    assert(stop_all());
    assert(total_kills==3 && kill_order[0]==203 && kill_order[1]==202 &&
           kill_order[2]==201);
}
static void command_authorization_and_dependency(void) {
    reset();
    struct svc_request request={SVC_MAGIC,SVC_VERSION,SVC_OP_STOP,SVC_CORE,0};
    registry[SVC_CORE].state=SVC_RUNNING;
    registry[SVC_SHELL].pid=999;
    registry[SVC_FLAKY].desired=1;
    assert(apply_command(&request,20)==SVC_BAD_DEPENDENCY);
    request.operation=SVC_OP_START;
    request.service=SVC_FLAKY;
    registry[SVC_CORE].state=SVC_FAILED;
    registry[SVC_FLAKY].desired=0;
    registry[SVC_FLAKY].state=SVC_STOPPED;
    assert(apply_command(&request,20)==SVC_BAD_DEPENDENCY);
    request.service=SVC_COUNT;
    assert(apply_command(&request,20)==SVC_BAD_REQUEST);
    request.operation=SVC_OP_STATUS;
    assert(apply_command(&request,20)==SVC_OK);
    request.operation=SVC_OP_RESTART;
    request.service=SVC_SHELL;
    assert(apply_command(&request,20)==SVC_BAD_REQUEST);
    request.magic=0;
    assert(apply_command(&request,20)==SVC_BAD_REQUEST);

    // A stopped optional service can be explicitly re-armed. A successful
    // START or RESTART resets its entire bounded failure budget.
    reset();
    registry[SVC_CORE].state=SVC_RUNNING;
    registry[SVC_FLAKY].state=SVC_FAILED;
    registry[SVC_FLAKY].attempts=3;
    request=(struct svc_request){SVC_MAGIC,SVC_VERSION,SVC_OP_STOP,SVC_FLAKY,0};
    assert(apply_command(&request,500)==SVC_OK &&
           registry[SVC_FLAKY].state==SVC_STOPPED &&
           registry[SVC_FLAKY].desired==0);
    request.operation=SVC_OP_START;
    assert(apply_command(&request,520)==SVC_OK &&
           registry[SVC_FLAKY].state==SVC_DOWN &&
           registry[SVC_FLAKY].desired==1 &&
           registry[SVC_FLAKY].attempts==0);
    request.operation=SVC_OP_RESTART;
    assert(apply_command(&request,540)==SVC_OK &&
           registry[SVC_FLAKY].state==SVC_DOWN &&
           registry[SVC_FLAKY].attempts==0);
}
int main(void){
    normal_session();
    failure_injection();
    dependency_failure_and_restart_window();
    dependency_graph_and_leaf_first_shutdown();
    command_authorization_and_dependency();
    puts("Persistent service manager registry, dependency fail-stop, restart window, IPC authentication and shutdown passed");
    return 0;
}
