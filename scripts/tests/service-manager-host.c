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
static int spoof_control, spoof_control_sent, shell_disconnect;
static long core_crash_at;
static unsigned core_crashes;
static long kill_order[MAX_CHILDREN];
struct control {
    unsigned operation, service;
    long at;
    int sent, answered;
    unsigned result, state, attempts;
    long answered_at;
};
static struct control controls[8];
static unsigned control_count;
static long shell_exit_at, response_failure;
static int oversized_control;
/* A remote SYS_KILL accepts a stop request before its owner CPU publishes
 * the zombie. These controls model that interleaving separately from reap. */
static long gKillDelayMs, gWaitChildError, gWaitNaturalStatus;
static long gKillAcknowledgeAt[MAX_CHILDREN], gNaturalStatus[MAX_CHILDREN];
static unsigned gChildWaitCalls, gPendingKillProbes;
static int gShellExitOnProbe;

static void reset(void) {
    memset(workers,0,sizeof(workers));
    memset(openfds,0,sizeof(openfds));memset(fdchannel,0,sizeof(fdchannel));
    memset(log_text,0,sizeof(log_text));memset(times,0,sizeof(times));
    memset(kill_order,0,sizeof(kill_order));
    memset(controls,0,sizeof(controls));
    count=channel_count=sleeps=total_exits=total_kills=chars=0;
    ticks=0;next_pid=101;
    failure_mode=clock_failure_at=spoof_ready=never_ready=0;
    spoof_control=spoof_control_sent=shell_disconnect=0;
    core_crash_at=0;core_crashes=0;
    control_count=0;response_failure=0;oversized_control=0;shell_exit_at=1000;
    gKillDelayMs=gWaitChildError=0;gWaitNaturalStatus=-1;
    gChildWaitCalls=gPendingKillProbes=0;gShellExitOnProbe=0;
    memset(gKillAcknowledgeAt,0,sizeof(gKillAcknowledgeAt));
    for (unsigned pIndex=0;pIndex<MAX_CHILDREN;pIndex++) gNaturalStatus[pIndex]=-1;
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
static struct control *next_control(void) {
    for (unsigned i=0;i<control_count;i++)
        if (!controls[i].answered) return &controls[i];
    return NULL;
}
static void add_control(unsigned operation,unsigned service,long at) {
    assert(control_count<8);
    controls[control_count++]=(struct control){operation,service,at,0,0,0,0,0,0};
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
            assert(count<MAX_CHILDREN && openfds[SVC_CHANNEL_FD]);
            int kind=-1;
            if(b==9 && !memcmp((const void *)a,"svc_alive",9))kind=SVC_CORE;
            if(b==9 && !memcmp((const void *)a,"svc_flaky",9))kind=SVC_FLAKY;
            if(b==5 && !memcmp((const void *)a,"shell",5))kind=SVC_SHELL;
            assert(kind>=0);
            if(failure_mode==1 || (failure_mode==2 && kind==SVC_FLAKY)) return -12;
            if(kind==SVC_FLAKY) {
                assert(registry[SVC_CORE].state==SVC_RUNNING);
                unsigned attempt=registry[SVC_FLAKY].attempts-1;
                assert(attempt<3);
                if(attempt>0) {
                    long previous=times[attempt-1];
                    long required=RESTART_BASE_MS<<(attempt-1);
                    assert(ticks-previous>=required);
                }
                times[attempt]=ticks;
            }
            if(kind==SVC_SHELL)
                assert(registry[SVC_CORE].state==SVC_RUNNING);
            struct worker *w=&workers[count++];
            *w=(struct worker){next_pid++,ticks,kind,(int)fdchannel[SVC_CHANNEL_FD],0,0,0,0};
            return w->pid;
        }
        case SYS_IPC_TRY_RECV: {
            assert(a>=3 && a<32 && openfds[a] && b && c==IPC_MAX_MESSAGE);
            struct worker *w=from_channel(fdchannel[a]);
            if(!w)return -11;
            if(gNaturalStatus[w-workers]>=0)return 0; // exit closed its final endpoint
            if(w->ack && w->kind==SVC_SHELL && shell_disconnect &&
               ticks>=w->start+80) return 0; // peer EOF without process exit
            struct svc_received_request *packet=(struct svc_received_request *)b;
            struct control *command=next_control();
            if(w->ack && w->kind==SVC_SHELL && command &&
               !command->sent && ticks>=command->at) {
                command->sent=1;
                memset(packet,0,sizeof(*packet));
                packet->peer=(struct ipc_peer){(unsigned long)w->pid,1000,1000};
                packet->data=(struct svc_request){SVC_MAGIC,SVC_VERSION,
                    (unsigned short)command->operation,(unsigned short)command->service,0};
                return oversized_control?IPC_MAX_MESSAGE:sizeof(packet->data);
            }
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
        case SYS_IPC_TRY_SEND: {
            assert(a>=3 && a<32 && openfds[a] && c==sizeof(struct svc_response));
            struct worker *w=from_channel(fdchannel[a]);
            assert(w && w->ready_sent);
            const struct svc_response *response=(const struct svc_response *)b;
            if (w->ack) {
                struct control *command=next_control();
                assert(w->kind==SVC_SHELL && command && command->sent);
                command->answered=1;
                command->answered_at=ticks;
                command->result=response->result;
                command->state=response->states[command->service];
                command->attempts=response->attempts[command->service];
                if (response_failure) { long failure=response_failure;response_failure=0;return failure; }
                return c;
            }
            assert(response->magic==SVC_MAGIC && response->version==SVC_VERSION &&
                   response->result==SVC_OK &&
                   response->states[w->kind]==SVC_RUNNING);
            w->ack=1;
            return c;
        }
        case SYS_TRY_WAIT: {
            struct worker *w=from_pid(a);
            assert(w && !w->reaped);
            unsigned pIndex=(unsigned)(w-workers);
            if(gShellExitOnProbe==1 && w->kind==SVC_SHELL && w->ack) {
                // The status probe observes a live shell. Immediately after
                // its return another CPU commits exit 0 and endpoint EOF.
                gShellExitOnProbe=2;gNaturalStatus[pIndex]=0;return -11;
            }
            if(gNaturalStatus[pIndex]>=0) {
                w->reaped=1;total_exits++;return gNaturalStatus[pIndex];
            }
            if(w->killed) {
                if(ticks<gKillAcknowledgeAt[pIndex]) {gPendingKillProbes++;return -11;}
                w->reaped=1;total_exits++;return 137;
            }
            if(w->kind==99 && w->ack) {
                w->reaped=1;total_exits++;return 42; // exited adopted grandchild
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
            if(w->kind==SVC_SHELL && w->ack && ticks>=shell_exit_at) {
                w->reaped=1;total_exits++;return 0;
            }
            return -11;
        }
        case SYS_CHILD_AFTER: {
            assert(b==0 && c==0 && a>=0);
            long found=0;
            for (unsigned i=0;i<count;i++) {
                if (workers[i].reaped || workers[i].pid<=a)continue;
                if (!found || workers[i].pid<found) found=workers[i].pid;
            }
            return found ? found : -10;
        }
        case SYS_KILL: {
            struct worker *w=from_pid(a);
            assert(w && !w->reaped);
            unsigned pIndex=(unsigned)(w-workers);
            if(gNaturalStatus[pIndex]>=0)return 1;
            if(!w->killed) {
                w->killed=1;kill_order[total_kills++]=a;
                gKillAcknowledgeAt[pIndex]=ticks+gKillDelayMs;
            }
            return 0;
        }
        case SYS_WAIT_CHILD_UNTIL: {
            struct worker *pWorker=from_pid(a);
            assert(pWorker && !pWorker->reaped && b>=ticks && c==0);
            assert((unsigned long)b-(unsigned long)ticks<=5000);
            gChildWaitCalls++;
            // Registered ownership and descriptors must survive the whole
            // blocked wait, including an error/timeout return.
            for(unsigned pId=0;pId<SVC_COUNT;pId++) if(registry[pId].pid==a) {
                assert(registry[pId].fd<0 || openfds[registry[pId].fd]);
            }
            long pStatus=mock_call(SYS_TRY_WAIT,a,0,0);
            if(pStatus!=-11)return pStatus;
            if(gWaitChildError)return gWaitChildError;
            assert(pWorker->killed);
            unsigned pIndex=(unsigned)(pWorker-workers);
            if(gKillAcknowledgeAt[pIndex]>b) {ticks=b;return -110;}
            ticks=gKillAcknowledgeAt[pIndex];
            if(gWaitNaturalStatus>=0)gNaturalStatus[pIndex]=gWaitNaturalStatus;
            return mock_call(SYS_TRY_WAIT,a,0,0);
        }
        case SYS_WAIT_EVENTS_UNTIL: {
            assert(a>=0 && (unsigned long)a<=0xffffffffUL && b>=ticks && c==0);
            sleeps++;
            if(clock_failure_at && sleeps==(unsigned)clock_failure_at)return -5;
            long next=b;
            for(unsigned i=0;i<count;i++) {
                const struct worker *w=&workers[i];
                if(w->reaped || w->killed)continue;
                long candidate=0;
                if(!w->ready_sent && !never_ready)candidate=w->start+20;
                else if(w->ack && w->kind==SVC_FLAKY)candidate=w->start+100;
                else if(w->ack && w->kind==SVC_SHELL)candidate=shell_exit_at;
                if(candidate>ticks && candidate<next)next=candidate;
                if(w->ack && w->kind==SVC_CORE && core_crash_at>ticks &&
                   core_crash_at<next)next=core_crash_at;
                if(w->ack && w->kind==SVC_SHELL &&
                   (shell_disconnect || (spoof_control && !spoof_control_sent)) &&
                   w->start+80>ticks && w->start+80<next)
                    next=w->start+80;
                struct control *command=next_control();
                if(w->ack && w->kind==SVC_SHELL && command && !command->sent &&
                   command->at>ticks && command->at<next) next=command->at;
            }
            ticks=next;
            unsigned long events=0;
            for(unsigned fd=0;fd<32;fd++)if(((unsigned long)a&(1UL<<fd))!=0) {
                assert(openfds[fd]);
                struct worker *w=from_channel(fdchannel[fd]);
                if(w && !w->reaped &&
                   ((!w->ready_sent && !never_ready && ticks>=w->start+20) ||
                    (w->ack && w->kind==SVC_SHELL &&
                     (shell_disconnect || (spoof_control && !spoof_control_sent)) &&
                     ticks>=w->start+80)))
                    events|=1UL<<fd;
                struct control *command=next_control();
                if(w && w->ack && w->kind==SVC_SHELL && command && !command->sent &&
                   ticks>=command->at) events|=1UL<<fd;
            }
            for(unsigned i=0;i<count;i++) {
                const struct worker *w=&workers[i];
                if(w->reaped || w->killed || !w->ack)continue;
                if((w->kind==SVC_FLAKY && ticks>=w->start+100) ||
                   (w->kind==SVC_SHELL && ticks>=shell_exit_at) ||
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
    reset();shell_disconnect=1;
    assert(runServiceManager()==81 && registry[SVC_SHELL].attempts==3 &&
           total_kills>=4 && !registry[SVC_SHELL].pid);
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

static void adopted_orphan_reaping(void) {
    reset();
    owner_pid=100;
    // First child is a live abandoned grandchild, second a legitimate
    // registered service: only the adopted unknown child may be killed.
    workers[0]=(struct worker){201,0,99,0,0,0,0,0};
    workers[1]=(struct worker){202,0,SVC_CORE,0,0,0,0,0};
    count=2;
    registry[SVC_CORE].pid=202;
    assert(reap_unmanaged());
    assert(total_kills==1 && kill_order[0]==201 &&
           workers[0].reaped && !workers[1].reaped);
    assert(reap_unmanaged() && total_kills==1); // idempotent
    reset();
    owner_pid=100;
    // A zombie adopted by PID 1 is reaped with its original exit status.
    // No extra kill syscall is issued to an already-exited process.
    workers[0]=(struct worker){301,0,99,0,0,1,0,0};
    count=1;
    assert(reap_unmanaged() && workers[0].reaped && total_kills==0);
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
    ticks=520;
    assert(apply_command(&request,520)==SVC_OK &&
           registry[SVC_FLAKY].state==SVC_STARTING &&
           registry[SVC_FLAKY].desired==1 &&
           registry[SVC_FLAKY].attempts==1 && registry[SVC_FLAKY].pid>0);
    long first_pid=registry[SVC_FLAKY].pid;
    request.operation=SVC_OP_RESTART;
    ticks=540;
    assert(apply_command(&request,540)==SVC_OK &&
           registry[SVC_FLAKY].state==SVC_STARTING &&
           registry[SVC_FLAKY].attempts==1 && registry[SVC_FLAKY].pid!=first_pid);
    assert(from_pid(first_pid)->reaped);
    assert(kill_and_reap(&registry[SVC_FLAKY]));
}

static unsigned starts_of(unsigned kind) {
    unsigned result=0;
    for (unsigned i=0;i<count;i++) if ((unsigned)workers[i].kind==kind) result++;
    return result;
}
static void no_leaked_children_or_channels(void) {
    assert(total_exits==count);
    for (unsigned i=0;i<count;i++) assert(workers[i].reaped);
    for (unsigned fd=3;fd<32;fd++) assert(!openfds[fd]);
}
static void full_loop_command_lifecycle(void) {
    /* No STATUS request follows START/RESTART. Only the real worker READY
     * event may wake the manager; this catches the old sixty-second delay
     * which an extra status query would accidentally conceal. */
    for (unsigned operation=SVC_OP_START;operation<=SVC_OP_RESTART;operation+=2) {
        reset();shell_exit_at=1800;
        add_control(operation,SVC_FLAKY,600);
        assert(runServiceManager()==0);
        const struct control *command=&controls[0];
        assert(command->answered && command->answered_at==600 &&
               command->result==SVC_OK && command->state==SVC_STARTING &&
               command->attempts==1);
        assert(starts_of(SVC_FLAKY)==6);
        unsigned starts_at_command=0;
        for (unsigned i=0;i<count;i++)
            if (workers[i].kind==SVC_FLAKY && workers[i].start==600) starts_at_command++;
        assert(starts_at_command==1);
        no_leaked_children_or_channels();
    }
    /* Ordinary STOP is persistent intent. Later core recovery must restore
     * the terminal without reviving the deliberately stopped optional child. */
    reset();shell_exit_at=1200;core_crash_at=700;
    add_control(SVC_OP_STOP,SVC_FLAKY,600);
    assert(runServiceManager()==0 && core_crashes==1);
    assert(controls[0].answered && controls[0].state==SVC_STOPPED &&
           controls[0].attempts==0 && controls[0].result==SVC_OK);
    assert(starts_of(SVC_CORE)==2 && starts_of(SVC_SHELL)==2 &&
           starts_of(SVC_FLAKY)==3);
    no_leaked_children_or_channels();

    // A dependent whose backoff elapsed while core is still starting cannot
    // make progress yet. Do not return an expired deadline and spin PID 1.
    reset();
    registry[SVC_CORE].state=SVC_STARTING;
    registry[SVC_CORE].pid=101;
    registry[SVC_CORE].ready_deadline=750;
    registry[SVC_FLAKY].state=SVC_BACKOFF;
    registry[SVC_FLAKY].retry_at=100;
    assert(event_deadline(200)==750);
}
static void bounded_control_failures(void) {
    reset();oversized_control=1;
    add_control(SVC_OP_STATUS,SVC_FLAKY,600);
    assert(runServiceManager()==0 && controls[0].answered &&
           controls[0].result==SVC_BAD_REQUEST && starts_of(SVC_SHELL)==1);
    no_leaked_children_or_channels();
    const long failures[]={-11,-32};
    for (unsigned i=0;i<sizeof(failures)/sizeof(failures[0]);i++) {
        reset();response_failure=failures[i];
        add_control(SVC_OP_STATUS,SVC_FLAKY,600);
        assert(runServiceManager()==0 && starts_of(SVC_CORE)==1 &&
               starts_of(SVC_SHELL)==2 && registry[SVC_SHELL].attempts==2);
        no_leaked_children_or_channels();
    }
    // An optional allocation failure consumes a finite startup budget,
    // closes both channel ends, and leaves the diagnostic shell usable.
    reset();failure_mode=2;
    assert(runServiceManager()==0 && starts_of(SVC_CORE)==1 &&
           starts_of(SVC_FLAKY)==0 && registry[SVC_FLAKY].attempts==3 &&
           starts_of(SVC_SHELL)==1);
    no_leaked_children_or_channels();
}
static struct record *startManagedChildForTest(unsigned aId) {
    owner_pid=100;ticks=100;
    if(aId!=SVC_CORE)registry[SVC_CORE].state=SVC_RUNNING;
    assert(start_entry(aId,ticks)==1);
    return &registry[aId];
}
static void remoteKillWaitsForActualOwnerExit(void) {
    reset();
    struct record *pService=startManagedChildForTest(SVC_CORE);
    long pPid=pService->pid,pFd=pService->fd;
    gKillDelayMs=25;
    assert(kill_and_reap(pService));
    assert(gChildWaitCalls==1 && gPendingKillProbes>0 && ticks==125);
    assert(from_pid(pPid)->reaped && pService->pid==0 && pService->fd==-1 &&
           pService->last_status==137 && !openfds[pFd]);

    // The same delayed acknowledgement must succeed in the complete real
    // shutdown path, not only when the helper is called directly.
    reset();gKillDelayMs=25;
    assert(runServiceManager()==0 && gChildWaitCalls==1);
    no_leaked_children_or_channels();
}
static void failedKillWaitPreservesIdentityAndEndpoint(void) {
    const long pErrors[]={-110,-5,-10};
    for(unsigned pCase=0;pCase<sizeof(pErrors)/sizeof(pErrors[0]);pCase++) {
        reset();
        struct record *pService=startManagedChildForTest(SVC_CORE);
        long pPid=pService->pid,pFd=pService->fd;
        pService->last_status=42;
        gKillDelayMs=pErrors[pCase]==-110?6000:25;
        gWaitChildError=pErrors[pCase]==-110?0:pErrors[pCase];
        assert(!kill_and_reap(pService));
        assert(gChildWaitCalls==1 && !from_pid(pPid)->reaped &&
               pService->pid==pPid && pService->fd==pFd && openfds[pFd] &&
               pService->last_status==42);
        if(pErrors[pCase]==-110)assert(ticks==5100);
    }
    // A missing or unrepresentable HPET deadline must fail without issuing
    // an unbounded wait or discarding ownership of the pending child.
    const long pClocks[]={-5,(long)(MAX_MS-100)};
    for(unsigned pCase=0;pCase<sizeof(pClocks)/sizeof(pClocks[0]);pCase++) {
        reset();
        struct record *pService=startManagedChildForTest(SVC_CORE);
        long pPid=pService->pid,pFd=pService->fd;
        ticks=pClocks[pCase];gKillDelayMs=25;
        assert(!kill_and_reap(pService));
        assert(gChildWaitCalls==0 && !from_pid(pPid)->reaped &&
               pService->pid==pPid && pService->fd==pFd && openfds[pFd]);
    }
}
static void naturalExitWinsAcceptedKillWithoutStatusRewrite(void) {
    reset();
    struct record *pService=startManagedChildForTest(SVC_CORE);
    gKillDelayMs=25;gWaitNaturalStatus=42;
    assert(kill_and_reap(pService));
    assert(total_kills==1 && gChildWaitCalls==1 && pService->last_status==42);

    reset();
    pService=startManagedChildForTest(SVC_CORE);
    gNaturalStatus[from_pid(pService->pid)-workers]=0;
    assert(kill_and_reap(pService));
    assert(total_kills==0 && pService->last_status==0);
}
static void remoteOrphanKillUsesBoundedOwnerWait(void) {
    reset();owner_pid=100;
    workers[0]=(struct worker){201,0,99,0,0,0,0,0};
    workers[1]=(struct worker){202,0,SVC_CORE,0,0,0,0,0};
    count=2;registry[SVC_CORE].pid=202;gKillDelayMs=25;
    assert(reap_unmanaged());
    assert(gChildWaitCalls==1 && workers[0].reaped && !workers[1].reaped &&
           total_kills==1 && ticks==25);

    reset();owner_pid=100;
    workers[0]=(struct worker){201,0,99,0,0,0,0,0};
    count=1;gKillDelayMs=6000;
    assert(!reap_unmanaged());
    assert(gChildWaitCalls==1 && !workers[0].reaped && ticks==5000);
}
static void shellExitBetweenStatusProbeAndEofShutsDown(void) {
    reset();
    struct record *pShell=startManagedChildForTest(SVC_SHELL);
    struct worker *pWorker=from_pid(pShell->pid);
    pShell->state=SVC_RUNNING;pShell->ready_once=1;
    pWorker->ack=pWorker->ready_sent=1;shell_active=1;
    for(unsigned pId=0;pId<SVC_COUNT;pId++)registry[pId].desired=0;
    gShellExitOnProbe=1;
    assert(advance_registry(ticks)==0 && gShellExitOnProbe==2 && !shutdown_requested);
    assert(check_control(ticks)==0);
    assert(shutdown_requested && !shell_active && pShell->state==SVC_STOPPED &&
           pShell->pid==0 && pShell->fd==-1 && pShell->last_status==0 &&
           total_kills==0 && pWorker->reaped);

    reset();gShellExitOnProbe=1;
    assert(runServiceManager()==0 && gShellExitOnProbe==2 &&
           starts_of(SVC_SHELL)==1 && ticks==shell_exit_at);
    no_leaked_children_or_channels();

    // A naturally finishing shell may also win after the stop request was
    // accepted. Its final zero status still means an orderly session exit.
    reset();pShell=startManagedChildForTest(SVC_SHELL);
    pWorker=from_pid(pShell->pid);
    pShell->state=SVC_RUNNING;pShell->ready_once=1;
    pWorker->ack=pWorker->ready_sent=1;shell_active=1;
    shell_disconnect=1;ticks=pWorker->start+80;
    gKillDelayMs=25;gWaitNaturalStatus=0;
    assert(check_control(ticks)==0 && shutdown_requested && !shell_active &&
           pShell->last_status==0 && pShell->state==SVC_STOPPED &&
           total_kills==1 && pWorker->reaped);
}
static void restartAndRecoveryUseTimeAfterRemoteStop(void) {
    reset();
    struct record *pService=startManagedChildForTest(SVC_FLAKY);
    long pOldPid=pService->pid;
    struct svc_request pRequest={SVC_MAGIC,SVC_VERSION,SVC_OP_RESTART,SVC_FLAKY,0};
    gKillDelayMs=800;
    assert(apply_command(&pRequest,ticks)==SVC_OK);
    assert(ticks==900 && from_pid(pOldPid)->reaped && pService->pid!=pOldPid &&
           pService->ready_deadline==ticks+READY_TIMEOUT_MS);

    reset();pService=startManagedChildForTest(SVC_SHELL);
    struct worker *pWorker=from_pid(pService->pid);
    pService->state=SVC_RUNNING;pService->ready_once=1;
    pWorker->ack=pWorker->ready_sent=1;shell_active=1;
    shell_disconnect=1;ticks=pWorker->start+80;gKillDelayMs=800;
    assert(check_control(ticks)==0 && !shutdown_requested);
    assert(ticks==980 && pService->state==SVC_BACKOFF &&
           pService->retry_at==ticks+RESTART_BASE_MS);

    reset();pService=startManagedChildForTest(SVC_CORE);
    never_ready=1;ticks=pService->ready_deadline;gKillDelayMs=800;
    assert(advance_registry(ticks)==0);
    assert(ticks==1650 && pService->state==SVC_BACKOFF &&
           pService->retry_at==ticks+RESTART_BASE_MS);

    // A core exit first stops its live dependent. Its own restart backoff
    // must start after that remote stop, not before the blocking traversal.
    reset();pService=startManagedChildForTest(SVC_CORE);
    pService->state=SVC_RUNNING;
    from_pid(pService->pid)->ack=1;
    struct record *pShell=startManagedChildForTest(SVC_SHELL);
    pShell->state=SVC_RUNNING;from_pid(pShell->pid)->ack=1;shell_active=1;
    core_crash_at=ticks;gKillDelayMs=800;
    assert(advance_registry(ticks)==0 && core_crashes==1);
    assert(ticks==900 && pService->last_status==73 && pService->state==SVC_BACKOFF &&
           pService->retry_at==ticks+RESTART_BASE_MS && pShell->pid==0 &&
           pShell->state==SVC_DOWN);
}
static void readinessFailureKeepsTheCollectedNaturalStatus(void) {
    for(unsigned pMalformed=0;pMalformed<2;pMalformed++) {
        const long pStatuses[]={0,42};
        for(unsigned pCase=0;pCase<sizeof(pStatuses)/sizeof(pStatuses[0]);pCase++) {
            reset();
            struct record *pService=startManagedChildForTest(SVC_CORE);
            long pPid=pService->pid;
            if(pMalformed) {spoof_ready=1;ticks+=20;}
            else {never_ready=1;ticks=pService->ready_deadline;}
            gKillDelayMs=25;gWaitNaturalStatus=pStatuses[pCase];
            assert(advance_registry(ticks)==0 && from_pid(pPid)->reaped);
            assert(pService->last_status==pStatuses[pCase] &&
                   pService->state==SVC_BACKOFF && pService->pid==0 &&
                   pService->retry_at==ticks+RESTART_BASE_MS);
        }
    }
}
int main(void){
    remoteKillWaitsForActualOwnerExit();
    failedKillWaitPreservesIdentityAndEndpoint();
    naturalExitWinsAcceptedKillWithoutStatusRewrite();
    remoteOrphanKillUsesBoundedOwnerWait();
    shellExitBetweenStatusProbeAndEofShutsDown();
    restartAndRecoveryUseTimeAfterRemoteStop();
    readinessFailureKeepsTheCollectedNaturalStatus();
    normal_session();
    failure_injection();
    dependency_failure_and_restart_window();
    dependency_graph_and_leaf_first_shutdown();
    adopted_orphan_reaping();
    command_authorization_and_dependency();
    full_loop_command_lifecycle();
    bounded_control_failures();
    puts("Persistent manager lifecycle, asynchronous stops, exit races, bounded IPC, restart budget and shutdown passed");
    return 0;
}
