#include "abi.h"
#include "service_protocol.h"

/* The original BSP PID 1 continues here after its one-time boot handoff.
 * It owns the three-entry service registry for its entire terminal session:
 * dependency-aware readiness, authenticated IPC control, monitored exits,
 * capped exponential restart with timer-backed waits and ordered shutdown.
 * The kernel remains the ultimate authority on PID ownership and memory.
 *
 * Initial optional-worker probation precedes the first terminal prompt.
 * That boot policy never prevents recovery of an established shell session.
 */
#define MAX_MS 0x7fffffffffffffffUL
enum { QUIET_WAKE_MS=60000, READY_TIMEOUT_MS=750, RESTART_BASE_MS=40, RESTART_WINDOW_MS=5000, MAX_ATTEMPTS=3 };
struct record {
    const char *name, *elf;
    unsigned name_length, elf_length, dependency;
    unsigned char desired, state, attempts, limit, ready_once;
    long pid, fd, ready_deadline, retry_at, last_status, window_started;
};

static struct record registry[SVC_COUNT] = {
    { "core", "svc_alive", 4, 9, SVC_COUNT, 1, SVC_DOWN, 0, MAX_ATTEMPTS, 0, 0, -1, 0, 0, 0, -1 },
    { "flaky", "svc_flaky", 5, 9, SVC_CORE, 1, SVC_DOWN, 0, MAX_ATTEMPTS, 0, 0, -1, 0, 0, 0, -1 },
    { "shell", "shell", 5, 5, SVC_CORE, 1, SVC_DOWN, 0, MAX_ATTEMPTS, 0, 0, -1, 0, 0, 0, -1 }
};
static long owner_pid;
static int shell_active, shutdown_requested, fatal_error, online_announced;
/* Read the complete bounded kernel message before checking its protocol.
 * A malformed oversized request must not stay queued behind EMSGSIZE and
 * repeatedly wake PID 1 without making progress. */
struct request_packet {
    struct ipc_peer peer;
    union { struct svc_request request; unsigned char bytes[IPC_MAX_MESSAGE]; } data;
};

static unsigned text_length(const char *text) {
    unsigned n=0;
    while (text[n]) n++;
    return n;
}

static int put(const char *value, unsigned count) {
    return os_call(SYS_WRITE,1,(long)value,count)==(long)count;
}
static int manager_phase(const char *action) {
    char line[]="AGENTOS MANAGER BEGIN ROOT=0000000000000000 COUNT=00000003\r\n";
    unsigned len=text_length(action);
    if (len!=5) return 0;
    for (unsigned i=0;i<5;i++) line[sizeof("AGENTOS MANAGER ")-1+i]=action[i];
    format_hex(line+sizeof("AGENTOS MANAGER BEGIN ROOT=")-1,(unsigned long)owner_pid,16);
    return put(line,sizeof(line)-1);
}

static int manager_event(const char *action, unsigned id) {
    /* Do not write asynchronous logs in the middle of interactive shell
     * command echo. While the shell is active, status remains inspectable
     * via the authenticated registry IPC protocol. */
    if (shell_active) return 1;
    char line[]="AGENTOS MANAGER READY ROOT=0000000000000000 SERVICE=flaky PID=0000000000000000 ATTEMPT=00000000\r\n";
    unsigned n=text_length(action);
    if (n!=5) return 0;
    for (unsigned i=0;i<5;i++) line[sizeof("AGENTOS MANAGER ")-1+i]=action[i];
    const char *name=registry[id].name;
    /* Fixed five-byte field avoids modifying the length of the diagnostic. */
    for (unsigned i=0;i<5;i++) line[sizeof("AGENTOS MANAGER READY ROOT=0000000000000000 SERVICE=")-1+i]=
        name[i] ? name[i] : ' ';
    format_hex(line+sizeof("AGENTOS MANAGER READY ROOT=")-1,(unsigned long)owner_pid,16);
    format_hex(line+sizeof("AGENTOS MANAGER READY ROOT=0000000000000000 SERVICE=flaky PID=")-1,
               (unsigned long)registry[id].pid,16);
    format_hex(line+sizeof("AGENTOS MANAGER READY ROOT=0000000000000000 SERVICE=flaky PID=0000000000000000 ATTEMPT=")-1,
               registry[id].attempts,8);
    return put(line,sizeof(line)-1);
}

static long clock_ms(void) { return os_call(SYS_MONOTONIC_MS,0,0,0); }
static long deadline(long now, unsigned delay) {
    if (now<0 || (unsigned long)now>MAX_MS-delay) return -1;
    return now+(long)delay;
}
static void close_fd(long fd) {
    if (fd>=0) (void)os_call(SYS_CLOSE,fd,0,0);
}
/* A cycle or out-of-range dependency fails closed. The registry comes from
 * the signed image, but it must still be structurally sound before PID 1
 * starts any services. Future compiled manifests use the same contract.
 */
static int reaches(unsigned id, unsigned ancestor) {
    unsigned dep=registry[id].dependency;
    for (unsigned hops=0;hops<SVC_COUNT;hops++) {
        if (dep==SVC_COUNT) return 0;
        if (dep>=SVC_COUNT) return -1;
        if (dep==ancestor) return 1;
        dep=registry[dep].dependency;
    }
    return -1;
}
static int registry_valid(void) {
    for (unsigned id=0;id<SVC_COUNT;id++) {
        const struct record *s=&registry[id];
        if (s->dependency>SVC_COUNT || reaches(id,id)!=0 || s->limit==0 ||
            s->name_length!=text_length(s->name) ||
            s->elf_length!=text_length(s->elf)) return 0;
        for (unsigned prev=0;prev<id;prev++)
            if (s->name_length==registry[prev].name_length) {
                unsigned i=0;
                for (;i<s->name_length && s->name[i]==registry[prev].name[i];i++) {}
                if (i==s->name_length) return 0;
            }
    }
    return 1;
}
static int has_dependency(unsigned id) {
    const unsigned dep=registry[id].dependency;
    return dep==SVC_COUNT || (dep<SVC_COUNT &&
        registry[dep].state==SVC_RUNNING);
}
static int valid_peer(const struct ipc_peer *peer, long pid) {
    return peer->pid==(unsigned long)pid && peer->uid==1000 && peer->gid==1000;
}

static void finish_endpoint(struct record *service) {
    if (service->fd>=0) { close_fd(service->fd); service->fd=-1; }
}

/* Reap a child after an authorized direct-child kill. Never mark successful
 * cleanup if the kernel reports a different/foreign process or still alive.
 */
static int kill_and_reap(struct record *service) {
    if (service->pid<=0) return 1;
    long stopped=os_call(SYS_KILL,service->pid,0,0);
    if (stopped!=0 && stopped!=1) return 0;
    long status=os_call(SYS_TRY_WAIT,service->pid,0,0);
    if (status<0) return 0;
    service->last_status=status;
    service->pid=0;
    finish_endpoint(service);
    return 1;
}

static int failed(unsigned id,long now,long status);

static int start_entry(unsigned id,long now) {
    struct record *service=&registry[id];
    if (service->pid || !service->desired || !has_dependency(id)) return 0;
    /* Attempts are scoped to a CPU-local monotonic restart window. A worker
     * which survived that window starts a fresh budget after its next exit;
     * a tight crash loop still gets exactly MAX_ATTEMPTS starts. Once FAILED,
     * the operator must explicitly rearm the service; no silent retries.
     */
    if (service->window_started<0 ||
        now-service->window_started>=RESTART_WINDOW_MS) {
        service->window_started=now;
        service->attempts=0;
    }
    if (service->attempts >= service->limit) {
        service->state=SVC_FAILED;
        return 0;
    }
    service->attempts++;
    unsigned long pair=0;
    long result=os_call(SYS_IPC_PAIR,(long)&pair,0,0);
    if (result!=0) return failed(id,now,result);
    long manager_fd=(long)(unsigned)(pair & 0xffffffffUL);
    long child_fd=(long)(unsigned)(pair >> 32);
    // Exactly one designated handle is inherited by the worker/shell. It
    // immediately closes all other inherited service-manager descriptors.
    if (os_call(SYS_DUP2,child_fd,SVC_CHANNEL_FD,0)!=SVC_CHANNEL_FD) {
        close_fd(manager_fd);close_fd(child_fd);return failed(id,now,-9);
    }
    long child=os_call(SYS_SPAWN,(long)service->elf,service->elf_length,0);
    close_fd(SVC_CHANNEL_FD);
    close_fd(child_fd);
    if (child<=0 || child==owner_pid) {
        close_fd(manager_fd);
        return failed(id,now,child<0?child:-5);
    }
    service->pid=child;
    service->fd=manager_fd;
    service->state=SVC_STARTING;
    service->ready_deadline=deadline(now,READY_TIMEOUT_MS);
    if (service->ready_deadline<0 || !manager_event("START",id)) return -1;
    return 1;
}

static int send_response(long fd,unsigned result) {
    struct svc_response answer={
        SVC_MAGIC, SVC_VERSION, (unsigned short)result, {0}, {0}, 0
    };
    for (unsigned i=0;i<SVC_COUNT;i++) {
        answer.states[i]=registry[i].state;
        answer.attempts[i]=registry[i].attempts;
    }
    // A stalled peer must not block the entire supervisor inside SEND.
    // One unanswered reply violates this synchronous control protocol; the
    // caller isolates that session using the normal bounded restart policy.
    return os_call(SYS_IPC_TRY_SEND,fd,(long)&answer,sizeof(answer))==(long)sizeof(answer);
}

static int finish_start(unsigned id, long now) {
    struct record *service=&registry[id];
    struct request_packet received;
    long n=os_call(SYS_IPC_TRY_RECV,service->fd,(long)&received,sizeof(received.data.bytes));
    if (n==-11) return 0;
    if (n!=sizeof(received.data.request) || !valid_peer(&received.peer,service->pid) ||
        received.data.request.magic!=SVC_MAGIC || received.data.request.version!=SVC_VERSION ||
        received.data.request.operation!=SVC_OP_READY || received.data.request.service!=id ||
        received.data.request.reserved!=0) return -1;
    service->state=SVC_RUNNING;
    service->ready_once=1;
    service->retry_at=0;
    if (id==SVC_SHELL) {
        // The shell waits for ACK before printing its prompt. This marker
        // therefore always precedes the real SHELL READY banner.
        char line[]="AGENTOS SHELL START PID=0000000000000000\r\n";
        format_hex(line+sizeof("AGENTOS SHELL START PID=")-1,(unsigned long)service->pid,16);
        if (!put(line,sizeof(line)-1)) return -1;
        shell_active=1;
    } else if (!manager_event("READY",id)) return -1;
    if (!send_response(service->fd,SVC_OK)) return -1;
    // The stable worker waits on this lifetime channel after READY. Keeping
    // both endpoints open lets it block on IPC instead of waking periodically.
    if (id==SVC_FLAKY) finish_endpoint(service);
    (void)now;
    return 1;
}

/* Traverse the validated DAG in postorder, not array order. Descendants
 * must stop before their own prerequisites, even if service IDs were later
 * reordered. A failed optional service stays failed until operator rearm.
 */
static int suspend_dependents(unsigned dependency) {
    for (unsigned id=0;id<SVC_COUNT;id++) {
        struct record *service=&registry[id];
        if (service->dependency!=dependency) continue;
        if (!suspend_dependents(id)) return 0;
        if (service->pid<=0) continue;
        if (!kill_and_reap(service)) return 0;
        service->state=service->desired?SVC_DOWN:SVC_STOPPED;
        service->attempts=0;
        service->window_started=-1;
        service->retry_at=0;
        service->ready_once=0;
        if (id==SVC_SHELL) shell_active=0;
    }
    return 1;
}

/* The same finite restart budget applies to pre-readiness crashes and
 * ordinary runtime exits. An explicit admin START/RESTART resets the budget.
 * A stable worker replenishes its budget after RESTART_WINDOW_MS; a crash
 * storm stays capped. No failure loops without a timer wait between attempts.
 */
static int failed(unsigned id,long now,long status) {
    struct record *service=&registry[id];
    service->pid=0;
    finish_endpoint(service);
    service->last_status=status;
    if (id==SVC_SHELL) shell_active=0;
    if (service->window_started>=0 &&
        now-service->window_started>=RESTART_WINDOW_MS) {
        service->window_started=now;
        service->attempts=0;
    }
    if (!service->desired) {
        service->state=SVC_STOPPED;
        return 0;
    }
    if (service->attempts>=service->limit) {
        service->state=SVC_FAILED;
        if (!manager_event("LIMIT",id)) return -1;
        if (id==SVC_CORE && !shell_active) return -1; // critical bootstrap
        if (id==SVC_SHELL) return -1;
    } else {
        unsigned delay=RESTART_BASE_MS << (service->attempts?service->attempts-1:0);
        service->retry_at=deadline(now,delay);
        if (service->retry_at<0) return -1;
        service->state=SVC_BACKOFF;
        if (!manager_event("RETRY",id)) return -1;
    }
    return 0;
}

static int apply_command(const struct svc_request *req,long now) {
    if (req->reserved || req->magic!=SVC_MAGIC || req->version!=SVC_VERSION)
        return SVC_BAD_REQUEST;
    if (req->operation==SVC_OP_STATUS) return SVC_OK;
    if (req->operation<SVC_OP_START || req->operation>SVC_OP_RESTART ||
        req->service>=SVC_SHELL) return SVC_BAD_REQUEST;
    struct record *service=&registry[req->service];
    if (req->operation==SVC_OP_START) {
        if (service->desired && service->state!=SVC_FAILED &&
            service->state!=SVC_STOPPED) return SVC_ALREADY_RUNNING;
        if (!has_dependency(req->service)) return SVC_BAD_DEPENDENCY;
        service->desired=1;service->attempts=0;service->window_started=-1;service->retry_at=now;
        service->state=SVC_DOWN;
    } else {
        // Never kill the authenticated caller's prerequisite before it
        // receives a reply; enforce this rule transitively for any DAG.
        for (unsigned id=0;id<SVC_COUNT;id++)
            if (id!=req->service && reaches(id,req->service)>0 &&
                (registry[id].desired || registry[id].pid>0))
                return SVC_BAD_DEPENDENCY;
        if (req->operation==SVC_OP_RESTART && !has_dependency(req->service))
            return SVC_BAD_DEPENDENCY;
        if (!kill_and_reap(service)) return SVC_INTERNAL_ERROR;
        service->desired=req->operation==SVC_OP_RESTART;
        service->attempts=0;
        service->window_started=-1;
        service->retry_at=now;
        service->state=service->desired?SVC_DOWN:SVC_STOPPED;
    }
    // An acknowledged START/RESTART means a real child has been created.
    // READY is deliberately separate and is reported by subsequent STATUS.
    if (service->desired && start_entry(req->service,now)!=1)
        return SVC_INTERNAL_ERROR;
    return SVC_OK;
}

static int recover_shell(long now) {
    if (!kill_and_reap(&registry[SVC_SHELL])) return -1;
    return failed(SVC_SHELL,now,137);
}

static int check_control(long now) {
    struct record *shell=&registry[SVC_SHELL];
    if (shell->state!=SVC_RUNNING || shell->fd<0) return 0;
    struct request_packet packet;
    long n=os_call(SYS_IPC_TRY_RECV,shell->fd,(long)&packet,sizeof(packet.data.bytes));
    if (n==-11) return 0;
    if (n<0) return -1; // unexpected kernel I/O failure
    if (n==0) {
        // A running shell closed its control endpoint without exiting:
        // an EOF socket stays forever readable. Stop/reap it and apply the
        // bounded restart policy; never spin endlessly on the same EOF.
        return recover_shell(now);
    }
    // An inherited or leaked endpoint is not authority to manage services.
    // Reject unauthorized sender PID or malformed payload without killing
    // the entire local supervisor (a trivial denial-of-service otherwise).
    if (!valid_peer(&packet.peer,shell->pid)) return 0;
    unsigned code=n==sizeof(packet.data.request)?
        apply_command(&packet.data.request,now):SVC_BAD_REQUEST;
    return send_response(shell->fd,code)?0:recover_shell(now);
}

static int can_start(unsigned id) {
    if (!has_dependency(id)) return 0;
    return id!=SVC_SHELL || online_announced ||
        !registry[SVC_FLAKY].desired || registry[SVC_FLAKY].state==SVC_FAILED ||
        reaches(SVC_FLAKY,SVC_SHELL)>0;
}

static int advance_registry(long now) {
    for (unsigned id=0;id<SVC_COUNT;id++) {
        struct record *service=&registry[id];
        if (service->pid>0) {
            // Reaping is always by the immediate owning manager process.
            long status=os_call(SYS_TRY_WAIT,service->pid,0,0);
            if (status>=0) {
                if (id==SVC_CORE && !suspend_dependents(SVC_CORE)) return -1;
                if (id==SVC_SHELL && status==0) {
                    service->pid=0;
                    finish_endpoint(service);
                    service->state=SVC_STOPPED;
                    shutdown_requested=1;
                    return 0;
                }
                if (failed(id,now,status)!=0) return -1;
                continue;
            }
            if (status!=-11) return -1;
            if (service->state==SVC_STARTING) {
                int ready=finish_start(id,now);
                if (ready<0) {
                    if (!kill_and_reap(service) || failed(id,now,-5)!=0) return -1;
                } else if (!ready && now>=service->ready_deadline) {
                    if (!kill_and_reap(service) || failed(id,now,137)!=0) return -1;
                }
            }
        } else if (service->desired &&
                   (service->state==SVC_DOWN ||
                    (service->state==SVC_BACKOFF && now>=service->retry_at)) &&
                   can_start(id)) {
            // The optional unstable service gets three real attempts during
            // boot probation. Once exhausted, the shell remains available
            // for diagnosis and manual restart; no background crash can
            // corrupt its initial prompt/transcript. Manager keeps running.
            if (id==SVC_SHELL && !online_announced) {
                if (!manager_phase("ONLIN")) return -1;
                online_announced=1;
            }
            if (start_entry(id,now)<0) return -1;
        }
    }
    return 0;
}

/* Compute the earliest real state transition, not an arbitrary 20 ms
 * polling quantum. The kernel multiplexes service IPC and child exits with
 * this deadline in one atomic wait. A long quiet deadline retains detection
 * of a stopped clock without busy checking a stable system.
 */
static long event_deadline(long now) {
    long next=deadline(now,QUIET_WAKE_MS);
    if (next<0) return -1;
    for (unsigned id=0;id<SVC_COUNT;id++) {
        const struct record *service=&registry[id];
        // State changes earlier in this iteration can make a dependency
        // runnable after its array position has already been visited.
        if (!service->pid && service->desired && service->state==SVC_DOWN &&
            can_start(id)) return now;
        if (service->pid>0 && service->state==SVC_STARTING &&
            service->ready_deadline<next) next=service->ready_deadline;
        if (!service->pid && service->desired && service->state==SVC_BACKOFF &&
            can_start(id) && service->retry_at<next) next=service->retry_at;
    }
    return next;
}
static long event_mask(void) {
    unsigned long mask=0;
    for (unsigned id=0;id<SVC_COUNT;id++) {
        const struct record *service=&registry[id];
        if (service->fd<0 || (service->state!=SVC_STARTING &&
            !(id==SVC_SHELL && service->state==SVC_RUNNING))) continue;
        if (service->fd>=32) return -1;
        mask|=1UL<<(unsigned)service->fd;
    }
    return (long)mask;
}

/* PID 1 also owns abandoned grandchildren. A service may spawn a child
 * and then crash before collecting it; the kernel adopts that child, but
 * does not reap it on behalf of userland. Scan only PID1-owned children,
 * leave registered services to their policy, and fail-stop unknown orphans.
 * An already exited adopted child is reaped without overwriting its status.
 */
static int reap_unmanaged(void) {
    long cursor=0;
    for (;;) {
        long child=os_call(SYS_CHILD_AFTER,cursor,0,0);
        if (child==-10) return 1;
        if (child<=cursor) return 0;
        cursor=child;
        int registered=0;
        for (unsigned id=0;id<SVC_COUNT;id++)
            if (registry[id].pid==child) { registered=1; break; }
        if (registered) continue;
        long status=os_call(SYS_TRY_WAIT,child,0,0);
        if (status==-11) {
            long stopped=os_call(SYS_KILL,child,0,0);
            if (stopped!=0 && stopped!=1) return 0;
            status=os_call(SYS_TRY_WAIT,child,0,0);
        }
        if (status<0) return 0;
    }
}

static int stop_subtree(unsigned id, unsigned char seen[SVC_COUNT]) {
    if (seen[id]) return 1;
    seen[id]=1;
    for (unsigned child=0;child<SVC_COUNT;child++)
        if (registry[child].dependency==id &&
            !stop_subtree(child,seen)) return 0;
    struct record *service=&registry[id];
    if (!kill_and_reap(service)) return 0;
    finish_endpoint(service);
    service->state=SVC_STOPPED;
    return 1;
}
static int stop_all(void) {
    // Reject all new work, then use a deterministic reverse topological order.
    unsigned char seen[SVC_COUNT]={0};
    for (unsigned id=0;id<SVC_COUNT;id++) registry[id].desired=0;
    for (unsigned id=0;id<SVC_COUNT;id++)
        if (!stop_subtree(id,seen)) return 0;
    return reap_unmanaged();
}

int runServiceManager(void) {
    owner_pid=os_call(SYS_GETPID,0,0,0);
    if (owner_pid<=0 || !registry_valid() || !manager_phase("BEGIN")) return 80;
    for (;;) {
        long now=clock_ms();
        if (now<0 || (unsigned long)now>MAX_MS-READY_TIMEOUT_MS-200)
            { fatal_error=1;break; }
        if (advance_registry(now)!=0) { fatal_error=1;break; }
        if (!reap_unmanaged()) { fatal_error=1;break; }
        if (shutdown_requested) break;
        if (check_control(now)!=0) { fatal_error=1;break; }
        long next=event_deadline(now);
        long mask=event_mask();
        if (next<0 || mask<0 || os_call(SYS_WAIT_EVENTS_UNTIL,mask,next,0)<0)
            { fatal_error=1;break; }
    }
    shell_active=0;
    if (!manager_phase("SHUTD")) fatal_error=1;
    if (!stop_all()) fatal_error=1;
    if (!manager_phase("ENDED")) fatal_error=1;
    return fatal_error ? 81 : 0;
}
