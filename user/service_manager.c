#include "abi.h"
#include "service_protocol.h"

/* Long-running CPU-root process, not a finite bootstrap demonstration.
 * It owns the three-entry service registry for its entire terminal session:
 * dependency-aware readiness, authenticated IPC control, monitored exits,
 * capped exponential restart with timer-backed waits and ordered shutdown.
 * The kernel remains the ultimate authority on PID ownership and memory.
 *
 * The current boot acceptance creates a separate short-lived init session
 * before this operational session. This process is the *operational root
 * reaper*, but it does not currently have the literal numeric PID 1.
 */
#define MAX_MS 0x7fffffffffffffffUL
enum { TICK_MS=20, READY_TIMEOUT_MS=750, RESTART_BASE_MS=40, RESTART_WINDOW_MS=5000, MAX_ATTEMPTS=3 };
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
static int has_dependency(unsigned id) {
    const unsigned dep=registry[id].dependency;
    return dep==SVC_COUNT || registry[dep].state==SVC_RUNNING;
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
    unsigned long pair=0;
    long result=os_call(SYS_IPC_PAIR,(long)&pair,0,0);
    if (result!=0) return -1;
    long manager_fd=(long)(unsigned)(pair & 0xffffffffUL);
    long child_fd=(long)(unsigned)(pair >> 32);
    // Exactly one designated handle is inherited by the worker/shell. It
    // immediately closes all other inherited service-manager descriptors.
    if (os_call(SYS_DUP2,child_fd,SVC_CHANNEL_FD,0)!=SVC_CHANNEL_FD) {
        close_fd(manager_fd);close_fd(child_fd);return -1;
    }
    long child=os_call(SYS_SPAWN,(long)service->elf,service->elf_length,0);
    close_fd(SVC_CHANNEL_FD);
    close_fd(child_fd);
    if (child<=0 || child==owner_pid) {
        close_fd(manager_fd);
        return -1;
    }
    service->pid=child;
    service->fd=manager_fd;
    service->attempts++;
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
    return os_call(SYS_IPC_SEND,fd,(long)&answer,sizeof(answer))==(long)sizeof(answer);
}

static int finish_start(unsigned id, long now) {
    struct record *service=&registry[id];
    struct svc_received_request received;
    long n=os_call(SYS_IPC_TRY_RECV,service->fd,(long)&received,sizeof(received.data));
    if (n==-11) return 0;
    if (n!=sizeof(received.data) || !valid_peer(&received.peer,service->pid) ||
        received.data.magic!=SVC_MAGIC || received.data.version!=SVC_VERSION ||
        received.data.operation!=SVC_OP_READY || received.data.service!=id ||
        received.data.reserved!=0) return -1;
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
    if (id!=SVC_SHELL) finish_endpoint(service);
    (void)now;
    return 1;
}

/* A lost dependency must not leave any of its direct dependents running
 * against stale state. Stop in reverse dependency order; only active processes
 * are reset, so a previously FAILED optional service stays FAILED until an
 * explicit operator action. The root continues its own bounded restart.
 */
static int suspend_dependents(unsigned dependency) {
    for (unsigned index=SVC_COUNT;index>0;index--) {
        unsigned id=index-1;
        struct record *service=&registry[id];
        if (service->dependency!=dependency || service->pid<=0) continue;
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
        if (req->service==SVC_CORE &&
            (registry[SVC_FLAKY].desired || registry[SVC_SHELL].pid>0))
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
    return SVC_OK;
}

static int check_control(long now) {
    struct record *shell=&registry[SVC_SHELL];
    if (shell->state!=SVC_RUNNING || shell->fd<0) return 0;
    struct svc_received_request packet;
    long n=os_call(SYS_IPC_TRY_RECV,shell->fd,(long)&packet,sizeof(packet.data));
    if (n==-11) return 0;
    if (n<0) return -1; // unexpected kernel I/O failure
    // An inherited or leaked endpoint is not authority to manage services.
    // Reject unauthorized sender PID or malformed payload without killing
    // the entire local supervisor (a trivial denial-of-service otherwise).
    if (n!=sizeof(packet.data) || !valid_peer(&packet.peer,shell->pid))
        return 0;
    unsigned code=apply_command(&packet.data,now);
    return send_response(shell->fd,code)?0:-1;
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
                   has_dependency(id) &&
                   (id!=SVC_SHELL || registry[SVC_FLAKY].state==SVC_FAILED)) {
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

static int stop_all(void) {
    // Stop admissions before descending in reverse dependency order.
    for (unsigned id=0;id<SVC_COUNT;id++) registry[id].desired=0;
    for (unsigned i=SVC_COUNT;i>0;i--) {
        struct record *service=&registry[i-1];
        if (!kill_and_reap(service)) return 0;
        finish_endpoint(service);
        service->state=SVC_STOPPED;
    }
    return 1;
}

int runServiceManager(void) {
    owner_pid=os_call(SYS_GETPID,0,0,0);
    if (owner_pid<=0 || !manager_phase("BEGIN")) return 80;
    for (;;) {
        long now=clock_ms();
        if (now<0 || (unsigned long)now>MAX_MS-READY_TIMEOUT_MS-200)
            { fatal_error=1;break; }
        if (advance_registry(now)!=0) { fatal_error=1;break; }
        if (shutdown_requested) break;
        if (check_control(now)!=0) { fatal_error=1;break; }
        long next=deadline(now,TICK_MS);
        if (next<0 || os_call(SYS_SLEEP_UNTIL,next,0,0)!=0)
            { fatal_error=1;break; }
    }
    shell_active=0;
    if (!manager_phase("SHUTD")) fatal_error=1;
    if (!stop_all()) fatal_error=1;
    if (!manager_phase("ENDED")) fatal_error=1;
    return fatal_error ? 81 : 0;
}
