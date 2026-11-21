#include "abi.h"

/*
 * Stage-3 PID-1 service supervisor: synchronous, finite acceptance profile.
 * Each child is a separate protected process. All exits (including forced
 * termination) are collected; no worker retains memory or descriptors after
 * completion. A true long-running service registry will build on this policy.
 */
enum {
    MAX_ATTEMPTS = 3,
    SERVICE_TIMEOUT_MS = 250,
    RESTART_BACKOFF_MS = 20,
    MAX_CLOCK_POLLS = 1000000
};

/* All service children are pinned to their parent's CPU. This monotonic
 * source has a CPU-local epoch, so durations are valid, absolute cross-CPU
 * timestamps are not. A frozen or failed clock is a hard error, not a timeout.
 */
static long clock_ms(void) { return os_call(SYS_MONOTONIC_MS,0,0,0); }

static int wait_backoff(unsigned delay_ms) {
    long start=clock_ms();
    if (start<0) return -1;
    for (unsigned polls=0;polls<MAX_CLOCK_POLLS;polls++) {
        long now=clock_ms();
        if (now<start) return -1;
        if ((unsigned long)(now-start)>=delay_ms) return 0;
        if (os_call(SYS_YIELD,0,0,0)<0) return -1;
    }
    return -1; // Clock stalled; never spin forever.
}

/* Bound the evidence of the supervised interval for independent verifiers.
 * User-mode output is a diagnostic, not a secure attestation.
 */
static int phase(const char event[5], unsigned long parent) {
    char line[] = "AGENTOS SUPERVISOR BEGIN PARENT=0000000000000000\r\n";
    for (unsigned i=0;i<5;i++) line[sizeof("AGENTOS SUPERVISOR ")-1+i]=event[i];
    format_hex(line+sizeof("AGENTOS SUPERVISOR BEGIN PARENT=")-1,parent,16);
    return os_call(SYS_WRITE,1,(long)line,sizeof(line)-1)==sizeof(line)-1;
}

static int record(const char event[4], unsigned long parent,
                  unsigned long child, unsigned long status, unsigned attempt) {
    char line[] = "AGENTOS SERVICE REAP PARENT=0000000000000000 CHILD=0000000000000000 STATUS=0000000000000000 ATTEMPT=00000000\r\n";
    enum {
        PARENT_AT = sizeof("AGENTOS SERVICE REAP PARENT=")-1,
        CHILD_AT = PARENT_AT + 16 + sizeof(" CHILD=")-1,
        STATUS_AT = CHILD_AT + 16 + sizeof(" STATUS=")-1,
        ATTEMPT_AT = STATUS_AT + 16 + sizeof(" ATTEMPT=")-1
    };
    for (unsigned i=0;i<4;i++) line[sizeof("AGENTOS SERVICE ")-1+i]=event[i];
    format_hex(line+PARENT_AT,parent,16);
    format_hex(line+CHILD_AT,child,16);
    format_hex(line+STATUS_AT,status,16);
    format_hex(line+ATTEMPT_AT,attempt,8);
    return os_call(SYS_WRITE,1,(long)line,sizeof(line)-1)==sizeof(line)-1;
}

/* Evidence of measured time before a forced kill, not of wall-clock UTC. */
static int record_duration(unsigned long parent, unsigned long child,
                           unsigned long duration_ms) {
    char line[] = "AGENTOS SERVICE DURATION PARENT=0000000000000000 CHILD=0000000000000000 MS=0000000000000000\r\n";
    enum {
        PARENT_AT = sizeof("AGENTOS SERVICE DURATION PARENT=")-1,
        CHILD_AT = PARENT_AT + 16 + sizeof(" CHILD=")-1,
        MS_AT = CHILD_AT + 16 + sizeof(" MS=")-1
    };
    format_hex(line+PARENT_AT,parent,16);
    format_hex(line+CHILD_AT,child,16);
    format_hex(line+MS_AT,duration_ms,16);
    return os_call(SYS_WRITE,1,(long)line,sizeof(line)-1)==sizeof(line)-1;
}

/* Kill/collect on a failing wait path to avoid leaving an unowned child.
 * A permanently failed kernel operation cannot guarantee recovery; report it.
 */
static void cancel_and_collect(long pid) {
    if (os_call(SYS_KILL,pid,0,0)>=0)
        (void)os_call(SYS_TRY_WAIT,pid,0,0);
}

/* Returns 0 after collection, 1 if a real monotonic deadline required
 * termination, -1 on a kernel/clock failure. A bounded poll count is only
 * a *clock-failure guard*, never treated as passage of wall-clock time.
 */
static int collect_child(long child, unsigned long *exit_status,
                         unsigned long *measured_ms) {
    long start=clock_ms();
    if (start<0) {
        cancel_and_collect(child);
        return -1;
    }
    for (unsigned polls=0;polls<MAX_CLOCK_POLLS;polls++) {
        long result=os_call(SYS_TRY_WAIT,child,0,0);
        if (result>=0) {
            *exit_status=(unsigned long)result;
            return 0;
        }
        if (result!=-11) {
            cancel_and_collect(child);
            return -1;
        }
        long now=clock_ms();
        if (now<start) {
            cancel_and_collect(child);
            return -1;
        }
        if ((unsigned long)(now-start)>=SERVICE_TIMEOUT_MS) {
            *measured_ms=(unsigned long)(now-start);
            // A worker may exit between the final poll and SYS_KILL.
            // A preexisting zombie is not a forced termination.
            long killed=os_call(SYS_KILL,child,0,0);
            if (killed<0) {
                cancel_and_collect(child);
                return -1;
            }
            long status=os_call(SYS_TRY_WAIT,child,0,0);
            if (status<0) return -1;
            *exit_status=(unsigned long)status;
            return killed==0 ? 1 : 0;
        }
        if (os_call(SYS_YIELD,0,0,0)<0) {
            cancel_and_collect(child);
            return -1;
        }
    }
    // If elapsed time never advances, do not invent a timeout record.
    cancel_and_collect(child);
    return -1;
}

/* 0 = clean completion; 1 = failure budget reached; 2 = stalled child killed;
 * -1 = kernel or logging error. Never spin indefinitely or restart after cap.
 */
static int supervise(const char *name, unsigned name_length,
                     unsigned max_attempts, unsigned long parent) {
    for (unsigned attempt=1;attempt<=max_attempts;attempt++) {
        // Exponential delay capped by the finite policy (20, 40 ms).
        // Delay occurs after the previous child has been fully reaped.
        if (attempt>1 && wait_backoff(RESTART_BACKOFF_MS << (attempt-2))!=0)
            return -1;
        long child=os_call(SYS_SPAWN,(long)name,name_length,0);
        if (child<=0 || (unsigned long)child==parent) return -1;
        unsigned long status=0, measured_ms=0;
        int outcome=collect_child(child,&status,&measured_ms);
        if (outcome<0) return -1;
        if (outcome==1) {
            if (!record_duration(parent,(unsigned long)child,measured_ms) ||
                !record("TIME",parent,(unsigned long)child,status,attempt) ||
                !record("STOP",parent,(unsigned long)child,status,attempt)) return -1;
            return 2;
        }
        if (status==0) {
            return record("DONE",parent,(unsigned long)child,status,attempt) ? 0 : -1;
        }
        if (!record("REAP",parent,(unsigned long)child,status,attempt)) return -1;
        if (attempt==max_attempts) {
            return record("STOP",parent,(unsigned long)child,status,attempt) ? 1 : -1;
        }
    }
    return -1;
}

/* This is called from the real first user process (PID 1 on BSP).
 * The second CPU repeats the same isolated process scenario for acceptance.
 */
int run_supervisor(void) {
    long parent=os_call(SYS_GETPID,0,0,0);
    // Prove that forced termination cannot target zero/self or an unknown PID.
    // These checks run before any worker is spawned.
    if (parent<=0 || os_call(SYS_KILL,0,0,0)!=-22 ||
        os_call(SYS_KILL,parent,0,0)!=-22 ||
        os_call(SYS_KILL,0x7fffffff,0,0)!=-3 ||
        !phase("BEGIN",(unsigned long)parent)) return 61;
    if (supervise("svc_ok",6,1,(unsigned long)parent)!=0) return 62;
    if (supervise("svc_fail",8,MAX_ATTEMPTS,(unsigned long)parent)!=1) return 63;
    if (supervise("svc_hang",8,1,(unsigned long)parent)!=2) return 64;
    return phase("ENDED",(unsigned long)parent) ? 0 : 65;
}
