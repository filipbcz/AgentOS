#include "abi.h"

/*
 * Stage-3 PID-1 service supervisor: synchronous, finite acceptance profile.
 * Each child is a separate protected process. All exits (including forced
 * termination) are collected; no worker retains memory or descriptors after
 * completion. A true long-running service registry will build on this policy.
 */
enum { MAX_ATTEMPTS = 3, MAX_IDLE_YIELDS = 128 };

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

/* Kill/collect on a failing wait path to avoid leaving an unowned child.
 * A permanently failed kernel operation cannot guarantee recovery; report it.
 */
static void cancel_and_collect(long pid) {
    if (os_call(SYS_KILL,pid,0,0)==0)
        (void)os_call(SYS_TRY_WAIT,pid,0,0);
}

/* Returns 0 after collection, 1 if the yield budget required a kill, -1 on
 * a failed syscall. Yield count is a bounded scheduling budget, NOT wall time.
 */
static int collect_child(long child, unsigned long *exit_status) {
    for (unsigned i=0;i<MAX_IDLE_YIELDS;i++) {
        long result=os_call(SYS_TRY_WAIT,child,0,0);
        if (result>=0) {
            *exit_status=(unsigned long)result;
            return 0;
        }
        if (result!=-11 || os_call(SYS_YIELD,0,0,0)<0) {
            cancel_and_collect(child);
            return -1;
        }
    }
    if (os_call(SYS_KILL,child,0,0)!=0) return -1;
    long status=os_call(SYS_TRY_WAIT,child,0,0);
    if (status<0) return -1;
    *exit_status=(unsigned long)status;
    return 1;
}

/* 0 = clean completion; 1 = failure budget reached; 2 = stalled child killed;
 * -1 = kernel or logging error. Never spin indefinitely or restart after cap.
 */
static int supervise(const char *name, unsigned name_length,
                     unsigned max_attempts, unsigned long parent) {
    for (unsigned attempt=1;attempt<=max_attempts;attempt++) {
        long child=os_call(SYS_SPAWN,(long)name,name_length,0);
        if (child<=0 || (unsigned long)child==parent) return -1;
        unsigned long status=0;
        int outcome=collect_child(child,&status);
        if (outcome<0) return -1;
        if (outcome==1) {
            if (!record("TIME",parent,(unsigned long)child,status,attempt) ||
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
