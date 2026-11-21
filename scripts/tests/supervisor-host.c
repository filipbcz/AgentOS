/*
 * Run the real user/supervisor.c against a deterministic syscall boundary.
 * Checks restart limits, child reaping, stalled-worker kill and error paths.
 * This is a host harness, not an AgentOS VM or scheduler simulation.
 */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../../user/abi.h"

static long mock_call(long op,long a,long b,long c);
#define os_call mock_call
#include "../../user/supervisor.c"
#undef os_call

enum { MAX_CHILDREN=16, LOG_BYTES=4096 };
static char log_text[LOG_BYTES];
static unsigned log_used, spawns, collected, kills, kill_attempts, yields, writes;
static unsigned spawn_error_at, write_error_at, yield_error_at, wait_error_at, clock_error_at, clock_calls;
static long clock_time_ms, kill_time_ms;
static int clock_frozen;
static unsigned freeze_on_spawn, clock_failure_after_spawn;
static long spawn_times[MAX_CHILDREN];
static long live_child;
static char live_kind; // 'o': success, 'f': failure, 'h': hung
static int killed, completed_before_kill, complete_on_last_yield;

static void reset(void) {
    memset(log_text,0,sizeof(log_text));
    log_used=spawns=collected=kills=kill_attempts=yields=writes=0;
    spawn_error_at=write_error_at=yield_error_at=wait_error_at=clock_error_at=clock_calls=0;
    clock_time_ms=kill_time_ms=0;clock_frozen=0;
    freeze_on_spawn=clock_failure_after_spawn=0;
    memset(spawn_times,0,sizeof(spawn_times));
    live_child=0; live_kind=0; killed=0; completed_before_kill=0; complete_on_last_yield=0;
}

static long mock_call(long op,long a,long b,long c) {
    (void)c;
    if (op==SYS_GETPID) return 1;
    if (op==SYS_MONOTONIC_MS) {
        clock_calls++;
        return clock_error_at && clock_calls==clock_error_at ? -5 : clock_time_ms;
    }
    if (op==SYS_SPAWN) {
        spawns++;
        if (spawns >= MAX_CHILDREN) abort();
        if (spawns==spawn_error_at) return -12;
        spawn_times[spawns]=clock_time_ms;
        if (spawns==freeze_on_spawn) clock_frozen=1;
        if (spawns==clock_failure_after_spawn) clock_error_at=clock_calls+1;
        if (live_child) abort();
        const char *name=(const char *)a;
        if (b==6 && memcmp(name,"svc_ok",6)==0) live_kind='o';
        else if (b==8 && memcmp(name,"svc_fail",8)==0) live_kind='f';
        else if (b==8 && memcmp(name,"svc_hang",8)==0) live_kind='h';
        else abort();
        live_child=100+spawns;
        killed=0;
        return live_child;
    }
    if (op==SYS_TRY_WAIT) {
        if (!live_child || a!=live_child) abort();
        if (wait_error_at && collected+1==wait_error_at && !killed) {
            wait_error_at=0;
            return -10;
        }
        if (live_kind=='h' && !killed && !completed_before_kill) return -11;
        long status=killed?137:(live_kind=='o' || completed_before_kill)?0:42;
        collected++;live_child=0;
        return status;
    }
    if (op==SYS_YIELD) {
        yields++;
        if (!clock_frozen) clock_time_ms += 10;
        return yields==yield_error_at?-5:0;
    }
    if (op==SYS_KILL) {
        if (a==0 || a==1) return -22;
        if (a==0x7fffffff) return -3;
        if (a!=live_child || !live_child) abort();
        kill_attempts++;
        if (complete_on_last_yield && live_kind=='h') {
            completed_before_kill=1;
            return 1;
        }
        kills++;
        kill_time_ms=clock_time_ms;
        killed=1;
        return 0;
    }
    if (op==SYS_WRITE) {
        if (a!=1 || c>256 || b==0) abort();
        writes++;
        if (writes==write_error_at) return -5;
        if (log_used+(unsigned)c>=LOG_BYTES) abort();
        memcpy(log_text+log_used,(const char *)b,(unsigned)c);
        log_used+=(unsigned)c;
        return c;
    }
    fprintf(stderr,"Unexpected syscall %ld(%ld,%ld,%ld)\n",op,a,b,c);
    abort();
}

static void append_duration(char *out,size_t capacity,
                            unsigned child,unsigned duration_ms) {
    size_t n=strlen(out);
    int written=snprintf(out+n,capacity-n,
        "AGENTOS SERVICE DURATION PARENT=%016x CHILD=%016x MS=%016x\r\n",
        1u,child,duration_ms);
    assert(written>0 && (size_t)written<capacity-n);
}

static void append_phase(char *out,size_t capacity,const char *kind) {
    size_t n=strlen(out);
    int written=snprintf(out+n,capacity-n,
        "AGENTOS SUPERVISOR %.5s PARENT=%016x\r\n",kind,1u);
    assert(written>0 && (size_t)written<capacity-n);
}

static void append_expected(char *out,size_t capacity,const char *kind,
                            unsigned child,unsigned status,unsigned attempt) {
    size_t n=strlen(out);
    int written=snprintf(out+n,capacity-n,
        "AGENTOS SERVICE %.4s PARENT=%016x CHILD=%016x STATUS=%016x ATTEMPT=%08x\r\n",
        kind,1u,child,status,attempt);
    assert(written>0 && (size_t)written<capacity-n);
}

static void success_case(void) {
    reset();
    assert(run_supervisor()==0);
    assert(spawns==5 && collected==5 && kills==1 && yields==31 && !live_child);
    assert(spawn_times[3]-spawn_times[2]>=RESTART_BACKOFF_MS);
    assert(spawn_times[4]-spawn_times[3]>=2*RESTART_BACKOFF_MS);
    assert(kill_time_ms-spawn_times[5]>=SERVICE_TIMEOUT_MS);
    char expected[LOG_BYTES]={0};
    append_phase(expected,sizeof(expected),"BEGIN");
    append_expected(expected,sizeof(expected),"DONE",101,0,1);
    append_expected(expected,sizeof(expected),"REAP",102,42,1);
    append_expected(expected,sizeof(expected),"REAP",103,42,2);
    append_expected(expected,sizeof(expected),"REAP",104,42,3);
    append_expected(expected,sizeof(expected),"STOP",104,42,3);
    append_duration(expected,sizeof(expected),105,SERVICE_TIMEOUT_MS);
    append_expected(expected,sizeof(expected),"TIME",105,137,1);
    append_expected(expected,sizeof(expected),"STOP",105,137,1);
    append_phase(expected,sizeof(expected),"ENDED");
    if (strcmp(expected,log_text)) {
        fprintf(stderr,"Unexpected supervisor transcript:\n%s\nExpected:\n%s\n",log_text,expected);
        abort();
    }
}

int main(void) {
    success_case();
    reset();spawn_error_at=3;
    assert(run_supervisor()==63 && spawns==3 && collected==2 && !live_child);
    reset();write_error_at=2;
    assert(run_supervisor()==62 && spawns==1 && collected==1 && !live_child);
    reset();yield_error_at=7;
    assert(run_supervisor()==64 && spawns==5 && collected==5 && kills==1 && !live_child);
    reset();wait_error_at=1;
    assert(run_supervisor()==62 && spawns==1 && collected==1 && kills==1 && !live_child);
    // Simulate the race where the final yield completes the worker and the
    // kernel finds an already-zombie child at kill time. Do not log TIME.
    reset();complete_on_last_yield=1;
    assert(supervise("svc_hang",8,1,1)==0);
    assert(spawns==1 && collected==1 && kills==0 && kill_attempts==1 &&
           yields==25 && !live_child);
    assert(strstr(log_text,"SERVICE DONE")!=NULL);
    assert(strstr(log_text,"SERVICE TIME")==NULL);
    assert(strstr(log_text,"SERVICE DURATION")==NULL);
    reset();clock_error_at=1;
    assert(run_supervisor()==62 && spawns==1 && collected==1 && kills==1 && !live_child);
    reset();clock_frozen=1;
    assert(run_supervisor()==63 && spawns==2 && collected==2 && kills==0 &&
           yields==MAX_CLOCK_POLLS && !live_child);
    // Frozen or failed clock DURING a live hanging service must fail closed,
    // forcibly clean up the child, and never claim a measured TIME event.
    reset();freeze_on_spawn=5;
    assert(run_supervisor()==64 && spawns==5 && collected==5 && kills==1 &&
           yields==6+MAX_CLOCK_POLLS && !live_child);
    assert(strstr(log_text,"SERVICE TIME")==NULL);
    assert(strstr(log_text,"SERVICE DURATION")==NULL);
    reset();clock_failure_after_spawn=5;
    assert(run_supervisor()==64 && spawns==5 && collected==5 && kills==1 && !live_child);
    assert(strstr(log_text,"SERVICE TIME")==NULL);
    assert(strstr(log_text,"SERVICE DURATION")==NULL);
    puts("Supervisor host acceptance: success, restart cap, stalled child kill, "
         "spawn/write/yield/wait failures passed");
    return 0;
}
