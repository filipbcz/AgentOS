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
static unsigned log_used, spawns, collected, kills, yields, writes;
static unsigned spawn_error_at, write_error_at, yield_error_at, wait_error_at;
static long live_child;
static char live_kind; // 'o': success, 'f': failure, 'h': hung
static int killed;

static void reset(void) {
    memset(log_text,0,sizeof(log_text));
    log_used=spawns=collected=kills=yields=writes=0;
    spawn_error_at=write_error_at=yield_error_at=wait_error_at=0;
    live_child=0; live_kind=0; killed=0;
}

static long mock_call(long op,long a,long b,long c) {
    (void)c;
    if (op==SYS_GETPID) return 1;
    if (op==SYS_SPAWN) {
        spawns++;
        if (spawns==spawn_error_at) return -12;
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
        if (live_kind=='h' && !killed) return -11;
        long status=killed?137:live_kind=='o'?0:42;
        collected++;live_child=0;
        return status;
    }
    if (op==SYS_YIELD) {
        yields++;
        return yields==yield_error_at?-5:0;
    }
    if (op==SYS_KILL) {
        if (a==0 || a==1) return -22;
        if (a==0x7fffffff) return -3;
        if (a!=live_child || !live_child) abort();
        kills++;
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
    assert(spawns==5 && collected==5 && kills==1 && yields==128 && !live_child);
    char expected[LOG_BYTES]={0};
    append_phase(expected,sizeof(expected),"BEGIN");
    append_expected(expected,sizeof(expected),"DONE",101,0,1);
    append_expected(expected,sizeof(expected),"REAP",102,42,1);
    append_expected(expected,sizeof(expected),"REAP",103,42,2);
    append_expected(expected,sizeof(expected),"REAP",104,42,3);
    append_expected(expected,sizeof(expected),"STOP",104,42,3);
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
    reset();yield_error_at=1;
    assert(run_supervisor()==64 && spawns==5 && collected==5 && kills==1 && !live_child);
    reset();wait_error_at=1;
    assert(run_supervisor()==62 && spawns==1 && collected==1 && kills==1 && !live_child);
    puts("Supervisor host acceptance: success, restart cap, stalled child kill, "
         "spawn/write/yield/wait failures passed");
    return 0;
}
