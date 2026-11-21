/* Run the real orphan lifecycle C code against a deterministic syscall model. */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../../user/abi.h"
static long mock_call(long,long,long,long);
#define os_call mock_call
#include "../../user/orphans.c"
#undef os_call
static char log_text[2048];
static int used, writes, spawn, waited, killed, reaped, fail_write, fail_spawn, fail_wait, hide_child, deny_kill, bad_status;
static int gDelayedKill, gKillPending, gKillWaits;
static long gKillWaitError, gKillCollectedStatus, gClockAfterKill;
static void reset(void) {
    memset(log_text,0,sizeof(log_text));
    used=writes=spawn=waited=killed=reaped=fail_write=fail_spawn=fail_wait=hide_child=deny_kill=bad_status=0;
    gDelayedKill=gKillPending=gKillWaits=0;
    gKillWaitError=0; gKillCollectedStatus=137; gClockAfterKill=20;
}
static long mock_call(long op,long a,long b,long c) {
    (void)c;
    switch(op) {
        case SYS_GETPID: return 1;
        case SYS_MONOTONIC_MS: return killed ? gClockAfterKill : 20;
        case SYS_CHILD_AFTER:
            if (b!=0) abort();
            if (a==0) return !spawn || (waited && (hide_child || reaped)) ? -10 :
                waited ? 102 : 101;
            if (a==102) return -10;
            abort();
        case SYS_SPAWN:
            assert(b==13 && memcmp((char *)a,"orphan_parent",13)==0);
            spawn++;
            return fail_spawn ? -12 : 101;
        case SYS_WAIT_CHILD_UNTIL:
            if (a==101) {
                assert(b==1020);
                if (fail_wait) return -110;
                waited++;
                return bad_status ? 77 : 0;
            }
            assert(a==102 && killed && gKillPending && !reaped);
            assert(b==gClockAfterKill+killTimeoutMs);
            gKillWaits++;
            if (gKillWaitError) return gKillWaitError;
            gKillPending=0;
            reaped++;
            return gKillCollectedStatus;
        case SYS_KILL:
            if (a==101 && waited) return -3;
            assert(a==102 && waited && !reaped);
            if (deny_kill) return -1;
            killed++;
            gKillPending=gDelayedKill;
            return 0;
        case SYS_TRY_WAIT:
            assert(a==102 && killed && !reaped);
            if (gKillPending) return -11;
            reaped++;
            return gKillCollectedStatus;
        case SYS_WRITE:
            assert(a==1 && b>0 && c>0 && c<256);
            writes++;
            if (writes==fail_write) return -5;
            assert(used+c<(long)sizeof(log_text));
            memcpy(log_text+used,(char *)b,c);
            used+=(int)c;
            return c;
    }
    abort();
}
int main(void) {
    reset();
    assert(run_orphans()==0 && spawn==1 && waited && killed && reaped);
    char expected[2048];
    int len=snprintf(expected,sizeof(expected),
        "AGENTOS ORPHAN BEGIN ROOT=%016x\r\n"
        "AGENTOS ORPHAN ADOPT ROOT=%016x PARENT=%016x CHILD=%016x STATUS=%016x\r\n"
        "AGENTOS ORPHAN REAPS ROOT=%016x PARENT=%016x CHILD=%016x STATUS=%016x\r\n"
        "AGENTOS ORPHAN ENDED ROOT=%016x\r\n",
        1,1,101,102,0,1,101,102,137,1);
    assert(len>0 && len<(int)sizeof(expected) && strcmp(expected,log_text)==0);
    reset();fail_spawn=1;assert(run_orphans()==73 && !waited);
    reset();fail_wait=1;assert(run_orphans()==75 && !killed);
    reset();bad_status=1;assert(run_orphans()==75 && !killed);
    reset();hide_child=1;assert(run_orphans()==76 && !killed);
    reset();deny_kill=1;assert(run_orphans()==78 && !killed);
    reset();fail_write=1;assert(run_orphans()==72 && !spawn);
    reset();fail_write=2;assert(run_orphans()==77 && !killed);
    reset();fail_write=3;assert(run_orphans()==81 && reaped);
    reset();fail_write=4;assert(run_orphans()==82 && reaped);
    reset();gDelayedKill=1;
    assert(run_orphans()==0 && killed==1 && reaped==1 && gKillWaits==1);
    assert(strcmp(expected,log_text)==0);
    reset();gDelayedKill=1;gKillWaitError=-110;
    assert(run_orphans()==79 && killed==1 && !reaped && gKillWaits==1);
    assert(strstr(log_text,"ORPHAN REAPS")==NULL);
    reset();gDelayedKill=1;gKillWaitError=-5;
    assert(run_orphans()==79 && !reaped && gKillWaits==1);
    reset();gDelayedKill=1;gClockAfterKill=-5;
    assert(run_orphans()==79 && !reaped && !gKillWaits);
    reset();gDelayedKill=1;gClockAfterKill=MAX_DEADLINE-killTimeoutMs+1;
    assert(run_orphans()==79 && !reaped && !gKillWaits);
    // Preserve a naturally published status; the deliberately hanging
    // orphan still must fail its strict 137 acceptance check in this case.
    reset();gDelayedKill=1;gKillCollectedStatus=0;
    assert(run_orphans()==79 && reaped==1 && gKillWaits==1);
    assert(strstr(log_text,"ORPHAN REAPS")==NULL);
    puts("Orphan lifecycle host tests passed: delayed remote acknowledgement, "
         "timeout, clock failure, overflow and actual status preservation");
    return 0;
}
