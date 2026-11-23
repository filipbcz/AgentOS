/* Compile the REAL freestanding service worker with a deterministic
 * syscall boundary. READY must not precede a successful timer self-check.
 * Simulations are host unit tests, never guest/VM evidence.
 */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "../../user/abi.h"
#include "../../user/service_protocol.h"

static long mock_call(long,long,long,long);
#define os_call mock_call
#define AGENTOS_FLAKY 1
#define runServiceWorker runFlakyWorker
#include "../../user/svc_worker.c"
#undef runServiceWorker
#undef AGENTOS_FLAKY
#define runServiceWorker runStableWorker
#define close_unrelated close_stable_unrelated
#include "../../user/svc_worker.c"
#undef close_unrelated
#undef runServiceWorker
#undef os_call

enum {
    GOOD=0, BAD_FIRST_CLOCK=1, CLOCK_OVERFLOW=2, SLEEP_FAILURE=3,
    PREMATURE_WAKE=4, BAD_AFTER_CLOCK=5, SPOOFED_ACK=6,
    INVALID_ACK=7, SEND_FAILURE=8, INVALID_ACK_STATE=9, INVALID_ACK_RESERVED=10,
    BAD_LIFETIME_MESSAGE=11, LIFETIME_IO_ERROR=12
};
static int scenario, clock_reads, sleeps, sent, received, fd_closed;
static int unrelated_closed, stdio_closed, first_timer_ok;
static long ticks;
static int stable_worker;

static void reset(int selected) {
    scenario=selected;
    clock_reads=sleeps=sent=received=fd_closed=0;
    unrelated_closed=stdio_closed=first_timer_ok=0;
    ticks=100;
    stable_worker=0;
}

static long mock_call(long op,long a,long b,long c) {
    switch (op) {
        case SYS_CLOSE:
            assert(b==0 && c==0);
            if (a==SVC_CHANNEL_FD) {
                assert(sent==1 && received==1 && !fd_closed);
                fd_closed=1;
            } else if (a>=3 && a<32) {
                assert(a!=SVC_CHANNEL_FD);
                unrelated_closed++;
            } else {
                assert(a>=0 && a<=2 && (fd_closed || stable_worker));
                stdio_closed++;
            }
            return 0;
        case SYS_MONOTONIC_MS:
            assert(a==0 && b==0 && c==0);
            clock_reads++;
            if (clock_reads==1 && scenario==BAD_FIRST_CLOCK) return -5;
            if (clock_reads==1 && scenario==CLOCK_OVERFLOW)
                return (long)(MAX_MS-19);
            if (clock_reads==2 && scenario==PREMATURE_WAKE) return 119;
            if (clock_reads==2 && scenario==BAD_AFTER_CLOCK) return -5;
            return ticks;
        case SYS_SLEEP_UNTIL:
            assert(b==0 && c==0 && a>ticks);
            sleeps++;
            if (sleeps==1) {
                assert(a==120 && sent==0);
                if (scenario==SLEEP_FAILURE) return -5;
                first_timer_ok=1;
            } else {
                assert(sleeps==2 && a==220 && sent==1 && received==1);
            }
            ticks=a;
            return 0;
        case SYS_IPC_SEND: {
            assert(a==SVC_CHANNEL_FD && b && c==sizeof(struct svc_request));
            assert(sent==0 && received==0 && first_timer_ok);
            assert(clock_reads==2 && sleeps==1 && ticks==120);
            const struct svc_request *ready=(const struct svc_request *)b;
            assert(ready->magic==SVC_MAGIC && ready->version==SVC_VERSION &&
                   ready->operation==SVC_OP_READY &&
                   ready->service==(stable_worker?SVC_CORE:SVC_FLAKY) &&
                   ready->reserved==0);
            sent++;
            return scenario==SEND_FAILURE ? -5 : c;
        }
        case SYS_IPC_RECV: {
            if (stable_worker && received==1) {
                assert(a==SVC_CHANNEL_FD && b && c==IPC_MAX_MESSAGE &&
                       sleeps==1 && clock_reads==2 && stdio_closed==3 && !fd_closed);
                received++;
                return scenario==BAD_LIFETIME_MESSAGE?12:
                    scenario==LIFETIME_IO_ERROR?-5:0;
            }
            assert(a==SVC_CHANNEL_FD && b && c==sizeof(struct svc_response));
            assert(sent==1 && received==0);
            received++;
            struct svc_received_response *reply=(struct svc_received_response *)b;
            memset(reply,0,sizeof(*reply));
            reply->peer=(struct ipc_peer){100,1000,1000};
            reply->data.magic=SVC_MAGIC;
            reply->data.version=SVC_VERSION;
            reply->data.result=SVC_OK;
            reply->data.states[stable_worker?SVC_CORE:SVC_FLAKY]=SVC_RUNNING;
            if (scenario==SPOOFED_ACK) reply->peer.uid=9999;
            if (scenario==INVALID_ACK) reply->data.result=SVC_BAD_REQUEST;
            if (scenario==INVALID_ACK_STATE) reply->data.states[stable_worker?SVC_CORE:SVC_FLAKY]=SVC_STARTING;
            if (scenario==INVALID_ACK_RESERVED) reply->data.reserved=1;
            return c;
        }
    }
    fprintf(stderr,"Unexpected worker syscall %ld(%ld,%ld,%ld)\n",op,a,b,c);
    assert(0);
    return -1;
}

static void test_good(void) {
    reset(GOOD);
    assert(runFlakyWorker()==42);
    assert(clock_reads==3 && sleeps==2 && sent==1 && received==1);
    assert(unrelated_closed==28 && stdio_closed==3 && fd_closed);
    assert(ticks==220);
}

static void test_bad_ready(int mode,int expected,int clocks,int sleep_count,
                           int send_count,int recv_count) {
    reset(mode);
    assert(runFlakyWorker()==expected);
    assert(clock_reads==clocks && sleeps==sleep_count);
    assert(sent==send_count && received==recv_count);
    assert(unrelated_closed==28);
    assert(!fd_closed && !stdio_closed);
}

static void test_stable_worker_lifetime(void) {
    for (int mode=GOOD;mode<=LIFETIME_IO_ERROR;mode++) {
        if (mode!=GOOD && mode!=BAD_LIFETIME_MESSAGE && mode!=LIFETIME_IO_ERROR) continue;
        reset(mode);stable_worker=1;
        assert(runStableWorker()==(mode==GOOD?0:129));
        assert(clock_reads==2 && sleeps==1 && sent==1 && received==2);
        assert(unrelated_closed==28 && stdio_closed==3 && !fd_closed);
        assert(ticks==120); // no periodic timer after READY
    }
}

int main(void) {
    test_good();
    test_bad_ready(BAD_FIRST_CLOCK,126,1,0,0,0);
    test_bad_ready(CLOCK_OVERFLOW,126,1,0,0,0);
    test_bad_ready(SLEEP_FAILURE,127,1,1,0,0);
    test_bad_ready(PREMATURE_WAKE,128,2,1,0,0);
    test_bad_ready(BAD_AFTER_CLOCK,128,2,1,0,0);
    test_bad_ready(SEND_FAILURE,121,2,1,1,0);
    test_bad_ready(SPOOFED_ACK,122,2,1,1,1);
    test_bad_ready(INVALID_ACK,122,2,1,1,1);
    test_bad_ready(INVALID_ACK_STATE,122,2,1,1,1);
    test_bad_ready(INVALID_ACK_RESERVED,122,2,1,1,1);
    test_stable_worker_lifetime();
    puts("Worker READY timer self-check, failures, IPC peer checks and event-driven lifetime passed");
    return 0;
}
