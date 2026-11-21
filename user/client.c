#include "ipc-test.h"

struct test_message { struct ipc_peer sender; unsigned char data[IPC_MAX_MESSAGE]; };

static int matches(const struct test_message *message, unsigned long self, unsigned length) {
    if (message->sender.pid != self || message->sender.uid != 1000 || message->sender.gid != 1000) return 0;
    for (unsigned i=0; i<length; i++) {
        if (message->data[i] != (unsigned char)(i * 73 + i / 251)) return 0;
    }
    return 1;
}

static int checkTimerStats(void) {
    unsigned long pBefore[4], pAfter[4];
    if (os_call(SYS_TIMER_STATS, (long)pBefore, sizeof(pBefore), 0) ||
        pBefore[0] != 1 || pBefore[3] > pBefore[2] ||
        os_call(SYS_TIMER_STATS, 0, sizeof(pBefore), 0) != -14 ||
        os_call(SYS_TIMER_STATS, -8, sizeof(pBefore), 0) != -14 ||
        os_call(SYS_TIMER_STATS, (long)&checkTimerStats, sizeof(pBefore), 0) != -14 ||
        os_call(SYS_TIMER_STATS, (long)pBefore, sizeof(pBefore)-1, 0) != -22 ||
        os_call(SYS_TIMER_STATS, (long)pBefore, sizeof(pBefore), 1) != -22 ||
        os_call(SYS_TIMER_STATS, (long)pAfter, sizeof(pAfter), 0) ||
        pAfter[0] != 1 || pAfter[1] < pBefore[1] ||
        pAfter[2] < pBefore[2] || pAfter[3] < pBefore[3] ||
        pAfter[3] > pAfter[2]) return 0;
    return 1;
}

static int check_channel(unsigned long self) {
    int fds[2];
    unsigned char payload[IPC_MAX_MESSAGE];
    struct test_message incoming;
    // A failed pair must release its allocation and leave descriptor slots free.
    if (os_call(SYS_IPC_PAIR, 0, 0, 0) != -14 ||
        os_call(SYS_IPC_SEND, 32, 0, 1) != -9 || os_call(SYS_IPC_RECV, 32, 0, 1) != -9 ||
        os_call(SYS_IPC_TRY_SEND, 32, 0, 1) != -9 ||
        os_call(SYS_IPC_SEND, 1, 0, 1) != -88 || os_call(SYS_IPC_RECV, 1, 0, 1) != -88 ||
        os_call(SYS_IPC_TRY_SEND, 1, 0, 1) != -88 ||
        os_call(SYS_IPC_PAIR, (long)fds, 0, 0) || fds[0] != 0 || fds[1] != 2) return 0;
    for (unsigned i=0; i<sizeof(payload); i++) payload[i] = (unsigned char)(i * 73 + i / 251);
    if (os_call(SYS_IPC_SEND, fds[0], (long)payload, 0) != -90 ||
        os_call(SYS_IPC_SEND, fds[0], (long)payload, IPC_MAX_MESSAGE + 1) != -90 ||
        os_call(SYS_IPC_SEND, fds[0], 0, 1) != -14) return 0;
    // Both directions have independent mailboxes; message boundaries survive.
    if (os_call(SYS_IPC_SEND, fds[0], (long)payload, sizeof(payload)) != sizeof(payload) ||
        os_call(SYS_IPC_TRY_SEND, fds[0], (long)payload, 1) != -11 ||
        os_call(SYS_IPC_SEND, fds[1], (long)payload, 1) != 1) return 0;
    // None of these failures may consume or damage the queued full-size message.
    if (os_call(SYS_IPC_RECV, fds[1], (long)&incoming, IPC_MAX_MESSAGE - 1) != -90 ||
        os_call(SYS_IPC_RECV, fds[1], 0, IPC_MAX_MESSAGE) != -14 ||
        os_call(SYS_IPC_RECV, fds[1], (long)&check_channel, IPC_MAX_MESSAGE) != -14 ||
        os_call(SYS_IPC_RECV, fds[1], -8, IPC_MAX_MESSAGE) != -14 ||
        os_call(SYS_IPC_RECV, fds[1], (long)&incoming, IPC_MAX_MESSAGE) != IPC_MAX_MESSAGE ||
        !matches(&incoming, self, IPC_MAX_MESSAGE) ||
        os_call(SYS_IPC_RECV, fds[0], (long)&incoming, IPC_MAX_MESSAGE) != 1 ||
        !matches(&incoming, self, 1)) return 0;
    // TRY_SEND must regain capacity after the receiver consumes the message;
    // EAGAIN above must have preserved the original full-size payload.
    if (os_call(SYS_IPC_TRY_RECV, fds[1], (long)&incoming, IPC_MAX_MESSAGE) != -11 ||
        os_call(SYS_IPC_TRY_SEND, fds[0], (long)payload, 7) != 7 ||
        os_call(SYS_IPC_RECV, fds[1], (long)&incoming, IPC_MAX_MESSAGE) != 7 ||
        !matches(&incoming, self, 7)) return 0;
    // Closing the original leaves its duplicate alive. Closing the sender must
    // still allow the queued message to drain before EOF and EPIPE.
    if (os_call(SYS_DUP2, fds[1], 3, 0) != 3 || os_call(SYS_CLOSE, fds[1], 0, 0) ||
        os_call(SYS_IPC_SEND, fds[0], (long)payload, sizeof(payload)) != sizeof(payload) ||
        os_call(SYS_CLOSE, fds[0], 0, 0) ||
        os_call(SYS_IPC_RECV, 3, (long)&incoming, IPC_MAX_MESSAGE) != IPC_MAX_MESSAGE ||
        !matches(&incoming, self, IPC_MAX_MESSAGE) ||
        os_call(SYS_IPC_RECV, 3, (long)&incoming, IPC_MAX_MESSAGE) != 0 ||
        os_call(SYS_IPC_TRY_SEND, 3, (long)payload, 1) != -32 ||
        os_call(SYS_IPC_SEND, 3, (long)payload, 1) != -32 || os_call(SYS_CLOSE, 3, 0, 0)) return 0;
    return 1;
}

int run_ipc(void) {
    unsigned long self = os_call(SYS_GETPID, 0, 0, 0);
    if (!checkTimerStats() || !check_channel(self)) return 28;
    int fds[2];
    if (os_call(SYS_IPC_PAIR, (long)fds, 0, 0)) return 21;
    // init has only stdout open. Give the service its endpoint at fd 3.
    if (fds[0] != 0 || os_call(SYS_DUP2, fds[1], 3, 0) != 3 ||
        (fds[1] != 3 && os_call(SYS_CLOSE, fds[1], 0, 0))) return 22;
    long service = os_call(SYS_SPAWN, (long)"service", 7, 0);
    if (service <= 0 || os_call(SYS_CLOSE, 3, 0, 0)) return 23;
    struct request request = {self * 0x9e3779b97f4a7c15UL + service, {0,0,0}};
    if (os_call(SYS_IPC_SEND, 0, (long)&request, sizeof(request)) != sizeof(request)) return 24;
    struct { struct ipc_peer sender; struct response data; } reply;
    if (os_call(SYS_IPC_RECV, 0, (long)&reply, sizeof(reply.data)) != sizeof(reply.data) ||
        reply.sender.pid != (unsigned long)service || reply.sender.uid != 1000 || reply.sender.gid != 1000 ||
        reply.data.observed.pid != self || reply.data.observed.uid != 1000 || reply.data.observed.gid != 1000 ||
        reply.data.answer != answer(request.challenge)) return 25;
    long status;
    while ((status=os_call(SYS_TRY_WAIT, service, 0, 0)) == -11) os_call(SYS_YIELD, 0, 0, 0);
    if (status || os_call(SYS_IPC_RECV, 0, (long)&reply, sizeof(reply.data)) != 0 ||
        os_call(SYS_IPC_SEND, 0, (long)&request, sizeof(request)) != -32 || os_call(SYS_CLOSE, 0, 0, 0)) return 26;
    return report("AGENTOS IPC REPLY PID=", reply.sender, self) ? 0 : 27;
}
