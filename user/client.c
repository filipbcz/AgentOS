#include "ipc-test.h"

int run_ipc(void) {
    int fds[2];
    if (os_call(SYS_IPC_PAIR, (long)fds, 0, 0)) return 21;
    // init has only stdout open. Give the service its endpoint at fd 3.
    if (fds[0] != 0 || os_call(SYS_DUP2, fds[1], 3, 0) != 3 ||
        (fds[1] != 3 && os_call(SYS_CLOSE, fds[1], 0, 0))) return 22;
    long service = os_call(SYS_SPAWN, (long)"service", 7, 0);
    if (service <= 0 || os_call(SYS_CLOSE, 3, 0, 0)) return 23;
    unsigned long self = os_call(SYS_GETPID, 0, 0, 0);
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
