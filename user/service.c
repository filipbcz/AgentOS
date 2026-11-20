#include "ipc-test.h"

int serve(void) {
    const long fd = 3;
    struct { struct ipc_peer sender; struct request data; } incoming;
    if (os_call(SYS_CLOSE, 0, 0, 0)) return 31;
    // Neither a short buffer nor a bad destination consumes the message.
    if (os_call(SYS_IPC_RECV, fd, (long)&incoming, 1) != -90 ||
        os_call(SYS_IPC_RECV, fd, 0, sizeof(incoming.data)) != -14 ||
        os_call(SYS_IPC_RECV, fd, (long)&incoming, sizeof(incoming.data)) != sizeof(incoming.data)) return 32;
    unsigned long self = os_call(SYS_GETPID, 0, 0, 0);
    struct ipc_peer peer = incoming.sender;
    if (!peer.pid || peer.pid == self || peer.uid != 1000 || peer.gid != 1000 ||
        incoming.data.claimed.pid != 0 || incoming.data.claimed.uid != 0 || incoming.data.claimed.gid != 0) return 33;
    if (!report("AGENTOS IPC SERVICE PID=", peer, self)) return 34;
    struct response reply = {answer(incoming.data.challenge), peer};
    return os_call(SYS_IPC_SEND, fd, (long)&reply, sizeof(reply)) == sizeof(reply) ? 0 : 35;
}
