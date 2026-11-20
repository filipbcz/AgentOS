#include "abi.h"

static const char source[] = "/data/transfer.bin";
static long open_ro(const char *name, long len) { return os_call(SYS_OPEN, (long)name, len, 0); }
static long close_fd(long fd) { return os_call(SYS_CLOSE, fd, 0, 0); }

int run_transfer(void) {
    int ends[2];
    unsigned char buffer[317];
    if (open_ro("/missing", 8) != -2 || open_ro("/data", 5) != -21 ||
        open_ro("/stage/..", 9) != -20 || os_call(SYS_PIPE, (long)source, 0, 0) != -14) return 1;
    if (os_call(SYS_PIPE, (long)ends, 0, 0) || close_fd(ends[0]) ||
        os_call(SYS_WRITE, ends[1], (long)source, 1) != -32 || close_fd(ends[1])) return 2;
    if (os_call(SYS_PIPE, (long)ends, 0, 0) || os_call(SYS_DUP2, ends[0], 0, 0) ||
        os_call(SYS_DUP2, ends[1], 3, 0) != 3) return 3;
    if (ends[0] != 0 && close_fd(ends[0])) return 4;
    if (ends[1] != 3 && close_fd(ends[1])) return 4;

    long child = os_call(SYS_SPAWN, (long)"receiver", 8, 0);
    if (child <= 0 || close_fd(0)) return 5;
    os_call(SYS_YIELD, 0, 0, 0);
    long file = open_ro(source, sizeof(source)-1);
    if (file < 0 || os_call(SYS_DUP2, file, 4, 0) != 4 ||
        os_call(SYS_READ, file, (long)source, 1) != -14) return 6;

    long total = 0;
    for (;;) {
        // Both descriptors refer to the same open description and cursor.
        long n = os_call(SYS_READ, total & 1 ? 4 : file, (long)buffer, sizeof(buffer));
        if (n < 0) return 7;
        if (!n) break;
        for (long sent = 0; sent < n;) {
            long count = os_call(SYS_WRITE, 3, (long)(buffer+sent), n-sent);
            if (count <= 0) return 8;
            sent += count;
        }
        total += n;
    }
    if (close_fd(file) || close_fd(4) || close_fd(3) || total != 8193 ||
        os_call(SYS_READ, file, (long)buffer, 1) != -9) return 9;
    long status;
    while ((status = os_call(SYS_TRY_WAIT, child, 0, 0)) == -11) os_call(SYS_YIELD, 0, 0, 0);
    if (status != 0) return 10;
    char message[] = "AGENTOS PIPE SENT PID=0000000000000000 CHILD=0000000000000000\r\n";
    format_hex(message + sizeof("AGENTOS PIPE SENT PID=")-1, os_call(SYS_GETPID, 0, 0, 0), 16);
    format_hex(message + sizeof(message)-19, child, 16);
    return os_call(SYS_WRITE, 1, (long)message, sizeof(message)-1) == sizeof(message)-1 ? 0 : 11;
}
