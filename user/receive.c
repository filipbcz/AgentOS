#include "abi.h"

int receive(void) {
    unsigned char bytes[193];
    unsigned count = 0, hash = 2166136261u;
    if (os_call(SYS_CLOSE, 3, 0, 0)) return 1;
    for (;;) {
        long n = os_call(SYS_READ, 0, (long)bytes, sizeof(bytes));
        if (n < 0) return 2;
        if (!n) break;
        for (long i = 0; i < n; ++i, ++count) {
            if (count >= 8193 || bytes[i] != (unsigned char)(count*73 + count/251*19)) return 3;
            hash = (hash ^ bytes[i]) * 16777619u;
        }
    }
    if (count != 8193 || os_call(SYS_READ, 0, (long)bytes, 1) != 0) return 4;
    char msg[] = "AGENTOS PIPE RECEIVED PID=0000000000000000 BYTES=00000000 FNV32=00000000\r\n";
    format_hex(msg + sizeof("AGENTOS PIPE RECEIVED PID=")-1, os_call(SYS_GETPID, 0, 0, 0), 16);
    format_hex(msg + sizeof(msg)-26, count, 8);
    format_hex(msg + sizeof(msg)-11, hash, 8);
    return os_call(SYS_WRITE, 1, (long)msg, sizeof(msg)-1) == sizeof(msg)-1 ? 0 : 5;
}
