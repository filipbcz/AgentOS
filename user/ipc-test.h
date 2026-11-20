#include "abi.h"

struct request { unsigned long challenge; struct ipc_peer claimed; };
struct response { unsigned long answer; struct ipc_peer observed; };
static inline unsigned long answer(unsigned long challenge) {
    return (challenge << 9 | challenge >> 55) ^ 0x6d97341bUL;
}
static inline long report(const char *prefix, struct ipc_peer peer, unsigned long self) {
    char line[120];
    unsigned n = 0;
    while (*prefix) line[n++] = *prefix++;
    format_hex(line+n, self, 16); n += 16;
    const char *fields[] = {" PEER=", " UID=", " GID="};
    unsigned long values[] = {peer.pid, peer.uid, peer.gid};
    for (unsigned i=0; i<3; i++) {
        const char *s = fields[i];
        while (*s) line[n++] = *s++;
        unsigned digits = i == 0 ? 16 : 8;
        format_hex(line+n, values[i], digits); n += digits;
    }
    line[n++]='\r'; line[n++]='\n';
    return os_call(SYS_WRITE, 1, (long)line, n) == n;
}
