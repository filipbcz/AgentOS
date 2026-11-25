// Executes the actual user shell with an injected syscall boundary. No native
// AgentOS syscall is issued on the host; the unused inline ABI helper is hidden.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../../user/abi.h"

static long mockCall(long aOp, long aFirst, long aSecond, long aThird);
#define os_call mockCall
#include "../../user/shell.c"
#undef os_call

/* Shell tests isolate command parsing and TTY I/O. The authenticated
 * manager protocol is exercised separately by service-manager integration
 * tests and real QEMU guest boots. */
int manager_connect(void) { return 1; }
int manager_command(unsigned op, unsigned service) {
    (void)op;(void)service;
    return 1;
}

static unsigned gReadChunk, gWriteChunk;
static const char *gMode, *gFilePath;
static FILE *gFile;
static unsigned gOpens, gCloses, gInputCalls, gWriteCalls;
static unsigned gStatsCalls, gSpawns, gWaits;
static long gForeground;
static unsigned long gClockMs=1000;

static int modeIs(const char *aMode) { return strcmp(gMode, aMode) == 0; }
static long mockCall(long aOp, long aFirst, long aSecond, long aThird) {
    if (aOp == SYS_GETPID) return modeIs("pid-error") ? -5 : 4242;
    if (aOp == SYS_SPAWN_FLAGS) {
        if (aThird != SPAWN_STDIO_ONLY || gForeground) abort();
        gSpawns++;
        if (aSecond<=0 || aSecond>128) return -36;
        if (modeIs("spawn-oom")) return -12;
        if (aSecond!=8 || memcmp((const void*)aFirst,"/program",8)) return -2;
        gForeground=4310;
        return gForeground;
    }
    if (aOp == SYS_WAIT_CHILD) {
        if (aFirst != gForeground || !gForeground || aSecond || aThird) abort();
        gWaits++;
        if (modeIs("wait-error")) return -10;
        if (modeIs("child-stdin") && fgetc(stdin)!='X') abort();
        gForeground=0;
        return modeIs("child-fault") ? 270 : modeIs("child-exit") ? 42 : 0;
    }
    if (aOp == SYS_TIMER_STATS) {
        if (!aFirst || aSecond!=32 || aThird) abort();
        if (modeIs("idle-stats-error")) return -14;
        unsigned long *pSample=(unsigned long *)aFirst;
        pSample[0]=modeIs("idle-version-error")?1:2;
        pSample[1]=modeIs("idle-overflow")?0x7fffffffffffffffUL-4999:gClockMs;
        pSample[2]=100+gStatsCalls*5;
        pSample[3]=20+gStatsCalls*5;
        if (modeIs("idle-counter-error") && gStatsCalls) pSample[2]=99;
        gStatsCalls++;
        return 0;
    }
    if (aOp == SYS_SLEEP_UNTIL) {
        if (aFirst!=(long)gClockMs+5000 || aSecond || aThird) abort();
        if (modeIs("idle-wait-error")) return -5;
        gClockMs=modeIs("idle-early-wake")?gClockMs+4999:(unsigned long)aFirst;
        return 0;
    }
    if (aOp == SYS_WRITE && aFirst == 1) {
        gWriteCalls++;
        if (modeIs("write-zero") || (modeIs("cat-write-zero") && gFile)) return 0;
        if (modeIs("write-error")) return -5;
        if (aThird < 0 || aThird > 256) abort();
        unsigned pLength = (unsigned)aThird < gWriteChunk ? (unsigned)aThird : gWriteChunk;
        return (long)fwrite((const void *)aSecond, 1, pLength, stdout);
    }
    if (aOp == SYS_READ && aFirst == 0) {
        if (gForeground) abort();
        gInputCalls++;
        if (modeIs("input-error")) return -5;
        if ((modeIs("input-overflow") && gInputCalls == 1) ||
            (modeIs("input-overflow-after-prefix") && gInputCalls == 5)) return -75;
        unsigned pLength = (unsigned)aThird < gReadChunk ? (unsigned)aThird : gReadChunk;
        return (long)fread((void *)aSecond, 1, pLength, stdin);
    }
    if (aOp == SYS_OPEN) {
        if (aThird != 0 || gFile) abort();
        if (aSecond != 8 || memcmp((const void *)aFirst, "/fixture", 8) || modeIs("open-error")) return -2;
        gFile = fopen(gFilePath, "rb");
        if (!gFile) abort();
        gOpens++;
        return 3;
    }
    if (aOp == SYS_READ && aFirst == 3 && gFile) {
        if (modeIs("file-error")) return -5;
        unsigned pLength = (unsigned)aThird < gReadChunk ? (unsigned)aThird : gReadChunk;
        return (long)fread((void *)aSecond, 1, pLength, gFile);
    }
    if (aOp == SYS_CLOSE && aFirst == 3 && gFile) {
        fclose(gFile);
        gFile = NULL;
        gCloses++;
        return modeIs("close-error") ? -5 : 0;
    }
    fprintf(stderr, "Unexpected syscall %lx(%ld,%ld,%ld)\n", aOp, aFirst, aSecond, aThird);
    abort();
}

int main(int aCount, char **aArgs) {
    if (aCount != 5) return 99;
    gReadChunk = (unsigned)strtoul(aArgs[1], NULL, 10);
    gWriteChunk = (unsigned)strtoul(aArgs[2], NULL, 10);
    if (!gReadChunk || !gWriteChunk) return 99;
    gMode = aArgs[3];
    gFilePath = aArgs[4];
    int pStatus = runShell();
    fprintf(stderr, "{\"opens\":%u,\"closes\":%u,\"inputCalls\":%u,\"writeCalls\":%u,\"spawns\":%u,\"waits\":%u}\n",
            gOpens, gCloses, gInputCalls, gWriteCalls,gSpawns,gWaits);
    return pStatus;
}
