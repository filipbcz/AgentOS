#include "../../user/abi.h"

/* Real native processes exercise the ordinary balancing policy. There is no
 * test affinity, forced-move syscall, fixed PID or shared userspace address
 * space. Every protocol wait and CPU-work phase has a finite HPET deadline. */
enum { pWorkers = 4, pRounds = 6, pPage = 4096, pWorkMs = 150,
       pSleepMs = 5000, pSleepWindowMs = 250, pTimeoutMs = 15000, pArmWorkMs = 50, pKillMs = 5000 };
enum { pReady = 1, pWork = 2, pRead = 3, pFinish = 4, pExit = 5, pArm = 6 };
static volatile unsigned char gMigrationMemory[8 * pPage] __attribute__((aligned(4096)));
static int gChannels[pWorkers][2], gPipe[2];
static long gFile, gRoot;

struct ScheduleStats {
    unsigned long fVersion, fCpu, fCpus, fMoves, fTotalMoves, fWakeups, fPid, fParent;
};
struct Command { unsigned long fKind, fValue; };
struct Report {
    unsigned long fKind, fSlot, fCpu, fMoves, fWork, fNow, fUntil, fValue, fObserved;
};
struct IncomingCommand { struct ipc_peer fPeer; struct Command fBody; };
struct IncomingReport { struct ipc_peer fPeer; struct Report fBody; };
struct Worker { long fPid; struct Report fReport; };
struct PipeRecord { unsigned long fPid, fSlot, fDigest; };
struct Progress {
    unsigned long fSlot, fPid, fCpu, fMoves, fWork, fNow, fUntil, fObserved;
};
_Static_assert(sizeof(struct ScheduleStats) == 64, "scheduler diagnostics layout");

static long now(void) { return os_call(SYS_MONOTONIC_MS, 0, 0, 0); }

static int scheduleStats(struct ScheduleStats *aStats) {
    return os_call(SYS_SCHED_STATS, (long)aStats, sizeof(*aStats), 0) == 0 &&
        aStats->fVersion == 1 && aStats->fCpus > 0 && aStats->fPid > 0 &&
        (aStats->fCpus != 1 || (aStats->fMoves == 0 && aStats->fTotalMoves == 0 && aStats->fWakeups == 0));
}

static void appendText(char *aLine, unsigned *aLength, const char *aText) {
    while (*aText) aLine[(*aLength)++] = *aText++;
}

static void appendField(char *aLine, unsigned *aLength, const char *aName, unsigned long aValue) {
    appendText(aLine, aLength, aName);
    format_hex(aLine + *aLength, aValue, 16);
    *aLength += 16;
}

static int output(char *aLine, unsigned aLength) {
    appendText(aLine, &aLength, "\r\n");
    return aLength <= 256 && os_call(SYS_WRITE, 1, (long)aLine, aLength) == aLength;
}

static int event(const char *aKind, const struct Progress *aProgress,
                 unsigned long aDetail, unsigned long aDigest) {
    char pLine[256];
    unsigned pLength = 0;
    appendText(pLine, &pLength, "AGENTOS MIGRATION ");
    appendText(pLine, &pLength, aKind);
    appendField(pLine, &pLength, " ROOT=", gRoot);
    appendField(pLine, &pLength, " CHILD=", aProgress->fPid);
    appendField(pLine, &pLength, " SLOT=", aProgress->fSlot);
    appendField(pLine, &pLength, " CPU=", aProgress->fCpu);
    appendField(pLine, &pLength, " MOVES=", aProgress->fMoves);
    appendField(pLine, &pLength, " WORK=", aProgress->fWork);
    appendField(pLine, &pLength, " NOW=", aProgress->fNow);
    appendField(pLine, &pLength, " UNTIL=", aProgress->fUntil);
    if (aKind[0] == 'I') {
        appendField(pLine, &pLength, " OFFSET=", aDetail);
        appendField(pLine, &pLength, " FNV=", aDigest);
    }
    if (aKind[0] == 'A') appendField(pLine, &pLength, " TOTAL=", aDetail);
    return output(pLine, pLength);
}

static int boundary(const char *aKind, const struct ScheduleStats *aStats,
                    unsigned long aObserved, unsigned long aTime) {
    char pLine[256];
    unsigned pLength = 0;
    appendText(pLine, &pLength, "AGENTOS MIGRATION ");
    appendText(pLine, &pLength, aKind);
    appendField(pLine, &pLength, " ROOT=", gRoot);
    appendField(pLine, &pLength, " CPUS=", aStats->fCpus);
    appendField(pLine, &pLength, " WORKERS=", pWorkers);
    appendField(pLine, &pLength, " OBSERVED=", aObserved);
    appendField(pLine, &pLength, " MIGRATIONS=", aStats->fTotalMoves);
    appendField(pLine, &pLength, " WAKEUPS=", aStats->fWakeups);
    appendField(pLine, &pLength, " NOW=", aTime);
    return output(pLine, pLength);
}

/* Foreground spawn inherits only stdio. DUP2(fd,fd) validates an open
 * descriptor without changing it, and CHILD_AFTER is scoped to its owner. */
static long descriptorMask(void) {
    unsigned long pMask = 0;
    for (long pFd = 0; pFd < 32; ++pFd) {
        long pResult = os_call(SYS_DUP2, pFd, pFd, 0);
        if (pResult == pFd) pMask |= 1UL << pFd;
        else if (pResult != -9) return -1;
    }
    return (long)pMask;
}

static int ownerEvent(const char *aKind, const struct ScheduleStats *aStats) {
    char pLine[256];
    unsigned pLength = 0;
    long pMask = descriptorMask();
    long pEmpty = os_call(SYS_CHILD_AFTER, 0, 0, 0);
    if (pMask != 7 || pEmpty != -10 || aStats->fPid != (unsigned long)gRoot ||
        aStats->fParent <= 1) return 0;
    appendText(pLine, &pLength, "AGENTOS MIGRATION ");
    appendText(pLine, &pLength, aKind);
    appendField(pLine, &pLength, " ROOT=", aStats->fPid);
    appendField(pLine, &pLength, " PARENT=", aStats->fParent);
    appendField(pLine, &pLength, " CPU=", aStats->fCpu);
    appendField(pLine, &pLength, " FDS=", pMask);
    appendField(pLine, &pLength, " CHILD_AFTER=", pEmpty);
    return output(pLine, pLength);
}

static int reaped(unsigned aSlot, long aChild, long aStatus, long aAgain) {
    char pLine[160];
    unsigned pLength = 0;
    appendText(pLine, &pLength, "AGENTOS MIGRATION REAP");
    appendField(pLine, &pLength, " ROOT=", gRoot);
    appendField(pLine, &pLength, " CHILD=", aChild);
    appendField(pLine, &pLength, " SLOT=", aSlot);
    appendField(pLine, &pLength, " STATUS=", aStatus);
    appendField(pLine, &pLength, " AGAIN=", aAgain);
    return output(pLine, pLength);
}

static int killEvent(const char *aKind, unsigned aSlot, const struct Worker *aWorker,
                     const struct ScheduleStats *aParent, long aNow, long aUntil) {
    char pLine[256];
    unsigned pLength = 0;
    appendText(pLine, &pLength, "AGENTOS MIGRATION ");
    appendText(pLine, &pLength, aKind);
    appendField(pLine, &pLength, " ROOT=", gRoot);
    appendField(pLine, &pLength, " CHILD=", aWorker->fPid);
    appendField(pLine, &pLength, " SLOT=", aSlot);
    appendField(pLine, &pLength, " CPU=", aParent->fCpu);
    appendField(pLine, &pLength, " OWNER=", aWorker->fReport.fCpu);
    appendField(pLine, &pLength, " TOTAL=", aParent->fTotalMoves);
    appendField(pLine, &pLength, " NOW=", aNow);
    appendField(pLine, &pLength, " UNTIL=", aUntil);
    if (aKind[0] == 'C') appendField(pLine, &pLength, " STATUS=", 137);
    return output(pLine, pLength);
}

static void childExit(unsigned aStatus) {
    (void)os_call(SYS_EXIT, aStatus, 0, 0);
    for (;;) (void)os_call(SYS_YIELD, 0, 0, 0);
}

static int sendReport(unsigned aKind, const struct Progress *aProgress, unsigned long aValue) {
    const struct Report pReport = {aKind, aProgress->fSlot, aProgress->fCpu,
        aProgress->fMoves, aProgress->fWork, aProgress->fNow, aProgress->fUntil,
        aValue, aProgress->fObserved};
    return os_call(SYS_IPC_SEND, gChannels[aProgress->fSlot][1],
                   (long)&pReport, sizeof(pReport)) == sizeof(pReport);
}

static int command(unsigned aSlot, struct Command *aCommand, long aLimit) {
    int pFd = gChannels[aSlot][1];
    long pEvents = os_call(SYS_WAIT_EVENTS_UNTIL, 1UL << pFd, aLimit, 0);
    if (pEvents <= 0 || !(pEvents & (1UL << pFd))) return 0;
    struct IncomingCommand pIncoming;
    if (os_call(SYS_IPC_TRY_RECV, pFd, (long)&pIncoming, sizeof(*aCommand)) != sizeof(*aCommand) ||
        pIncoming.fPeer.pid != (unsigned long)gRoot ||
        pIncoming.fPeer.uid != 1000 || pIncoming.fPeer.gid != 1000) return 0;
    *aCommand = pIncoming.fBody;
    return 1;
}

static int observe(struct Progress *aProgress) {
    struct ScheduleStats pStats;
    long pNow = now();
    if (pNow < 0 || !scheduleStats(&pStats) || pStats.fPid != aProgress->fPid ||
        pStats.fParent != (unsigned long)gRoot || pStats.fMoves < aProgress->fMoves ||
        (unsigned long)pNow < aProgress->fNow) return 0;
    /* Keep the last logged CPU until a millisecond has actually elapsed.
     * This proves work/time progression, including a move observed after wake. */
    if (pStats.fCpu != aProgress->fCpu && (unsigned long)pNow > aProgress->fNow) {
        if (pStats.fMoves <= aProgress->fMoves) return 0;
        aProgress->fCpu = pStats.fCpu;
        aProgress->fMoves = pStats.fMoves;
        aProgress->fNow = pNow;
        ++aProgress->fObserved;
        if (!event("MOVED", aProgress, 0, 0)) return 0;
    }
    return 1;
}

static int workBefore(struct Progress *aProgress, unsigned long aLimit, unsigned long aDeadline) {
    for (;;) {
        long pNow = now();
        if (pNow < 0 || (unsigned long)pNow >= aDeadline) return 0;
        if ((unsigned long)pNow >= aLimit) return 1;
        for (unsigned pIndex = 0; pIndex < 1024; ++pIndex) {
            ++aProgress->fWork;
            __asm__ volatile ("" : "+r"(aProgress->fWork) :: "memory");
        }
        if (!observe(aProgress) || os_call(SYS_YIELD, 0, 0, 0) != 0) return 0;
    }
}

static int workUntil(struct Progress *aProgress, unsigned long aLimit) {
    return workBefore(aProgress, aLimit, aProgress->fUntil);
}

static int sleepToDeadline(struct Progress *aProgress) {
    long pWindow = (long)aProgress->fUntil - pSleepWindowMs;
    if (os_call(SYS_SLEEP_UNTIL, pWindow, 0, 0) != 0) return 0;
    long pEntry = now();
    if (pEntry < pWindow || (unsigned long)pEntry >= aProgress->fUntil ||
        os_call(SYS_SLEEP_UNTIL, aProgress->fUntil, 0, 0) != 0) return 0;
    long pWake = now();
    if (pWake < (long)aProgress->fUntil) return 0;
    /* Publish the actual entry time after waking: serial output must not
     * consume the interval between this measurement and the blocking call. */
    aProgress->fNow = pEntry;
    return event("SLEEP", aProgress, 0, 0);
}

/* A counter bracket proves this owner report remained current through the
 * parent's later KILL/WAIT. SEND need not imply that the sender has blocked.
 * If necessary, a pair performs bounded work to recreate real imbalance. */
static int armReport(struct Progress *aProgress, unsigned long aWorkMs, long aTimeout) {
    long pNow = now();
    if ((aWorkMs != 0 && aWorkMs != pArmWorkMs) || pNow < 0 ||
        pNow > aTimeout - (long)aWorkMs ||
        (aWorkMs && !workBefore(aProgress, pNow + aWorkMs, aTimeout))) return 0;
    for (;;) {
        ++aProgress->fWork;
        if (!observe(aProgress)) return 0;
        pNow = now();
        struct ScheduleStats pStats;
        if (pNow < 0 || pNow >= aTimeout || !scheduleStats(&pStats) ||
            pStats.fPid != aProgress->fPid || pStats.fParent != (unsigned long)gRoot ||
            pStats.fMoves < aProgress->fMoves || (unsigned long)pNow < aProgress->fNow) return 0;
        if (pStats.fCpu != aProgress->fCpu) {
            if (os_call(SYS_YIELD, 0, 0, 0) != 0) return 0;
            continue;
        }
        aProgress->fMoves = pStats.fMoves;
        aProgress->fNow = pNow;
        return event("ARMED", aProgress, pStats.fTotalMoves, 0) &&
            sendReport(pArm, aProgress, pStats.fTotalMoves);
    }
}

static unsigned long expectedDigest(unsigned long aOffset) {
    unsigned pDigest = 2166136261U;
    for (unsigned pIndex = 0; pIndex < 16; ++pIndex) {
        unsigned long pPosition = aOffset + pIndex;
        pDigest = (pDigest ^ (unsigned char)(pPosition * 73 + pPosition / 251 * 19)) * 16777619U;
    }
    return pDigest;
}

static unsigned long byteDigest(const volatile unsigned char *aBytes) {
    unsigned pDigest = 2166136261U;
    for (unsigned pIndex = 0; pIndex < 16; ++pIndex)
        pDigest = (pDigest ^ aBytes[pIndex]) * 16777619U;
    return pDigest;
}

static void worker(unsigned aSlot) {
    for (unsigned pIndex = 0; pIndex < pWorkers; ++pIndex) {
        if (os_call(SYS_CLOSE, gChannels[pIndex][0], 0, 0) != 0 ||
            (pIndex != aSlot && os_call(SYS_CLOSE, gChannels[pIndex][1], 0, 0) != 0)) childExit(151);
    }
    if (os_call(SYS_CLOSE, gPipe[0], 0, 0) != 0) childExit(152);
    struct ScheduleStats pStats;
    long pNow = now();
    if (pNow < 0 || pNow > 0x7fffffffffffffffL - pTimeoutMs ||
        !scheduleStats(&pStats) || pStats.fParent != (unsigned long)gRoot) childExit(153);
    struct Progress pProgress = {aSlot, pStats.fPid, pStats.fCpu, pStats.fMoves,
                                1, pNow, pNow + pSleepMs, 0};
    long pTimeout = pNow + pTimeoutMs;
    if (!event("START", &pProgress, 0, 0) || !sendReport(pReady, &pProgress, 0)) childExit(154);
    unsigned pLastRound = 0;
    int pReadDone = 0, pFinished = 0;
    for (;;) {
        struct Command pCommand;
        if (!command(aSlot, &pCommand, pTimeout)) childExit(155);
        if (pCommand.fKind == pWork) {
            pNow = now();
            if (pReadDone || pNow < 0 || pCommand.fValue <= pLastRound ||
                pCommand.fValue > pRounds || (unsigned long)pNow + pWorkMs >= pProgress.fUntil ||
                !workUntil(&pProgress, pNow + pWorkMs)) childExit(156);
            pLastRound = pCommand.fValue;
            if (!sendReport(pWork, &pProgress, pLastRound)) childExit(157);
        } else if (pCommand.fKind == pRead) {
            if (pReadDone || pCommand.fValue != 16 * (aSlot + 1) ||
                gMigrationMemory[0] != 0x31 || gMigrationMemory[(aSlot + 1) * pPage] != 0) childExit(158);
            // One page was resident before fork; both other pages were lazy.
            gMigrationMemory[0] = (unsigned char)(0x70 + aSlot);
            gMigrationMemory[(aSlot + 1) * pPage] = (unsigned char)(0x40 + aSlot);
            volatile unsigned char *pBytes = gMigrationMemory + 6 * pPage;
            if (os_call(SYS_READ, gFile, (long)pBytes, 16) != 16 ||
                byteDigest(pBytes) != expectedDigest(pCommand.fValue)) childExit(159);
            struct PipeRecord pRecord = {pProgress.fPid, aSlot, byteDigest(pBytes)};
            if (os_call(SYS_WRITE, gPipe[1], (long)&pRecord, sizeof(pRecord)) != sizeof(pRecord) ||
                os_call(SYS_CLOSE, gFile, 0, 0) != 0 || os_call(SYS_CLOSE, gPipe[1], 0, 0) != 0) childExit(160);
            ++pProgress.fWork;
            if (!observe(&pProgress)) childExit(161);
            pNow = now();
            if (pNow < 0) childExit(162);
            pProgress.fNow = pNow;
            if (!event("IO", &pProgress, pCommand.fValue, pRecord.fDigest) ||
                !sendReport(pRead, &pProgress, pRecord.fDigest)) childExit(163);
            pReadDone = 1;
        } else if (pCommand.fKind == pFinish) {
            if (!pReadDone || pFinished ||
                !workUntil(&pProgress, pProgress.fUntil - pWorkers * pSleepWindowMs)) childExit(164);
            if (!sleepToDeadline(&pProgress)) childExit(165);
            ++pProgress.fWork;
            if (!observe(&pProgress)) childExit(166);
            pNow = now();
            if (pNow < 0 || (unsigned long)pNow < pProgress.fUntil ||
                gMigrationMemory[0] != (unsigned char)(0x70 + aSlot) ||
                gMigrationMemory[(aSlot + 1) * pPage] != (unsigned char)(0x40 + aSlot)) childExit(167);
            pProgress.fNow = pNow;
            if (!event("DONE", &pProgress, 0, 0) || !sendReport(pFinish, &pProgress, 0)) childExit(168);
            pFinished = 1;
        } else if (pCommand.fKind == pExit && pFinished) {
            if (os_call(SYS_CLOSE, gChannels[aSlot][1], 0, 0) != 0) childExit(169);
            childExit(0);
        } else if (pCommand.fKind == pArm && pFinished) {
            if (!armReport(&pProgress, pCommand.fValue, pTimeout)) childExit(187);
        } else childExit(170);
    }
}

static int sendCommand(unsigned aSlot, unsigned aKind, unsigned long aValue) {
    const struct Command pCommand = {aKind, aValue};
    return os_call(SYS_IPC_SEND, gChannels[aSlot][0],
                   (long)&pCommand, sizeof(pCommand)) == sizeof(pCommand);
}

static int receiveReport(struct Worker *aWorker, unsigned aSlot, unsigned aKind, long aLimit) {
    int pFd = gChannels[aSlot][0];
    long pEvents = os_call(SYS_WAIT_EVENTS_UNTIL, 1UL << pFd, aLimit, 0);
    struct IncomingReport pIncoming;
    if (pEvents <= 0 || !(pEvents & (1UL << pFd)) ||
        os_call(SYS_IPC_TRY_RECV, pFd, (long)&pIncoming, sizeof(pIncoming.fBody)) != sizeof(pIncoming.fBody) ||
        pIncoming.fPeer.pid != (unsigned long)aWorker->fPid ||
        pIncoming.fPeer.uid != 1000 || pIncoming.fPeer.gid != 1000 ||
        pIncoming.fBody.fKind != aKind || pIncoming.fBody.fSlot != aSlot ||
        (aKind != pReady && (pIncoming.fBody.fWork < aWorker->fReport.fWork ||
                            pIncoming.fBody.fUntil != aWorker->fReport.fUntil))) return 0;
    aWorker->fReport = pIncoming.fBody;
    if (aKind == pRead) {
        struct ScheduleStats pReader;
        char pLine[256];
        unsigned pLength = 0;
        if (!scheduleStats(&pReader)) return 0;
        appendText(pLine, &pLength, "AGENTOS MIGRATION AUTH");
        appendField(pLine, &pLength, " ROOT=", gRoot);
        appendField(pLine, &pLength, " CHILD=", pIncoming.fPeer.pid);
        appendField(pLine, &pLength, " SLOT=", aSlot);
        appendField(pLine, &pLength, " UID=", pIncoming.fPeer.uid);
        appendField(pLine, &pLength, " GID=", pIncoming.fPeer.gid);
        appendField(pLine, &pLength, " SENDER=", pIncoming.fBody.fCpu);
        appendField(pLine, &pLength, " READER=", pReader.fCpu);
        appendField(pLine, &pLength, " FNV=", pIncoming.fBody.fValue);
        if (!output(pLine, pLength)) return 0;
    }
    return 1;
}

static int migrationScenario(void) {
    struct ScheduleStats pBefore, pAfter;
    struct Worker pChildren[pWorkers] = {0};
    unsigned char pBytes[16];
    long pNow = now();
    gRoot = os_call(SYS_GETPID, 0, 0, 0);
    if (gRoot <= 0 || pNow < 0 || pNow > 0x7fffffffffffffffL - pTimeoutMs ||
        !scheduleStats(&pBefore) || pBefore.fPid != (unsigned long)gRoot ||
        os_call(SYS_SCHED_STATS, 0, sizeof(pBefore), 0) != -14 ||
        os_call(SYS_SCHED_STATS, (long)&pBefore, sizeof(pBefore) - 1, 0) != -22 ||
        os_call(SYS_SCHED_STATS, (long)&pBefore, sizeof(pBefore), 1) != -22 ||
        !ownerEvent("OWNER", &pBefore) || !boundary("BEGIN", &pBefore, 0, pNow)) return 171;
    long pTimeout = pNow + pTimeoutMs;
    gMigrationMemory[0] = 0x31;
    static const char pFile[] = "/data/transfer.bin";
    gFile = os_call(SYS_OPEN, (long)pFile, sizeof(pFile) - 1, 0);
    if (gFile < 0 || os_call(SYS_READ, gFile, (long)pBytes, 16) != 16 ||
        byteDigest(pBytes) != expectedDigest(0) || os_call(SYS_PIPE, (long)gPipe, 0, 0) != 0) return 172;
    for (unsigned pIndex = 0; pIndex < pWorkers; ++pIndex)
        if (os_call(SYS_IPC_PAIR, (long)gChannels[pIndex], 0, 0) != 0) return 173;
    for (unsigned pIndex = 0; pIndex < pWorkers; ++pIndex) {
        long pChild = os_call(SYS_FORK, 0, 0, 0);
        if (pChild < 0) return 174;
        if (pChild == 0) worker(pIndex);
        pChildren[pIndex].fPid = pChild;
        if (!receiveReport(&pChildren[pIndex], pIndex, pReady, pTimeout)) return 176;
        /* Give each worker a distinct final sleep window on a shared vCPU.
         * Each deadline is still fixed by the child's clock before any work. */
        if (pIndex + 1 < pWorkers &&
            os_call(SYS_SLEEP_UNTIL, pChildren[pIndex].fReport.fNow + pSleepWindowMs, 0, 0) != 0)
            return 176;
    }
    if (os_call(SYS_CLOSE, gPipe[1], 0, 0) != 0) return 175;
    for (unsigned pIndex = 0; pIndex < pWorkers; ++pIndex)
        if (os_call(SYS_CLOSE, gChannels[pIndex][1], 0, 0) != 0) return 176;
    // READY proves these tasks have run and published their identities. Wake
    // only a same-CPU pair; all other children and then the parent stay asleep.
    for (unsigned pRound = 1; pRound <= pRounds; ++pRound) {
        unsigned pFirst = 0, pSecond = 1;
        int pFound = 0;
        for (unsigned pI = 0; pI < pWorkers && !pFound; ++pI)
            for (unsigned pJ = pI + 1; pJ < pWorkers; ++pJ)
                if (pChildren[pI].fReport.fCpu == pChildren[pJ].fReport.fCpu) {
                    pFirst = pI; pSecond = pJ; pFound = 1; break;
                }
        if (!sendCommand(pFirst, pWork, pRound) || !sendCommand(pSecond, pWork, pRound) ||
            !receiveReport(&pChildren[pFirst], pFirst, pWork, pTimeout) ||
            !receiveReport(&pChildren[pSecond], pSecond, pWork, pTimeout) ||
            pChildren[pFirst].fReport.fValue != pRound ||
            pChildren[pSecond].fReport.fValue != pRound) return 177;
    }
    for (unsigned pIndex = 0; pIndex < pWorkers; ++pIndex) {
        if (!sendCommand(pIndex, pRead, 16 * (pIndex + 1)) ||
            !receiveReport(&pChildren[pIndex], pIndex, pRead, pTimeout) ||
            pChildren[pIndex].fReport.fValue != expectedDigest(16 * (pIndex + 1))) return 178;
    }
    unsigned pSeen = 0;
    for (unsigned pIndex = 0; pIndex < pWorkers; ++pIndex) {
        struct PipeRecord pRecord;
        if (os_call(SYS_READ, gPipe[0], (long)&pRecord, sizeof(pRecord)) != sizeof(pRecord) ||
            pRecord.fSlot >= pWorkers || pSeen & (1U << pRecord.fSlot) ||
            pRecord.fPid != (unsigned long)pChildren[pRecord.fSlot].fPid ||
            pRecord.fDigest != expectedDigest(16 * (pRecord.fSlot + 1))) return 179;
        pSeen |= 1U << pRecord.fSlot;
    }
    if (os_call(SYS_READ, gPipe[0], (long)pBytes, 1) != 0 ||
        os_call(SYS_READ, gFile, (long)pBytes, 16) != 16 ||
        byteDigest(pBytes) != expectedDigest(16 * (pWorkers + 1)) ||
        os_call(SYS_CLOSE, gFile, 0, 0) != 0 || os_call(SYS_CLOSE, gPipe[0], 0, 0) != 0 ||
        gMigrationMemory[0] != 0x31) return 180;
    for (unsigned pIndex = 1; pIndex < 8; ++pIndex)
        if (gMigrationMemory[pIndex * pPage] != 0) return 181;
    for (unsigned pIndex = 0; pIndex < pWorkers; ++pIndex)
        if (!sendCommand(pIndex, pFinish, 0)) return 182;
    unsigned long pWorkObserved = 0;
    for (unsigned pIndex = 0; pIndex < pWorkers; ++pIndex) {
        if (!receiveReport(&pChildren[pIndex], pIndex, pFinish, pTimeout)) return 183;
        pWorkObserved += pChildren[pIndex].fReport.fObserved;
    }
    if (pBefore.fCpus > 1 && pWorkObserved < 2) return 188;
    unsigned pVictim = pWorkers;
    struct ScheduleStats pKillParent;
    for (unsigned pAttempt = 0; pAttempt < 8 && pVictim == pWorkers; ++pAttempt) {
        for (unsigned pIndex = 0; pIndex < pWorkers; ++pIndex) {
            pNow = now();
            if (pNow < 0 || pNow > pTimeout - pKillMs - 20 ||
                os_call(SYS_SLEEP_UNTIL, pNow + 20, 0, 0) != 0 ||
                !sendCommand(pIndex, pArm, 0) ||
                !receiveReport(&pChildren[pIndex], pIndex, pArm, pTimeout) ||
                !scheduleStats(&pKillParent) || pKillParent.fPid != (unsigned long)gRoot) return 189;
            const struct Report *pReport = &pChildren[pIndex].fReport;
            if (pReport->fValue == pKillParent.fTotalMoves &&
                (pBefore.fCpus == 1 || pReport->fCpu != pKillParent.fCpu)) {
                pVictim = pIndex;
                break;
            }
        }
        if (pVictim != pWorkers) break;
        // Four blocked workers may all be local. Wake a same-CPU pair for
        // real CPU work so the ordinary balancer can distribute them again.
        unsigned pFirst = 0, pSecond = 1;
        int pFound = 0;
        for (unsigned pI = 0; pI < pWorkers && !pFound; ++pI)
            for (unsigned pJ = pI + 1; pJ < pWorkers; ++pJ)
                if (pChildren[pI].fReport.fCpu == pChildren[pJ].fReport.fCpu) {
                    pFirst = pI; pSecond = pJ; pFound = 1; break;
                }
        if (!sendCommand(pFirst, pArm, pArmWorkMs) || !sendCommand(pSecond, pArm, pArmWorkMs) ||
            !receiveReport(&pChildren[pFirst], pFirst, pArm, pTimeout) ||
            !receiveReport(&pChildren[pSecond], pSecond, pArm, pTimeout)) return 189;
    }
    pNow = now();
    if (pVictim == pWorkers || pNow < 0 || pNow > pTimeout - pKillMs) return 190;
    long pKillUntil = pNow + pKillMs;
    if (!killEvent("KILL", pVictim, &pChildren[pVictim], &pKillParent, pNow, pKillUntil) ||
        os_call(SYS_KILL, pChildren[pVictim].fPid, 0, 0) != 0) return 191;
    long pKillStatus = os_call(SYS_WAIT_CHILD_UNTIL, pChildren[pVictim].fPid, pKillUntil, 0);
    if (pKillStatus != 137) return 191;
    pNow = now();
    struct ScheduleStats pCollected;
    if (pNow < 0 || pNow > pKillUntil || !scheduleStats(&pCollected) ||
        pCollected.fPid != (unsigned long)gRoot || pCollected.fCpu != pKillParent.fCpu ||
        pCollected.fTotalMoves != pKillParent.fTotalMoves ||
        !killEvent("COLLECT", pVictim, &pChildren[pVictim], &pCollected, pNow, pKillUntil)) return 191;
    unsigned long pObserved = 0, pChildMoves = 0;
    for (unsigned pIndex = 0; pIndex < pWorkers; ++pIndex) {
        pObserved += pChildren[pIndex].fReport.fObserved;
        pChildMoves += pChildren[pIndex].fReport.fMoves;
    }
    for (unsigned pIndex = 0; pIndex < pWorkers; ++pIndex)
        if (pIndex != pVictim && !sendCommand(pIndex, pExit, 0)) return 184;
    for (unsigned pIndex = 0; pIndex < pWorkers; ++pIndex) {
        long pStatus = pIndex == pVictim ? pKillStatus :
            os_call(SYS_WAIT_CHILD_UNTIL, pChildren[pIndex].fPid, pTimeout, 0);
        long pAgain = os_call(SYS_TRY_WAIT, pChildren[pIndex].fPid, 0, 0);
        if (pStatus != (pIndex == pVictim ? 137 : 0) || pAgain != -10 ||
            !reaped(pIndex, pChildren[pIndex].fPid, pStatus, pAgain) ||
            os_call(SYS_CLOSE, gChannels[pIndex][0], 0, 0) != 0) return 185;
    }
    pNow = now();
    if (pNow < 0 || !scheduleStats(&pAfter) || pAfter.fPid != (unsigned long)gRoot ||
        pAfter.fCpus != pBefore.fCpus || pAfter.fTotalMoves < pBefore.fTotalMoves ||
        pAfter.fWakeups < pBefore.fWakeups ||
        pAfter.fTotalMoves - pBefore.fTotalMoves < pChildMoves ||
        (pAfter.fCpus == 1 && (pObserved != 0 || pAfter.fTotalMoves != pBefore.fTotalMoves)) ||
        (pAfter.fCpus > 1 && (pObserved < 2 || pAfter.fTotalMoves - pBefore.fTotalMoves < pObserved ||
                           pAfter.fWakeups == pBefore.fWakeups)) ||
        pAfter.fParent != pBefore.fParent ||
        !boundary("ENDED", &pAfter, pObserved, pNow) || !ownerEvent("CLEAN", &pAfter)) return 186;
    return 0;
}

int runMigration(void) {
    int pStatus = migrationScenario();
    if (pStatus != 0) {
        char pLine[120];
        unsigned pLength = 0;
        appendText(pLine, &pLength, "AGENTOS MIGRATION FAILED");
        appendField(pLine, &pLength, " ROOT=", gRoot);
        appendField(pLine, &pLength, " CODE=", pStatus);
        (void)output(pLine, pLength);
    }
    return pStatus;
}
