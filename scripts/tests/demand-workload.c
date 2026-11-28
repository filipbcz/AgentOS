#include "../../user/abi.h"

/* This standalone staged ELF reserves this real NOBITS segment. Accesses below deliberately
 * reach different 2 MiB page-table ranges, leaving nearly all pages untouched.
 * No kernel test hook, synthetic memory backend or special ELF is involved.
 */
enum { pPageSize = 4096, pMiB = 1024 * 1024 };
static volatile unsigned char gDemandZero[16 * pMiB] __attribute__((aligned(4096)));
static const unsigned char gDemandImage[3 * pPageSize] __attribute__((aligned(4096))) = {
    [pPageSize] = 0x31, [pPageSize + 63] = 0x92, [2 * pPageSize + 9] = 0xc7
};
static const char gDemandFile[] = "/data/transfer.bin";

struct VmStats {
    unsigned long fVersion, fReserved, fResident, fTables, fMetadata;
    unsigned long fDemand, fCopies, fPromotions;
};
_Static_assert(sizeof(struct VmStats) == 64, "VM statistics ABI");

static void appendText(char *aLine, unsigned *aLength, const char *aText) {
    while (*aText) aLine[(*aLength)++] = *aText++;
}

static void appendField(char *aLine, unsigned *aLength, const char *aName, unsigned long aValue) {
    appendText(aLine, aLength, aName);
    format_hex(aLine + *aLength, aValue, 16);
    *aLength += 16;
}

static int writePhase(const char *aEvent, unsigned long aRoot,
                      unsigned long aChild, unsigned long aAddress) {
    char pLine[256];
    unsigned pLength = 0;
    appendText(pLine, &pLength, "AGENTOS DEMAND ");
    appendText(pLine, &pLength, aEvent);
    appendField(pLine, &pLength, " ROOT=", aRoot);
    appendField(pLine, &pLength, " CHILD=", aChild);
    appendField(pLine, &pLength, " ADDRESS=", aAddress);
    appendText(pLine, &pLength, "\r\n");
    return pLength <= sizeof(pLine) &&
        os_call(SYS_WRITE, 1, (long)pLine, pLength) == pLength;
}

static int readStats(struct VmStats *aStats) {
    return os_call(SYS_VM_STATS, (long)aStats, sizeof(*aStats), 0) == 0 &&
        aStats->fVersion == 1 && aStats->fMetadata == 1 &&
        aStats->fReserved >= 4096 && aStats->fResident < aStats->fReserved &&
        aStats->fTables >= 4;
}

static int writeStats(const char *aEvent, unsigned long aRoot, const struct VmStats *aStats) {
    char pLine[256];
    unsigned pLength = 0;
    appendText(pLine, &pLength, "AGENTOS DEMAND ");
    appendText(pLine, &pLength, aEvent);
    appendField(pLine, &pLength, " ROOT=", aRoot);
    appendField(pLine, &pLength, " RESERVED=", aStats->fReserved);
    appendField(pLine, &pLength, " RESIDENT=", aStats->fResident);
    appendField(pLine, &pLength, " TABLES=", aStats->fTables);
    appendField(pLine, &pLength, " META=", aStats->fMetadata);
    appendField(pLine, &pLength, " DEMAND=", aStats->fDemand);
    appendField(pLine, &pLength, " COPIES=", aStats->fCopies);
    appendField(pLine, &pLength, " PROMOTES=", aStats->fPromotions);
    appendText(pLine, &pLength, "\r\n");
    return pLength <= sizeof(pLine) &&
        os_call(SYS_WRITE, 1, (long)pLine, pLength) == pLength;
}

static void childDone(unsigned aStatus) {
    (void)os_call(SYS_EXIT, aStatus, 0, 0);
    for (;;) (void)os_call(SYS_YIELD, 0, 0, 0);
}

static long waitChild(long aChild) {
    long pNow = os_call(SYS_MONOTONIC_MS, 0, 0, 0);
    if (pNow < 0 || (unsigned long)pNow > 0x7fffffffffffffffUL - 5000) return -1;
    return os_call(SYS_WAIT_CHILD_UNTIL, aChild, pNow + 5000, 0);
}

static int checkFirstTouch(unsigned long aRoot) {
    struct VmStats pBefore, pAfter;
    /* Warm the reporting path before measuring first accesses. */
    if (!readStats(&pBefore) || pBefore.fResident >= 256 ||
        !writeStats("BASE", aRoot, &pBefore)) return 111;
    if (!readStats(&pBefore)) return 112;
    const unsigned long pOffsets[4] = {0, 2 * pMiB, 6 * pMiB, sizeof(gDemandZero) - 1};
    for (unsigned pIndex = 0; pIndex < 4; ++pIndex) {
        if (gDemandZero[pOffsets[pIndex]] != 0) return 113;
        gDemandZero[pOffsets[pIndex]] = (unsigned char)(0x11 + pIndex);
    }
    if (!readStats(&pAfter) || pAfter.fReserved != pBefore.fReserved ||
        pAfter.fResident < pBefore.fResident + 4 ||
        pAfter.fResident > pBefore.fResident + 8 ||
        pAfter.fDemand < pBefore.fDemand + 4 ||
        pAfter.fDemand > pBefore.fDemand + 8 ||
        !writeStats("TOUCH", aRoot, &pAfter)) return 114;
    return 0;
}

static int checkLazyIo(unsigned long aRoot) {
    struct VmStats pBefore, pAfter;
    unsigned char pBytes[64];
    int pPipe[2];
    long pFd = os_call(SYS_OPEN, (long)gDemandFile, sizeof(gDemandFile) - 1, 0);
    if (pFd < 0 || !readStats(&pBefore)) return 115;
    /* Reject a valid-first-byte/invalid-tail destination before advancing
     * the file offset, then fill a previously absent BSS page through read. */
    if (os_call(SYS_READ, pFd, 0x10000000000UL - 8, 16) != -14 ||
        os_call(SYS_READ, pFd, (long)(gDemandZero + 4 * pMiB), 16) != 16) return 116;
    for (unsigned pIndex = 0; pIndex < 16; ++pIndex)
        if (gDemandZero[4 * pMiB + pIndex] != (unsigned char)(pIndex * 73)) return 117;
    if (os_call(SYS_CLOSE, pFd, 0, 0) != 0 ||
        os_call(SYS_PIPE, (long)pPipe, 0, 0) != 0) return 118;
    /* Kernel copy-in is the first access to this zero page. */
    if (os_call(SYS_WRITE, pPipe[1], (long)(gDemandZero + 5 * pMiB), 64) != 64 ||
        os_call(SYS_READ, pPipe[0], (long)pBytes, 64) != 64) return 119;
    for (unsigned pIndex = 0; pIndex < sizeof(pBytes); ++pIndex)
        if (pBytes[pIndex] != 0) return 120;
    /* Kernel copy-in pages in read-only ELF contents; copy-out crosses the
     * boundary between two untouched writable pages. */
    volatile unsigned char *pOutput = gDemandZero + 7 * pMiB + pPageSize - 16;
    if (os_call(SYS_WRITE, pPipe[1], (long)(gDemandImage + pPageSize), 64) != 64 ||
        os_call(SYS_READ, pPipe[0], (long)pOutput, 64) != 64) return 121;
    for (unsigned pIndex = 0; pIndex < 64; ++pIndex) {
        unsigned char pExpected = pIndex == 0 ? 0x31 : pIndex == 63 ? 0x92 : 0;
        if (pOutput[pIndex] != pExpected) return 122;
    }
    if (os_call(SYS_CLOSE, pPipe[0], 0, 0) != 0 ||
        os_call(SYS_CLOSE, pPipe[1], 0, 0) != 0) return 123;
    /* Even the returned endpoint array starts on an absent page. */
    volatile int *pPair = (volatile int *)(gDemandZero + 8 * pMiB);
    if (os_call(SYS_IPC_PAIR, (long)pPair, 0, 0) != 0 ||
        os_call(SYS_IPC_SEND, pPair[0], (long)(gDemandZero + 9 * pMiB), 32) != 32 ||
        os_call(SYS_IPC_RECV, pPair[1], (long)(gDemandZero + 10 * pMiB), 32) != 32) return 124;
    const volatile struct ipc_peer *pPeer = (const volatile struct ipc_peer *)(gDemandZero + 10 * pMiB);
    if (pPeer->pid != aRoot || pPeer->uid != 1000 || pPeer->gid != 1000) return 125;
    for (unsigned pIndex = 0; pIndex < 32; ++pIndex)
        if (gDemandZero[10 * pMiB + sizeof(*pPeer) + pIndex] != 0) return 126;
    if (os_call(SYS_CLOSE, pPair[0], 0, 0) != 0 ||
        os_call(SYS_CLOSE, pPair[1], 0, 0) != 0 || !readStats(&pAfter) ||
        pAfter.fDemand < pBefore.fDemand + 8 ||
        pAfter.fResident >= 256 || !writePhase("IO", aRoot, 0, 0)) return 127;
    return 0;
}

static int checkFork(unsigned long aRoot) {
    long pChild = os_call(SYS_FORK, 0, 0, 0);
    if (pChild < 0) return 128;
    if (pChild == 0) {
        struct VmStats pBefore, pAfter;
        if (!readStats(&pBefore) || gDemandZero[0] != 0x11 ||
            gDemandZero[12 * pMiB] != 0) childDone(129);
        /* One page existed before fork; the other had never been touched. */
        gDemandZero[0] = 0x71;
        gDemandZero[12 * pMiB] = 0x72;
        long pFd = os_call(SYS_OPEN, (long)gDemandFile, sizeof(gDemandFile) - 1, 0);
        if (pFd < 0 || os_call(SYS_READ, pFd,
            (long)(gDemandZero + 12 * pMiB + pPageSize), 16) != 16 ||
            os_call(SYS_CLOSE, pFd, 0, 0) != 0) childDone(130);
        for (unsigned pIndex = 0; pIndex < 16; ++pIndex)
            if (gDemandZero[12 * pMiB + pPageSize + pIndex] != (unsigned char)(pIndex * 73)) childDone(131);
        if (!readStats(&pAfter) || pAfter.fDemand < pBefore.fDemand + 2 ||
            pAfter.fCopies < pBefore.fCopies + 1 ||
            !writePhase("CHILD", aRoot, (unsigned long)os_call(SYS_GETPID, 0, 0, 0), 0)) childDone(132);
        childDone(0);
    }
    if (waitChild(pChild) != 0 || gDemandZero[0] != 0x11 ||
        gDemandZero[12 * pMiB] != 0) return 133;
    for (unsigned pIndex = 0; pIndex < 16; ++pIndex)
        if (gDemandZero[12 * pMiB + pPageSize + pIndex] != 0) return 134;
    if (!writePhase("REAPS", aRoot, pChild, 0)) return 135;
    return 0;
}

static int checkProtection(unsigned long aRoot, unsigned aKind, unsigned long aAddress) {
    const char *pEvent = aKind == 0 ? "GUARD" : aKind == 1 ? "NX" : "RO";
    if (!writePhase(pEvent, aRoot, 0, aAddress)) return 136;
    long pChild = os_call(SYS_FORK, 0, 0, 0);
    if (pChild < 0) return 137;
    if (pChild == 0) {
        if (aKind == 0) {
            __asm__ volatile ("movb (%0), %%al" :: "r"(aAddress) : "rax", "memory");
        } else if (aKind == 1) {
            __asm__ volatile ("call *%0" :: "r"(aAddress) : "memory");
        } else {
            __asm__ volatile ("movb $0x5a, (%0)" :: "r"(aAddress) : "memory");
        }
        childDone(138);
    }
    if (waitChild(pChild) != 270 || !writePhase("FAULT", aRoot, pChild, aAddress)) return 139;
    return 0;
}

/* The locality controller must not pre-touch the workload entry page. */
__attribute__((aligned(4096))) int runDemandPaging(void) {
    struct VmStats pStats;
    long pRoot = os_call(SYS_GETPID, 0, 0, 0);
    if (pRoot <= 0 ||
        os_call(SYS_VM_STATS, (long)&pStats, sizeof(pStats) - 1, 0) != -22 ||
        os_call(SYS_VM_STATS, (long)&pStats, sizeof(pStats), 1) != -22 ||
        os_call(SYS_VM_STATS, 0, sizeof(pStats), 0) != -14 ||
        os_call(SYS_VM_STATS, -32, sizeof(pStats), 0) != -14 ||
        os_call(SYS_VM_STATS, (long)gDemandImage, sizeof(pStats), 0) != -14 ||
        !writePhase("BEGIN", pRoot, 0, 0)) return 110;
    int pStatus = checkFirstTouch(pRoot);
    if (pStatus != 0) return pStatus;
    pStatus = checkLazyIo(pRoot);
    if (pStatus != 0) return pStatus;
    pStatus = checkFork(pRoot);
    if (pStatus != 0) return pStatus;
    pStatus = checkProtection(pRoot, 0, 0x10000000000UL - 5 * pPageSize);
    if (pStatus != 0) return pStatus;
    pStatus = checkProtection(pRoot, 1, (unsigned long)(gDemandZero + 14 * pMiB));
    if (pStatus != 0) return pStatus;
    pStatus = checkProtection(pRoot, 2, (unsigned long)(gDemandImage + 2 * pPageSize + 9));
    if (pStatus != 0) return pStatus;
    return writePhase("ENDED", pRoot, 0, 0) ? 0 : 140;
}
