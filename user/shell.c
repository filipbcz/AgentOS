#include "abi.h"
#include "service_protocol.h"
int manager_connect(void);
int manager_command(unsigned op,unsigned service);

enum { commandCapacity = 256, outputChunk = 256 };

static unsigned textLength(const char *aText) {
    unsigned pLength = 0;
    while (aText[pLength]) pLength++;
    return pLength;
}

static int writeAll(const char *aData, unsigned aLength) {
    while (aLength) {
        unsigned pCount = aLength < outputChunk ? aLength : outputChunk;
        long pWritten = os_call(SYS_WRITE, 1, (long)aData, pCount);
        if (pWritten <= 0 || (unsigned long)pWritten > pCount) return 0;
        aData += pWritten;
        aLength -= (unsigned)pWritten;
    }
    return 1;
}

static int writeText(const char *aText) { return writeAll(aText, textLength(aText)); }

static int writeNumber(unsigned long aNumber) {
    char pDigits[20];
    unsigned pFirst = sizeof(pDigits);
    do {
        pDigits[--pFirst] = '0' + aNumber % 10;
        aNumber /= 10;
    } while (aNumber);
    return writeAll(pDigits + pFirst, sizeof(pDigits) - pFirst);
}

static int writeError(const char *aOperation, long aError) {
    return writeText(aOperation) && writeText(" (") &&
        (aError >= 0 || writeText("-")) &&
        writeNumber(aError < 0 ? -(unsigned long)aError : (unsigned long)aError) &&
        writeText(")\r\n");
}

static int isSpace(char aByte) { return aByte == ' ' || aByte == '\t'; }
static char *skipSpaces(char *aText) {
    while (isSpace(*aText)) aText++;
    return aText;
}
static int equals(const char *aLeft, const char *aRight) {
    while (*aLeft && *aLeft == *aRight) { aLeft++; aRight++; }
    return *aLeft == *aRight;
}

static int catFile(const char *aPath) {
    long pFd = os_call(SYS_OPEN, (long)aPath, textLength(aPath), 0);
    if (pFd < 0) return writeError("cat: open failed", pFd);
    char pBuffer[outputChunk];
    int pOutputOk = 1;
    for (;;) {
        long pRead = os_call(SYS_READ, pFd, (long)pBuffer, sizeof(pBuffer));
        if (pRead < 0) { pOutputOk = writeError("cat: read failed", pRead); break; }
        if (!pRead) break;
        if ((unsigned long)pRead > sizeof(pBuffer) || !writeAll(pBuffer, (unsigned)pRead)) {
            pOutputOk = 0;
            break;
        }
    }
    long pClosed = os_call(SYS_CLOSE, pFd, 0, 0);
    if (pOutputOk && pClosed < 0) pOutputOk = writeError("cat: close failed", pClosed);
    return pOutputOk;
}

static int measureIdle(void) {
    struct timerSample {
        unsigned long fVersion, fMonotonicMs, fTimerIrqs, fIdleTimerIrqs;
    } pBefore, pAfter;
    _Static_assert(sizeof(struct timerSample)==32,"native timer statistics v2");
    long pResult=os_call(SYS_TIMER_STATS,(long)&pBefore,sizeof(pBefore),0);
    if (pResult<0) return writeError("idle: statistics failed",pResult);
    if (pBefore.fVersion!=2 || pBefore.fMonotonicMs>0x7fffffffffffffffUL-5000)
        return writeError("idle: invalid clock",-5);
    pResult=os_call(SYS_SLEEP_UNTIL,(long)(pBefore.fMonotonicMs+5000),0,0);
    if (pResult!=0) return writeError("idle: wait failed",pResult);
    pResult=os_call(SYS_TIMER_STATS,(long)&pAfter,sizeof(pAfter),0);
    if (pResult<0) return writeError("idle: statistics failed",pResult);
    if (pAfter.fVersion!=2 || pAfter.fMonotonicMs<pBefore.fMonotonicMs+5000 ||
        pAfter.fTimerIrqs<pBefore.fTimerIrqs ||
        pAfter.fIdleTimerIrqs<pBefore.fIdleTimerIrqs ||
        pAfter.fIdleTimerIrqs-pBefore.fIdleTimerIrqs>pAfter.fTimerIrqs-pBefore.fTimerIrqs)
        return writeError("idle: invalid measurement",-5);
    char pLine[]="AGENTOS RUNTIME IDLE MS=0000000000000000 TIMERS=0000000000000000 IDLE=0000000000000000\r\n";
    format_hex(pLine+sizeof("AGENTOS RUNTIME IDLE MS=")-1,
               pAfter.fMonotonicMs-pBefore.fMonotonicMs,16);
    format_hex(pLine+sizeof("AGENTOS RUNTIME IDLE MS=0000000000000000 TIMERS=")-1,
               pAfter.fTimerIrqs-pBefore.fTimerIrqs,16);
    format_hex(pLine+sizeof("AGENTOS RUNTIME IDLE MS=0000000000000000 TIMERS=0000000000000000 IDLE=")-1,
               pAfter.fIdleTimerIrqs-pBefore.fIdleTimerIrqs,16);
    return writeAll(pLine,sizeof(pLine)-1);
}

// Foreground native programs use the ordinary process interface. Only
// stdio is inherited: the parent's service-manager authority stays private.
static int runProgram(const char *aPath) {
    long pPid = os_call(SYS_SPAWN, (long)aPath, textLength(aPath), SPAWN_STDIO_ONLY);
    if (pPid <= 0) return writeError("run: spawn failed", pPid < 0 ? pPid : -5) ? 1 : -1;
    long pStatus = os_call(SYS_WAIT_CHILD, pPid, 0, 0);
    if (pStatus < 0) {
        // The child's lifetime is uncertain. Do not read the same terminal
        // while the foreground child may own its input; PID1 reaps orphans.
        (void)writeError("run: wait failed", pStatus);
        return -1;
    }
    return writeText("exit status ") && writeNumber((unsigned long)pStatus) &&
           writeText("\r\n") ? 1 : -1;
}

// Returns 1 to continue, 0 for an explicit exit and -1 after an output failure.
static int executeLine(char *aLine) {
    char *pCommand = skipSpaces(aLine);
    if (!*pCommand) return 1;
    char *pArgs = pCommand;
    while (*pArgs && !isSpace(*pArgs)) pArgs++;
    if (*pArgs) *pArgs++ = 0;
    pArgs = skipSpaces(pArgs);
    int pOk;
    if (equals(pCommand, "echo")) {
        pOk = writeText(pArgs) && writeText("\r\n");
    } else if (equals(pCommand, "cat")) {
        char *pEnd = pArgs;
        while (*pEnd && !isSpace(*pEnd)) pEnd++;
        char *pRest = pEnd;
        if (*pEnd) { *pEnd = 0; pRest = skipSpaces(pEnd + 1); }
        pOk = !*pArgs || *pRest ? writeText("usage: cat PATH\r\n") : catFile(pArgs);
    } else if (equals(pCommand, "run")) {
        char *pEnd = pArgs;
        while (*pEnd && !isSpace(*pEnd)) pEnd++;
        char *pRest = pEnd;
        if (*pEnd) { *pEnd = 0; pRest = skipSpaces(pEnd + 1); }
        if (!*pArgs || *pRest) return writeText("usage: run PATH\r\n") ? 1 : -1;
        return runProgram(pArgs);
    } else if (equals(pCommand, "services") && !*pArgs) {
        pOk = manager_command(SVC_OP_STATUS,0xffff);
    } else if (equals(pCommand, "idle") && !*pArgs) {
        pOk = measureIdle();
    } else if (equals(pCommand, "service")) {
        char *pVerb = pArgs;
        while (*pArgs && !isSpace(*pArgs)) pArgs++;
        if (*pArgs) *pArgs++ = 0;
        pArgs = skipSpaces(pArgs);
        char *pName = pArgs;
        while (*pArgs && !isSpace(*pArgs)) pArgs++;
        if (*pArgs) *pArgs++ = 0;
        pArgs = skipSpaces(pArgs);
        unsigned pService=equals(pName,"core")?SVC_CORE:
            equals(pName,"flaky")?SVC_FLAKY:SVC_COUNT;
        unsigned pOperation=equals(pVerb,"start")?SVC_OP_START:
            equals(pVerb,"stop")?SVC_OP_STOP:
            equals(pVerb,"restart")?SVC_OP_RESTART:0;
        pOk = pService>=SVC_SHELL || !pOperation || *pArgs ?
            writeText("usage: service start|stop|restart core|flaky\r\n") :
            manager_command(pOperation,pService);
    } else if (equals(pCommand, "help") && !*pArgs) {
        pOk = writeText("help       List commands\r\npid        Show process ID\r\n"
                       "echo TEXT  Print text\r\ncat PATH   Read an initramfs file\r\n"
                       "run PATH   Run a native program\r\n"
                       "services   Show service registry\r\n"
                       "service start|stop|restart core|flaky\r\n"
                       "idle       Measure timer wakeups over 5 seconds\r\n"
                       "exit       Close the shell\r\n");
    } else if (equals(pCommand, "pid") && !*pArgs) {
        long pPid = os_call(SYS_GETPID, 0, 0, 0);
        pOk = pPid < 0 ? writeError("pid: failed", pPid) :
            writeNumber((unsigned long)pPid) && writeText("\r\n");
    } else if (equals(pCommand, "exit") && !*pArgs) {
        return 0;
    } else {
        pOk = writeText("error: unknown command or arguments; use help\r\n");
    }
    return pOk ? 1 : -1;
}

static int finishLine(char *aLine, unsigned aLength, int aRejected) {
    if (aRejected) {
        return writeText(aRejected == 1 ? "error: command too long\r\n" :
                                         "error: invalid command byte\r\n") ? 1 : -1;
    }
    aLine[aLength] = 0;
    return executeLine(aLine);
}

// Read exactly up to the command boundary, also for redirected stdin.
// Never read ahead bytes intended for a foreground program.
int runShell(void) {
    char pLine[commandCapacity];
    char pInput[1];
    unsigned pUsed = 0;
    int pRejected = 0;
    if (!manager_connect()) return 2;
    if (!writeText("AGENTOS SHELL READY\r\nagentos> ")) return 2;
    for (;;) {
        long pRead = os_call(SYS_READ, 0, (long)pInput, sizeof(pInput));
        if (pRead == -75) {
            // Canonical TTY owns discard-through-newline overflow quarantine.
            pUsed = 0;
            pRejected = 0;
            if (!writeText("error: input line too long\r\nagentos> ")) return 2;
            continue;
        }
        if (pRead < 0) {
            return writeError("shell: input failed", pRead) ? 1 : 2;
        }
        if ((unsigned long)pRead > sizeof(pInput)) return 1;
        if (!pRead) {
            if (pUsed || pRejected) {
                int pResult = finishLine(pLine, pUsed, pRejected);
                if (pResult < 0) return 2;
            }
            return writeText("\r\nAGENTOS SHELL EXIT\r\n") ? 0 : 2;
        }
        for (long pIndex = 0; pIndex < pRead; pIndex++) {
            unsigned char pByte = (unsigned char)pInput[pIndex];
            if (pByte == '\n') {
                int pResult = finishLine(pLine, pUsed, pRejected);
                if (pResult < 0) return 2;
                if (!pResult) return writeText("AGENTOS SHELL EXIT\r\n") ? 0 : 2;
                pUsed = 0;
                pRejected = 0;
                if (!writeText("agentos> ")) return 2;
            } else if (!pRejected) {
                if ((pByte < 32 && pByte != '\t') || pByte > 126) pRejected = 2;
                else if (pUsed == sizeof(pLine) - 1) pRejected = 1;
                else pLine[pUsed++] = (char)pByte;
            }
        }
    }
}
