/* Exercise the guest's actual work and sleep paths across a forced host
 * scheduling boundary. Guest acceptance still requires real CPU movement. */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "../../user/abi.h"

static long mock_call(long, long, long, long);
#define os_call mock_call
#include "migration-workload.c"
#undef os_call

static long clockMs, wakeOffset[2], targets[2];
static unsigned cpu, moves, sleeps, moveRecords, sleepRecords;
static unsigned long lastWork;

static long mock_call(long op, long a, long b, long c) {
    switch (op) {
    case SYS_MONOTONIC_MS:
        return clockMs;
    case SYS_SCHED_STATS:
        *(struct ScheduleStats *)a = (struct ScheduleStats){1, cpu, 2, moves, moves, 0, 9, 1};
        return 0;
    case SYS_YIELD:
        cpu ^= 1;
        ++moves;
        ++clockMs;
        return 0;
    case SYS_SLEEP_UNTIL:
        assert(sleeps < 2 && a >= clockMs);
        targets[sleeps] = a;
        clockMs = a + wakeOffset[sleeps++];
        return 0;
    case SYS_WRITE: {
        char line[257] = {0};
        assert(a == 1 && c > 0 && (size_t)c < sizeof(line));
        memcpy(line, (const void *)b, c);
        if (strstr(line, " MOVED ")) {
            unsigned long work;
            assert(sscanf(strstr(line, " WORK="), " WORK=%lx", &work) == 1);
            assert(work > lastWork);
            lastWork = work;
            ++moveRecords;
        } else {
            unsigned long entry;
            assert(strstr(line, " SLEEP ") && sleeps == 2);
            assert(sscanf(strstr(line, " NOW="), " NOW=%lx", &entry) == 1);
            assert(entry == (unsigned long)(targets[0] + wakeOffset[0]));
            clockMs += 300; /* A slow console must not delay sleep entry. */
            ++sleepRecords;
        }
        return c;
    }
    default:
        assert(0);
        return -1;
    }
}

static void checkSleep(long firstOffset, long finalOffset, int success, unsigned expectedSleeps) {
    struct Progress progress = {.fUntil = 5000};
    clockMs = 4000;
    sleeps = sleepRecords = 0;
    wakeOffset[0] = firstOffset;
    wakeOffset[1] = finalOffset;
    assert(sleepToDeadline(&progress) == success);
    assert(sleeps == expectedSleeps && targets[0] == 4750);
    if (sleeps == 2) assert(targets[1] == 5000);
    assert(sleepRecords == (unsigned)success);
}

int main(void) {
    gRoot = 1;
    cpu = moves = 1;
    clockMs = 10;
    struct Progress progress = {.fPid = 9, .fWork = 1};
    assert(workBefore(&progress, 11, 100));
    /* The yield returned on a different CPU just as this work phase ended. */
    assert(cpu == 0 && moveRecords == 1 && lastWork == 1025);
    assert(workBefore(&progress, 12, 100));
    assert(moveRecords == 2 && lastWork == 2049);
    checkSleep(17, 9, 1, 2);
    checkSleep(250, 0, 0, 1);
    checkSleep(-1, 0, 0, 1);
    checkSleep(0, -1, 0, 2);
    puts("Migration work continuity and absolute sleep boundaries passed");
    return 0;
}
