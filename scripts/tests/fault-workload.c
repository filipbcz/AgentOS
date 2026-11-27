/* Test-only userspace isolation regression; no kernel test mode.
 * Use the same native stack extent and protected-page fault as the existing
 * native-v2 boot fixture. The last aligned word lies above the entry RSP
 * (USER_END-16), outside ordinary call frames, in each private stack. */
#include "../../user/abi.h"

#define STACK_END 0x10000000000UL
#define TEST_FAULT_ADDRESS 0x02000000UL
#define SENTINEL_ADDRESS (STACK_END-8)
#define SENTINEL (*(volatile unsigned long *)SENTINEL_ADDRESS)
#define MAX_DEADLINE 0x7fffffffffffffffL
enum { waitMs=5000 };

static void append(char *aLine,unsigned *aLength,const char *aText) {
    while (*aText) aLine[(*aLength)++]=*aText++;
}

static int record(const char *aKind,const char *const aNames[],
                  const unsigned long aValues[],unsigned aCount) {
    char pLine[400];
    unsigned pLength=0;
    append(pLine,&pLength,"AGENTOS TEST FAULT ");
    append(pLine,&pLength,aKind);
    for (unsigned i=0;i<aCount;++i) {
        append(pLine,&pLength,aNames[i]);
        format_hex(pLine+pLength,aValues[i],16);
        pLength+=16;
    }
    append(pLine,&pLength,"\r\n");
    return pLength<=sizeof(pLine) &&
        os_call(SYS_WRITE,1,(long)pLine,pLength)==pLength;
}

#ifdef FAULT_PROBE
/* A fresh spawned ELF has a separate stack and page-table root. Write the
 * same virtual word as the parent, publish actual identity and placement,
 * then perform only the historical controlled fault. No data is disclosed
 * if the protection unexpectedly fails; the child instead exits nonzero. */
int runFaultProbe(void) {
    unsigned long pStats[8];
    long pPid=os_call(SYS_GETPID,0,0,0);
    SENTINEL=~0UL;
    if (pPid<=0 || os_call(SYS_SCHED_STATS,(long)pStats,sizeof(pStats),0)!=0)
        return 1;
    long pMs=os_call(SYS_MONOTONIC_MS,0,0,0);
    if (pMs<0 || pStats[0]!=1 || pStats[6]!=(unsigned long)pPid ||
        pStats[7]==0 || pStats[7]==pStats[6] || pStats[2]<1 ||
        pStats[3]>pStats[4] || pStats[4]>=0x8000000000000000UL ||
        SENTINEL!=~0UL) return 1;
    const char *const pNames[]={" PID="," PARENT="," APIC="," CPUS="," MOVES=",
                               " TOTAL="," MS="," VA="," VALUE="};
    const unsigned long pValues[]={pStats[6],pStats[7],pStats[1],pStats[2],
                                  pStats[3],pStats[4],(unsigned long)pMs,
                                  SENTINEL_ADDRESS,SENTINEL};
    if (!record("PROBE",pNames,pValues,9)) return 1;
    (void)*(volatile unsigned int *)TEST_FAULT_ADDRESS;
    return 1;
}
#else
static int abortChild(long aChild,long aDeadline) {
    if (aChild>0) {
        (void)os_call(SYS_KILL,aChild,0,0);
        (void)os_call(SYS_WAIT_CHILD_UNTIL,aChild,aDeadline,0);
    }
    return 64;
}

int run_fault(long aDeadline) {
    long pPid=os_call(SYS_GETPID,0,0,0);
    long pEmpty=os_call(SYS_CHILD_AFTER,0,0,0);
    if (pPid<=0 || pEmpty!=-10) return 60;
    SENTINEL=(unsigned long)pPid;
    long pInvalid=os_call(SYS_WRITE,1,TEST_FAULT_ADDRESS,8);
    long pCross=os_call(SYS_WRITE,1,STACK_END-1,2);
    long pUnknown=os_call(-1,0,0,0);
    const char *const pBeforeNames[]={" PID="," VA="," VALUE="," INVALID=",
                                     " CROSS="," UNKNOWN="," EMPTY="};
    const unsigned long pBeforeValues[]={(unsigned long)pPid,SENTINEL_ADDRESS,
        SENTINEL,(unsigned long)pInvalid,(unsigned long)pCross,
        (unsigned long)pUnknown,(unsigned long)pEmpty};
    if (!record("BEFORE",pBeforeNames,pBeforeValues,7) ||
        pInvalid!=-14 || pCross!=-14 || pUnknown!=-38 ||
        SENTINEL!=(unsigned long)pPid) return 61;

    static const char pPath[]="fault-probe";
    long pChild=os_call(SYS_SPAWN,(long)pPath,sizeof(pPath)-1,0);
    if (pChild<=0 || pChild==pPid) return 62;
    long pStart=os_call(SYS_MONOTONIC_MS,0,0,0);
    if (pStart<0 || pStart>MAX_DEADLINE-waitMs || pStart>aDeadline)
        return abortChild(pChild,aDeadline);
    long pUntil=pStart+waitMs;
    long pStatus=os_call(SYS_WAIT_CHILD_UNTIL,pChild,pUntil,0);
    long pEnd=os_call(SYS_MONOTONIC_MS,0,0,0);
    if (pStatus<0) return abortChild(pChild,aDeadline);
    long pAgain=os_call(SYS_TRY_WAIT,pChild,0,0);
    pEmpty=os_call(SYS_CHILD_AFTER,0,0,0);
    const char *const pAfterNames[]={" PID="," CHILD="," START="," UNTIL=",
        " END="," STATUS="," AGAIN="," EMPTY="," VA="," VALUE="};
    const unsigned long pAfterValues[]={(unsigned long)pPid,(unsigned long)pChild,
        (unsigned long)pStart,(unsigned long)pUntil,(unsigned long)pEnd,
        (unsigned long)pStatus,(unsigned long)pAgain,(unsigned long)pEmpty,
        SENTINEL_ADDRESS,SENTINEL};
    if (!record("COLLECT",pAfterNames,pAfterValues,10) ||
        pStatus!=270 || pAgain!=-10 || pEmpty!=-10 ||
        pEnd<pStart || pEnd>pUntil || pEnd>aDeadline ||
        SENTINEL!=(unsigned long)pPid) return 63;
    return 0;
}
#endif
