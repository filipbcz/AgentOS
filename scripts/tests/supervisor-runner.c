/* Test-only workload, invoked by the ordinary shell. */
#include "../../user/abi.h"

int run_supervisor(void);

int runSupervisorWorkload(void) {
    unsigned long pStats[8]={0};
    long pPid=os_call(SYS_GETPID,0,0,0);
    if (pPid<=0 || os_call(SYS_SCHED_STATS,(long)pStats,sizeof(pStats),0)!=0 ||
        pStats[0]!=1 || pStats[6]!=(unsigned long)pPid || pStats[7]<=1 ||
        pStats[7]>=(unsigned long)pPid || os_call(SYS_CHILD_AFTER,0,0,0)!=-10)
        return 66;
    char pLine[]="AGENTOS TEST RUNNER PID=0000000000000000 PARENT=0000000000000000\r\n";
    format_hex(pLine+sizeof("AGENTOS TEST RUNNER PID=")-1,pStats[6],16);
    format_hex(pLine+sizeof("AGENTOS TEST RUNNER PID=0000000000000000 PARENT=")-1,pStats[7],16);
    if (os_call(SYS_WRITE,1,(long)pLine,sizeof(pLine)-1)!=sizeof(pLine)-1) return 67;
    int pResult=run_supervisor();
    if (pResult!=0) return pResult;
    /* No direct child, including a zombie, may remain after collection. */
    return os_call(SYS_CHILD_AFTER,0,0,0)==-10 ? 0 : 68;
}
