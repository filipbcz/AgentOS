#include "abi.h"

/* Exercise real orphan adoption in the CPU-local root process after services
 * have finished. On error init exits and the kernel's root-death policy must
 * stop any remaining descendant. No speculative claims about global PID1.
 */
#define MAX_DEADLINE 0x7fffffffffffffffUL

static int boundary(const char *phase, long root) {
    char line[]="AGENTOS ORPHAN BEGIN ROOT=0000000000000000\r\n";
    for (unsigned i=0;i<5;i++) line[sizeof("AGENTOS ORPHAN ")-1+i]=phase[i];
    format_hex(line+sizeof("AGENTOS ORPHAN BEGIN ROOT=")-1,(unsigned long)root,16);
    return os_call(SYS_WRITE,1,(long)line,sizeof(line)-1)==sizeof(line)-1;
}

static int report(const char *event,long root,long parent,long child,
                  unsigned long status) {
    char line[]="AGENTOS ORPHAN ADOPT ROOT=0000000000000000 PARENT=0000000000000000 CHILD=0000000000000000 STATUS=0000000000000000\r\n";
    enum {
        ROOT_AT=sizeof("AGENTOS ORPHAN ADOPT ROOT=")-1,
        PARENT_AT=ROOT_AT+16+sizeof(" PARENT=")-1,
        CHILD_AT=PARENT_AT+16+sizeof(" CHILD=")-1,
        STATUS_AT=CHILD_AT+16+sizeof(" STATUS=")-1
    };
    for (unsigned i=0;i<5;i++) line[sizeof("AGENTOS ORPHAN ")-1+i]=event[i];
    format_hex(line+ROOT_AT,(unsigned long)root,16);
    format_hex(line+PARENT_AT,(unsigned long)parent,16);
    format_hex(line+CHILD_AT,(unsigned long)child,16);
    format_hex(line+STATUS_AT,status,16);
    return os_call(SYS_WRITE,1,(long)line,sizeof(line)-1)==sizeof(line)-1;
}

int run_orphans(void) {
    long root=os_call(SYS_GETPID,0,0,0);
    if (root<=0 || os_call(SYS_CHILD_AFTER,0,0,0)!=-10) return 71;
    if (!boundary("BEGIN",root)) return 72;
    long parent=os_call(SYS_SPAWN,(long)"orphan_parent",13,0);
    if (parent<=0 || parent==root) return 73;
    long start=os_call(SYS_MONOTONIC_MS,0,0,0);
    if (start<0 || (unsigned long)start>MAX_DEADLINE-1000) return 74;
    long result=os_call(SYS_WAIT_CHILD_UNTIL,parent,start+1000,0);
    if (result!=0) return 75;
    /* After the intermediate parent is fully reaped, its live child must
     * have become a direct child of this CPU's root/init process. */
    long adopted=os_call(SYS_CHILD_AFTER,0,0,0);
    if (adopted<=parent || os_call(SYS_CHILD_AFTER,adopted,0,0)!=-10 ||
        os_call(SYS_KILL,parent,0,0)!=-3) return 76;
    if (!report("ADOPT",root,parent,adopted,0)) return 77;
    if (os_call(SYS_KILL,adopted,0,0)!=0) return 78;
    if (os_call(SYS_TRY_WAIT,adopted,0,0)!=137) return 79;
    if (os_call(SYS_CHILD_AFTER,0,0,0)!=-10) return 80;
    if (!report("REAPS",root,parent,adopted,137)) return 81;
    return boundary("ENDED",root) ? 0 : 82;
}
