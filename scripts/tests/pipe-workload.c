/* Separate runtime pipe test; the shell's three stdio descriptors stay intact. */
#include "../../user/abi.h"

enum { pipeReadFd=10, pipeWriteFd=11, duplicateFd=12, largeRead=1317, smallRead=317 };
static const char source[]="/data/transfer.bin";
static long open_ro(const char *name,long len) { return os_call(SYS_OPEN,(long)name,len,0); }
static int closeFd(int *fd) {
    if (*fd<0) return 1;
    int ok=os_call(SYS_CLOSE,*fd,0,0)==0;
    *fd=-1;
    return ok;
}
static int privateSlot(int fd) { return fd>=3 && fd<pipeReadFd; }

int run_pipe_transfer(long deadline) {
    int ends[2]={-1,-1},rd=-1,wr=-1,file=-1,duplicate=-1;
    unsigned char buffer[largeRead];
    long child=0,total=0,direct=0,dupReads=0,writes=0,shortWrites=0;
    int rc=1;
    if (open_ro("/missing",8)!=-2 || open_ro("/data",5)!=-21 ||
        open_ro("/stage/..",9)!=-20 || os_call(SYS_PIPE,(long)source,0,0)!=-14) goto done;
    rc=2;
    if (os_call(SYS_PIPE,(long)ends,0,0) || !privateSlot(ends[0]) ||
        !privateSlot(ends[1]) || !closeFd(&ends[0]) ||
        os_call(SYS_WRITE,ends[1],(long)source,1)!=-32 || !closeFd(&ends[1])) goto done;
    rc=3;
    if (os_call(SYS_PIPE,(long)ends,0,0) || !privateSlot(ends[0]) ||
        !privateSlot(ends[1]) || ends[0]==ends[1]) goto done;
    if (os_call(SYS_DUP2,ends[0],pipeReadFd,0)!=pipeReadFd) goto done;
    rd=pipeReadFd;
    if (os_call(SYS_DUP2,ends[1],pipeWriteFd,0)!=pipeWriteFd) goto done;
    wr=pipeWriteFd;
    rc=4;
    if (!closeFd(&ends[0]) || !closeFd(&ends[1])) goto done;
    rc=5;
    child=os_call(SYS_SPAWN,(long)"pipe-receiver",13,0);
    if (child<=0 || !closeFd(&rd) || os_call(SYS_YIELD,0,0,0)!=0) goto done;
    rc=6;
    file=(int)open_ro(source,sizeof(source)-1);
    if (!privateSlot(file) || os_call(SYS_DUP2,file,duplicateFd,0)!=duplicateFd) goto done;
    duplicate=duplicateFd;
    if (os_call(SYS_READ,file,(long)source,1)!=-14) goto done;
    for (;;) {
        long ms=os_call(SYS_MONOTONIC_MS,0,0,0);
        rc=7;
        if (ms<0 || ms>deadline) goto done;
        int useDup=(int)(total&1);
        long request=total?smallRead:largeRead;
        long n=os_call(SYS_READ,useDup?duplicate:file,(long)buffer,request);
        if (n<0 || n>request || n>8193-total) goto done;
        if (!n) break;
        if (useDup) ++dupReads; else ++direct;
        rc=8;
        for (long sent=0;sent<n;) {
            long count=os_call(SYS_WRITE,wr,(long)(buffer+sent),n-sent);
            if (count<=0 || count>n-sent) goto done;
            ++writes;
            if (count<n-sent) ++shortWrites;
            sent+=count;
        }
        total+=n;
    }
    rc=9;
    int closed=file;
    if (!closeFd(&file) || !closeFd(&duplicate) || !closeFd(&wr) ||
        total!=8193 || !direct || !dupReads || !shortWrites ||
        os_call(SYS_READ,closed,(long)buffer,1)!=-9) goto done;
    rc=10;
    long status=os_call(SYS_WAIT_CHILD_UNTIL,child,deadline,0);
    if (status<0) goto done;
    long collected=child;
    child=0;
    if (status!=0 || os_call(SYS_TRY_WAIT,collected,0,0)!=-10 ||
        os_call(SYS_CHILD_AFTER,0,0,0)!=-10) goto done;
    rc=11;
    long pid=os_call(SYS_GETPID,0,0,0);
    if (pid<=0) goto done;
    char line[]="AGENTOS PIPE TEST SENT PID=0000000000000000 CHILD=0000000000000000 BYTES=0000000000000000 DIRECT=0000000000000000 DUP=0000000000000000 WRITES=0000000000000000 SHORT=0000000000000000\r\n";
    const unsigned long values[]={(unsigned long)pid,(unsigned long)collected,(unsigned long)total,
        (unsigned long)direct,(unsigned long)dupReads,(unsigned long)writes,(unsigned long)shortWrites};
    unsigned field=0;
    for (unsigned i=0;i<sizeof(line)-1 && field<7;++i)
        if (line[i]=='=') { format_hex(line+i+1,values[field++],16); i+=16; }
    if (field==7 && os_call(SYS_WRITE,1,(long)line,sizeof(line)-1)==sizeof(line)-1) rc=0;
done:
    (void)closeFd(&ends[0]); (void)closeFd(&ends[1]);
    (void)closeFd(&rd); (void)closeFd(&wr); (void)closeFd(&file); (void)closeFd(&duplicate);
    if (child>0) {
        (void)os_call(SYS_KILL,child,0,0);
        (void)os_call(SYS_WAIT_CHILD_UNTIL,child,deadline,0);
    }
    return rc;
}
