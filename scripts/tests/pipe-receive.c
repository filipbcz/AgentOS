/* Independent receiving address space; every received byte is checked. */
#include "../../user/abi.h"

enum { pipeReadFd=10, pipeWriteFd=11 };
static int snapshot(const char *phase) {
    unsigned long s[8];
    long pid=os_call(SYS_GETPID,0,0,0);
    if (pid<=0 || os_call(SYS_SCHED_STATS,(long)s,64,0)!=0 ||
        s[0]!=1 || s[6]!=(unsigned long)pid || !s[7]) return 0;
    long ms=os_call(SYS_MONOTONIC_MS,0,0,0);
    if (ms<0) return 0;
    char line[]="AGENTOS PIPE TEST BEGIN PID=0000000000000000 PARENT=0000000000000000 APIC=0000000000000000 CPUS=0000000000000000 MOVES=0000000000000000 TOTAL=0000000000000000 MS=0000000000000000\r\n";
    for (unsigned i=0;i<5;++i) line[sizeof("AGENTOS PIPE TEST ")-1+i]=phase[i];
    const unsigned long values[]={s[6],s[7],s[1],s[2],s[3],s[4],(unsigned long)ms};
    unsigned field=0;
    for (unsigned i=0;i<sizeof(line)-1 && field<7;++i)
        if (line[i]=='=') { format_hex(line+i+1,values[field++],16); i+=16; }
    return field==7 && os_call(SYS_WRITE,1,(long)line,sizeof(line)-1)==sizeof(line)-1;
}

int receive(void) {
    unsigned char bytes[193];
    unsigned count=0,hash=2166136261u;
    if (os_call(SYS_CLOSE,pipeWriteFd,0,0) || !snapshot("BEGIN")) return 1;
    for (;;) {
        long n=os_call(SYS_READ,pipeReadFd,(long)bytes,sizeof(bytes));
        if (n<0 || n>(long)sizeof(bytes)) return 2;
        if (!n) break;
        for (long i=0;i<n;++i,++count) {
            if (count>=8193 || bytes[i]!=(unsigned char)(count*73+count/251*19)) return 3;
            hash=(hash^bytes[i])*16777619u;
        }
    }
    if (count!=8193 || os_call(SYS_READ,pipeReadFd,(long)bytes,1)!=0 ||
        os_call(SYS_CLOSE,pipeReadFd,0,0) || !snapshot("ENDED")) return 4;
    long pid=os_call(SYS_GETPID,0,0,0);
    if (pid<=0) return 5;
    char msg[]="AGENTOS PIPE TEST RECEIVED PID=0000000000000000 BYTES=00000000 FNV32=00000000 EOF=00000002\r\n";
    format_hex(msg+sizeof("AGENTOS PIPE TEST RECEIVED PID=")-1,(unsigned long)pid,16);
    format_hex(msg+sizeof("AGENTOS PIPE TEST RECEIVED PID=0000000000000000 BYTES=")-1,count,8);
    format_hex(msg+sizeof("AGENTOS PIPE TEST RECEIVED PID=0000000000000000 BYTES=00000000 FNV32=")-1,hash,8);
    return os_call(SYS_WRITE,1,(long)msg,sizeof(msg)-1)==sizeof(msg)-1?0:5;
}
