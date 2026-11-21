#include "abi.h"
#include "service_protocol.h"

/* The shell is the *only* authenticated command peer of the CPU-root
 * service manager. The endpoint is inherited at a documented fixed fd,
 * never located by poking at kernel descriptor or process structures.
 */
static unsigned long supervisor_pid;
static unsigned length(const char *string) {
    unsigned n=0;while(string[n])n++;return n;
}
static int write_text(const char *s) {
    unsigned n=length(s);
    return os_call(SYS_WRITE,1,(long)s,n)==(long)n;
}
static int write_number(unsigned value) {
    char digits[11];
    unsigned pos=sizeof(digits);
    do {digits[--pos]=(char)('0'+value%10);value/=10;}while(value);
    return os_call(SYS_WRITE,1,(long)(digits+pos),sizeof(digits)-pos)==
        (long)(sizeof(digits)-pos);
}

static int exchange(unsigned op,unsigned service,struct svc_response *out) {
    struct svc_request request={
        SVC_MAGIC,SVC_VERSION,(unsigned short)op,(unsigned short)service,0
    };
    if (os_call(SYS_IPC_SEND,SVC_CHANNEL_FD,(long)&request,
                sizeof(request))!=sizeof(request)) return 0;
    struct svc_received_response reply;
    if (os_call(SYS_IPC_RECV,SVC_CHANNEL_FD,(long)&reply,
                sizeof(reply.data))!=sizeof(reply.data) ||
        reply.peer.pid==0 || reply.peer.uid!=1000 || reply.peer.gid!=1000 ||
        (supervisor_pid && reply.peer.pid!=supervisor_pid) ||
        reply.data.magic!=SVC_MAGIC || reply.data.version!=SVC_VERSION ||
        reply.data.reserved) return 0;
    supervisor_pid=reply.peer.pid;
    *out=reply.data;
    return 1;
}

int manager_connect(void) {
    for(long fd=3;fd<32;fd++)
        if(fd!=SVC_CHANNEL_FD) (void)os_call(SYS_CLOSE,fd,0,0);
    struct svc_response result;
    return exchange(SVC_OP_READY,SVC_SHELL,&result) &&
           result.result==SVC_OK &&
           result.states[SVC_SHELL]==SVC_RUNNING;
}

int manager_command(unsigned op,unsigned service) {
    static const char *names[SVC_COUNT]={"core","flaky","shell"};
    static const char *states[]={
        "down","starting","running","backoff","failed","stopped"
    };
    struct svc_response response;
    if (!exchange(op,service,&response))
        return write_text("service: manager IPC failed\r\n");
    if (response.result!=SVC_OK) {
        const char *message="service: invalid request\r\n";
        if(response.result==SVC_BAD_DEPENDENCY)
            message="service: dependency active or unavailable\r\n";
        else if(response.result==SVC_ALREADY_RUNNING)
            message="service: already running\r\n";
        else if(response.result==SVC_INTERNAL_ERROR)
            message="service: kernel operation failed\r\n";
        return write_text(message);
    }
    for(unsigned i=0;i<SVC_COUNT;i++) {
        if(response.states[i]>SVC_STOPPED ||
           !write_text(names[i]) || !write_text(": ") ||
           !write_text(states[response.states[i]]) ||
           !write_text(" (attempts=") ||
           !write_number(response.attempts[i]) ||
           !write_text(")\r\n")) return 0;
    }
    return 1;
}
