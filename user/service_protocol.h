#ifndef AGENTOS_SERVICE_PROTOCOL_H
#define AGENTOS_SERVICE_PROTOCOL_H

/* On-wire messages travel through kernel IPC, preceded at reception by
 * struct ipc_peer: identity comes exclusively from the kernel, never
 * from user-supplied payload bytes. 9 is a per-child inherited endpoint.
 */
#define SVC_CHANNEL_FD 9
#define SVC_MAGIC 0x31435653UL /* "SVC1" in little endian */
#define SVC_VERSION 1
#define SVC_COUNT 3
#define SVC_CORE 0
#define SVC_FLAKY 1
#define SVC_SHELL 2

#define SVC_OP_READY 0
#define SVC_OP_STATUS 1
#define SVC_OP_START 2
#define SVC_OP_STOP 3
#define SVC_OP_RESTART 4

#define SVC_DOWN 0
#define SVC_STARTING 1
#define SVC_RUNNING 2
#define SVC_BACKOFF 3
#define SVC_FAILED 4
#define SVC_STOPPED 5

#define SVC_OK 0
#define SVC_BAD_REQUEST 1
#define SVC_BAD_DEPENDENCY 2
#define SVC_INTERNAL_ERROR 3
#define SVC_ALREADY_RUNNING 4

struct svc_request {
    unsigned magic;
    unsigned short version;
    unsigned short operation;
    unsigned short service;
    unsigned short reserved;
};
struct svc_response {
    unsigned magic;
    unsigned short version;
    unsigned short result;
    unsigned char states[SVC_COUNT];
    unsigned char attempts[SVC_COUNT];
    unsigned short reserved;
};
struct svc_received_request {
    struct ipc_peer peer;
    struct svc_request data;
};
struct svc_received_response {
    struct ipc_peer peer;
    struct svc_response data;
};
_Static_assert(sizeof(struct svc_request)==12,"versioned service request");
_Static_assert(sizeof(struct svc_response)==16,"versioned service response");
_Static_assert(sizeof(struct svc_received_request)==32,"IPC peer+request padded to 8 bytes");
_Static_assert(sizeof(struct svc_received_response)==32,"IPC peer+response");
#endif
