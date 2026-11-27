/*
 * Isolated firmware probe, never linked into AgentOS.
 * PI MP Services supplies execution on each actual enabled processor.
 * Record the firmware's original mode before explicitly enabling x2APIC
 * if necessary. Restore a legacy mode through the disabled state before
 * returning to firmware. No IPI, external interrupt or remapping test.
 */
#include <efi.h>
#include <efilib.h>
#include <stdint.h>

typedef struct Mp Mp;
typedef VOID (EFIAPI *ApProcedure)(VOID *);
typedef struct {
    UINT64 id;
    UINT32 flags;
    UINT32 package, core, thread;
    UINT8 extended[64];
} ProcessorInfo;
struct Mp {
    EFI_STATUS (EFIAPI *count)(Mp *, UINTN *, UINTN *);
    EFI_STATUS (EFIAPI *info)(Mp *, UINTN, ProcessorInfo *);
    VOID *startup_all;
    EFI_STATUS (EFIAPI *startup_one)(Mp *, ApProcedure, UINTN, EFI_EVENT,
                                      UINTN, VOID *, BOOLEAN *);
    VOID *switch_bsp;
    VOID *enable_disable;
    EFI_STATUS (EFIAPI *who)(Mp *, UINTN *);
};

#define APIC_BASE 0x1bu
#define X2_ID 0x802u
#define APIC_MODE 0xc00ULL
#define XAPIC 0x800ULL
#define X2APIC 0xc00ULL

static VOID note(const char *s) {
    for (; *s; ++s)
        __asm__ volatile("outb %0,$0xe9" :: "a"((UINT8)*s));
}
static VOID field(const char *name, UINT64 value) {
    note(name);
    for (int shift=60; shift>=0; shift-=4) {
        UINT8 digit=(UINT8)"0123456789abcdef"[(value>>shift)&15];
        __asm__ volatile("outb %0,$0xe9" :: "a"(digit));
    }
}
static VOID cpuid(UINT32 leaf, UINT32 subleaf, UINT32 *a, UINT32 *b,
                  UINT32 *c, UINT32 *d) {
    __asm__ volatile("cpuid":"=a"(*a),"=b"(*b),"=c"(*c),"=d"(*d)
                     :"a"(leaf),"c"(subleaf));
}
static UINT64 rdmsr(UINT32 reg) {
    UINT32 lo,hi;
    __asm__ volatile("rdmsr":"=a"(lo),"=d"(hi):"c"(reg):"memory");
    return ((UINT64)hi<<32)|lo;
}
static VOID wrmsr(UINT32 reg, UINT64 value) {
    __asm__ volatile("wrmsr"::"c"(reg),"a"((UINT32)value),
                     "d"((UINT32)(value>>32)):"memory");
}
typedef struct {
    UINTN index;
    UINT64 expected;
    BOOLEAN ok;
} ProbeContext;

static VOID EFIAPI probe_cpu(VOID *argument) {
    ProbeContext *ctx=argument;
    UINT32 a,b,c,d,max,unused1,unused2,unused3;
    cpuid(0,0,&max,&unused1,&unused2,&unused3);
    cpuid(1,0,&a,&b,&c,&d);
    note("CPU CPUID"); field(" INDEX=",ctx->index); field(" MAX=",max);
    field(" EAX=",a); field(" EBX=",b); field(" ECX=",c); field(" EDX=",d); note("\n");
    if (max>=0xb) {
        UINT32 ta,tb,tc,td;
        cpuid(0xb,0,&ta,&tb,&tc,&td);
        note("CPU TOPOLOGY"); field(" INDEX=",ctx->index);
        field(" EAX=",ta); field(" EBX=",tb); field(" ECX=",tc); field(" EDX=",td); note("\n");
    }
    if (!(c&(1u<<21)) || !(d&(1u<<9)) || !(d&(1u<<5))) return;
    UINT64 flags;
    __asm__ volatile("pushfq; popq %0; cli":"=r"(flags)::"memory");
    UINT64 before=rdmsr(APIC_BASE);
    note("CPU BEFORE"); field(" INDEX=",ctx->index); field(" BASE=",before); note("\n");
    if ((before&APIC_MODE)==XAPIC) {
        note("CPU ENABLE X2APIC"); field(" INDEX=",ctx->index); note("\n");
        wrmsr(APIC_BASE,before|0x400);
    }
    UINT64 active=rdmsr(APIC_BASE), id=~0ULL;
    if ((active&APIC_MODE)==X2APIC) id=rdmsr(X2_ID);
    note("CPU ACTIVE"); field(" INDEX=",ctx->index); field(" BASE=",active);
    field(" ID=",id); note("\n");
    if ((before&APIC_MODE)==XAPIC && (active&APIC_MODE)==X2APIC) {
        // The direct x2APIC -> xAPIC transition is architecturally invalid.
        wrmsr(APIC_BASE,before&~APIC_MODE);
        wrmsr(APIC_BASE,before);
    }
    UINT64 after=rdmsr(APIC_BASE);
    note("CPU RESTORED"); field(" INDEX=",ctx->index); field(" BASE=",after); note("\n");
    ctx->ok=(active&APIC_MODE)==X2APIC && id==ctx->expected && after==before;
    if (flags&0x200) __asm__ volatile("sti":::"memory");
}

static EFI_STATUS security_value(CHAR16 *name, UINT8 *value) {
    EFI_GUID global=EFI_GLOBAL_VARIABLE;
    UINTN bytes=1;
    EFI_STATUS status=RT->GetVariable(name,&global,NULL,&bytes,value);
    if (EFI_ERROR(status)) return status;
    return bytes==1?EFI_SUCCESS:EFI_COMPROMISED_DATA;
}

static EFI_STATUS inspect(EFI_SYSTEM_TABLE *table) {
    note("TABLES"); field(" ST=",(UINTN)table); note("\n");
    UINT8 secure=0xff,setup=0xff;
    EFI_STATUS secure_status=security_value(L"SecureBoot",&secure);
    EFI_STATUS setup_status=security_value(L"SetupMode",&setup);
    note("SECURITY"); field(" SECURE=",secure); field(" SETUP=",setup);
    field(" SECURE_STATUS=",secure_status); field(" SETUP_STATUS=",setup_status); note("\n");
    if (EFI_ERROR(secure_status) || EFI_ERROR(setup_status) || secure!=1 || setup!=0)
        return EFI_SECURITY_VIOLATION;
    EFI_GUID guid={0x3fdda605,0xa76e,0x4f46,{0xad,0x29,0x12,0xf4,0x53,0x1b,0x3d,0x08}};
    Mp *mp=NULL;
    EFI_STATUS status=BS->LocateProtocol(&guid,NULL,(VOID **)&mp);
    note("MP LOCATE"); field(" STATUS=",status); note("\n");
    if (EFI_ERROR(status)) return status;
    UINTN total=0,enabled=0,bsp=~(UINTN)0;
    status=mp->count(mp,&total,&enabled);
    note("MP COUNT"); field(" STATUS=",status); field(" TOTAL=",total);
    field(" ENABLED=",enabled); note("\n");
    if (EFI_ERROR(status)) return status;
    status=mp->who(mp,&bsp);
    note("MP WHO"); field(" STATUS=",status); field(" BSP=",bsp); note("\n");
    if (EFI_ERROR(status)) return status;
    if (!total || total>1024 || bsp>=total) return EFI_COMPROMISED_DATA;
    // Enumerate firmware's actual records, including disabled ones.
    for (UINTN i=0; i<total; ++i) {
        ProcessorInfo info={0};
        status=mp->info(mp,i,&info);
        note("MP INFO"); field(" INDEX=",i); field(" STATUS=",status);
        field(" ID=",info.id); field(" FLAGS=",info.flags);
        field(" PACKAGE=",info.package); field(" CORE=",info.core);
        field(" THREAD=",info.thread); note("\n");
        if (EFI_ERROR(status)) return status;
    }
    if (enabled!=2) return EFI_COMPROMISED_DATA;
    UINTN measured=0;
    BOOLEAN all_ok=TRUE;
    for (UINTN i=0; i<total; ++i) {
        ProcessorInfo info={0};
        status=mp->info(mp,i,&info);
        if (EFI_ERROR(status)) return status;
        if (!(info.flags&2)) continue;
        if (++measured>enabled) return EFI_COMPROMISED_DATA;
        ProbeContext ctx={i,info.id,FALSE};
        if (i==bsp) {
            probe_cpu(&ctx);
        } else {
            status=mp->startup_one(mp,probe_cpu,i,NULL,5000000,&ctx,NULL);
            note("MP STARTUP"); field(" INDEX=",i); field(" STATUS=",status); note("\n");
            if (EFI_ERROR(status)) return status;
        }
        if (!ctx.ok) all_ok=FALSE;
    }
    return all_ok && measured==enabled?EFI_SUCCESS:EFI_COMPROMISED_DATA;
}
EFI_STATUS efi_main(EFI_HANDLE image, EFI_SYSTEM_TABLE *table) {
    InitializeLib(image,table);
    EFI_STATUS status=inspect(table);
    note("END"); field(" STATUS=",status); note("\n");
    // Keep the live firmware tables and the completed observation stable
    // until the host has captured them. Do not boot a product or OS.
    for (;;) __asm__ volatile("pause");
}
