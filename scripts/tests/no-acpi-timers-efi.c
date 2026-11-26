/*
 * Isolated QEMU q35/OVMF platform fixture. NOT part of AgentOS, its
 * production EFI, or initramfs. Both this application and the unchanged
 * AgentOS EFI are independently authenticated by the isolated test db.
 *
 * Preserve the firmware's working PM timer until ExitBootServices (OVMF
 * AcpiTimerLib needs it). Publish valid replacement ACPI roots with an
 * optional PM_TMR absent; disable q35 ICH9 PM I/O decode on successful
 * EBS notification. No production code or CPUID is patched.
 */
#include <efi.h>
#include <efilib.h>
#include <stdint.h>

#define LIMIT 0x100000u
#define HEADER 36u
#define MAX_ROOTS 2u
#define LPC_CFG 0x8000f800u
#define ICH9_ID 0x29188086u
#define PMBASE_MASK 0xff80u
#define ACPI_EN 0x80u

static uint32_t original_port;
static EFI_SYSTEM_TABLE *system_table;

static void out8(uint16_t port, uint8_t value) {
    __asm__ volatile("outb %0,%1" :: "a"(value), "Nd"(port));
}
static void out32(uint16_t port, uint32_t value) {
    __asm__ volatile("outl %0,%1" :: "a"(value), "Nd"(port));
}
static uint32_t in32(uint16_t port) {
    uint32_t value;
    __asm__ volatile("inl %1,%0" : "=a"(value) : "Nd"(port));
    return value;
}
static void note(const char *s) {
    for (; *s; ++s) out8(0xe9, (uint8_t)*s);
}
static void hex(uint64_t value) {
    for (int shift=60; shift>=0; shift-=4)
        out8(0xe9, (uint8_t)"0123456789abcdef"[(value>>shift)&15]);
}
static void field(const char *name, uint64_t value) { note(name); hex(value); }
static uint32_t le32(const uint8_t *p) {
    return (uint32_t)p[0] | (uint32_t)p[1]<<8 | (uint32_t)p[2]<<16 | (uint32_t)p[3]<<24;
}
static uint64_t le64(const uint8_t *p) { return le32(p) | (uint64_t)le32(p+4)<<32; }
static void store(uint8_t *p, uint64_t value, UINTN bytes) {
    for (UINTN i=0; i<bytes; ++i) p[i]=(uint8_t)(value>>(8*i));
}
static uint8_t checksum(const uint8_t *p, UINTN bytes) {
    uint8_t result=0;
    for (UINTN i=0; i<bytes; ++i) result=(uint8_t)(result+p[i]);
    return result;
}
static void fix_checksum(uint8_t *p, UINTN bytes, UINTN offset) {
    p[offset]=0;
    p[offset]=(uint8_t)(0-checksum(p,bytes));
}
static BOOLEAN signature(const uint8_t *p, const char *s, UINTN bytes) {
    return CompareMem((VOID *)p,(VOID *)s,bytes)==0;
}
static BOOLEAN range(uint64_t address, UINTN bytes) {
    return address>=4096 && address<0x100000000ULL && bytes &&
           bytes<=LIMIT && address+bytes<=0x100000000ULL;
}
static UINTN table_size(const uint8_t *p) {
    if (!range((UINTN)p,HEADER)) return 0;
    UINTN n=le32(p+4);
    return n>=HEADER && range((UINTN)p,n) && !checksum(p,n) ? n : 0;
}
static uint8_t *clone(const uint8_t *p, UINTN bytes) {
    EFI_PHYSICAL_ADDRESS address=0xffffffffu;
    if (!range((UINTN)p,bytes) ||
        EFI_ERROR(BS->AllocatePages(AllocateMaxAddress,EfiACPIReclaimMemory,
                                    (bytes+4095)/4096,&address))) return NULL;
    uint8_t *copy=(uint8_t *)(UINTN)address;
    CopyMem(copy,(VOID *)p,bytes);
    return copy;
}

/* Do not alter the existing firmware tables in place. All addresses,
 * checksums and the root list are validated before replacement. The
 * original FADT is retained for OVMF; both OS-facing roots use a copy. */
static uint8_t *replace_root(uint64_t address, UINTN width) {
    if (!range(address,HEADER)) return NULL;
    const uint8_t *root=(const uint8_t *)(UINTN)address;
    UINTN size=table_size(root);
    if (!size || !signature(root,width==8?"XSDT":"RSDT",4) ||
        (size-HEADER)%width) return NULL;
    uint8_t *copy=clone(root,size);
    if (!copy) return NULL;
    UINTN fadt_count=0, madt_count=0;
    for (UINTN offset=HEADER; offset<size; offset+=width) {
        uint64_t child=width==8?le64(root+offset):le32(root+offset);
        if (!range(child,HEADER)) return NULL;
        const uint8_t *table=(const uint8_t *)(UINTN)child;
        UINTN n=table_size(table);
        if (!n || signature(table,"HPET",4)) return NULL;
        if (signature(table,"APIC",4)) {
            if (++madt_count!=1 || n<44 || !(le32(table+40)&1)) return NULL;
        }
        if (!signature(table,"FACP",4)) continue;
        if (++fadt_count!=1 || n<116 || (le32(table+112)&(1u<<20))) return NULL;
        uint32_t legacy=le32(table+76);
        if (legacy!=original_port || table[91]!=4) return NULL;
        if (n>=220) {
            const uint8_t *gas=table+208;
            if (le64(gas+4) && (gas[0]!=1 || le64(gas+4)!=original_port)) return NULL;
        }
        uint8_t *fadt=clone(table,n);
        if (!fadt) return NULL;
        store(fadt+76,0,4);
        fadt[91]=0;
        store(fadt+112,le32(fadt+112)&~((1u<<8)|(1u<<15)),4);
        if (n>=220) store(fadt+208,0,8), store(fadt+216,0,4);
        else if (n>208) return NULL;
        fix_checksum(fadt,n,9);
        store(copy+offset,(UINTN)fadt,width);
    }
    if (fadt_count!=1 || madt_count!=1) return NULL;
    fix_checksum(copy,size,9);
    return copy;
}

static uint8_t *replace_rsdp(const uint8_t *old, BOOLEAN extended) {
    if (!range((UINTN)old,20) || !signature(old,"RSD PTR ",8) || checksum(old,20)) return NULL;
    UINTN size=20;
    if (extended || old[15]>=2) {
        if (!range((UINTN)old,36) || old[15]<2) return NULL;
        size=le32(old+20);
        if (size<36 || !range((UINTN)old,size) || checksum(old,size)) return NULL;
    }
    uint8_t *copy=clone(old,size);
    if (!copy) return NULL;
    if (le32(old+16)) {
        uint8_t *root=replace_root(le32(old+16),4);
        if (!root) return NULL;
        store(copy+16,(UINTN)root,4);
    } else if (size==20) return NULL;
    if (size>=36) {
        uint8_t *root=replace_root(le64(old+24),8);
        if (!root) return NULL;
        store(copy+24,(UINTN)root,8);
    }
    fix_checksum(copy,20,8);
    if (size>=36) fix_checksum(copy,size,32);
    return copy;
}

static uint32_t config(uint32_t offset) {
    out32(0xcf8,LPC_CFG|offset);
    return in32(0xcfc);
}

/* Standard EBS event: OVMF has terminated memory services and stopped its
 * boot timer. No allocation or firmware calls here. This disables the
 * entire ICH9 PM I/O bank, not just the PM timer. The test is expressly
 * not evidence for ACPI power-management functions. */
static VOID EFIAPI disable_pm(EFI_EVENT event, VOID *context) {
    (void)event; (void)context;
    uint32_t previous=in32(0xcf8);
    uint32_t id=config(0);
    uint32_t base=config(0x40)&PMBASE_MASK;
    uint32_t before=config(0x44);
    if (id==ICH9_ID && base+8==original_port && (before&ACPI_EN)) {
        out8(0xcfc,(uint8_t)(before&~ACPI_EN));
    }
    uint32_t after=config(0x44);
    out32(0xcf8,previous);
    note("FIXTURE EBS");
    field(" ST=",(UINTN)system_table); field(" PMPORT=",original_port);
    field(" LPC=",id); field(" PMBASE=",base);
    field(" CTRL_BEFORE=",before); field(" CTRL_AFTER=",after);
    field(" PORT_AFTER=",in32((uint16_t)original_port)); note("\n");
}
static BOOLEAN variable_is(CHAR16 *name, uint8_t expected) {
    EFI_GUID global=EFI_GLOBAL_VARIABLE;
    UINTN bytes=1;
    uint8_t value=0xff;
    return RT->GetVariable(name,&global,NULL,&bytes,&value)==EFI_SUCCESS &&
           bytes==1 && value==expected;
}
static BOOLEAN invariant_tsc(void) {
    uint32_t a,b,c,d;
    __asm__ volatile("cpuid":"=a"(a),"=b"(b),"=c"(c),"=d"(d):"a"(0x80000000u),"c"(0));
    if (a<0x80000007u) return FALSE;
    __asm__ volatile("cpuid":"=a"(a),"=b"(b),"=c"(c),"=d"(d):"a"(0x80000007u),"c"(0));
    return !!(d&(1u<<8));
}

EFI_STATUS efi_main(EFI_HANDLE image, EFI_SYSTEM_TABLE *table) {
    InitializeLib(image,table);
    system_table=table;
    note("FIXTURE ENTRY\n");
    if (!variable_is(L"SecureBoot",1) || !variable_is(L"SetupMode",0))
        return EFI_SECURITY_VIOLATION;
    uint32_t previous=in32(0xcf8);
    uint32_t id=config(0);
    uint32_t base=config(0x40)&PMBASE_MASK;
    uint32_t control=config(0x44);
    out32(0xcf8,previous);
    if (id!=ICH9_ID || !base || !(control&ACPI_EN)) return EFI_UNSUPPORTED;
    original_port=base+8;
    EFI_GUID acpi20=ACPI_20_TABLE_GUID;
    EFI_GUID acpi10=ACPI_TABLE_GUID;
    uint8_t *copies[MAX_ROOTS]={NULL,NULL};
    UINTN count=0;
    for (UINTN i=0; i<table->NumberOfTableEntries; ++i) {
        EFI_CONFIGURATION_TABLE *entry=&table->ConfigurationTable[i];
        int index=!CompareGuid(&entry->VendorGuid,&acpi20)?0:
                  (!CompareGuid(&entry->VendorGuid,&acpi10)?1:-1);
        if (index<0) continue;
        if (copies[index]) return EFI_COMPROMISED_DATA;
        copies[index]=replace_rsdp(entry->VendorTable,index==0);
        if (!copies[index]) return EFI_COMPROMISED_DATA;
        ++count;
    }
    if (!copies[0] || !count) return EFI_NOT_FOUND;
    EFI_STATUS status=BS->InstallConfigurationTable(&acpi20,copies[0]);
    if (EFI_ERROR(status)) return status;
    if (copies[1]) {
        status=BS->InstallConfigurationTable(&acpi10,copies[1]);
        if (EFI_ERROR(status)) return status;
    }
    note("FIXTURE PREPARED");
    field(" ST=",(UINTN)table); field(" PMPORT=",original_port);
    field(" RSDP20=",(UINTN)copies[0]); field(" RSDP10=",(UINTN)copies[1]);
    field(" INVTSC=",invariant_tsc()); note("\n");

    EFI_EVENT ebs;
    status=BS->CreateEvent(EVT_SIGNAL_EXIT_BOOT_SERVICES,TPL_NOTIFY,disable_pm,NULL,&ebs);
    if (EFI_ERROR(status)) return status;
    EFI_LOADED_IMAGE *loaded;
    status=BS->HandleProtocol(image,&LoadedImageProtocol,(VOID **)&loaded);
    if (EFI_ERROR(status)) return status;
    EFI_DEVICE_PATH *path=FileDevicePath(loaded->DeviceHandle,L"\\EFI\\BOOT\\AGENTOS.EFI");
    if (!path) return EFI_OUT_OF_RESOURCES;
    EFI_HANDLE child;
    status=BS->LoadImage(FALSE,image,path,NULL,0,&child);
    if (EFI_ERROR(status)) { note("FIXTURE LOAD ERROR="); hex(status); note("\n"); return status; }
    note("FIXTURE VERIFIED LOAD\n");
    status=BS->StartImage(child,NULL,NULL);
    note("FIXTURE CHILD RETURN="); hex(status); note("\n");
    return EFI_ERROR(status)?status:EFI_ABORTED;
}
