#include <efi.h>
#include <efilib.h>
#include <elf.h>
#include "gop-select.h"
#include "boot-map.h"
#include "kernel-elf.h"

extern UINT8 elf_start[], elf_end[], archive_start[], archive_end[];
typedef struct {
    UINT64 version, fb;
    UINT32 width, height, stride, format;
    UINT64 map, size, desc, desc_version, rsdp, archive, archive_size;
    UINT64 image_base, image_size, stack_base, ap_boot;
    UINT64 log_level;
} BootInfo;

static BOOLEAN flag(CHAR16 *name, UINT8 expected) {
    EFI_GUID global = EFI_GLOBAL_VARIABLE;
    UINT8 value = 0xff;
    UINTN n = sizeof(value);
    return RT->GetVariable(name, &global, NULL, &n, &value) == EFI_SUCCESS &&
           n == 1 && value == expected;
}

// Load the signed, self-contained static PIE into any suitable available
// identity-mapped memory below the user PML4 slot. No preferred physical
// address, external dynamic linker or writable executable segment in ELF.
static EFI_STATUS load_kernel(UINT64 *entry, EFI_PHYSICAL_ADDRESS *base, UINTN *pages) {
    size_t length = elf_end - elf_start;
    KernelElf elf;
    if (!kernel_elf_parse(elf_start, length, &elf)) return EFI_LOAD_ERROR;
    UINTN count = elf.size / KERNEL_PAGE;
    EFI_PHYSICAL_ADDRESS address = KERNEL_LIMIT - 1;
    EFI_STATUS status = BS->AllocatePages(AllocateMaxAddress, EfiLoaderCode, count, &address);
    if (EFI_ERROR(status)) return status;
    uint64_t relocated_entry;
    if (!kernel_elf_load(elf_start, length, (void *)(UINTN)address, address,
                         elf.size, &relocated_entry)) {
        BS->FreePages(address, count);
        return EFI_LOAD_ERROR;
    }
    *entry = relocated_entry;
    *base = address;
    *pages = count;
    return EFI_SUCCESS;
}

// EFI/BOOT/BOOT.LOG configures structured boot diagnostics.
// Accepted values (case-sensitive): quiet|info|debug, optionally followed
// by a space and serial|screen|both|none. Missing/invalid -> info both.
// Bits 0..1: level, bit 8: serial, bit 9: framebuffer.
// Raw acceptance markers and fatal crash diagnostics remain on COM1.
#define LOG_SERIAL 0x100
#define LOG_SCREEN 0x200
static UINT64 boot_log_level(EFI_HANDLE device) {
    EFI_FILE_HANDLE root = LibOpenRoot(device), file;
    if (!root) return 1 | LOG_SERIAL | LOG_SCREEN;
    EFI_STATUS s = root->Open(root, &file, L"\\EFI\\BOOT\\BOOT.LOG", EFI_FILE_MODE_READ, 0);
    root->Close(root);
    if (EFI_ERROR(s)) return 1 | LOG_SERIAL | LOG_SCREEN;
    CHAR8 value[32];
    UINTN n = sizeof(value);
    s = file->Read(file, &n, value);
    file->Close(file);
    if (EFI_ERROR(s) || n == sizeof(value)) return 1 | LOG_SERIAL | LOG_SCREEN;
    while (n && (value[n-1]=='\r' || value[n-1]=='\n' || value[n-1]==' ')) --n;
    UINTN split = 0;
    while (split < n && value[split] != ' ') ++split;
    UINT64 level;
    if (split == 5 && !CompareMem(value, "quiet", 5)) level = 0;
    else if (split == 4 && !CompareMem(value, "info", 4)) level = 1;
    else if (split == 5 && !CompareMem(value, "debug", 5)) level = 2;
    else return 1 | LOG_SERIAL | LOG_SCREEN;
    if (split == n) return level | LOG_SERIAL | LOG_SCREEN;
    UINTN offset = split + 1, size = n - offset;
    if (size == 6 && !CompareMem(value+offset, "serial", 6)) return level | LOG_SERIAL;
    if (size == 6 && !CompareMem(value+offset, "screen", 6)) return level | LOG_SCREEN;
    if (size == 4 && !CompareMem(value+offset, "both", 4)) return level | LOG_SERIAL | LOG_SCREEN;
    if (size == 4 && !CompareMem(value+offset, "none", 4)) return level;
    return 1 | LOG_SERIAL | LOG_SCREEN;
}

static GopMode gop_mode(const EFI_GRAPHICS_OUTPUT_MODE_INFORMATION *mode) {
    return (GopMode){mode->HorizontalResolution, mode->VerticalResolution,
        mode->PixelsPerScanLine, mode->PixelFormat, mode->PixelInformation.RedMask,
        mode->PixelInformation.GreenMask, mode->PixelInformation.BlueMask,
        mode->PixelInformation.ReservedMask};
}

static int gop_current(void *context, GopFramebuffer *out) {
    EFI_GRAPHICS_OUTPUT_PROTOCOL *gop = context;
    if (!gop->Mode || !gop->Mode->Info ||
        gop->Mode->SizeOfInfo < sizeof(EFI_GRAPHICS_OUTPUT_MODE_INFORMATION) ||
        gop->Mode->Mode >= gop->Mode->MaxMode) return 0;
    *out = (GopFramebuffer){gop_mode(gop->Mode->Info),
        gop->Mode->FrameBufferBase, gop->Mode->FrameBufferSize};
    return 1;
}

static int gop_query(void *context, uint32_t index, GopMode *out) {
    EFI_GRAPHICS_OUTPUT_PROTOCOL *gop = context;
    EFI_GRAPHICS_OUTPUT_MODE_INFORMATION *mode = NULL;
    UINTN size = 0;
    EFI_STATUS status = gop->QueryMode(gop, index, &size, &mode);
    if (EFI_ERROR(status)) return status == EFI_NOT_STARTED ?
        GOP_QUERY_NOT_STARTED : GOP_QUERY_FAILED;
    int valid = mode && size >= sizeof(*mode);
    if (valid) *out = gop_mode(mode);
    if (mode) BS->FreePool(mode);
    return valid ? GOP_QUERY_OK : GOP_QUERY_FAILED;
}

static int gop_activate(void *context, uint32_t index) {
    EFI_GRAPHICS_OUTPUT_PROTOCOL *gop = context;
    return !EFI_ERROR(gop->SetMode(gop, index));
}

// Identity-mapped loader-owned data must stay out of the user PML4
// slot beginning at 512 GiB. This is a kernel VA-layout constraint, not
// a machine-specific memory address.
#define BOOT_DATA_LIMIT ((UINT64_C(1) << 39) - 1)

static BootMapResult firmware_map_read(void *context, void *buffer, size_t *size,
                                       size_t *key, size_t *descriptor, uint32_t *version) {
    (void)context;
    UINTN n = *size, map_key = 0, stride = 0;
    UINT32 revision = 0;
    EFI_STATUS status = BS->GetMemoryMap(&n, buffer, &map_key, &stride, &revision);
    *size = n;
    *key = map_key;
    *descriptor = stride;
    *version = revision;
    if (status == EFI_SUCCESS) return BOOT_MAP_OK;
    if (status == EFI_BUFFER_TOO_SMALL) return BOOT_MAP_GROW;
    return BOOT_MAP_ERROR;
}

static EFI_STATUS allocate_data_pages(UINTN pages, EFI_PHYSICAL_ADDRESS limit,
                                      EFI_PHYSICAL_ADDRESS *base) {
    EFI_PHYSICAL_ADDRESS address = limit;
    EFI_STATUS status = BS->AllocatePages(AllocateMaxAddress, EfiLoaderData, pages, &address);
    if (EFI_ERROR(status)) return status;
    // Free even an unusable allocation before returning an error.
    if (address < EFI_PAGE_SIZE || address % EFI_PAGE_SIZE || address > limit ||
        pages > (limit - address + 1) / EFI_PAGE_SIZE) {
        BS->FreePages(address, pages);
        return EFI_LOAD_ERROR;
    }
    *base = address;
    return EFI_SUCCESS;
}

static BootMapResult firmware_map_allocate(void *context, size_t capacity, void **buffer) {
    (void)context;
    EFI_PHYSICAL_ADDRESS address;
    EFI_STATUS status = allocate_data_pages(capacity / EFI_PAGE_SIZE, BOOT_DATA_LIMIT, &address);
    if (status == EFI_OUT_OF_RESOURCES) return BOOT_MAP_NO_MEMORY;
    if (EFI_ERROR(status)) return BOOT_MAP_ERROR;
    *buffer = (void *)(UINTN)address;
    return BOOT_MAP_OK;
}

static BootMapResult firmware_map_release(void *context, void *buffer, size_t capacity) {
    (void)context;
    return BS->FreePages((UINTN)buffer, capacity / EFI_PAGE_SIZE) == EFI_SUCCESS ?
        BOOT_MAP_OK : BOOT_MAP_ERROR;
}

static BootMapResult firmware_exit_services(void *context, size_t key) {
    EFI_STATUS status = BS->ExitBootServices((EFI_HANDLE)context, key);
    if (status == EFI_SUCCESS) return BOOT_MAP_OK;
    if (status == EFI_INVALID_PARAMETER) return BOOT_MAP_STALE;
    return BOOT_MAP_ERROR;
}

// A failed ExitBootServices may already have partially shut down firmware.
// Do not return to the boot manager or use firmware consoles in that state.
static __attribute__((noreturn)) void halt_failed_handoff(void) {
    __asm__ volatile("cli" ::: "memory");
    for (;;) __asm__ volatile("hlt" ::: "memory");
}

static BootInfo info = {.version = 3};

EFI_STATUS efi_main(EFI_HANDLE image, EFI_SYSTEM_TABLE *table) {
    InitializeLib(image, table);
    if (!flag(L"SecureBoot", 1) || !flag(L"SetupMode", 0)) return EFI_SECURITY_VIOLATION;
    EFI_GRAPHICS_OUTPUT_PROTOCOL *gop;
    EFI_STATUS s = BS->LocateProtocol(&GraphicsOutputProtocol, NULL, (void **)&gop);
    if (EFI_ERROR(s)) return s;
    if (!gop || !gop->Mode || !gop->QueryMode || !gop->SetMode) return EFI_UNSUPPORTED;
    GopAccess access = {gop, gop->Mode->MaxMode, gop_current, gop_query, gop_activate};
    GopFramebuffer framebuffer;
    if (!gop_select(&access, &framebuffer)) return EFI_UNSUPPORTED;
    info.fb = framebuffer.base;
    info.width = framebuffer.mode.width;
    info.height = framebuffer.mode.height;
    info.stride = framebuffer.mode.stride;
    info.format = framebuffer.mode.format;
    EFI_LOADED_IMAGE *loaded;
    s = BS->HandleProtocol(image, &LoadedImageProtocol, (void **)&loaded);
    if (EFI_ERROR(s)) return s;
    info.log_level = boot_log_level(loaded->DeviceHandle);
    if ((info.log_level & LOG_SCREEN) && (info.log_level & 3)) Print(L"[INFO] UEFI SECURE BOOT ACTIVE\r\n");
    info.image_base = (UINTN)loaded->ImageBase;
    info.image_size = loaded->ImageSize;
    info.archive = (UINTN)archive_start;
    info.archive_size = archive_end-archive_start;
    EFI_GUID acpi = ACPI_20_TABLE_GUID;
    for (UINTN i=0; i<table->NumberOfTableEntries; i++)
        if (!CompareGuid(&table->ConfigurationTable[i].VendorGuid, &acpi))
            info.rsdp = (UINTN)table->ConfigurationTable[i].VendorTable;
    UINT64 entry;
    EFI_PHYSICAL_ADDRESS kernel_base = 0, stack_base = 0, ap_base = 0;
    UINTN kernel_pages = 0;
    BootMap map = {0};
    BootMapAccess access_map = {image, firmware_map_read, firmware_map_allocate,
                                firmware_map_release, firmware_exit_services};
    s = load_kernel(&entry, &kernel_base, &kernel_pages);
    if (EFI_ERROR(s)) return s;
    if ((info.log_level & LOG_SERIAL) && (info.log_level & 3)) Print(L"[INFO] KERNEL ELF LOADED\r\n");
    s = allocate_data_pages(8, BOOT_DATA_LIMIT, &stack_base);
    if (EFI_ERROR(s)) goto fail;
    info.stack_base = stack_base;
    // Both the SIPI page and its mailbox must fit below 1 MiB.
    s = allocate_data_pages(2, 0xfffff, &ap_base);
    if (EFI_ERROR(s)) goto fail;
    info.ap_boot = ap_base;

    BootMapResult result = boot_map_capture(&access_map, &map);
    if (result != BOOT_MAP_OK) {
        if (map.exit_attempted) halt_failed_handoff();
        s = result == BOOT_MAP_NO_MEMORY ? EFI_OUT_OF_RESOURCES :
            result == BOOT_MAP_LIMIT ? EFI_ABORTED : EFI_LOAD_ERROR;
        goto fail;
    }
    // Boot services are gone. Publish only the successful final snapshot.
    info.map = (UINTN)map.buffer;
    info.size = map.size;
    info.desc = map.descriptor_size;
    info.desc_version = map.version;
    __asm__ volatile("cli; cld; mov %0, %%rsp; call *%1; ud2"
                     :: "r"(info.stack_base+8*4096), "r"(entry), "D"(&info) : "memory");
    __builtin_unreachable();

fail:
    // Only reached before the first ExitBootServices call.
    boot_map_release(&access_map, &map);
    if (ap_base) BS->FreePages(ap_base, 2);
    if (stack_base) BS->FreePages(stack_base, 8);
    BS->FreePages(kernel_base, kernel_pages);
    return s;
}
