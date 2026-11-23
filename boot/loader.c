#include <efi.h>
#include <efilib.h>
#include <elf.h>

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

// Stage 1 link script produces exactly one aligned, executable load segment.
static EFI_STATUS load_kernel(UINT64 *entry) {
    UINTN n = elf_end - elf_start;
    Elf64_Ehdr *e = (void *)elf_start;
    if (n < sizeof(*e) || CompareMem(e->e_ident, ELFMAG, SELFMAG) ||
        e->e_ident[EI_CLASS] != ELFCLASS64 || e->e_ident[EI_DATA] != ELFDATA2LSB ||
        e->e_machine != EM_X86_64 || e->e_type != ET_EXEC || e->e_phnum != 1 ||
        e->e_phentsize != sizeof(Elf64_Phdr) || e->e_phoff > n - sizeof(Elf64_Phdr))
        return EFI_LOAD_ERROR;
    Elf64_Phdr *p = (void *)(elf_start + e->e_phoff);
    if (p->p_type != PT_LOAD || p->p_flags != (PF_R|PF_X) ||
        p->p_paddr != 0x02000000 || p->p_paddr != p->p_vaddr ||
        p->p_offset > n || p->p_filesz > n-p->p_offset ||
        p->p_filesz > p->p_memsz || p->p_memsz > 16*1024*1024 ||
        e->e_entry < p->p_vaddr || e->e_entry-p->p_vaddr >= p->p_filesz)
        return EFI_LOAD_ERROR;
    EFI_PHYSICAL_ADDRESS address = p->p_paddr;
    EFI_STATUS s = BS->AllocatePages(AllocateAddress, EfiLoaderCode,
                                     EFI_SIZE_TO_PAGES(p->p_memsz), &address);
    if (EFI_ERROR(s)) return s;
    SetMem((void *)address, p->p_memsz, 0);
    CopyMem((void *)address, elf_start+p->p_offset, p->p_filesz);
    *entry = e->e_entry;
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

static BootInfo info = {.version = 3};

EFI_STATUS efi_main(EFI_HANDLE image, EFI_SYSTEM_TABLE *table) {
    InitializeLib(image, table);
    if (!flag(L"SecureBoot", 1) || !flag(L"SetupMode", 0)) return EFI_SECURITY_VIOLATION;
    EFI_GRAPHICS_OUTPUT_PROTOCOL *gop;
    EFI_STATUS s = BS->LocateProtocol(&GraphicsOutputProtocol, NULL, (void **)&gop);
    if (EFI_ERROR(s)) return s;
    EFI_GRAPHICS_OUTPUT_MODE_INFORMATION *mode = gop->Mode->Info;
    info.fb = gop->Mode->FrameBufferBase;
    info.width = mode->HorizontalResolution;
    info.height = mode->VerticalResolution;
    info.stride = mode->PixelsPerScanLine;
    info.format = mode->PixelFormat;
    if (!info.fb || info.width < 200 || info.height < 64 || info.format > 1 ||
        info.stride < info.width || (UINT64)info.stride*info.height > gop->Mode->FrameBufferSize/4)
        return EFI_UNSUPPORTED;
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
    s=load_kernel(&entry);
    if (EFI_ERROR(s)) return s;
    if ((info.log_level & LOG_SERIAL) && (info.log_level & 3)) Print(L"[INFO] KERNEL ELF LOADED\r\n");
    s=BS->AllocatePages(AllocateAnyPages, EfiLoaderData, 8, &info.stack_base);
    if (EFI_ERROR(s)) return s;
    // SIPI vector names a 4 KiB page below 1 MiB. Reserve its mailbox too.
    info.ap_boot = 0x9ffff;
    s=BS->AllocatePages(AllocateMaxAddress, EfiLoaderData, 2, &info.ap_boot);
    if (EFI_ERROR(s) || info.ap_boot < EFI_PAGE_SIZE) return EFI_OUT_OF_RESOURCES;
    UINTN capacity=0, key=0;
    UINT32 version;
    s = BS->GetMemoryMap(&capacity, NULL, &key, &info.desc, &version);
    if (s != EFI_BUFFER_TOO_SMALL) return EFI_LOAD_ERROR;
    capacity += 32*info.desc;
    s=BS->AllocatePool(EfiLoaderData, capacity, (void **)&info.map);
    if (EFI_ERROR(s)) return s;
    for (UINTN attempt=0; attempt<8; attempt++) {
        info.size=capacity;
        s=BS->GetMemoryMap(&info.size, (void *)info.map, &key, &info.desc, &version);
        if (EFI_ERROR(s)) return s;
        info.desc_version=version;
        s=BS->ExitBootServices(image,key);
        if (s == EFI_INVALID_PARAMETER) continue;
        if (EFI_ERROR(s)) return s;
        __asm__ volatile("cli; cld; mov %0, %%rsp; call *%1; ud2"
                         :: "r"(info.stack_base+8*4096), "r"(entry), "D"(&info) : "memory");
        __builtin_unreachable();
    }
    return EFI_ABORTED;
}
