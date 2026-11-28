#ifndef AGENTOS_BOOT_MAP_H
#define AGENTOS_BOOT_MAP_H

#include <stddef.h>
#include <stdint.h>

#define BOOT_PAGE_SIZE 4096u
#define BOOT_DESCRIPTOR_MIN 40u
#define BOOT_MAP_READ_LIMIT 32u
#define BOOT_EXIT_LIMIT 8u

typedef enum {
    BOOT_MAP_OK, BOOT_MAP_GROW, BOOT_MAP_STALE, BOOT_MAP_ERROR,
    BOOT_MAP_NO_MEMORY, BOOT_MAP_INVALID, BOOT_MAP_LIMIT
} BootMapResult;

typedef struct {
    void *buffer;
    size_t capacity, size, descriptor_size;
    uint32_t version;
    int exit_attempted;
} BootMap;

typedef struct {
    void *context;
    BootMapResult (*read)(void *, void *, size_t *, size_t *, size_t *, uint32_t *);
    BootMapResult (*allocate)(void *, size_t, void **);
    BootMapResult (*release)(void *, void *, size_t);
    BootMapResult (*exit_services)(void *, size_t);
} BootMapAccess;

// Size includes headroom for descriptor changes caused by allocation itself.
// The caller allocates whole pages, and all arithmetic is checked.
static size_t boot_map_capacity(size_t needed) {
    size_t slack = needed / 4;
    if (slack < BOOT_PAGE_SIZE) slack = BOOT_PAGE_SIZE;
    if (!needed || needed > SIZE_MAX - slack) return 0;
    size_t total = needed + slack;
    if (total > SIZE_MAX - (BOOT_PAGE_SIZE - 1)) return 0;
    return (total + BOOT_PAGE_SIZE - 1) & ~(size_t)(BOOT_PAGE_SIZE - 1);
}

// Keep ownership if firmware rejects the release. Never call after a
// successful ExitBootServices: the final map belongs to the kernel.
static BootMapResult boot_map_release(const BootMapAccess *access, BootMap *map) {
    if (map->buffer) {
        BootMapResult result = access->release(access->context, map->buffer, map->capacity);
        if (result != BOOT_MAP_OK) return result;
    }
    map->buffer = NULL;
    map->capacity = map->size = map->descriptor_size = 0;
    map->version = 0;
    return BOOT_MAP_OK;
}

// UEFI 2.11 sections 7.2.3 and 7.4.6. After the first exit attempt
// only memory allocation services and ExitBootServices may be called.
// The final map is transferred only on success. On failure the caller
// still owns any buffer; exit_attempted distinguishes safe return from
// a potentially partially shut down firmware.
static BootMapResult boot_map_capture(const BootMapAccess *access, BootMap *map) {
    unsigned exits = 0;
    for (unsigned reads = 0; reads < BOOT_MAP_READ_LIMIT; ++reads) {
        size_t size = map->capacity, key = 0, descriptor = 0;
        uint32_t version = 0;
        BootMapResult result = access->read(access->context, map->buffer,
                                           &size, &key, &descriptor, &version);
        if (result == BOOT_MAP_GROW) {
            if (size <= map->capacity) return BOOT_MAP_INVALID;
            size_t capacity = boot_map_capacity(size);
            if (!capacity) return BOOT_MAP_INVALID;
            result = boot_map_release(access, map);
            if (result != BOOT_MAP_OK) return result;
            void *buffer = NULL;
            result = access->allocate(access->context, capacity, &buffer);
            if (result != BOOT_MAP_OK) return result;
            if (!buffer) return BOOT_MAP_INVALID;
            map->buffer = buffer;
            map->capacity = capacity;
            continue;
        }
        if (result != BOOT_MAP_OK) return result;
        // The existing kernel handoff ABI supports descriptor version 1,
        // including future-compatible larger strides of that version.
        if (!map->buffer || !size || size > map->capacity ||
            version != 1 || descriptor < BOOT_DESCRIPTOR_MIN ||
            size % descriptor != 0) return BOOT_MAP_INVALID;
        map->exit_attempted = 1;
        result = access->exit_services(access->context, key);
        if (result == BOOT_MAP_OK) {
            map->size = size;
            map->descriptor_size = descriptor;
            map->version = version;
            return BOOT_MAP_OK;
        }
        if (result != BOOT_MAP_STALE) return result;
        if (++exits == BOOT_EXIT_LIMIT) return BOOT_MAP_LIMIT;
        // Discard the stale key. Retry with an entirely fresh snapshot.
    }
    return BOOT_MAP_LIMIT;
}
#endif
