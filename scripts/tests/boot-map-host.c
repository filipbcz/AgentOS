#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include "../../boot/boot-map.h"

typedef struct {
    size_t needed, key, descriptor;
    uint32_t version;
    void *owned;
    size_t capacity;
    unsigned reads, allocations, releases, exits, stale;
    int grow_after_allocation, grow_after_exit, fail_alloc, fail_release;
    int invalid_success, fail_read, fail_exit, always_grow, exited, fresh;
} Firmware;

static BootMapResult read_map(void *context, void *buffer, size_t *size,
                              size_t *key, size_t *descriptor, uint32_t *version) {
    Firmware *f = context;
    assert(!f->exited && buffer == f->owned && *size == f->capacity);
    ++f->reads;
    f->fresh = 0;
    if (f->fail_read) return BOOT_MAP_ERROR;
    if (*size < f->needed) {
        *size = f->needed;
        return BOOT_MAP_GROW;
    }
    *size = f->invalid_success ? f->capacity + 1 : f->needed;
    *descriptor = f->descriptor;
    *version = f->version;
    *key = ++f->key;
    f->fresh = 1;
    return BOOT_MAP_OK;
}

static BootMapResult allocate(void *context, size_t size, void **buffer) {
    Firmware *f = context;
    assert(!f->exited && !f->owned && size % BOOT_PAGE_SIZE == 0);
    ++f->allocations;
    f->fresh = 0;
    if (f->fail_alloc) return BOOT_MAP_NO_MEMORY;
    // Contents are not consumed by the loader algorithm; use actual owned
    // memory to verify replacement and release without enormous fixtures.
    f->owned = malloc(1);
    assert(f->owned);
    f->capacity = size;
    *buffer = f->owned;
    if (f->always_grow || f->grow_after_allocation) {
        f->needed = size + f->descriptor;
        f->grow_after_allocation = 0;
    }
    return BOOT_MAP_OK;
}

static BootMapResult release(void *context, void *buffer, size_t size) {
    Firmware *f = context;
    assert(!f->exited && buffer == f->owned && size == f->capacity);
    ++f->releases;
    f->fresh = 0;
    if (f->fail_release) return BOOT_MAP_ERROR;
    free(buffer);
    f->owned = NULL;
    f->capacity = 0;
    return BOOT_MAP_OK;
}

static BootMapResult exit_services(void *context, size_t key) {
    Firmware *f = context;
    assert(!f->exited && f->fresh && key == f->key);
    ++f->exits;
    f->fresh = 0;
    if (f->fail_exit) return BOOT_MAP_ERROR;
    if (f->stale) {
        --f->stale;
        if (f->grow_after_exit) {
            f->needed = f->capacity + f->descriptor;
            f->grow_after_exit = 0;
        }
        return BOOT_MAP_STALE;
    }
    f->exited = 1;
    return BOOT_MAP_OK;
}

static Firmware fixture(void) {
    return (Firmware){.needed = 480, .descriptor = 48, .version = 1};
}

static BootMapAccess access(Firmware *f) {
    return (BootMapAccess){f, read_map, allocate, release, exit_services};
}

static void dispose_success(Firmware *f, BootMap *map) {
    assert(f->exited && map->exit_attempted && map->buffer == f->owned);
    assert(map->size == f->needed && map->descriptor_size == f->descriptor);
    assert(map->version == f->version);
    // Firmware services are gone; emulate the kernel owning the map.
    free(map->buffer);
    *map = (BootMap){0};
}

int main(void) {
    assert(!boot_map_capacity(0));
    assert(!boot_map_capacity(SIZE_MAX));
    assert(!boot_map_capacity(SIZE_MAX - 4096));
    assert(boot_map_capacity(4096) == 8192);

    BootMap map = {0};
    Firmware f = fixture();
    BootMapAccess a = access(&f);
    assert(boot_map_capture(&a, &map) == BOOT_MAP_OK);
    assert(f.reads == 2 && f.allocations == 1 && f.exits == 1 && !f.releases);
    dispose_success(&f, &map);

    f = fixture(); a = access(&f);
    f.descriptor = 64; f.needed = 640;
    f.grow_after_allocation = 1; f.grow_after_exit = 1; f.stale = 2;
    assert(boot_map_capture(&a, &map) == BOOT_MAP_OK);
    assert(f.allocations == 3 && f.releases == 2 && f.exits == 3);
    dispose_success(&f, &map);

    f = fixture(); a = access(&f); f.fail_alloc = 1;
    assert(boot_map_capture(&a, &map) == BOOT_MAP_NO_MEMORY);
    assert(!map.exit_attempted && !map.buffer && !f.exits);

    f = fixture(); a = access(&f); f.fail_read = 1;
    assert(boot_map_capture(&a, &map) == BOOT_MAP_ERROR);
    assert(!map.exit_attempted && !map.buffer);

    f = fixture(); a = access(&f); f.invalid_success = 1;
    assert(boot_map_capture(&a, &map) == BOOT_MAP_INVALID);
    assert(!f.exits && !map.exit_attempted);
    assert(boot_map_release(&a, &map) == BOOT_MAP_OK && !f.owned);

    for (unsigned i = 0; i < 3; ++i) {
        f = fixture(); a = access(&f);
        if (i == 0) f.version = 2;
        if (i == 1) f.descriptor = 32;
        if (i == 2) f.needed++;
        assert(boot_map_capture(&a, &map) == BOOT_MAP_INVALID && !f.exits);
        assert(boot_map_release(&a, &map) == BOOT_MAP_OK && !f.owned);
    }

    f = fixture(); a = access(&f); f.grow_after_allocation = 1; f.fail_release = 1;
    assert(boot_map_capture(&a, &map) == BOOT_MAP_ERROR);
    assert(map.buffer == f.owned && f.releases == 1 && !f.exits);
    f.fail_release = 0;
    assert(boot_map_release(&a, &map) == BOOT_MAP_OK);

    f = fixture(); a = access(&f); f.stale = BOOT_EXIT_LIMIT;
    assert(boot_map_capture(&a, &map) == BOOT_MAP_LIMIT);
    assert(map.exit_attempted && f.exits == BOOT_EXIT_LIMIT && !map.size);
    assert(boot_map_release(&a, &map) == BOOT_MAP_OK);
    map = (BootMap){0};

    f = fixture(); a = access(&f); f.fail_exit = 1;
    assert(boot_map_capture(&a, &map) == BOOT_MAP_ERROR && map.exit_attempted);
    assert(boot_map_release(&a, &map) == BOOT_MAP_OK);
    map = (BootMap){0};

    f = fixture(); a = access(&f); f.always_grow = 1;
    assert(boot_map_capture(&a, &map) == BOOT_MAP_LIMIT);
    assert(f.reads == BOOT_MAP_READ_LIMIT && !map.exit_attempted);
    assert(boot_map_release(&a, &map) == BOOT_MAP_OK && !f.owned);

    puts("UEFI memory map growth, ownership and ExitBootServices retry: OK");
    return 0;
}
