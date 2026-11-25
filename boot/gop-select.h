#ifndef AGENTOS_GOP_SELECT_H
#define AGENTOS_GOP_SELECT_H

#include <stdint.h>

typedef struct {
    uint32_t width, height, stride, format;
    uint32_t red, green, blue, reserved;
} GopMode;

typedef struct {
    GopMode mode;
    uint64_t base, size;
} GopFramebuffer;

// A query may require SetMode first on an unstarted GOP implementation.
enum { GOP_QUERY_FAILED, GOP_QUERY_OK, GOP_QUERY_NOT_STARTED };

typedef struct {
    void *context;
    uint32_t count;
    int (*current)(void *, GopFramebuffer *);
    int (*query)(void *, uint32_t, GopMode *);
    int (*activate)(void *, uint32_t);
} GopAccess;

// Normalize canonical PixelBitMask modes to the existing boot ABI's RGB/BGR
// layouts. BLT-only and other bit layouts cannot be written by this console.
static int gop_layout(GopMode *mode) {
    if (mode->width < 200 || mode->height < 64 || mode->stride < mode->width)
        return 0;
    if (mode->format <= 1) return 1;
    if (mode->format != 2 || mode->green != 0xff00u ||
        (mode->reserved & 0xffffffu)) return 0;
    if (mode->red == 0xffu && mode->blue == 0xff0000u) mode->format = 0;
    else if (mode->red == 0xff0000u && mode->blue == 0xffu) mode->format = 1;
    else return 0;
    return 1;
}

static int gop_framebuffer_valid(GopFramebuffer *fb) {
    if (!gop_layout(&fb->mode)) return 0;
    uint64_t pixels = (uint64_t)fb->mode.stride * fb->mode.height;
    // The current kernel handoff maps the framebuffer in the low canonical
    // identity range. Validate the entire visible area, not just its base.
    const uint64_t limit = UINT64_C(1) << 47;
    return fb->base >= 4096 && !(fb->base & 3) && fb->base < limit &&
           pixels <= fb->size / 4 && pixels <= (limit - fb->base) / 4;
}

// Preserve a usable firmware-selected mode. Otherwise try the advertised
// modes in firmware order, validating the actual framebuffer after SetMode.
// A failed query or activation does not prevent trying the remaining modes.
static int gop_select(const GopAccess *access, GopFramebuffer *out) {
    GopFramebuffer fb;
    if (access->current(access->context, &fb) && gop_framebuffer_valid(&fb)) {
        *out = fb;
        return 1;
    }
    for (uint32_t index = 0; index < access->count; ++index) {
        GopMode mode;
        int result = access->query(access->context, index, &mode);
        if (result != GOP_QUERY_NOT_STARTED &&
            (result != GOP_QUERY_OK || !gop_layout(&mode))) continue;
        if (access->activate(access->context, index) &&
            access->current(access->context, &fb) && gop_framebuffer_valid(&fb)) {
            *out = fb;
            return 1;
        }
    }
    return 0;
}
#endif
