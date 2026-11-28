#include <assert.h>
#include <stdio.h>
#include "../../boot/gop-select.h"

typedef struct {
    GopFramebuffer modes[5];
    int current, started, query_error, activation_error;
    unsigned queried, activated;
} Mock;

static int current(void *context, GopFramebuffer *out) {
    Mock *mock = context;
    if (!mock->started) return 0;
    *out = mock->modes[mock->current];
    return 1;
}

static int query(void *context, uint32_t index, GopMode *out) {
    Mock *mock = context;
    mock->queried++;
    if (!mock->started) return GOP_QUERY_NOT_STARTED;
    if ((int)index == mock->query_error) return GOP_QUERY_FAILED;
    *out = mock->modes[index].mode;
    return GOP_QUERY_OK;
}

static int activate(void *context, uint32_t index) {
    Mock *mock = context;
    mock->activated++;
    if ((int)index == mock->activation_error) return 0;
    mock->started = 1;
    mock->current = (int)index;
    return 1;
}

static GopFramebuffer mode(uint32_t format) {
    return (GopFramebuffer){{640, 480, 672, format, 0, 0, 0, 0},
                            0xe0000000, 672 * 480 * 4};
}

static Mock fixture(void) {
    Mock mock = {.current = 0, .started = 1, .query_error = -1, .activation_error = -1};
    for (unsigned i = 0; i < 5; ++i) mock.modes[i] = mode(1);
    return mock;
}

static int select_mode(Mock *mock, GopFramebuffer *out) {
    GopAccess access = {mock, 5, current, query, activate};
    return gop_select(&access, out);
}

int main(void) {
    GopFramebuffer out = {0};
    Mock mock = fixture();
    assert(select_mode(&mock, &out) && out.mode.format == 1);
    assert(mock.queried == 0 && mock.activated == 0);

    mock = fixture();
    mock.modes[0] = mode(3); // BLT-only current mode
    mock.query_error = 1;
    mock.activation_error = 2;
    mock.modes[3].size = 1; // SetMode succeeds but actual framebuffer is invalid
    mock.modes[4].mode = (GopMode){800, 600, 800, 2, 0xff, 0xff00, 0xff0000, 0xff000000};
    mock.modes[4].size = 800 * 600 * 4;
    assert(select_mode(&mock, &out));
    assert(mock.current == 4 && mock.queried == 5 && mock.activated == 3);
    assert(out.mode.format == 0 && out.mode.width == 800);

    mock = fixture();
    mock.started = 0;
    mock.modes[0] = mode(3);
    assert(select_mode(&mock, &out) && mock.current == 1);
    assert(mock.activated == 2);

    mock = fixture();
    for (unsigned i = 0; i < 5; ++i) mock.modes[i] = mode(3);
    out.base = 123;
    assert(!select_mode(&mock, &out) && out.base == 123);
    assert(mock.activated == 0);

    GopFramebuffer fb = mode(0);
    fb.mode.stride = 639;
    assert(!gop_framebuffer_valid(&fb));
    fb = mode(0); fb.mode.height = 63;
    assert(!gop_framebuffer_valid(&fb));
    fb = mode(0); fb.base = 1;
    assert(!gop_framebuffer_valid(&fb));
    fb = mode(0); fb.base |= 1;
    assert(!gop_framebuffer_valid(&fb));
    fb = mode(0); fb.size--;
    assert(!gop_framebuffer_valid(&fb));
    fb = mode(0); fb.base = (UINT64_C(1) << 47) - fb.size;
    assert(gop_framebuffer_valid(&fb));
    fb.base += 4;
    assert(!gop_framebuffer_valid(&fb));
    fb = mode(0); fb.mode.stride = fb.mode.height = UINT32_MAX; fb.size = UINT64_MAX;
    assert(!gop_framebuffer_valid(&fb));
    fb = mode(2); fb.mode.red = 0xff0000; fb.mode.green = 0xff00; fb.mode.blue = 0xff;
    assert(gop_framebuffer_valid(&fb) && fb.mode.format == 1);
    fb = mode(2); fb.mode.red = 0xf800; fb.mode.green = 0x7e0; fb.mode.blue = 0x1f;
    assert(!gop_framebuffer_valid(&fb));
    puts("GOP selection and framebuffer validation: OK");
}
