/* Test pattern: see testpattern.h. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "testpattern.h"
#include "font5x7.h"

#define BOX 48

static int W, H;
static uint8_t *fb, *bg;            /* displayed frame, static background */
static uint8_t palette[768];
static rdp_session *sess;
static int box_x, box_y, box_dx, box_dy;
static char last_key[64], last_mouse[64];
static int resize_w, resize_h;      /* pending middle-click resize */
static unsigned long generation;    /* bumped on every framebuffer change */
static char *clip_text;
static size_t clip_len;

enum { C_GREY, C_BLACK, C_WHITE, C_BLUE, C_ORANGE, C_RED, C_GREEN, C_BLUE2, C_YELLOW };

static void fill(uint8_t *buf, int x, int y, int w, int h, int c)
{
    int r;
    generation++;
    if (x < 0) { w += x; x = 0; }
    if (y < 0) { h += y; y = 0; }
    if (x + w > W) w = W - x;
    if (y + h > H) h = H - y;
    for (r = 0; r < h; r++)
        memset(buf + (size_t)(y + r) * W + x, c, (size_t)(w > 0 ? w : 0));
}

static void text(uint8_t *buf, int x, int y, int scale, int c, const char *str)
{
    for (; *str; str++, x += 6 * scale) {
        const uint8_t *g = font5x7_glyph(*str);
        int col, row;
        for (col = 0; col < 5; col++)
            for (row = 0; row < 7; row++)
                if (g[col] & (1 << row))
                    fill(buf, x + col * scale, y + row * scale, scale, scale, c);
    }
}

static void make_palette(void)
{
    static const uint8_t fixed[9][3] = {
        {0xaa, 0xaa, 0xaa}, {0x00, 0x00, 0x00}, {0xff, 0xff, 0xff},
        {0x66, 0x88, 0xbb}, {0xff, 0x88, 0x00}, {0xee, 0x22, 0x22},
        {0x22, 0xcc, 0x22}, {0x22, 0x44, 0xee}, {0xee, 0xdd, 0x22}
    };
    int i;

    memcpy(palette, fixed, sizeof(fixed));
    for (i = 0; i < 64; i++) {      /* grey, red, green, blue ramps */
        uint8_t v = (uint8_t)(i * 4 + i / 16);
        uint8_t *p;
        p = palette + (16 + i) * 3;  p[0] = p[1] = p[2] = v;
        p = palette + (80 + i) * 3;  p[0] = v; p[1] = p[2] = 0;
        p = palette + (144 + i) * 3; p[1] = v; p[0] = p[2] = 0;
        if (i < 48) { p = palette + (208 + i) * 3; p[2] = (uint8_t)(i * 255 / 47); p[0] = p[1] = 0; }
    }
}

static void draw_status(void)
{
    char line[96];

    fill(bg, 16, H - 72, W - 72, 60, C_WHITE);
    snprintf(line, sizeof(line), "MOUSE: %s", last_mouse);
    text(bg, 24, H - 66, 2, C_BLACK, line);
    snprintf(line, sizeof(line), "KEY: %s", last_key);
    text(bg, 24, H - 44, 2, C_BLACK, line);
    memcpy(fb + (size_t)(H - 72) * W, bg + (size_t)(H - 72) * W, (size_t)60 * W);
    if (sess)
        rdp_mark_dirty(sess, 0, H - 72, W, 60);
}

static void draw_background(void)
{
    int i, x;

    fill(bg, 0, 0, W, H, C_GREY);
    fill(bg, 0, 0, W, 22, C_BLUE);
    text(bg, 6, 4, 2, C_WHITE, "AMIGA RDP PROTOTYPE");
    fill(bg, W - 22, 2, 18, 18, C_WHITE);           /* fake depth gadget */
    fill(bg, W - 18, 6, 10, 10, C_BLACK);

    for (i = 0; i < 256; i++)                       /* all palette entries */
        fill(bg, 64 + i * 2, 40, 2, 24, i);
    text(bg, 64, 68, 1, C_BLACK, "PALETTE 0-255");

    /* Corner markers: orientation check (rows are sent bottom-up) */
    fill(bg, 0, 22, 40, 40, C_RED);
    text(bg, 8, 34, 2, C_WHITE, "TL");
    fill(bg, W - 40, H - 40, 40, 40, C_GREEN);
    text(bg, W - 32, H - 28, 2, C_WHITE, "BR");

    for (x = 0; x < 512; x++) {                     /* gradients */
        fill(bg, 64 + x, 90, 1, 20, 16 + x / 8);
        fill(bg, 64 + x, 112, 1, 20, 80 + x / 8);
        fill(bg, 64 + x, 134, 1, 20, 144 + x / 8);
        fill(bg, 64 + x, 156, 1, 20, 208 + x * 48 / 512);
    }
    for (i = 0; i < 8; i++)
        fill(bg, 64 + i * 64, 186, 64, 30, i + 1);

    text(bg, 64, 230, 2, C_BLACK, "CLICK TO PAINT, TYPE TO TEST KEYS");
    text(bg, 64, 252, 1, C_BLACK, "RIGHT-CLICK TO BEEP, MIDDLE-CLICK TO RESIZE");
    draw_status();
    memcpy(fb, bg, (size_t)W * H);
}

static void draw_box(int x, int y)
{
    int r, c;
    for (r = 0; r < BOX; r += 8)
        for (c = 0; c < BOX; c += 8)
            fill(fb, x + c, y + r, 8, 8, ((r + c) / 8) & 1 ? C_WHITE : C_RED);
}

int tp_init(int w, int h)
{
    uint8_t *nfb, *nbg;

    if (w < 640 || h < 400)
        return -1;
    nfb = malloc((size_t)w * h);
    nbg = malloc((size_t)w * h);
    if (!nfb || !nbg) {
        free(nfb);
        free(nbg);
        return -1;
    }
    free(fb);
    free(bg);
    fb = nfb; bg = nbg;
    W = w; H = h;
    make_palette();
    return 0;
}

int tp_resize(int w, int h)
{
    if (tp_init(w, h))
        return -1;
    box_x = 100; box_y = 260;
    draw_background();
    return 0;
}

int tp_resize_requested(int *w, int *h)
{
    if (!resize_w)
        return 0;
    *w = resize_w; *h = resize_h;
    resize_w = 0;
    return 1;
}

unsigned long tp_generation(void) { return generation; }
int tp_width(void) { return W; }
int tp_height(void) { return H; }

uint8_t *tp_fb(void) { return fb; }
const uint8_t *tp_palette(void) { return palette; }

void tp_reset(rdp_session *s)
{
    sess = s;
    strcpy(last_key, "-");
    strcpy(last_mouse, "-");
    box_x = 100; box_y = 260; box_dx = 3; box_dy = 2;
    draw_background();
}

void tp_animate(void)
{
    int r, ox = box_x, oy = box_y;

    for (r = 0; r < BOX; r++)       /* restore background under old box */
        memcpy(fb + (size_t)(oy + r) * W + ox, bg + (size_t)(oy + r) * W + ox, BOX);
    box_x += box_dx; box_y += box_dy;
    if (box_x < 0 || box_x + BOX > W) { box_dx = -box_dx; box_x += 2 * box_dx; }
    if (box_y < 250 || box_y + BOX > H - 80) { box_dy = -box_dy; box_y += 2 * box_dy; }
    draw_box(box_x, box_y);
    if (sess) {
        rdp_mark_dirty(sess, ox, oy, BOX, BOX);
        rdp_mark_dirty(sess, box_x, box_y, BOX, BOX);
    }
}

static void on_key(void *ctx, unsigned flags, unsigned code)
{
    (void)ctx;
    snprintf(last_key, sizeof(last_key), "SCANCODE %02X%s%s", code,
             flags & RDP_KBD_EXTENDED ? " EXT" : "", flags & RDP_KBD_RELEASE ? " UP" : " DOWN");
    printf("key: scancode 0x%02x flags 0x%04x\n", code, flags);
    draw_status();
}

static void on_unicode(void *ctx, unsigned flags, unsigned code)
{
    (void)ctx;
    snprintf(last_key, sizeof(last_key), "UNICODE %04X%s", code,
             flags & RDP_KBD_RELEASE ? " UP" : " DOWN");
    printf("unicode: U+%04x flags 0x%04x\n", code, flags);
    draw_status();
}

static void on_mouse(void *ctx, unsigned flags, unsigned x, unsigned y)
{
    (void)ctx;
    snprintf(last_mouse, sizeof(last_mouse), "%u,%u%s%s%s", x, y,
             (flags & RDP_PTR_DOWN) && (flags & RDP_PTR_BUTTON1) ? " LEFT" : "",
             (flags & RDP_PTR_DOWN) && (flags & RDP_PTR_BUTTON2) ? " RIGHT" : "",
             flags & RDP_PTR_WHEEL ? " WHEEL" : "");
    if (!(flags & RDP_PTR_MOVE))
        printf("mouse: %u,%u flags 0x%04x\n", x, y, flags);
    if ((flags & RDP_PTR_DOWN) && (flags & RDP_PTR_BUTTON3)) {
        resize_w = W == 640 ? 800 : 640;    /* like switching screens */
        resize_h = W == 640 ? 600 : 512;
        printf("resize requested (middle click): %dx%d\n", resize_w, resize_h);
    }
    if ((flags & RDP_PTR_DOWN) && (flags & RDP_PTR_BUTTON2) && sess) {
        printf("beep (right click)\n");
        rdp_beep(sess, 880, 150);           /* stands in for DisplayBeep() */
    }
    if ((flags & RDP_PTR_DOWN) && (flags & RDP_PTR_BUTTON1) && (int)y > 22 && (int)y < H - 80) {
        fill(bg, (int)x - 3, (int)y - 3, 7, 7, C_ORANGE);
        fill(fb, (int)x - 3, (int)y - 3, 7, 7, C_ORANGE);
        if (sess)
            rdp_mark_dirty(sess, (int)x - 3, (int)y - 3, 7, 7);
    }
    draw_status();
}

static void on_sync(void *ctx, unsigned toggles)
{
    (void)ctx;
    printf("sync: toggle flags 0x%x\n", toggles);
}

/* Host clipboard: TP_CLIP_TEXT followed by 2000 'y's (so it needs several
 * virtual channel chunks), until the client sends something. */
static long clip_get(void *ctx, const char **text)
{
    (void)ctx;
    if (!clip_text) {
        size_t n = strlen(TP_CLIP_TEXT);
        clip_text = malloc(n + 2000 + 1);
        if (!clip_text)
            return -1;
        memcpy(clip_text, TP_CLIP_TEXT, n);
        memset(clip_text + n, 'y', 2000);
        clip_len = n + 2000;
        clip_text[clip_len] = 0;
    }
    *text = clip_text;
    return (long)clip_len;
}

static void clip_set(void *ctx, const char *text, size_t len)
{
    char shown[80 * 4 + 1], *o = shown;
    size_t i;

    (void)ctx;
    for (i = 0; i < len && i < 80; i++) {
        unsigned char c = (unsigned char)text[i];
        if (c == '\n')
            o += sprintf(o, "\\n");
        else if (c < 0x20 || c > 0x7e || c == '\\')
            o += sprintf(o, "\\x%02x", c);
        else
            *o++ = (char)c;
    }
    *o = 0;
    printf("clipboard from client (%lu bytes): %s\n", (unsigned long)len, shown);
    fflush(stdout);
    free(clip_text);
    clip_text = malloc(len + 1);
    if (clip_text) {
        memcpy(clip_text, text, len);
        clip_text[len] = 0;
        clip_len = len;
    }
}

void tp_set_callbacks(rdp_callbacks *cb)
{
    cb->key = on_key;
    cb->unicode = on_unicode;
    cb->mouse = on_mouse;
    cb->sync = on_sync;
    cb->clip_get = clip_get;
    cb->clip_set = clip_set;
}
