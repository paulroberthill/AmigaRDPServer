/* Server-drawn password prompt: see login.h. */
#include <stdlib.h>
#include <string.h>

#include "login.h"
#include "rdp.h"
#include "font5x7.h"

enum { C_BG, C_WHITE, C_BLACK, C_BLUE, C_RED, C_GREY };

static const uint8_t palette[256 * 3] = {
    0x55, 0x55, 0x55,   /* background */
    0xff, 0xff, 0xff,
    0x00, 0x00, 0x00,
    0x66, 0x88, 0xbb,   /* Workbench blue title bar */
    0xcc, 0x22, 0x22,
    0xaa, 0xaa, 0xaa
};

struct rdp_login {
    int w, h, scale;
    int bx, by, bw, bh;         /* dialog box */
    uint8_t *fb;
    char text[LOGIN_MAXLEN + 1];
    int len;
    int shift_l, shift_r, caps, altgr, ctrl;
    char message[48];
};

/* ------------------------------------------------------------------ */
/* Drawing                                                            */
/* ------------------------------------------------------------------ */

static void fill(rdp_login *l, int x, int y, int w, int h, int c)
{
    int r;
    if (x < 0) { w += x; x = 0; }
    if (y < 0) { h += y; y = 0; }
    if (x + w > l->w) w = l->w - x;
    if (y + h > l->h) h = l->h - y;
    for (r = 0; r < h; r++)
        memset(l->fb + (size_t)(y + r) * l->w + x, c, (size_t)(w > 0 ? w : 0));
}

static void text(rdp_login *l, int x, int y, int c, const char *str)
{
    int sc = l->scale;
    for (; *str; str++, x += 6 * sc) {
        const uint8_t *g = font5x7_glyph(*str);
        int col, row;
        for (col = 0; col < 5; col++)
            for (row = 0; row < 7; row++)
                if (g[col] & (1 << row))
                    fill(l, x + col * sc, y + row * sc, sc, sc, c);
    }
}

#define CH(l) (6 * (l)->scale)          /* character cell width */
#define LH(l) (10 * (l)->scale)         /* line height */

/* The parts that change: the password field and the message line. */
static void draw_field(rdp_login *l)
{
    int sc = l->scale, x = l->bx + 4 * sc, y = l->by + 6 * LH(l) / 2 + 12 * sc;
    int fw = l->bw - 8 * sc, maxch = (fw - 4 * sc) / CH(l) - 1, n, i;
    char stars[LOGIN_MAXLEN + 2];

    fill(l, x, y, fw, LH(l) + 4 * sc, C_BLACK);
    fill(l, x + sc, y + sc, fw - 2 * sc, LH(l) + 2 * sc, C_WHITE);
    n = l->len < maxch ? l->len : maxch;
    for (i = 0; i < n; i++)
        stars[i] = '*';
    stars[n] = 0;
    text(l, x + 3 * sc, y + 3 * sc, C_BLACK, stars);
    fill(l, x + 3 * sc + n * CH(l), y + 2 * sc, sc, 9 * sc, C_BLACK);   /* cursor */

    y += LH(l) + 10 * sc;
    fill(l, l->bx + sc, y, l->bw - 2 * sc, LH(l), C_GREY);
    text(l, x, y, C_RED, l->message);
}

static void draw_all(rdp_login *l)
{
    int sc = l->scale;

    fill(l, 0, 0, l->w, l->h, C_BG);
    fill(l, l->bx - sc, l->by - sc, l->bw + 2 * sc, l->bh + 2 * sc, C_BLACK);
    fill(l, l->bx, l->by, l->bw, l->bh, C_GREY);
    fill(l, l->bx, l->by, l->bw, LH(l) + 4 * sc, C_BLUE);
    text(l, l->bx + 4 * sc, l->by + 3 * sc, C_WHITE, "AMIGA RDP SERVER");
    text(l, l->bx + 4 * sc, l->by + LH(l) * 2, C_BLACK, "ENTER PASSWORD:");
    draw_field(l);
}

rdp_login *login_new(int width, int height)
{
    rdp_login *l = calloc(1, sizeof(*l));

    if (!l)
        return NULL;
    l->fb = malloc((size_t)width * height);
    if (!l->fb) {
        free(l);
        return NULL;
    }
    l->w = width; l->h = height;
    l->scale = width >= 560 && height >= 300 ? 2 : 1;
    l->bw = 32 * CH(l);
    l->bh = 8 * LH(l);
    if (l->bw > width) l->bw = width;
    l->bx = (width - l->bw) / 2;
    l->by = (height - l->bh) / 2;
    draw_all(l);
    return l;
}

void login_free(rdp_login *l)
{
    if (l) {
        memset(l->text, 0, sizeof(l->text));
        free(l->fb);
        free(l);
    }
}

const uint8_t *login_fb(const rdp_login *l) { return l->fb; }
const uint8_t *login_palette(void) { return palette; }
const char *login_text(const rdp_login *l) { return l->text; }

void login_dirty_rect(const rdp_login *l, int *x, int *y, int *w, int *h)
{
    *x = l->bx; *y = l->by; *w = l->bw; *h = l->bh;
}

void login_reset(rdp_login *l, const char *message)
{
    memset(l->text, 0, sizeof(l->text));
    l->len = 0;
    strncpy(l->message, message ? message : "", sizeof(l->message) - 1);
    draw_field(l);
}

/* ------------------------------------------------------------------ */
/* Keyboard                                                           */
/* ------------------------------------------------------------------ */

/* US layout, PC set-1 scancodes 0x00-0x39: unshifted and shifted. */
static const char us_plain[0x3a] =
    "\0\0" "1234567890-=" "\0\0" "qwertyuiop[]" "\0\0" "asdfghjkl;'`" "\0\\" "zxcvbnm,./" "\0*\0 ";
static const char us_shift[0x3a] =
    "\0\0" "!@#$%^&*()_+" "\0\0" "QWERTYUIOP{}" "\0\0" "ASDFGHJKL:\"~" "\0|" "ZXCVBNM<>?" "\0*\0 ";

static int to_char(rdp_login *l, unsigned flags, unsigned sc, uint32_t layout)
{
    int shift = l->shift_l || l->shift_r, c;
    int uk = (layout & 0xffff) == 0x0809;

    if (flags & RDP_KBD_EXTENDED)
        return sc == 0x35 ? '/' : 0;        /* keypad / */
    if (sc >= 0x47 && sc <= 0x53) {         /* keypad digits */
        static const char kp[] = "789-456+1230.";
        return kp[sc - 0x47];
    }
    if (sc == 0x56)                         /* ISO key left of Z */
        return shift ? '|' : '\\';
    if (sc >= sizeof(us_plain))
        return 0;
    if (uk) {
        switch (sc) {
        case 0x03: if (shift) return '"'; break;
        case 0x04: if (shift) return 0xa3; break;           /* pound sign */
        case 0x28: return shift ? '@' : '\'';
        case 0x29: return shift ? 0xac : '`';               /* not sign */
        case 0x2b: return shift ? '~' : '#';
        }
    }
    c = (unsigned char)(shift ? us_shift[sc] : us_plain[sc]);
    if (l->caps && c >= 'a' && c <= 'z')
        c -= 32;
    else if (l->caps && c >= 'A' && c <= 'Z')
        c += 32;
    return c;
}

static int add_char(rdp_login *l, int c)
{
    if (c <= 0 || c > 0xff || l->len >= LOGIN_MAXLEN)
        return LOGIN_NONE;
    l->text[l->len++] = (char)c;
    l->message[0] = 0;
    draw_field(l);
    return LOGIN_CHANGED;
}

int login_key(rdp_login *l, unsigned flags, unsigned sc, uint32_t layout)
{
    int down = !(flags & RDP_KBD_RELEASE), ext = (flags & RDP_KBD_EXTENDED) != 0;

    switch (sc) {
    case 0x2a: l->shift_l = down; return LOGIN_NONE;
    case 0x36: l->shift_r = down; return LOGIN_NONE;
    case 0x1d: l->ctrl = down; return LOGIN_NONE;
    case 0x38: if (ext) l->altgr = down; return LOGIN_NONE;
    case 0x3a: if (down) l->caps = !l->caps; return LOGIN_NONE;
    }
    if (!down || l->ctrl || l->altgr)
        return LOGIN_NONE;
    switch (sc) {
    case 0x1c:                              /* Return / keypad Enter */
        return LOGIN_SUBMIT;
    case 0x0e:                              /* Backspace */
        if (l->len > 0) {
            l->text[--l->len] = 0;
            draw_field(l);
            return LOGIN_CHANGED;
        }
        return LOGIN_NONE;
    case 0x01:                              /* Esc clears */
        login_reset(l, "");
        return LOGIN_CHANGED;
    }
    return add_char(l, to_char(l, flags, sc, layout));
}

int login_unicode(rdp_login *l, unsigned flags, unsigned code)
{
    if (flags & RDP_KBD_RELEASE)
        return LOGIN_NONE;
    if (code == '\r' || code == '\n')
        return LOGIN_SUBMIT;
    if (code < 0x20)
        return LOGIN_NONE;
    return add_char(l, (int)code);
}

void login_sync(rdp_login *l, unsigned toggles)
{
    l->caps = (toggles & 0x04) != 0;        /* TS_SYNC_CAPS_LOCK */
    l->shift_l = l->shift_r = l->ctrl = l->altgr = 0;
}
