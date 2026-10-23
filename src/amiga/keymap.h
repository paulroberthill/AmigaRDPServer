/*
 * PC set-1 scancodes (as sent by RDP clients) -> Amiga raw key codes.
 *
 * Both are positional, so the Amiga's own keymap (e.g. "gb") decides which
 * characters they produce. ISO layout is assumed: PC 0x2B (the '#' key
 * beside Return on a UK keyboard) maps to Amiga 0x2B, and PC 0x56 (the key
 * left of Z) maps to Amiga 0x30. Keys missing from classic Amiga keyboards
 * use the codes AmigaOS 3.5+ PC-keyboard drivers use (Insert 0x47,
 * PgUp 0x48, PgDn 0x49, F11 0x4B, PrtScr 0x6D, Pause 0x6E, F12 0x6F,
 * Home 0x70, End 0x71). 0xFF = not mapped.
 *
 * Right Ctrl is the Right Amiga key, for Amiga shortcuts such as RAmiga-C
 * (copy): mstsc keeps Windows-key combinations for Windows itself unless it
 * is full screen. Left Ctrl stays Ctrl. The Windows keys are also the Amiga
 * keys.
 */
#ifndef RDP_AMIGA_KEYMAP_H
#define RDP_AMIGA_KEYMAP_H

#define RK_NONE 0xff

static const unsigned char pc_to_amiga[128] = {
    /* 0x00 */ RK_NONE, 0x45, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,   /* -, Esc, 1..6 */
    /* 0x08 */ 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x41, 0x42,      /* 7..0, -, =, BS, Tab */
    /* 0x10 */ 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,      /* Q..I */
    /* 0x18 */ 0x18, 0x19, 0x1a, 0x1b, 0x44, 0x63, 0x20, 0x21,      /* O, P, [, ], Return, Ctrl, A, S */
    /* 0x20 */ 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29,      /* D..L, ; */
    /* 0x28 */ 0x2a, 0x00, 0x60, 0x2b, 0x31, 0x32, 0x33, 0x34,      /* ', `, LShift, #, Z..V */
    /* 0x30 */ 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x61, 0x5d,      /* B, N, M, ',', '.', /, RShift, KP* */
    /* 0x38 */ 0x64, 0x40, 0x62, 0x50, 0x51, 0x52, 0x53, 0x54,      /* LAlt, Space, Caps, F1..F5 */
    /* 0x40 */ 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x3d,      /* F6..F10, NumLock, ScrLock, KP7 */
    /* 0x48 */ 0x3e, 0x3f, 0x4a, 0x2d, 0x2e, 0x2f, 0x5e, 0x1d,      /* KP8, KP9, KP-, KP4..6, KP+, KP1 */
    /* 0x50 */ 0x1e, 0x1f, 0x0f, 0x3c, RK_NONE, RK_NONE, 0x30, 0x4b,/* KP2, KP3, KP0, KP., -, -, ISO \, F11 */
    /* 0x58 */ 0x6f, RK_NONE, RK_NONE, RK_NONE, RK_NONE, RK_NONE, RK_NONE, RK_NONE, /* F12 */
    /* 0x60 */ RK_NONE, RK_NONE, RK_NONE, RK_NONE, RK_NONE, RK_NONE, RK_NONE, RK_NONE,
    /* 0x68 */ RK_NONE, RK_NONE, RK_NONE, RK_NONE, RK_NONE, RK_NONE, RK_NONE, RK_NONE,
    /* 0x70 */ RK_NONE, RK_NONE, RK_NONE, RK_NONE, RK_NONE, RK_NONE, RK_NONE, RK_NONE,
    /* 0x78 */ RK_NONE, RK_NONE, RK_NONE, RK_NONE, RK_NONE, RK_NONE, RK_NONE, RK_NONE
};

/* Extended (0xE0-prefixed) scancodes. */
static const unsigned char pc_ext_to_amiga[128] = {
    /* 0x00 */ RK_NONE, RK_NONE, RK_NONE, RK_NONE, RK_NONE, RK_NONE, RK_NONE, RK_NONE,
    /* 0x08 */ RK_NONE, RK_NONE, RK_NONE, RK_NONE, RK_NONE, RK_NONE, RK_NONE, RK_NONE,
    /* 0x10 */ RK_NONE, RK_NONE, RK_NONE, RK_NONE, RK_NONE, RK_NONE, RK_NONE, RK_NONE,
    /* 0x18 */ RK_NONE, RK_NONE, RK_NONE, RK_NONE, 0x43, 0x67, RK_NONE, RK_NONE,      /* KP Enter, RCtrl = RAmiga */
    /* 0x20 */ RK_NONE, RK_NONE, RK_NONE, RK_NONE, RK_NONE, RK_NONE, RK_NONE, RK_NONE,
    /* 0x28 */ RK_NONE, RK_NONE, RK_NONE, RK_NONE, RK_NONE, RK_NONE, RK_NONE, RK_NONE,
    /* 0x30 */ RK_NONE, RK_NONE, RK_NONE, RK_NONE, RK_NONE, 0x5c, RK_NONE, 0x6d,      /* KP/, PrtScr */
    /* 0x38 */ 0x65, RK_NONE, RK_NONE, RK_NONE, RK_NONE, RK_NONE, RK_NONE, RK_NONE,   /* RAlt/AltGr */
    /* 0x40 */ RK_NONE, RK_NONE, RK_NONE, RK_NONE, RK_NONE, 0x6e, RK_NONE, 0x70,      /* Pause, Home */
    /* 0x48 */ 0x4c, 0x48, RK_NONE, 0x4f, RK_NONE, 0x4e, RK_NONE, 0x71,               /* Up, PgUp, Left, Right, End */
    /* 0x50 */ 0x4d, 0x49, 0x47, 0x46, RK_NONE, RK_NONE, RK_NONE, RK_NONE,            /* Down, PgDn, Ins, Del */
    /* 0x58 */ RK_NONE, RK_NONE, RK_NONE, 0x66, 0x67, 0x67, RK_NONE, RK_NONE,         /* LWin, RWin, Menu */
    /* 0x60 */ RK_NONE, RK_NONE, RK_NONE, RK_NONE, RK_NONE, RK_NONE, RK_NONE, RK_NONE,
    /* 0x68 */ RK_NONE, RK_NONE, RK_NONE, RK_NONE, RK_NONE, RK_NONE, RK_NONE, RK_NONE,
    /* 0x70 */ RK_NONE, RK_NONE, RK_NONE, RK_NONE, RK_NONE, RK_NONE, RK_NONE, RK_NONE,
    /* 0x78 */ RK_NONE, RK_NONE, RK_NONE, RK_NONE, RK_NONE, RK_NONE, RK_NONE, RK_NONE
};

/* Amiga raw codes on the numeric keypad (get IEQUALIFIER_NUMERICPAD). */
static int amiga_is_keypad(unsigned raw)
{
    switch (raw) {
    case 0x0f: case 0x1d: case 0x1e: case 0x1f: case 0x2d: case 0x2e: case 0x2f:
    case 0x3c: case 0x3d: case 0x3e: case 0x3f: case 0x43: case 0x4a:
    case 0x5a: case 0x5b: case 0x5c: case 0x5d: case 0x5e:
        return 1;
    }
    return 0;
}

#endif
