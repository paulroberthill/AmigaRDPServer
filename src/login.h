/*
 * Server-drawn password prompt, shown to RDP clients before the real
 * screen. Standard RDP Security has no NLA, so mstsc connects without
 * asking for credentials; like Windows and xrdp in this mode, the server
 * draws its own login screen and reads the password from key events.
 */
#ifndef RDP_LOGIN_H
#define RDP_LOGIN_H

#include <stdint.h>

#define LOGIN_MAXLEN 63

typedef struct rdp_login rdp_login;

/* Returned by login_key(). */
enum { LOGIN_NONE, LOGIN_CHANGED, LOGIN_SUBMIT };

rdp_login *login_new(int width, int height);
void login_free(rdp_login *l);

/* 8-bit indexed framebuffer (pitch == width) and its 256-entry palette. */
const uint8_t *login_fb(const rdp_login *l);
const uint8_t *login_palette(void);

/* Area that changes when the text or message changes. */
void login_dirty_rect(const rdp_login *l, int *x, int *y, int *w, int *h);

/*
 * Feed a scancode event (RDP flags as in rdp.h). `layout` is the client's
 * keyboard layout id from its core data (0x809 = UK; others use US).
 */
int login_key(rdp_login *l, unsigned flags, unsigned scancode, uint32_t layout);
/* Feed a Unicode key event (code points up to U+00FF are accepted). */
int login_unicode(rdp_login *l, unsigned flags, unsigned code);
/* Lock-key state from a sync event (TS_SYNC_* flags). */
void login_sync(rdp_login *l, unsigned toggles);

/* Typed text (Latin-1), and clearing it with a message such as an error. */
const char *login_text(const rdp_login *l);
void login_reset(rdp_login *l, const char *message);

#endif
