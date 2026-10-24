/*
 * Minimal RDP server core: connection sequence with Standard RDP Security,
 * licensing bypass, capability exchange, input, and uncompressed bitmap
 * updates from an 8-bit indexed framebuffer.
 *
 * Platform-independent: networking, randomness, logging and input delivery
 * go through rdp_callbacks so the same core can run on Linux (prototype)
 * and AmigaOS (bsdsocket.library, input.device).
 */
#ifndef RDP_RDP_H
#define RDP_RDP_H

#include <stdint.h>
#include <stddef.h>

/* Keyboard event flags (slow-path values; fast-path ones are translated). */
#define RDP_KBD_EXTENDED  0x0100
#define RDP_KBD_EXTENDED1 0x0200
#define RDP_KBD_RELEASE   0x8000

/* Mouse pointer flags (TS_POINTER_EVENT) */
#define RDP_PTR_WHEEL         0x0200
#define RDP_PTR_WHEEL_NEG     0x0100
#define RDP_PTR_MOVE          0x0800
#define RDP_PTR_DOWN          0x8000
#define RDP_PTR_BUTTON1       0x1000  /* left */
#define RDP_PTR_BUTTON2       0x2000  /* right */
#define RDP_PTR_BUTTON3       0x4000  /* middle */

typedef struct {
    void *ctx;
    /* Send all bytes; return 0 on success, -1 on error. */
    int (*send)(void *ctx, const uint8_t *data, size_t len);
    /* Receive exactly len bytes; return 0 on success, -1 on error/EOF. */
    int (*recv)(void *ctx, uint8_t *data, size_t len);
    /* Fill out with unpredictable bytes (server random). */
    void (*random)(void *ctx, uint8_t *out, size_t len);
    void (*log)(void *ctx, const char *msg);
    /* Input events; any may be NULL. */
    void (*key)(void *ctx, unsigned flags, unsigned scancode);
    void (*unicode)(void *ctx, unsigned flags, unsigned code);
    void (*mouse)(void *ctx, unsigned flags, unsigned x, unsigned y);
    void (*sync)(void *ctx, unsigned toggle_flags);
    /*
     * Clipboard sharing over the "cliprdr" channel (both NULL = off).
     * Text is Latin-1 with LF line endings. clip_get returns the length of
     * the host clipboard text and points *text at it (valid until the next
     * call), or -1 if there is none. clip_set receives text copied on the
     * client. Neither is called before the client has logged in.
     */
    long (*clip_get)(void *ctx, const char **text);
    void (*clip_set)(void *ctx, const char *text, size_t len);
} rdp_callbacks;

typedef struct {
    int width, height;          /* desktop size; multiples of 4 */
    int bpp;                    /* wire colour depth: 8, 15, 16, 24 or 32 */
    /*
     * Framebuffer, owned by the host. Either 8-bit palette indices
     * (fb_wire == 0, converted through `palette`), or pixels already in the
     * wire format for `bpp` (fb_wire == 1): 15 = RGB555 LE, 16 = RGB565 LE,
     * 24 = B,G,R, 32 = B,G,R,X. `pitch` is bytes per row (0 = packed).
     */
    const uint8_t *fb;
    int pitch;
    int fb_wire;
    const uint8_t *palette;     /* 256 RGB triplets (indexed mode) */
    /*
     * How to answer a client that asks for TLS/NLA:
     * 0 = RDP_NEG_RSP selecting PROTOCOL_RDP (what the spec prescribes),
     * 1 = RDP_NEG_FAILURE SSL_NOT_ALLOWED_BY_SERVER and close (xrdp style;
     *     the client is expected to reconnect asking for PROTOCOL_RDP).
     */
    int neg_fail;
    /*
     * Password (Latin-1) required before the client sees the screen or can
     * send input; NULL or "" disables authentication. A password sent by
     * the client (saved credentials) is checked first; otherwise the
     * server shows its own login prompt. Three wrong attempts disconnect.
     */
    const char *password;
    int no_compress;            /* send bitmaps uncompressed (default: RLE) */
    int verbose;                /* log every PDU */
    int quiet;                  /* log only warnings and errors */
} rdp_config;

typedef struct rdp_session rdp_session;

/*
 * Server key (needed before the first session): a 512-bit RSA key,
 * little-endian, and its public exponent. The signed certificate sent to
 * clients is built from it. Returns 0, or -1 for an unusable key.
 */
int rdp_set_server_key(const uint8_t modulus[64], const uint8_t privexp[64], uint32_t e);

/* Generate a new key (e = 65537) from the given random source, e.g. once
 * per install, saving it for later runs. Returns 0 or -1. */
int rdp_generate_server_key(uint8_t modulus[64], uint8_t privexp[64], uint32_t *e,
                            void (*random)(void *ctx, uint8_t *out, size_t len), void *ctx);

rdp_session *rdp_session_new(const rdp_config *cfg, const rdp_callbacks *cb);
void rdp_session_free(rdp_session *s);

/*
 * Change the desktop size (e.g. the front screen changed), with a new
 * framebuffer in the same format (pitch 0 = packed). The client is taken
 * through a Deactivation-Reactivation sequence: rdp_session_active() is
 * false until it has finished, then the whole screen is sent again.
 * Width must be a multiple of 4. Returns 0, or -1 on error.
 */
int rdp_session_resize(rdp_session *s, int width, int height, const uint8_t *fb, int pitch);

/* Read and handle one incoming PDU (blocks until it has arrived).
 * Returns 0 to continue, -1 when the connection should be closed. */
int rdp_session_process(rdp_session *s);

/* True once the client has finished the connection sequence and logged in
 * (before that the host need not capture the screen; its input callbacks
 * are not called and its rdp_mark_dirty() calls are ignored). */
int rdp_session_active(const rdp_session *s);

/* True if the session ended because of wrong passwords (hosts should
 * pause before accepting another connection, to slow down guessing). */
int rdp_session_auth_failed(const rdp_session *s);

/* Framebuffer changed in this rectangle / palette changed. */
void rdp_mark_dirty(rdp_session *s, int x, int y, int w, int h);
void rdp_palette_changed(rdp_session *s);

/* Send pending screen updates. Returns 0 or -1 on send error. */
int rdp_flush(rdp_session *s);

/* The host clipboard has new text: offer it to the client (it is fetched
 * through clip_get when something is pasted there). */
int rdp_clipboard_changed(rdp_session *s);

/* Ask the client to play a beep (e.g. from DisplayBeep()). */
int rdp_beep(rdp_session *s, unsigned freq_hz, unsigned duration_ms);

#endif
