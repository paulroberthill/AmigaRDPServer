/*
 * Clipboard redirection, server side (MS-RDPECLIP), plain text only.
 *
 * Text crosses this interface as Latin-1 with LF line endings (what an
 * Amiga clipboard holds); the module converts to and from the UTF-16 /
 * CRLF that Windows uses.
 */
#ifndef RDP_CLIPRDR_H
#define RDP_CLIPRDR_H

#include <stdint.h>
#include <stddef.h>

typedef struct cliprdr cliprdr;

typedef struct {
    void *ctx;
    /* Send one complete clipboard PDU on the cliprdr channel. */
    int (*send)(void *ctx, const uint8_t *data, size_t len);
    void (*log)(void *ctx, const char *msg);
    /* Host clipboard text: return its length and point *text at it (valid
     * until the next call), or return -1 if there is none. */
    long (*get_text)(void *ctx, const char **text);
    /* New clipboard text from the client. */
    void (*set_text)(void *ctx, const char *text, size_t len);
} cliprdr_io;

cliprdr *cliprdr_new(const cliprdr_io *io);
void cliprdr_free(cliprdr *c);

/* Begin the initialisation sequence (capabilities + Monitor Ready). */
int cliprdr_start(cliprdr *c);

/* Handle one complete (reassembled) clipboard PDU from the client.
 * Returns 0, or -1 on a send error. */
int cliprdr_receive(cliprdr *c, const uint8_t *data, size_t len);

/* The host clipboard has new text: offer it to the client. */
int cliprdr_local_changed(cliprdr *c);

#endif
