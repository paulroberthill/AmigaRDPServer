/*
 * Clipboard redirection (MS-RDPECLIP), server side, text only.
 *
 * Windows -> host: when the client announces a Format List containing
 * CF_UNICODETEXT (or CF_TEXT), the text is requested straight away and
 * handed to the host, so it is there when an Amiga program pastes.
 *
 * Host -> Windows: cliprdr_local_changed() announces CF_UNICODETEXT; the
 * client asks for the data (Format Data Request) when something is pasted,
 * and only then is the host clipboard read.
 */
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cliprdr.h"

#define CB_MONITOR_READY         0x0001
#define CB_FORMAT_LIST           0x0002
#define CB_FORMAT_LIST_RESPONSE  0x0003
#define CB_FORMAT_DATA_REQUEST   0x0004
#define CB_FORMAT_DATA_RESPONSE  0x0005
#define CB_TEMP_DIRECTORY        0x0006
#define CB_CLIP_CAPS             0x0007

#define CB_RESPONSE_OK           0x0001
#define CB_RESPONSE_FAIL         0x0002

#define CB_USE_LONG_FORMAT_NAMES 0x00000002

#define CF_TEXT                  1
#define CF_UNICODETEXT           13

#define MAX_TEXT                 (512 * 1024)   /* largest clip we accept */

struct cliprdr {
    cliprdr_io io;
    int started;            /* Monitor Ready sent */
    int long_names;         /* both sides support long format names */
    int pending_announce;   /* host clipboard changed before we started */
    unsigned requested;     /* format asked from the client, 0 if none */
};

static void cb_log(cliprdr *c, const char *fmt, ...) __attribute__((format(printf, 2, 3)));

static void cb_log(cliprdr *c, const char *fmt, ...)
{
    char buf[200];
    va_list ap;

    if (!c->io.log)
        return;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    c->io.log(c->io.ctx, buf);
}

static void put16(uint8_t *p, unsigned v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
static void put32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}
static unsigned get16(const uint8_t *p) { return p[0] | (p[1] << 8); }
static uint32_t get32(const uint8_t *p)
{
    return p[0] | (p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* Send a PDU: 8-byte CLIPRDR_HEADER followed by `len` bytes of `data`. */
static int send_pdu(cliprdr *c, unsigned type, unsigned flags, const uint8_t *data, size_t len)
{
    uint8_t small[64], *buf = len + 8 <= sizeof(small) ? small : malloc(len + 8);
    int rc;

    if (!buf)
        return -1;
    put16(buf, type);
    put16(buf + 2, flags);
    put32(buf + 4, (uint32_t)len);
    if (len)
        memcpy(buf + 8, data, len);
    rc = c->io.send(c->io.ctx, buf, len + 8);
    if (buf != small)
        free(buf);
    return rc;
}

cliprdr *cliprdr_new(const cliprdr_io *io)
{
    cliprdr *c = calloc(1, sizeof(*c));
    if (c)
        c->io = *io;
    return c;
}

void cliprdr_free(cliprdr *c)
{
    free(c);
}

static int send_format_list(cliprdr *c)
{
    uint8_t list[36];

    memset(list, 0, sizeof(list));
    put32(list, CF_UNICODETEXT);    /* standard format: empty name */
    cb_log(c, "clipboard: offering host text to the client");
    /* long form: id + empty UTF-16 name; short form: id + 32-byte name */
    return send_pdu(c, CB_FORMAT_LIST, 0, list, c->long_names ? 6 : 36);
}

int cliprdr_start(cliprdr *c)
{
    static const uint8_t caps[16] = {
        1, 0, 0, 0,                 /* cCapabilitiesSets = 1, pad */
        1, 0, 12, 0,                /* CB_CAPSTYPE_GENERAL, length 12 */
        2, 0, 0, 0,                 /* CB_CAPS_VERSION_2 */
        CB_USE_LONG_FORMAT_NAMES, 0, 0, 0
    };

    if (c->started)
        return 0;
    c->started = 1;
    cb_log(c, "clipboard: starting (capabilities, Monitor Ready)");
    if (send_pdu(c, CB_CLIP_CAPS, 0, caps, sizeof(caps)) ||
        send_pdu(c, CB_MONITOR_READY, 0, NULL, 0))
        return -1;
    return 0;
}

int cliprdr_local_changed(cliprdr *c)
{
    if (!c->started) {
        c->pending_announce = 1;
        return 0;
    }
    return send_format_list(c);
}

/* Map the commonest non-Latin-1 punctuation; everything else becomes '?'. */
static char from_unicode(unsigned u)
{
    if (u < 0x100)
        return (char)u;
    switch (u) {
    case 0x2018: case 0x2019: case 0x201a: case 0x2032: return '\'';
    case 0x201c: case 0x201d: case 0x201e: case 0x2033: return '"';
    case 0x2010: case 0x2011: case 0x2012: case 0x2013: case 0x2014: case 0x2212: return '-';
    case 0x2022: case 0x00b7: return '*';
    case 0x2026: return '.';            /* ellipsis: single dot, keeps length 1 */
    case 0x20ac: return 'E';            /* euro sign */
    case 0x00a0: case 0x2002: case 0x2003: case 0x2009: case 0x202f: return ' ';
    }
    return '?';
}

/* Client text (UTF-16LE or ANSI) -> Latin-1, CRLF -> LF, stop at NUL. */
static void deliver_text(cliprdr *c, const uint8_t *p, size_t len, int unicode)
{
    char *out = malloc(len + 1);
    size_t i, n = 0, step = unicode ? 2 : 1;

    if (!out)
        return;
    for (i = 0; i + step <= len; i += step) {
        unsigned u = unicode ? get16(p + i) : p[i];
        if (u == 0)
            break;
        if (unicode && u >= 0xd800 && u <= 0xdbff && i + 4 <= len) {
            i += 2;                     /* surrogate pair: one character */
            out[n++] = '?';
            continue;
        }
        if (u == '\r') {
            unsigned next = i + 2 * step <= len ? (unicode ? get16(p + i + step) : p[i + step]) : 0;
            if (next == '\n')
                continue;               /* drop the CR of CRLF */
            u = '\n';
        }
        out[n++] = from_unicode(u);
    }
    out[n] = 0;
    cb_log(c, "clipboard: received %lu characters from the client", (unsigned long)n);
    if (c->io.set_text)
        c->io.set_text(c->io.ctx, out, n);
    free(out);
}

/* Host text (Latin-1, LF) -> UTF-16LE with CRLF and a terminating NUL. */
static int send_host_text(cliprdr *c)
{
    const char *text = NULL;
    long len = c->io.get_text ? c->io.get_text(c->io.ctx, &text) : -1;
    uint8_t *buf;
    size_t i, n = 0;
    int rc;

    if (len < 0 || !text)
        return send_pdu(c, CB_FORMAT_DATA_RESPONSE, CB_RESPONSE_FAIL, NULL, 0);
    if (len > MAX_TEXT)
        len = MAX_TEXT;
    buf = malloc((size_t)len * 4 + 2);  /* worst case: every char a LF -> CRLF */
    if (!buf)
        return send_pdu(c, CB_FORMAT_DATA_RESPONSE, CB_RESPONSE_FAIL, NULL, 0);
    for (i = 0; i < (size_t)len; i++) {
        unsigned char ch = (unsigned char)text[i];
        if (ch == 0)
            break;
        if (ch == '\n' && (i == 0 || text[i - 1] != '\r')) {
            put16(buf + n, '\r');
            n += 2;
        }
        put16(buf + n, ch);
        n += 2;
    }
    put16(buf + n, 0);
    n += 2;
    cb_log(c, "clipboard: sending %lu characters to the client", (unsigned long)(n / 2 - 1));
    rc = send_pdu(c, CB_FORMAT_DATA_RESPONSE, CB_RESPONSE_OK, buf, n);
    free(buf);
    return rc;
}

/* Find CF_UNICODETEXT / CF_TEXT in a Format List; returns 0 if absent. */
static unsigned pick_format(cliprdr *c, const uint8_t *p, size_t len)
{
    unsigned best = 0;
    size_t i = 0;

    while (i + 4 <= len) {
        uint32_t id = get32(p + i);
        if (c->long_names) {            /* id + NUL-terminated UTF-16 name */
            i += 4;
            while (i + 2 <= len && get16(p + i))
                i += 2;
            i += 2;
        } else
            i += 36;                    /* id + 32-byte name */
        if (id == CF_UNICODETEXT)
            best = CF_UNICODETEXT;
        else if (id == CF_TEXT && !best)
            best = CF_TEXT;
    }
    return best;
}

int cliprdr_receive(cliprdr *c, const uint8_t *data, size_t len)
{
    unsigned type, flags;
    size_t dlen;
    const uint8_t *p = data + 8;

    if (len < 8)
        return 0;
    type = get16(data);
    flags = get16(data + 2);
    dlen = get32(data + 4);
    if (dlen > len - 8)                 /* trailing padding beyond dataLen is fine */
        return 0;

    switch (type) {
    case CB_CLIP_CAPS:
        if (dlen >= 16 && get16(p + 4) == 1)
            c->long_names = (get32(p + 12) & CB_USE_LONG_FORMAT_NAMES) != 0;
        cb_log(c, "clipboard: client capabilities (%s format names)",
             c->long_names ? "long" : "short");
        return 0;
    case CB_TEMP_DIRECTORY:
        return 0;
    case CB_FORMAT_LIST: {
        unsigned fmt = pick_format(c, p, dlen);
        uint8_t req[4];
        if (send_pdu(c, CB_FORMAT_LIST_RESPONSE, CB_RESPONSE_OK, NULL, 0))
            return -1;
        if (c->pending_announce) {      /* our clipboard, held back until now */
            c->pending_announce = 0;
            if (send_format_list(c))
                return -1;
        }
        if (!fmt)
            return 0;
        /* Fetch it now, so it is in the host clipboard before anyone pastes. */
        c->requested = fmt;
        put32(req, fmt);
        return send_pdu(c, CB_FORMAT_DATA_REQUEST, 0, req, 4);
    }
    case CB_FORMAT_LIST_RESPONSE:
        if (flags & CB_RESPONSE_FAIL)
            cb_log(c, "clipboard: client refused our format list");
        return 0;
    case CB_FORMAT_DATA_REQUEST: {
        uint32_t want = dlen >= 4 ? get32(p) : 0;
        if (want == CF_UNICODETEXT)
            return send_host_text(c);
        cb_log(c, "clipboard: client asked for format %lu, which we don't have",
             (unsigned long)want);
        return send_pdu(c, CB_FORMAT_DATA_RESPONSE, CB_RESPONSE_FAIL, NULL, 0);
    }
    case CB_FORMAT_DATA_RESPONSE:
        if (c->requested && (flags & CB_RESPONSE_OK))
            deliver_text(c, p, dlen, c->requested == CF_UNICODETEXT);
        c->requested = 0;
        return 0;
    default:
        return 0;   /* locking, file contents: not supported */
    }
}
