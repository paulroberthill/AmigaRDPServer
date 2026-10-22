/*
 * Minimal RDP server core. References are to [MS-RDPBCGR] sections.
 *
 * Wire layering of a slow-path PDU:
 *   TPKT (4) | X.224 data (3) | MCS SendData (7-8) | security header (4 [+8])
 *   | share control header (6) | share data header (12) | payload
 */
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cliprdr.h"
#include "login.h"
#include "rdp.h"
#include "rle.h"
#include "sec.h"
#include "serverkey.h"
#include "stream.h"

#define BUFSZ 0x10000

#define MCS_SERVER_ID   1002
#define MCS_IO_CHANNEL  1003
#define SHARE_ID        0x000103ea
#define MAX_CHANNELS    31

#define TILE 64

/* Security header flags (2.2.8.1.1.2.1) */
#define SEC_EXCHANGE_PKT        0x0001
#define SEC_ENCRYPT             0x0008
#define SEC_INFO_PKT            0x0040
#define SEC_LICENSE_PKT         0x0080
#define SEC_LICENSE_ENCRYPT     0x0200  /* _CS from server, _SC from client */

/* PDU types */
#define PDUTYPE_DEMANDACTIVE    0x1
#define PDUTYPE_CONFIRMACTIVE   0x3
#define PDUTYPE_DEACTIVATEALL   0x6
#define PDUTYPE_DATA            0x7

#define PDUTYPE2_UPDATE             0x02
#define PDUTYPE2_CONTROL            0x14
#define PDUTYPE2_POINTER            0x1b
#define PDUTYPE2_INPUT              0x1c
#define PDUTYPE2_SYNCHRONIZE        0x1f
#define PDUTYPE2_REFRESH_RECT       0x21
#define PDUTYPE2_PLAY_SOUND         0x22
#define PDUTYPE2_SUPPRESS_OUTPUT    0x23
#define PDUTYPE2_SHUTDOWN_REQUEST   0x24
#define PDUTYPE2_SHUTDOWN_DENIED    0x25
#define PDUTYPE2_FONTLIST           0x27
#define PDUTYPE2_FONTMAP            0x28
#define PDUTYPE2_PERSISTENT_LIST    0x2b

#define CTRLACTION_REQUEST_CONTROL  1
#define CTRLACTION_GRANTED_CONTROL  2
#define CTRLACTION_COOPERATE        4

struct rdp_session {
    rdp_config cfg;
    rdp_callbacks cb;
    rdp_sec sec;

    int got_cr, got_ci;
    uint32_t requested_protocols;
    int neg_req_present;
    int lic_encrypt;            /* client accepts encrypted licensing PDUs */
    uint16_t channel_ids[MAX_CHANNELS];
    char channel_names[MAX_CHANNELS][9];
    uint32_t channel_opts[MAX_CHANNELS];
    int nchannels;

    /* Static virtual channels: clipboard, and incoming chunk reassembly */
    cliprdr *clip;
    unsigned clip_chan;         /* MCS id of "cliprdr", 0 if not offered */
    uint32_t clip_opts;
    uint8_t *vc_buf;
    size_t vc_len, vc_total;
    unsigned user_id;           /* the client's MCS user channel */

    int active;                 /* finished connection finalisation */
    int demand_sent;            /* a Demand Active has gone out */
    uint32_t kbd_layout;        /* client keyboard layout id (CS_CORE) */

    /* Authentication (see rdp_config.password) */
    int authed;
    int auth_attempts, auth_failed;
    rdp_login *login;           /* prompt shown until authed */
    uint8_t login_lut[256 * 4];
    uint8_t login_keys[256];    /* keys held at the prompt (scancode | ext << 7) */
    unsigned last_sync;         /* lock-key state, replayed to the host on login */

    int suppress;               /* client asked us to stop sending output */
    int tiles_x, tiles_y;
    uint8_t *dirty;
    int palette_dirty;
    uint8_t lut[256 * 4];       /* palette converted to wire pixel format */
    uint8_t tile[TILE * TILE * 4];  /* one raw tile, before compression */
    unsigned long stat_tiles, stat_raw, stat_sent;
    unsigned client_extra_flags;    /* General capability set extraFlags */

    uint8_t ibuf[BUFSZ];
    uint8_t obuf[BUFSZ + 64];
    uint8_t pbuf[BUFSZ];
};

static void rlog(rdp_session *s, const char *fmt, ...)
{
    char buf[512];
    va_list ap;

    if (!s->cb.log)
        return;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    s->cb.log(s->cb.ctx, buf);
}

#define vlog(s, ...) do { if ((s)->cfg.verbose) rlog((s), __VA_ARGS__); } while (0)

/* ------------------------------------------------------------------ */
/* Low-level framing                                                  */
/* ------------------------------------------------------------------ */

static int send_raw(rdp_session *s, const uint8_t *data, size_t len)
{
    return s->cb.send(s->cb.ctx, data, len);
}

/* TPKT + X.224 Data TPDU around an MCS payload. */
static int send_x224_data(rdp_session *s, const uint8_t *payload, size_t len)
{
    size_t total = len + 7;
    uint8_t *o = s->obuf;

    if (total > sizeof(s->obuf))
        return -1;
    o[0] = 3; o[1] = 0; o[2] = (uint8_t)(total >> 8); o[3] = (uint8_t)total;
    o[4] = 2; o[5] = 0xf0; o[6] = 0x80;
    if (payload != o + 7)
        memmove(o + 7, payload, len);
    return send_raw(s, o, total);
}

/*
 * MCS Send Data Indication on `channel`, with a security header.
 * The payload is copied, MACed and encrypted when `encrypt` is set.
 */
static int send_mcs(rdp_session *s, unsigned channel, unsigned secflags,
                    const uint8_t *data, size_t len, int encrypt)
{
    uint8_t *o = s->obuf;
    size_t ud_len = len + 4 + (encrypt ? 8 : 0), hdr, total;
    size_t pos;

    hdr = 7 + 6 + (ud_len >= 0x80 ? 2 : 1);
    total = hdr + ud_len;
    if (total > 0xffff || total > sizeof(s->obuf))
        return -1;

    o[0] = 3; o[1] = 0; o[2] = (uint8_t)(total >> 8); o[3] = (uint8_t)total;
    o[4] = 2; o[5] = 0xf0; o[6] = 0x80;
    o[7] = 0x68;                                    /* sendDataIndication */
    o[8] = 0; o[9] = MCS_SERVER_ID - 1001;          /* initiator */
    o[10] = (uint8_t)(channel >> 8); o[11] = (uint8_t)channel;
    o[12] = 0x70;                                   /* priority + segmentation */
    pos = 13;
    if (ud_len >= 0x80) {
        o[pos++] = (uint8_t)(0x80 | (ud_len >> 8));
        o[pos++] = (uint8_t)ud_len;
    } else
        o[pos++] = (uint8_t)ud_len;

    if (encrypt)
        secflags |= SEC_ENCRYPT;
    put_u16le(o + pos, secflags);
    put_u16le(o + pos + 2, 0);
    pos += 4;
    if (encrypt) {
        memcpy(o + pos + 8, data, len);
        sec_mac(&s->sec, o + pos + 8, len, o + pos);
        sec_encrypt(&s->sec, o + pos + 8, len);
    } else
        memcpy(o + pos, data, len);
    return send_raw(s, o, total);
}

/* Data PDUs: caller writes payload at pbuf + 18. */
#define DATA_HDR 18

static int send_data_pdu(rdp_session *s, unsigned type2, size_t payload_len)
{
    uint8_t *p = s->pbuf;
    size_t total = DATA_HDR + payload_len;

    put_u16le(p, (unsigned)total);
    put_u16le(p + 2, 0x10 | PDUTYPE_DATA);
    put_u16le(p + 4, MCS_SERVER_ID);
    p[6] = (uint8_t)SHARE_ID; p[7] = (uint8_t)(SHARE_ID >> 8);
    p[8] = (uint8_t)(SHARE_ID >> 16); p[9] = (uint8_t)(SHARE_ID >> 24);
    p[10] = 0;                                  /* pad */
    p[11] = 1;                                  /* STREAM_LOW */
    put_u16le(p + 12, (unsigned)(total - 14));  /* uncompressedLength */
    p[14] = (uint8_t)type2;
    p[15] = 0;                                  /* compressedType */
    put_u16le(p + 16, 0);                       /* compressedLength */
    return send_mcs(s, MCS_IO_CHANNEL, 0, p, total, 1);
}

/* ------------------------------------------------------------------ */
/* Static virtual channels (2.2.6.1) and the clipboard                */
/* ------------------------------------------------------------------ */

#define CHANNEL_CHUNK_LENGTH        1600
#define CHANNEL_FLAG_FIRST          0x01
#define CHANNEL_FLAG_LAST           0x02
#define CHANNEL_FLAG_SHOW_PROTOCOL  0x10
#define CHANNEL_OPTION_SHOW_PROTOCOL 0x00200000
#define VC_MAX_MESSAGE              (1024 * 1024)

/* Send one virtual channel message, split into CHANNEL_PDU_HEADER chunks. */
static int vc_send(rdp_session *s, unsigned chan, uint32_t opts, const uint8_t *data, size_t len)
{
    uint8_t chunk[8 + CHANNEL_CHUNK_LENGTH];
    size_t off = 0;

    do {
        size_t n = len - off > CHANNEL_CHUNK_LENGTH ? CHANNEL_CHUNK_LENGTH : len - off;
        uint32_t flags = (off == 0 ? CHANNEL_FLAG_FIRST : 0) |
                         (off + n == len ? CHANNEL_FLAG_LAST : 0) |
                         (opts & CHANNEL_OPTION_SHOW_PROTOCOL ? CHANNEL_FLAG_SHOW_PROTOCOL : 0);
        put_u16le(chunk, (unsigned)len);
        put_u16le(chunk + 2, (unsigned)(len >> 16));
        put_u16le(chunk + 4, flags);
        put_u16le(chunk + 6, 0);
        memcpy(chunk + 8, data + off, n);
        if (send_mcs(s, chan, 0, chunk, 8 + n, 1))
            return -1;
        off += n;
    } while (off < len);
    return 0;
}

static int clip_send(void *ctx, const uint8_t *data, size_t len)
{
    rdp_session *s = ctx;
    return vc_send(s, s->clip_chan, s->clip_opts, data, len);
}

static void clip_log(void *ctx, const char *msg)
{
    rlog((rdp_session *)ctx, "%s", msg);
}

static long clip_get(void *ctx, const char **text)
{
    rdp_session *s = ctx;
    return s->cb.clip_get(s->cb.ctx, text);
}

static void clip_set(void *ctx, const char *text, size_t len)
{
    rdp_session *s = ctx;
    if (s->cb.clip_set)
        s->cb.clip_set(s->cb.ctx, text, len);
}

/* The clipboard runs only once the session is active and logged in. */
static int maybe_start_clipboard(rdp_session *s)
{
    if (s->clip && s->clip_chan && s->active && s->authed)
        return cliprdr_start(s->clip);
    return 0;
}

int rdp_clipboard_changed(rdp_session *s)
{
    /* Before the clipboard has started this only marks it to be offered
     * once it does (it never starts if the client has no "cliprdr"). */
    return s->clip ? cliprdr_local_changed(s->clip) : 0;
}

/* Incoming chunk on a virtual channel (already decrypted). */
static int vc_receive(rdp_session *s, unsigned chan, stream *in)
{
    uint32_t total, flags;
    size_t n;

    if (chan != s->clip_chan || !s->clip || !s->authed) {
        vlog(s, "<- %u bytes on virtual channel %u ignored", (unsigned)s_left(in), chan);
        return 0;
    }
    total = s_u32le(in);
    flags = s_u32le(in);
    if (in->err)
        return 0;
    n = s_left(in);
    if ((flags & CHANNEL_FLAG_FIRST) && (flags & CHANNEL_FLAG_LAST))
        return cliprdr_receive(s->clip, in->p, n);      /* the common case */
    if (flags & CHANNEL_FLAG_FIRST) {
        free(s->vc_buf);
        s->vc_buf = total <= VC_MAX_MESSAGE ? malloc(total) : NULL;
        s->vc_total = s->vc_buf ? total : 0;
        s->vc_len = 0;
        if (!s->vc_buf)
            rlog(s, "virtual channel message of %lu bytes dropped", (unsigned long)total);
    }
    if (!s->vc_buf || s->vc_len + n > s->vc_total)
        return 0;
    memcpy(s->vc_buf + s->vc_len, in->p, n);
    s->vc_len += n;
    if (flags & CHANNEL_FLAG_LAST) {
        int rc = s->vc_len == s->vc_total ? cliprdr_receive(s->clip, s->vc_buf, s->vc_len) : 0;
        free(s->vc_buf);
        s->vc_buf = NULL;
        return rc;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Connection sequence: X.224 and MCS                                 */
/* ------------------------------------------------------------------ */

/* 2.2.1.1 X.224 Connection Request -> 2.2.1.2 Connection Confirm */
static int handle_x224_cr(rdp_session *s, stream *in)
{
    uint8_t li = s_u8(in), code = s_u8(in), cc[19];
    size_t n;

    if (code != 0xe0 || li < 6)
        return -1;
    s_skip(in, 5);                  /* dst-ref, src-ref, class */
    /* optional "Cookie: mstshash=...\r\n" or routing token */
    if (s_left(in) >= 2 && in->p[0] != 0x01) {
        uint8_t *q = in->p;
        while (q + 1 < in->end && !(q[0] == '\r' && q[1] == '\n'))
            q++;
        if (q + 1 < in->end) {
            rlog(s, "X.224 CR cookie: %.*s", (int)(q - in->p), (char *)in->p);
            in->p = q + 2;
        }
    }
    if (s_left(in) >= 8 && in->p[0] == 0x01) {    /* TYPE_RDP_NEG_REQ */
        s_skip(in, 4);
        s->requested_protocols = s_u32le(in);
        s->neg_req_present = 1;
    }
    rlog(s, "X.224 CR: negotiation %s, requestedProtocols=0x%x%s%s%s",
         s->neg_req_present ? "present" : "absent", (unsigned)s->requested_protocols,
         s->requested_protocols & 1 ? " TLS" : "", s->requested_protocols & 2 ? " CredSSP" : "",
         s->requested_protocols & 8 ? " RDSTLS" : "");

    n = 0;
    cc[n++] = 3; cc[n++] = 0; cc[n++] = 0; cc[n++] = 0;   /* TPKT, length below */
    cc[n++] = s->neg_req_present ? 14 : 6;                /* LI */
    cc[n++] = 0xd0;                                       /* CC */
    cc[n++] = 0; cc[n++] = 0;                             /* dst-ref */
    cc[n++] = 0x12; cc[n++] = 0x34;                       /* src-ref */
    cc[n++] = 0;                                          /* class 0 */
    if (s->neg_req_present) {
        int fail = s->cfg.neg_fail && s->requested_protocols != 0;
        cc[n++] = fail ? 0x03 : 0x02;     /* RDP_NEG_FAILURE / RDP_NEG_RSP */
        cc[n++] = 0;                      /* flags */
        cc[n++] = 8; cc[n++] = 0;         /* length */
        cc[n++] = fail ? 2 : 0;           /* SSL_NOT_ALLOWED_BY_SERVER / PROTOCOL_RDP */
        cc[n++] = 0; cc[n++] = 0; cc[n++] = 0;
        if (fail) {
            cc[3] = (uint8_t)n;
            rlog(s, "-> RDP_NEG_FAILURE (SSL_NOT_ALLOWED_BY_SERVER); "
                    "client should reconnect with Standard RDP Security");
            send_raw(s, cc, n);
            return -1;
        }
        rlog(s, "-> RDP_NEG_RSP selectedProtocol=PROTOCOL_RDP");
    }
    cc[3] = (uint8_t)n;
    s->got_cr = 1;
    return send_raw(s, cc, n);
}

static size_t ber_read_len(stream *in)
{
    uint8_t b = s_u8(in);
    size_t len = 0;
    int i;

    if (!(b & 0x80))
        return b;
    for (i = 0; i < (b & 0x7f) && i < 4; i++)
        len = (len << 8) | s_u8(in);
    return len;
}

static size_t per_read_len(stream *in)
{
    uint8_t b = s_u8(in);
    if (b & 0x80)
        return ((size_t)(b & 0x7f) << 8) | s_u8(in);
    return b;
}

static void ber_write_len(stream *w, size_t len)
{
    if (len < 0x80)
        w_u8(w, (unsigned)len);
    else if (len < 0x100) {
        w_u8(w, 0x81); w_u8(w, (unsigned)len);
    } else {
        w_u8(w, 0x82); w_u16be(w, (unsigned)len);
    }
}

static void per_write_len(stream *w, size_t len)
{
    if (len < 0x80)
        w_u8(w, (unsigned)len);
    else
        w_u16be(w, (unsigned)(0x8000 | len));
}

/* Parse the client data blocks from the GCC Conference Create Request. */
static int parse_client_data(rdp_session *s, stream *in)
{
    uint32_t enc_methods = 0, ext_enc_methods = 0;

    while (s_left(in) >= 4) {
        uint16_t type = s_u16le(in), len = s_u16le(in);
        stream b;

        if (len < 4 || (size_t)(len - 4) > s_left(in))
            return -1;
        s_init(&b, in->p, len - 4);
        in->p += len - 4;

        switch (type) {
        case 0xc001: {  /* CS_CORE 2.2.1.3.2 */
            uint32_t ver = s_u32le(&b);
            unsigned w = s_u16le(&b), h = s_u16le(&b), hi_depth = 0, supp = 0, early = 0;
            uint16_t name[16];
            char cname[17];
            int i;
            uint32_t sel = 0;

            s_skip(&b, 2 + 2);                  /* colorDepth, SASSequence */
            s->kbd_layout = s_u32le(&b);
            uint32_t build = s_u32le(&b);
            for (i = 0; i < 16; i++)
                name[i] = s_u16le(&b);
            for (i = 0; i < 16 && name[i]; i++)
                cname[i] = name[i] < 128 ? (char)name[i] : '?';
            cname[i] = 0;
            s_skip(&b, 12 + 64);                /* keyboard type/sub/fn, ime */
            if (s_left(&b) >= 2 + 2 + 4 + 2 + 2 + 2) {
                s_skip(&b, 2 + 2 + 4);          /* postBeta2ColorDepth, productId, serial */
                hi_depth = s_u16le(&b);
                supp = s_u16le(&b);
                early = s_u16le(&b);
            }
            if (s_left(&b) >= 64 + 2 + 4) {
                s_skip(&b, 64 + 2);
                sel = s_u32le(&b);
            }
            rlog(s, "CS_CORE: version 0x%08x, client \"%s\" build %u, %ux%u, "
                    "highColorDepth %u, supportedColorDepths 0x%x, earlyCaps 0x%x, "
                    "serverSelectedProtocol %u, keyboard layout 0x%x",
                 (unsigned)ver, cname, (unsigned)build, w, h, hi_depth, supp, early,
                 (unsigned)sel, (unsigned)s->kbd_layout);
            break;
        }
        case 0xc002:    /* CS_SECURITY 2.2.1.3.3 */
            enc_methods = s_u32le(&b);
            ext_enc_methods = s_u32le(&b);
            rlog(s, "CS_SECURITY: encryptionMethods 0x%x ext 0x%x",
                 (unsigned)enc_methods, (unsigned)ext_enc_methods);
            break;
        case 0xc003: {  /* CS_NET 2.2.1.3.4 */
            uint32_t count = s_u32le(&b), i;
            for (i = 0; i < count && s_left(&b) >= 12; i++) {
                uint32_t opts;
                if (s->nchannels < MAX_CHANNELS) {
                    s_read(&b, s->channel_names[s->nchannels], 8);
                    s->channel_names[s->nchannels][8] = 0;
                    s->channel_ids[s->nchannels] = (uint16_t)(MCS_IO_CHANNEL + 1 + s->nchannels);
                    opts = s_u32le(&b);
                    s->channel_opts[s->nchannels] = opts;
                    rlog(s, "CS_NET: channel \"%s\" options 0x%08x -> id %u",
                         s->channel_names[s->nchannels], (unsigned)opts,
                         s->channel_ids[s->nchannels]);
                    if (!strcmp(s->channel_names[s->nchannels], "cliprdr")) {
                        s->clip_chan = s->channel_ids[s->nchannels];
                        s->clip_opts = opts;
                    }
                    s->nchannels++;
                } else
                    s_skip(&b, 12);
            }
            break;
        }
        default:
            rlog(s, "client data block 0x%04x (%u bytes) ignored", type, len);
            break;
        }
    }
    /* Some locales put the methods in extEncryptionMethods instead. */
    if (!((enc_methods | ext_enc_methods) & 0x02)) {
        rlog(s, "client does not offer 128-bit RC4 (methods 0x%x/0x%x); unsupported",
             (unsigned)enc_methods, (unsigned)ext_enc_methods);
        return -1;
    }
    return 0;
}

/* 2.2.1.3 MCS Connect Initial -> 2.2.1.4 MCS Connect Response */
static int handle_mcs_connect_initial(rdp_session *s, stream *in)
{
    stream w, ud;
    size_t len;
    int i;
    uint8_t *blocks, *start;
    uint8_t *p;

    if (s_u8(in) != 0x7f || s_u8(in) != 0x65)
        return -1;
    ber_read_len(in);
    /* callingDomainSelector, calledDomainSelector, upwardFlag,
     * target/minimum/maximum parameters, then userData. */
    for (i = 0; i < 6; i++) {
        s_u8(in);
        len = ber_read_len(in);
        s_skip(in, len);
    }
    if (s_u8(in) != 0x04)
        return -1;
    len = ber_read_len(in);
    if (in->err || len > s_left(in))
        return -1;
    s_init(&ud, in->p, len);

    /* GCC Conference Create Request: find the "Duca" H.221 key, then
     * a PER length and the client data blocks. */
    for (p = ud.p; p + 4 <= ud.end && memcmp(p, "Duca", 4); p++)
        ;
    if (p + 4 > ud.end)
        return -1;
    ud.p = p + 4;
    len = per_read_len(&ud);
    if (ud.err || len > s_left(&ud))
        return -1;
    ud.end = ud.p + len;
    if (parse_client_data(s, &ud))
        return -1;

    s->cb.random(s->cb.ctx, s->sec.server_random, 32);

    /* Build the server data blocks first (in pbuf), then wrap them. */
    s_init(&w, s->pbuf, sizeof(s->pbuf));
    blocks = w.p;
    /* SC_CORE */
    w_u16le(&w, 0x0c01); w_u16le(&w, 12);
    w_u32le(&w, 0x00080004);
    w_u32le(&w, s->requested_protocols);
    /* SC_NET */
    w_u16le(&w, 0x0c03); w_u16le(&w, (unsigned)(8 + 2 * ((s->nchannels + 1) & ~1)));
    w_u16le(&w, MCS_IO_CHANNEL);
    w_u16le(&w, (unsigned)s->nchannels);
    for (i = 0; i < s->nchannels; i++)
        w_u16le(&w, s->channel_ids[i]);
    if (s->nchannels & 1)
        w_u16le(&w, 0);
    /* SC_SECURITY */
    w_u16le(&w, 0x0c02); w_u16le(&w, 4 + 16 + 32 + server_cert_len);
    w_u32le(&w, 0x00000002);        /* ENCRYPTION_METHOD_128BIT */
    w_u32le(&w, 2);                 /* ENCRYPTION_LEVEL_CLIENT_COMPATIBLE */
    w_u32le(&w, 32);
    w_u32le(&w, server_cert_len);
    w_bytes(&w, s->sec.server_random, 32);
    w_bytes(&w, server_cert, server_cert_len);
    len = (size_t)(w.p - blocks);

    /* MCS Connect Response (BER) wrapping the GCC Conference Create
     * Response (PER) wrapping the blocks; built in obuf after TPKT/X.224. */
    {
        uint8_t gcc[64];
        stream g;
        size_t gcc_len, body_len;
        stream o;

        s_init(&g, gcc, sizeof(gcc));
        w_bytes(&g, "\x00\x05\x00\x14\x7c\x00\x01", 7);   /* t124 OID */
        /* connectPDU length (ignored by clients, but keep it right) */
        per_write_len(&g, 13 + (len >= 0x80 ? 2 : 1) + len);
        w_bytes(&g, "\x14\x76\x0a\x01\x01\x00\x01\xc0\x00McDn", 13);
        per_write_len(&g, len);
        gcc_len = (size_t)(g.p - gcc);

        body_len = 3 + 3 + 28 + 1 + (gcc_len + len < 0x80 ? 1 : gcc_len + len < 0x100 ? 2 : 3)
                   + gcc_len + len;
        s_init(&o, s->obuf + 7, sizeof(s->obuf) - 7);
        start = o.p;
        w_u8(&o, 0x7f); w_u8(&o, 0x66);
        ber_write_len(&o, body_len);
        w_bytes(&o, "\x0a\x01\x00", 3);                   /* result */
        w_bytes(&o, "\x02\x01\x00", 3);                   /* calledConnectId */
        w_bytes(&o, "\x30\x1a\x02\x01\x22\x02\x01\x03\x02\x01\x00\x02\x01\x01"
                    "\x02\x01\x00\x02\x01\x01\x02\x03\x00\xff\xf8\x02\x01\x02", 28);
        w_u8(&o, 0x04);
        ber_write_len(&o, gcc_len + len);
        w_bytes(&o, gcc, gcc_len);
        w_bytes(&o, blocks, len);
        if (o.err)
            return -1;
        s->got_ci = 1;
        rlog(s, "-> MCS Connect Response (%u channels, 128-bit RC4, %u-byte certificate)",
             (unsigned)s->nchannels, server_cert_len);
        return send_x224_data(s, start, (size_t)(o.p - start));
    }
}

/* ------------------------------------------------------------------ */
/* Capability exchange and finalisation                               */
/* ------------------------------------------------------------------ */

static void cap_begin(stream *w, uint8_t **hdr, unsigned type)
{
    *hdr = w->p;
    w_u16le(w, type);
    w_u16le(w, 0);
}

static void cap_end(stream *w, uint8_t *hdr)
{
    put_u16le(hdr + 2, (unsigned)(w->p - hdr));
}

/* 2.2.1.13.1 Demand Active PDU */
static int send_demand_active(rdp_session *s)
{
    stream w;
    uint8_t *hdr, *caps, *lencaps;
    int ncaps = 0;

    s_init(&w, s->pbuf, sizeof(s->pbuf));
    w_u16le(&w, 0);                         /* totalLength, patched */
    w_u16le(&w, 0x10 | PDUTYPE_DEMANDACTIVE);
    w_u16le(&w, MCS_SERVER_ID);
    w_u32le(&w, SHARE_ID);
    w_u16le(&w, 4);                         /* lengthSourceDescriptor */
    lencaps = w.p;
    w_u16le(&w, 0);                         /* lengthCombinedCapabilities */
    w_bytes(&w, "RDP", 4);
    caps = w.p;
    w_u16le(&w, 0);                         /* numberCapabilities */
    w_u16le(&w, 0);

    cap_begin(&w, &hdr, 9);                 /* Share */
    w_u16le(&w, MCS_SERVER_ID); w_u16le(&w, 0);
    cap_end(&w, hdr); ncaps++;

    cap_begin(&w, &hdr, 1);                 /* General */
    w_u16le(&w, 0);                         /* osMajorType: unspecified */
    w_u16le(&w, 0);                         /* osMinorType */
    w_u16le(&w, 0x0200);                    /* TS_CAPS_PROTOCOLVERSION */
    w_u16le(&w, 0);
    w_u16le(&w, 0);                         /* compressionTypes */
    /* LONG_CREDENTIALS_SUPPORTED | NO_BITMAP_COMPRESSION_HDR */
    w_u16le(&w, 0x0004 | 0x0400);
    w_u16le(&w, 0); w_u16le(&w, 0); w_u16le(&w, 0);
    w_u8(&w, 1);                            /* refreshRectSupport */
    w_u8(&w, 1);                            /* suppressOutputSupport */
    cap_end(&w, hdr); ncaps++;

    cap_begin(&w, &hdr, 20);                /* Virtual channel */
    w_u32le(&w, 0);
    cap_end(&w, hdr); ncaps++;

    cap_begin(&w, &hdr, 14);                /* Font */
    w_u16le(&w, 1); w_u16le(&w, 0);
    cap_end(&w, hdr); ncaps++;

    cap_begin(&w, &hdr, 2);                 /* Bitmap */
    w_u16le(&w, (unsigned)s->cfg.bpp);
    w_u16le(&w, 1); w_u16le(&w, 1); w_u16le(&w, 1);
    w_u16le(&w, (unsigned)s->cfg.width);
    w_u16le(&w, (unsigned)s->cfg.height);
    w_u16le(&w, 0);
    w_u16le(&w, 1);                         /* desktopResizeFlag */
    w_u16le(&w, 1);                         /* bitmapCompressionFlag */
    w_u8(&w, 0); w_u8(&w, 0);
    w_u16le(&w, 1);                         /* multipleRectangleSupport */
    w_u16le(&w, 0);
    cap_end(&w, hdr); ncaps++;

    cap_begin(&w, &hdr, 3);                 /* Order: no drawing orders */
    w_zero(&w, 16 + 4);
    w_u16le(&w, 1); w_u16le(&w, 20); w_u16le(&w, 0);
    w_u16le(&w, 1);                         /* maximumOrderLevel */
    w_u16le(&w, 0);
    w_u16le(&w, 0x0022);                    /* COLORINDEX | NEGOTIATEORDERSUPPORT */
    w_zero(&w, 32);                         /* orderSupport: none */
    w_u16le(&w, 0); w_u16le(&w, 0);
    w_u32le(&w, 0);
    w_u32le(&w, 480 * 480);                 /* desktopSaveSize */
    w_u16le(&w, 0); w_u16le(&w, 0); w_u16le(&w, 0); w_u16le(&w, 0);
    cap_end(&w, hdr); ncaps++;

    cap_begin(&w, &hdr, 10);                /* Colour table cache */
    w_u16le(&w, 6); w_u16le(&w, 0);
    cap_end(&w, hdr); ncaps++;

    cap_begin(&w, &hdr, 8);                 /* Pointer */
    w_u16le(&w, 1); w_u16le(&w, 25); w_u16le(&w, 25);
    cap_end(&w, hdr); ncaps++;

    cap_begin(&w, &hdr, 13);                /* Input */
    /* SCANCODES | MOUSEX | FASTPATH_INPUT2 | UNICODE */
    w_u16le(&w, 0x0001 | 0x0004 | 0x0020 | 0x0010);
    w_u16le(&w, 0);
    w_u32le(&w, 0x409); w_u32le(&w, 4); w_u32le(&w, 0); w_u32le(&w, 12);
    w_zero(&w, 64);
    cap_end(&w, hdr); ncaps++;

    put_u16le(caps, (unsigned)ncaps);
    put_u16le(lencaps, (unsigned)(w.p - caps));
    w_u32le(&w, 0);                         /* sessionId */
    put_u16le(s->pbuf, (unsigned)(w.p - s->pbuf));
    if (w.err)
        return -1;
    rlog(s, "-> Demand Active (%dx%d, %d bpp)", s->cfg.width, s->cfg.height, s->cfg.bpp);
    s->demand_sent = 1;
    return send_mcs(s, MCS_IO_CHANNEL, 0, s->pbuf, (size_t)(w.p - s->pbuf), 1);
}

/* 2.2.3.1 Deactivate All PDU */
static int send_deactivate_all(rdp_session *s)
{
    uint8_t *p = s->pbuf;

    put_u16le(p, 13);
    put_u16le(p + 2, 0x10 | PDUTYPE_DEACTIVATEALL);
    put_u16le(p + 4, MCS_SERVER_ID);
    p[6] = (uint8_t)SHARE_ID; p[7] = (uint8_t)(SHARE_ID >> 8);
    p[8] = (uint8_t)(SHARE_ID >> 16); p[9] = (uint8_t)(SHARE_ID >> 24);
    put_u16le(p + 10, 1);           /* lengthSourceDescriptor */
    p[12] = 0;                      /* sourceDescriptor */
    rlog(s, "-> Deactivate All");
    return send_mcs(s, MCS_IO_CHANNEL, 0, p, 13, 1);
}

/* 2.2.1.12 License Error PDU - Valid Client: skips licensing entirely. */
static int send_license_valid_client(rdp_session *s)
{
    static const uint8_t lic[16] = {
        0xff, 0x03, 0x10, 0x00,     /* ERROR_ALERT, PREAMBLE_VERSION_3_0, size 16 */
        0x07, 0x00, 0x00, 0x00,     /* STATUS_VALID_CLIENT */
        0x02, 0x00, 0x00, 0x00,     /* ST_NO_TRANSITION */
        0x04, 0x00, 0x00, 0x00      /* BB_ERROR_BLOB, length 0 */
    };
    rlog(s, "-> License Error PDU (valid client)%s", s->lic_encrypt ? ", encrypted" : "");
    return send_mcs(s, MCS_IO_CHANNEL,
                    SEC_LICENSE_PKT | (s->lic_encrypt ? SEC_LICENSE_ENCRYPT : 0),
                    lic, sizeof(lic), s->lic_encrypt);
}

static void parse_confirm_active(rdp_session *s, stream *in)
{
    unsigned lsd, ncaps, i;

    s_skip(in, 4 + 2);          /* shareId, originatorId */
    lsd = s_u16le(in);
    s_u16le(in);                /* lengthCombinedCapabilities */
    s_skip(in, lsd);
    ncaps = s_u16le(in);
    s_skip(in, 2);
    for (i = 0; i < ncaps && !in->err; i++) {
        unsigned type = s_u16le(in), len = s_u16le(in);
        stream c;

        if (len < 4 || len - 4 > s_left(in))
            break;
        s_init(&c, in->p, len - 4);
        in->p += len - 4;
        if (type == 1) {
            s_skip(&c, 10);
            s->client_extra_flags = s_u16le(&c);
            rlog(s, "  client General caps: extraFlags 0x%04x", s->client_extra_flags);
        } else if (type == 2) {
            unsigned bpp = s_u16le(&c), w, h;
            s_skip(&c, 6);
            w = s_u16le(&c); h = s_u16le(&c);
            /* mstsc echoes its own requested size/depth here but still uses
             * the server's Demand Active values, so this is informational. */
            rlog(s, "  client Bitmap caps: %u bpp, %ux%u", bpp, w, h);
        } else if (type == 13) {
            rlog(s, "  client Input caps: flags 0x%04x", s_u16le(&c));
        } else
            vlog(s, "  client capability %u (%u bytes)", type, len);
    }
    rlog(s, "<- Confirm Active (%u capability sets)", ncaps);
}

static int send_synchronize(rdp_session *s)
{
    uint8_t *p = s->pbuf + DATA_HDR;
    put_u16le(p, 1);                /* SYNCMSGTYPE_SYNC */
    put_u16le(p + 2, 0);            /* targetUser (3.3.5.3.19: zero) */
    return send_data_pdu(s, PDUTYPE2_SYNCHRONIZE, 4);
}

static int send_control(rdp_session *s, unsigned action, unsigned grant, uint32_t control)
{
    uint8_t *p = s->pbuf + DATA_HDR;
    put_u16le(p, action);
    put_u16le(p + 2, grant);
    put_u16le(p + 4, (unsigned)control);
    put_u16le(p + 6, (unsigned)(control >> 16));
    return send_data_pdu(s, PDUTYPE2_CONTROL, 8);
}

static int send_font_map(rdp_session *s)
{
    uint8_t *p = s->pbuf + DATA_HDR;
    put_u16le(p, 0); put_u16le(p + 2, 0);
    put_u16le(p + 4, 3);            /* FONTMAP_FIRST | FONTMAP_LAST */
    put_u16le(p + 6, 4);
    return send_data_pdu(s, PDUTYPE2_FONTMAP, 8);
}

static int send_default_pointer(rdp_session *s)
{
    uint8_t *p = s->pbuf + DATA_HDR;
    put_u16le(p, 1);                /* TS_PTRMSGTYPE_SYSTEM */
    put_u16le(p + 2, 0);
    put_u16le(p + 4, 0x7f00);       /* SYSPTR_DEFAULT */
    put_u16le(p + 6, 0);
    return send_data_pdu(s, PDUTYPE2_POINTER, 8);
}

int rdp_beep(rdp_session *s, unsigned freq_hz, unsigned duration_ms)
{
    uint8_t *p = s->pbuf + DATA_HDR;
    if (!s->active || !s->authed)
        return 0;
    put_u16le(p, duration_ms & 0xffff); put_u16le(p + 2, duration_ms >> 16);
    put_u16le(p + 4, freq_hz & 0xffff); put_u16le(p + 6, freq_hz >> 16);
    return send_data_pdu(s, PDUTYPE2_PLAY_SOUND, 8);
}

/* ------------------------------------------------------------------ */
/* Graphics                                                           */
/* ------------------------------------------------------------------ */

static int bytes_per_pixel(int bpp)
{
    return (bpp + 7) / 8;
}

/* Convert a 256-entry RGB palette to wire pixels for `bpp`. */
static void build_lut(int bpp, const uint8_t *pal, uint8_t *lut)
{
    int i;

    if (!pal)
        return;
    for (i = 0; i < 256; i++) {
        unsigned r = pal[i * 3], g = pal[i * 3 + 1], b = pal[i * 3 + 2], v;
        switch (bpp) {
        case 15:
            v = ((r >> 3) << 10) | ((g >> 3) << 5) | (b >> 3);
            lut[i * 2] = (uint8_t)v; lut[i * 2 + 1] = (uint8_t)(v >> 8);
            break;
        case 16:
            v = ((r >> 3) << 11) | ((g >> 2) << 5) | (b >> 3);
            lut[i * 2] = (uint8_t)v; lut[i * 2 + 1] = (uint8_t)(v >> 8);
            break;
        case 24:
            lut[i * 3] = (uint8_t)b; lut[i * 3 + 1] = (uint8_t)g;
            lut[i * 3 + 2] = (uint8_t)r;
            break;
        case 32:
            lut[i * 4] = (uint8_t)b; lut[i * 4 + 1] = (uint8_t)g;
            lut[i * 4 + 2] = (uint8_t)r; lut[i * 4 + 3] = 0xff;
            break;
        }
    }
}

/* 2.2.9.1.1.3.1.1 Palette Update */
static int send_palette(rdp_session *s)
{
    uint8_t *p = s->pbuf + DATA_HDR;
    put_u16le(p, 2);                /* UPDATETYPE_PALETTE */
    put_u16le(p + 2, 0);
    put_u16le(p + 4, 256); put_u16le(p + 6, 0);
    memcpy(p + 8, s->authed ? s->cfg.palette : login_palette(), 768);
    return send_data_pdu(s, PDUTYPE2_UPDATE, 8 + 768);
}

/* Raw wire-format pixels of a rectangle: bottom-up rows, `wpad` wide (the
 * padding repeats the last pixel, which compresses best). */
static void raw_rect(rdp_session *s, uint8_t *d, int x, int y, int w, int h, int wpad)
{
    int bpp = bytes_per_pixel(s->cfg.bpp), row, col;
    /* Until the client has logged in, show the login prompt instead. */
    const uint8_t *fb = s->authed ? s->cfg.fb : login_fb(s->login);
    const uint8_t *lut = s->authed ? s->lut : s->login_lut;
    int pitch = s->authed ? s->cfg.pitch : s->cfg.width;
    int wire = s->authed && s->cfg.fb_wire;

    for (row = h - 1; row >= 0; row--) {
        const uint8_t *src = fb + (size_t)(y + row) * pitch + (size_t)x * (wire ? bpp : 1);
        uint8_t *line = d;
        if (wire) {
            memcpy(d, src, (size_t)w * bpp);
            d += w * bpp;
        } else switch (bpp) {
        case 1:
            memcpy(d, src, (size_t)w);
            d += w;
            break;
        case 2:
            for (col = 0; col < w; col++) {
                d[0] = lut[src[col] * 2];
                d[1] = lut[src[col] * 2 + 1];
                d += 2;
            }
            break;
        case 3:
            for (col = 0; col < w; col++) {
                memcpy(d, lut + src[col] * 3, 3);
                d += 3;
            }
            break;
        case 4:
            for (col = 0; col < w; col++) {
                memcpy(d, lut + src[col] * 4, 4);
                d += 4;
            }
            break;
        }
        for (col = w; col < wpad; col++, d += bpp)
            memcpy(d, line + (size_t)(w - 1) * bpp, (size_t)bpp);
    }
}

/*
 * Write one TS_BITMAP_DATA for the given rectangle, RLE-compressed when
 * that is possible and smaller. Rows are bottom-up, padded to a multiple
 * of 4 pixels. Returns the bytes written to `out`.
 */
static size_t encode_rect(rdp_session *s, uint8_t *out, int x, int y, int w, int h)
{
    int bpp = bytes_per_pixel(s->cfg.bpp), wpad = (w + 3) & ~3;
    size_t raw_len = (size_t)wpad * h * bpp, clen = 0;

    raw_rect(s, s->tile, x, y, w, h, wpad);

    put_u16le(out, (unsigned)x);
    put_u16le(out + 2, (unsigned)y);
    put_u16le(out + 4, (unsigned)(x + w - 1));
    put_u16le(out + 6, (unsigned)(y + h - 1));
    put_u16le(out + 8, (unsigned)wpad);
    put_u16le(out + 10, (unsigned)h);
    put_u16le(out + 12, (unsigned)s->cfg.bpp);

    /*
     * Interleaved RLE exists for 8-24 bpp only. When both sides support
     * NO_BITMAP_COMPRESSION_HDR (mstsc and Windows servers do), the 8-byte
     * TS_CD_HEADER is left out, as Windows does. Otherwise it is sent with
     * cbScanWidth as the line size in bytes, as xrdp and rdesktop treat it
     * (MS-RDPBCGR says pixels; the two differ above 8 bpp). Leave room so
     * that a compressed tile is never bigger than the raw one.
     */
    int hdr = (s->client_extra_flags & 0x0400) ? 0 : 8;
    if (!s->cfg.no_compress && s->cfg.bpp != 32)
        clen = rle_encode(s->tile, wpad, h, bpp, out + 18 + hdr, raw_len - hdr - 1);
    s->stat_tiles++;
    s->stat_raw += raw_len;
    if (clen) {
        put_u16le(out + 16, (unsigned)(hdr + clen));
        if (hdr) {
            put_u16le(out + 14, 0x0001);    /* BITMAP_COMPRESSION */
            put_u16le(out + 18, 0);         /* cbCompFirstRowSize */
            put_u16le(out + 20, (unsigned)clen);
            put_u16le(out + 22, (unsigned)(wpad * bpp));
            put_u16le(out + 24, (unsigned)raw_len);
        } else
            put_u16le(out + 14, 0x0401);    /* | NO_BITMAP_COMPRESSION_HDR */
        s->stat_sent += hdr + clen;
        return 18 + hdr + clen;
    }
    put_u16le(out + 14, 0);                 /* uncompressed */
    put_u16le(out + 16, (unsigned)raw_len);
    memcpy(out + 18, s->tile, raw_len);
    s->stat_sent += raw_len;
    return 18 + raw_len;
}

static void mark_dirty(rdp_session *s, int x, int y, int w, int h)
{
    int tx0, ty0, tx1, ty1, tx, ty;

    if (x < 0) { w += x; x = 0; }
    if (y < 0) { h += y; y = 0; }
    if (x + w > s->cfg.width) w = s->cfg.width - x;
    if (y + h > s->cfg.height) h = s->cfg.height - y;
    if (w <= 0 || h <= 0)
        return;
    tx0 = x / TILE; ty0 = y / TILE;
    tx1 = (x + w - 1) / TILE; ty1 = (y + h - 1) / TILE;
    for (ty = ty0; ty <= ty1; ty++)
        for (tx = tx0; tx <= tx1; tx++)
            s->dirty[ty * s->tiles_x + tx] = 1;
}

void rdp_mark_dirty(rdp_session *s, int x, int y, int w, int h)
{
    if (s->authed)              /* the login prompt is drawn by us */
        mark_dirty(s, x, y, w, h);
}

void rdp_palette_changed(rdp_session *s)
{
    build_lut(s->cfg.bpp, s->cfg.palette, s->lut);
    if (!s->authed)
        return;
    s->palette_dirty = 1;
    /* In high colour the pixels themselves change on the wire. */
    if (s->cfg.bpp != 8)
        mark_dirty(s, 0, 0, s->cfg.width, s->cfg.height);
}

/*
 * Bitmap updates are packed into PDUs of at most PDU_DATA_MAX bytes: the
 * MCS length encoding (PER) cannot express 16384 or more without
 * fragmentation, which clients reject.
 */
#define PDU_DATA_MAX 16000

int rdp_flush(rdp_session *s)
{
    int t, sub, ntiles = s->tiles_x * s->tiles_y, bpp = bytes_per_pixel(s->cfg.bpp);

    if (!s->active || s->suppress)
        return 0;
    if (s->palette_dirty && s->cfg.bpp == 8) {
        if (send_palette(s))
            return -1;
    }
    s->palette_dirty = 0;

    t = sub = 0;                    /* sub: first row of tile t still to send */
    while (t < ntiles) {
        /* 2.2.9.1.1.3.1.2 Bitmap Update: pack rectangles into one PDU */
        uint8_t *p = s->pbuf + DATA_HDR, *q = p + 4;
        unsigned nrects = 0;

        for (; t < ntiles; t++, sub = 0) {
            int tx, ty, x, y, w, h, wpad, rows_max;

            if (!s->dirty[t])
                continue;
            tx = t % s->tiles_x; ty = t / s->tiles_x;
            x = tx * TILE; y = ty * TILE;
            w = s->cfg.width - x < TILE ? s->cfg.width - x : TILE;
            h = s->cfg.height - y < TILE ? s->cfg.height - y : TILE;
            wpad = (w + 3) & ~3;
            /* a raw 64x64 tile at 32 bpp is too big for one PDU: split it */
            rows_max = (PDU_DATA_MAX - 4 - 18) / (wpad * bpp);
            if (rows_max > TILE)
                rows_max = TILE;
            while (sub < h) {
                int rows = h - sub < rows_max ? h - sub : rows_max;
                size_t need = 18 + (size_t)wpad * rows * bpp;   /* raw worst case */
                if (nrects && (size_t)(q - p) + need > PDU_DATA_MAX)
                    goto send;
                q += encode_rect(s, q, x, y + sub, w, rows);
                nrects++;
                sub += rows;
            }
            s->dirty[t] = 0;
        }
    send:
        if (!nrects)
            break;
        put_u16le(p, 1);            /* UPDATETYPE_BITMAP */
        put_u16le(p + 2, nrects);
        if (send_data_pdu(s, PDUTYPE2_UPDATE, (size_t)(q - p)))
            return -1;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Authentication                                                     */
/* ------------------------------------------------------------------ */

#define MAX_AUTH_ATTEMPTS 3

/* Compare in time that depends only on the configured password's length. */
static int pw_equal(const char *given, const char *want)
{
    size_t lg = strlen(given), lw = strlen(want), i;
    unsigned diff = lg != lw;

    for (i = 0; i < lw; i++)
        diff |= (unsigned char)(i < lg ? given[i] : 0) ^ (unsigned char)want[i];
    return diff == 0;
}

static void login_changed(rdp_session *s)
{
    int x, y, w, h;
    login_dirty_rect(s->login, &x, &y, &w, &h);
    mark_dirty(s, x, y, w, h);
}

static int auth_success(rdp_session *s)
{
    rlog(s, "client authenticated");
    s->authed = 1;
    login_free(s->login);
    s->login = NULL;
    s->palette_dirty = 1;
    mark_dirty(s, 0, 0, s->cfg.width, s->cfg.height);
    if (s->cb.sync)             /* tell the host the client's lock keys */
        s->cb.sync(s->cb.ctx, s->last_sync);
    return maybe_start_clipboard(s);
}

/* Returns -1 when the client should be disconnected. */
static int check_password(rdp_session *s, const char *given)
{
    char msg[40];

    if (pw_equal(given, s->cfg.password))
        return auth_success(s);
    s->auth_attempts++;
    rlog(s, "wrong password (attempt %d of %d)", s->auth_attempts, MAX_AUTH_ATTEMPTS);
    if (s->auth_attempts >= MAX_AUTH_ATTEMPTS) {
        rlog(s, "too many wrong passwords; disconnecting");
        s->auth_failed = 1;
        return -1;
    }
    snprintf(msg, sizeof(msg), "WRONG PASSWORD - %d TRIES LEFT",
             MAX_AUTH_ATTEMPTS - s->auth_attempts);
    login_reset(s->login, msg);
    login_changed(s);
    return 0;
}

static int login_result(rdp_session *s, int r)
{
    if (r == LOGIN_CHANGED)
        login_changed(s);
    else if (r == LOGIN_SUBMIT)
        return check_password(s, login_text(s->login));
    return 0;
}

/* Input events go to the host once logged in, else to the prompt. */
static int deliver_key(rdp_session *s, unsigned flags, unsigned sc)
{
    unsigned id = (sc & 0x7f) | (flags & RDP_KBD_EXTENDED ? 0x80 : 0);

    if (s->authed) {
        /* swallow the release of keys pressed at the prompt (e.g. Return) */
        if (s->login_keys[id]) {
            s->login_keys[id] = 0;
            if (flags & RDP_KBD_RELEASE)
                return 0;
        }
        if (s->cb.key)
            s->cb.key(s->cb.ctx, flags, sc);
        return 0;
    }
    if (!s->active)
        return 0;
    s->login_keys[id] = !(flags & RDP_KBD_RELEASE);
    return login_result(s, login_key(s->login, flags, sc, s->kbd_layout));
}

static int deliver_unicode(rdp_session *s, unsigned flags, unsigned code)
{
    if (s->authed) {
        if (s->cb.unicode)
            s->cb.unicode(s->cb.ctx, flags, code);
        return 0;
    }
    return s->active ? login_result(s, login_unicode(s->login, flags, code)) : 0;
}

static void deliver_mouse(rdp_session *s, unsigned flags, unsigned x, unsigned y)
{
    if (s->authed && s->cb.mouse)
        s->cb.mouse(s->cb.ctx, flags, x, y);
}

static void deliver_sync(rdp_session *s, unsigned toggles)
{
    s->last_sync = toggles;
    if (s->authed) {
        if (s->cb.sync)
            s->cb.sync(s->cb.ctx, toggles);
    } else
        login_sync(s->login, toggles);
}

/* ------------------------------------------------------------------ */
/* Input                                                              */
/* ------------------------------------------------------------------ */

static int input_slowpath(rdp_session *s, stream *in)
{
    unsigned n = s_u16le(in), i;

    s_skip(in, 2);
    for (i = 0; i < n && !in->err; i++) {
        unsigned type, a, b, c;
        s_skip(in, 4);              /* eventTime */
        type = s_u16le(in);
        a = s_u16le(in); b = s_u16le(in); c = s_u16le(in);
        if (in->err)
            break;
        switch (type) {
        case 0x0000:                /* SYNC: pad2, toggleFlags(4) */
            deliver_sync(s, b | (c << 16));
            break;
        case 0x0004:                /* SCANCODE: flags, code, pad */
            if (deliver_key(s, a, b))
                return -1;
            break;
        case 0x0005:                /* UNICODE */
            if (deliver_unicode(s, a, b))
                return -1;
            break;
        case 0x8001:                /* MOUSE */
        case 0x8002:                /* MOUSEX (extra buttons) */
            deliver_mouse(s, a, b, c);
            break;
        }
    }
    return 0;
}

/* 2.2.8.1.2 Fast-path input; `in` holds the decrypted events. */
static int input_fastpath(rdp_session *s, stream *in, unsigned nevents)
{
    unsigned i;

    if (nevents == 0)
        nevents = s_u8(in);
    for (i = 0; i < nevents && !in->err; i++) {
        uint8_t hdr = s_u8(in);
        unsigned flags = hdr & 0x1f, code = hdr >> 5, a, b, c, kf;

        switch (code) {
        case 0:                     /* SCANCODE */
            a = s_u8(in);
            kf = (flags & 1 ? RDP_KBD_RELEASE : 0) | (flags & 2 ? RDP_KBD_EXTENDED : 0) |
                 (flags & 4 ? RDP_KBD_EXTENDED1 : 0);
            if (!in->err && deliver_key(s, kf, a))
                return -1;
            break;
        case 1:                     /* MOUSE */
        case 2:                     /* MOUSEX */
            a = s_u16le(in); b = s_u16le(in); c = s_u16le(in);
            if (!in->err)
                deliver_mouse(s, a, b, c);
            break;
        case 3:                     /* SYNC */
            deliver_sync(s, flags);
            break;
        case 4:                     /* UNICODE */
            a = s_u16le(in);
            kf = flags & 1 ? RDP_KBD_RELEASE : 0;
            if (!in->err && deliver_unicode(s, kf, a))
                return -1;
            break;
        case 6:                     /* QOE timestamp */
            s_skip(in, 4);
            break;
        default:
            rlog(s, "unknown fast-path input event %u", code);
            return 0;
        }
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Incoming data on the I/O channel                                   */
/* ------------------------------------------------------------------ */

/* Read a Client Info string of `cb` bytes plus terminator, as Latin-1. */
static void read_info_string(stream *in, unsigned cb, int unicode, char *out, size_t outsz)
{
    unsigned n = unicode ? cb / 2 + 1 : cb + 1, i;
    size_t o = 0;

    for (i = 0; i < n; i++) {
        unsigned c = unicode ? s_u16le(in) : s_u8(in);
        if (o + 1 < outsz && c)
            out[o++] = c <= 0xff ? (char)c : '?';
    }
    out[o] = 0;
}

/* 2.2.1.11 Client Info PDU. Returns -1 to disconnect. */
static int handle_client_info(rdp_session *s, stream *in)
{
    uint32_t flags;
    unsigned cb_domain, cb_user, cb_pass;
    char user[64], domain[64], pass[LOGIN_MAXLEN + 1];
    int unicode, rc = 0;

    s_skip(in, 4);                  /* CodePage */
    flags = s_u32le(in);
    cb_domain = s_u16le(in);
    cb_user = s_u16le(in);
    cb_pass = s_u16le(in);
    s_skip(in, 4);                  /* shell, workdir lengths */
    unicode = (flags & 0x10) != 0;  /* INFO_UNICODE */
    read_info_string(in, cb_domain, unicode, domain, sizeof(domain));
    read_info_string(in, cb_user, unicode, user, sizeof(user));
    read_info_string(in, cb_pass, unicode, pass, sizeof(pass));
    if (in->err) {
        rlog(s, "<- Client Info (flags 0x%08x, truncated)", (unsigned)flags);
        pass[0] = 0;
    } else
        rlog(s, "<- Client Info: user \"%s\" domain \"%s\" flags 0x%08x, %s password",
             user, domain, (unsigned)flags, pass[0] ? "with" : "no");

    /* Saved credentials: check them now; otherwise the prompt asks. */
    if (!s->authed && pass[0])
        rc = check_password(s, pass);
    memset(pass, 0, sizeof(pass));
    return rc;
}

static int handle_data_pdu(rdp_session *s, stream *in)
{
    unsigned type2;

    s_skip(in, 4 + 1 + 1 + 2);      /* shareId, pad, streamId, uncompressedLength */
    type2 = s_u8(in);
    s_skip(in, 1 + 2);              /* compressedType, compressedLength */
    if (in->err)
        return -1;

    switch (type2) {
    case PDUTYPE2_SYNCHRONIZE:
        rlog(s, "<- Synchronize");
        return send_synchronize(s);
    case PDUTYPE2_CONTROL: {
        unsigned action = s_u16le(in);
        rlog(s, "<- Control action %u", action);
        if (action == CTRLACTION_COOPERATE)
            return send_control(s, CTRLACTION_COOPERATE, 0, 0);
        if (action == CTRLACTION_REQUEST_CONTROL)
            return send_control(s, CTRLACTION_GRANTED_CONTROL, s->user_id, MCS_SERVER_ID);
        return 0;
    }
    case PDUTYPE2_PERSISTENT_LIST:
        rlog(s, "<- Persistent Key List");
        return 0;
    case PDUTYPE2_FONTLIST:
        rlog(s, "<- Font List");
        if (send_font_map(s) || send_default_pointer(s))
            return -1;
        rlog(s, "connection sequence complete; %s",
             s->authed ? "session active" : "showing login prompt");
        s->active = 1;
        s->palette_dirty = 1;
        mark_dirty(s, 0, 0, s->cfg.width, s->cfg.height);
        if (maybe_start_clipboard(s))
            return -1;
        return rdp_flush(s);
    case PDUTYPE2_INPUT:
        return input_slowpath(s, in);
    case PDUTYPE2_REFRESH_RECT: {
        unsigned n = s_u8(in), i;
        s_skip(in, 3);
        for (i = 0; i < n && !in->err; i++) {
            int l = s_u16le(in), t = s_u16le(in), r = s_u16le(in), b = s_u16le(in);
            mark_dirty(s, l, t, r - l + 1, b - t + 1);
        }
        vlog(s, "<- Refresh Rect (%u)", n);
        return 0;
    }
    case PDUTYPE2_SUPPRESS_OUTPUT: {
        unsigned allow = s_u8(in);
        rlog(s, "<- Suppress Output: %s", allow ? "resume" : "suppress");
        s->suppress = !allow;
        if (allow)
            mark_dirty(s, 0, 0, s->cfg.width, s->cfg.height);
        return 0;
    }
    case PDUTYPE2_SHUTDOWN_REQUEST:
        vlog(s, "<- Shutdown Request -> Shutdown Denied");
        return send_data_pdu(s, PDUTYPE2_SHUTDOWN_DENIED, 0);
    default:
        rlog(s, "<- data PDU type2 0x%02x ignored", type2);
        return 0;
    }
}

static int handle_send_data_request(rdp_session *s, stream *in)
{
    unsigned channel, flags;
    size_t len;

    s_skip(in, 2);                  /* initiator */
    channel = s_u16be(in);
    s_skip(in, 1);                  /* priority/segmentation */
    len = per_read_len(in);
    if (in->err || len > s_left(in))
        return -1;
    in->end = in->p + len;

    flags = s_u16le(in);
    s_skip(in, 2);                  /* flagsHi */

    if (flags & SEC_EXCHANGE_PKT) {
        uint32_t elen = s_u32le(in);
        if (in->err || elen > s_left(in) || sec_establish(&s->sec, in->p, elen)) {
            rlog(s, "bad Security Exchange PDU");
            return -1;
        }
        s->lic_encrypt = (flags & SEC_LICENSE_ENCRYPT) != 0;
        rlog(s, "<- Security Exchange: session keys derived");
        return 0;
    }
    if (!s->sec.ready) {
        rlog(s, "data before security exchange");
        return -1;
    }
    if (flags & SEC_ENCRYPT) {
        uint8_t mac[8], want[8];
        s_read(in, mac, 8);
        if (in->err)
            return -1;
        sec_decrypt(&s->sec, in->p, s_left(in));
        sec_mac(&s->sec, in->p, s_left(in), want);
        if (memcmp(mac, want, 8))
            rlog(s, "WARNING: MAC mismatch on client PDU (flags 0x%04x)", flags);
    }

    if (channel != MCS_IO_CHANNEL)
        return vc_receive(s, channel, in);
    if (flags & SEC_INFO_PKT) {
        if (handle_client_info(s, in) ||
            send_license_valid_client(s) || send_demand_active(s))
            return -1;
        return 0;
    }
    if (flags & SEC_LICENSE_PKT) {
        rlog(s, "<- licensing PDU ignored");
        return 0;
    }

    /* Share control header */
    while (s_left(in) >= 6) {
        uint8_t *start = in->p;
        unsigned total = s_u16le(in), type = s_u16le(in);
        stream pdu;

        s_skip(in, 2);              /* pduSource */
        if (total == 0x8000) {      /* flow control PDU */
            in->p = start + 8 <= in->end ? start + 8 : in->end;
            continue;
        }
        if (total < 6 || start + total > in->end)
            return -1;
        s_init(&pdu, in->p, (size_t)(start + total - in->p));
        in->p = start + total;
        switch (type & 0xf) {
        case PDUTYPE_CONFIRMACTIVE:
            parse_confirm_active(s, &pdu);
            break;
        case PDUTYPE_DATA:
            if (handle_data_pdu(s, &pdu))
                return -1;
            break;
        default:
            rlog(s, "<- share control PDU type %u ignored", type & 0xf);
            break;
        }
    }
    return 0;
}

static int handle_mcs(rdp_session *s, stream *in)
{
    uint8_t b = s_u8(in);
    unsigned choice = b >> 2;
    uint8_t reply[8];

    switch (choice) {
    case 1:                         /* erectDomainRequest */
        vlog(s, "<- MCS Erect Domain");
        return 0;
    case 8:                         /* disconnectProviderUltimatum */
        rlog(s, "<- MCS Disconnect Provider Ultimatum");
        return -1;
    case 10:                        /* attachUserRequest */
        /* Windows numbers the user channel after the static channels. */
        s->user_id = MCS_IO_CHANNEL + 1 + (unsigned)s->nchannels;
        reply[0] = 0x2e; reply[1] = 0;
        reply[2] = (uint8_t)((s->user_id - 1001) >> 8); reply[3] = (uint8_t)(s->user_id - 1001);
        rlog(s, "<- MCS Attach User -> user channel %u", s->user_id);
        return send_x224_data(s, reply, 4);
    case 14: {                      /* channelJoinRequest */
        unsigned chan;
        s_skip(in, 2);
        chan = s_u16be(in);
        reply[0] = 0x3e; reply[1] = 0;
        reply[2] = (uint8_t)((s->user_id - 1001) >> 8); reply[3] = (uint8_t)(s->user_id - 1001);
        reply[4] = reply[6] = (uint8_t)(chan >> 8);
        reply[5] = reply[7] = (uint8_t)chan;
        vlog(s, "<- MCS Channel Join %u", chan);
        return send_x224_data(s, reply, 8);
    }
    case 25:                        /* sendDataRequest */
        return handle_send_data_request(s, in);
    default:
        rlog(s, "<- MCS PDU %u ignored", choice);
        return 0;
    }
}

static int handle_fastpath(rdp_session *s, uint8_t hdr, stream *in)
{
    unsigned nevents = (hdr >> 2) & 0xf;

    if (hdr & 0x80) {               /* FASTPATH_INPUT_ENCRYPTED */
        uint8_t mac[8], want[8];
        s_read(in, mac, 8);
        if (in->err || !s->sec.ready)
            return -1;
        sec_decrypt(&s->sec, in->p, s_left(in));
        sec_mac(&s->sec, in->p, s_left(in), want);
        if (memcmp(mac, want, 8))
            rlog(s, "WARNING: MAC mismatch on fast-path input");
    }
    return input_fastpath(s, in, nevents);
}

int rdp_session_process(rdp_session *s)
{
    uint8_t *b = s->ibuf;
    size_t len;
    stream in;

    if (s->cb.recv(s->cb.ctx, b, 2))
        return -1;
    if (b[0] == 3) {                                /* TPKT */
        if (s->cb.recv(s->cb.ctx, b + 2, 2))
            return -1;
        len = ((size_t)b[2] << 8) | b[3];
        if (len < 7 || s->cb.recv(s->cb.ctx, b + 4, len - 4))
            return -1;
        s_init(&in, b + 4, len - 4);
        if (!s->got_cr)
            return handle_x224_cr(s, &in);
        if (b[5] == 0x80) {                         /* X.224 Disconnect Request */
            rlog(s, "<- X.224 Disconnect Request");
            return -1;
        }
        if (b[4] != 2 || b[5] != 0xf0)
            return -1;
        s_skip(&in, 3);
        if (!s->got_ci)
            return handle_mcs_connect_initial(s, &in);
        return handle_mcs(s, &in);
    } else {                                        /* fast-path */
        size_t hl = 2;
        len = b[1];
        if (len & 0x80) {
            if (s->cb.recv(s->cb.ctx, b + 2, 1))
                return -1;
            len = ((len & 0x7f) << 8) | b[2];
            hl = 3;
        }
        if (len < hl || s->cb.recv(s->cb.ctx, b + hl, len - hl))
            return -1;
        s_init(&in, b + hl, len - hl);
        return handle_fastpath(s, b[0], &in);
    }
}

int rdp_session_active(const rdp_session *s)
{
    return s->active && s->authed;
}

int rdp_session_auth_failed(const rdp_session *s)
{
    return s->auth_failed;
}

/* Allocate the tile map for the current desktop size. */
static int alloc_tiles(rdp_session *s)
{
    uint8_t *d;
    int tx = (s->cfg.width + TILE - 1) / TILE, ty = (s->cfg.height + TILE - 1) / TILE;

    d = calloc((size_t)(tx * ty), 1);
    if (!d)
        return -1;
    free(s->dirty);
    s->dirty = d;
    s->tiles_x = tx;
    s->tiles_y = ty;
    return 0;
}

int rdp_session_resize(rdp_session *s, int width, int height, const uint8_t *fb, int pitch)
{
    rdp_config old = s->cfg;

    if (width <= 0 || height <= 0 || (width & 3))
        return -1;
    s->cfg.width = width;
    s->cfg.height = height;
    s->cfg.fb = fb;
    s->cfg.pitch = pitch ? pitch : width * (s->cfg.fb_wire ? bytes_per_pixel(s->cfg.bpp) : 1);
    if (alloc_tiles(s)) {
        s->cfg = old;
        return -1;
    }
    if (s->login) {                 /* still at the prompt: redraw it at the new size */
        rdp_login *l = login_new(width, height);
        if (!l)
            return -1;
        login_free(s->login);
        s->login = l;
    }
    rlog(s, "desktop resized to %dx%d", width, height);
    if (!s->demand_sent)            /* the first Demand Active will carry it */
        return 0;
    /*
     * 1.3.1.3 Deactivation-Reactivation: the client re-runs capability
     * exchange and connection finalisation; the Font List at the end makes
     * the session active again and the whole screen is resent.
     */
    s->active = 0;
    if (send_deactivate_all(s) || send_demand_active(s))
        return -1;
    return 0;
}

rdp_session *rdp_session_new(const rdp_config *cfg, const rdp_callbacks *cb)
{
    rdp_session *s;

    if (cfg->width <= 0 || cfg->height <= 0 || (cfg->width & 3) ||
        (cfg->bpp != 8 && cfg->bpp != 15 && cfg->bpp != 16 && cfg->bpp != 24 &&
         cfg->bpp != 32))
        return NULL;
    s = calloc(1, sizeof(*s));
    if (!s)
        return NULL;
    s->cfg = *cfg;
    if (!s->cfg.pitch)
        s->cfg.pitch = cfg->width * (cfg->fb_wire ? bytes_per_pixel(cfg->bpp) : 1);
    s->cb = *cb;
    if (alloc_tiles(s)) {
        free(s);
        return NULL;
    }
    build_lut(s->cfg.bpp, s->cfg.palette, s->lut);
    if (cb->clip_get || cb->clip_set) {
        cliprdr_io io;
        io.ctx = s;
        io.send = clip_send;
        io.log = clip_log;
        io.get_text = cb->clip_get ? clip_get : NULL;
        io.set_text = clip_set;
        s->clip = cliprdr_new(&io);
    }
    s->authed = !cfg->password || !cfg->password[0];
    if (!s->authed) {
        s->login = login_new(cfg->width, cfg->height);
        if (!s->login) {
            rdp_session_free(s);
            return NULL;
        }
        build_lut(s->cfg.bpp, login_palette(), s->login_lut);
    }
    return s;
}

void rdp_session_free(rdp_session *s)
{
    if (s) {
        if (s->stat_tiles) {
            /* per mille, without overflowing 32-bit longs on the Amiga */
            unsigned long pm = s->stat_raw >= 1000 ? s->stat_sent / (s->stat_raw / 1000) : 1000;
            rlog(s, "sent %lu tiles: %lu KB of %lu KB raw (%lu.%lu%%)", s->stat_tiles,
                 s->stat_sent / 1024, s->stat_raw / 1024, pm / 10, pm % 10);
        }
        login_free(s->login);
        cliprdr_free(s->clip);
        free(s->vc_buf);
        free(s->dirty);
        free(s);
    }
}
