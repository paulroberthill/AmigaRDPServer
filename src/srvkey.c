/*
 * Server key and proprietary certificate (MS-RDPBCGR 2.2.1.4.3.1.1).
 *
 * Standard RDP Security needs the server's public key wrapped in a
 * certificate signed with the Terminal Services signing key, whose private
 * half Microsoft publishes (5.3.3.1.1). The certificate is built here at
 * runtime, so hosts can use a key generated on first run (keygen.c)
 * instead of one compiled into the binary.
 */
#include <string.h>

#include "crypto.h"
#include "keygen.h"
#include "rdp.h"
#include "serverkey.h"

uint8_t server_cert[SERVER_CERT_BYTES];
unsigned server_cert_len;
uint8_t server_modulus[SERVER_KEY_BYTES];
uint8_t server_privexp[SERVER_KEY_BYTES];

/* MS-RDPBCGR 5.3.3.1.1 Terminal Services Signing Key (little-endian) */
static const uint8_t ts_n[64] = {
    0x3d, 0x3a, 0x5e, 0xbd, 0x72, 0x43, 0x3e, 0xc9, 0x4d, 0xbb, 0xc1, 0x1e, 0x4a, 0xba, 0x5f, 0xcb,
    0x3e, 0x88, 0x20, 0x87, 0xef, 0xf5, 0xc1, 0xe2, 0xd7, 0xb7, 0x6b, 0x9a, 0xf2, 0x52, 0x45, 0x95,
    0xce, 0x63, 0x65, 0x6b, 0x58, 0x3a, 0xfe, 0xef, 0x7c, 0xe7, 0xbf, 0xfe, 0x3d, 0xf6, 0x5c, 0x7d,
    0x6c, 0x5e, 0x06, 0x09, 0x1a, 0xf5, 0x61, 0xbb, 0x20, 0x93, 0x09, 0x5f, 0x05, 0x6d, 0xea, 0x87
};
static const uint8_t ts_d[64] = {
    0x87, 0xa7, 0x19, 0x32, 0xda, 0x11, 0x87, 0x55, 0x58, 0x00, 0x16, 0x16, 0x25, 0x65, 0x68, 0xf8,
    0x24, 0x3e, 0xe6, 0xfa, 0xe9, 0x67, 0x49, 0x94, 0xcf, 0x92, 0xcc, 0x33, 0x99, 0xe8, 0x08, 0x60,
    0x17, 0x9a, 0x12, 0x9f, 0x24, 0xdd, 0xb1, 0x24, 0x99, 0xc7, 0x3a, 0xb8, 0x0a, 0x7b, 0x0d, 0xdd,
    0x35, 0x07, 0x79, 0x17, 0x0b, 0x51, 0x9b, 0xb3, 0xc7, 0x10, 0x01, 0x13, 0xe7, 0x3f, 0xf3, 0x5f
};

static uint8_t *put32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
    return p + 4;
}

static uint8_t *put16(uint8_t *p, unsigned v)
{
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
    return p + 2;
}

int rdp_set_server_key(const uint8_t modulus[64], const uint8_t privexp[64], uint32_t e)
{
    uint8_t *p = server_cert, *head_end, sig_in[64], sig[64];
    md5_ctx md5;

    if (!(modulus[63] & 0x80) || !(modulus[0] & 1))
        return -1;                  /* need an odd 512-bit modulus */
    memcpy(server_modulus, modulus, 64);
    memcpy(server_privexp, privexp, 64);

    p = put32(p, 1);                /* dwVersion: CERT_CHAIN_VERSION_1 */
    p = put32(p, 1);                /* dwSigAlgId: SIGNATURE_ALG_RSA */
    p = put32(p, 1);                /* dwKeyAlgId: KEY_EXCHANGE_ALG_RSA */
    p = put16(p, 0x0006);           /* BB_RSA_KEY_BLOB */
    p = put16(p, 20 + 72);
    memcpy(p, "RSA1", 4);
    p = put32(p + 4, 72);           /* keylen: modulus + 8 bytes padding */
    p = put32(p, 512);              /* bitlen */
    p = put32(p, 63);               /* datalen */
    p = put32(p, e);
    memcpy(p, modulus, 64);
    memset(p + 64, 0, 8);
    p += 72;
    head_end = p;

    /* 5.3.3.1.2: MD5 of the first six fields, padded, signed with the
     * TS private key as a little-endian number */
    md5_init(&md5);
    md5_update(&md5, server_cert, (size_t)(head_end - server_cert));
    md5_final(&md5, sig_in);
    sig_in[16] = 0x00;
    memset(sig_in + 17, 0xff, 45);
    sig_in[62] = 0x01;
    sig_in[63] = 0x00;
    if (rsa_modexp_le(sig, sig_in, ts_d, sizeof(ts_d), ts_n, sizeof(ts_n)))
        return -1;

    p = put16(p, 0x0008);           /* BB_RSA_SIGNATURE_BLOB */
    p = put16(p, 72);
    memcpy(p, sig, 64);
    memset(p + 64, 0, 8);
    p += 72;
    server_cert_len = (unsigned)(p - server_cert);
    return 0;
}

int rdp_generate_server_key(uint8_t modulus[64], uint8_t privexp[64], uint32_t *e,
                            void (*random)(void *ctx, uint8_t *out, size_t len), void *ctx)
{
    return rsa512_generate(modulus, privexp, e, random, ctx);
}
