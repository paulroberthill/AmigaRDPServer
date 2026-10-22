/* RDP Standard Security key derivation and stream encryption. */
#include <string.h>
#include "sec.h"
#include "serverkey.h"

static const uint8_t pad1[40] = {
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36
};
static const uint8_t pad2[48] = {
    0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
    0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
    0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
    0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c
};

/* SaltedHash(S, I) = MD5(S + SHA(I + S + ClientRandom + ServerRandom)) */
static void salted_hash(const rdp_sec *s, const uint8_t secret[48],
                        const char *salt, uint8_t out[16])
{
    sha1_ctx sha;
    md5_ctx md5;
    uint8_t shasig[20];

    sha1_init(&sha);
    sha1_update(&sha, salt, strlen(salt));
    sha1_update(&sha, secret, 48);
    sha1_update(&sha, s->client_random, 32);
    sha1_update(&sha, s->server_random, 32);
    sha1_final(&sha, shasig);
    md5_init(&md5);
    md5_update(&md5, secret, 48);
    md5_update(&md5, shasig, 20);
    md5_final(&md5, out);
}

/* FinalHash(K) = MD5(K + ClientRandom + ServerRandom) */
static void final_hash(const rdp_sec *s, const uint8_t key[16], uint8_t out[16])
{
    md5_ctx md5;
    md5_init(&md5);
    md5_update(&md5, key, 16);
    md5_update(&md5, s->client_random, 32);
    md5_update(&md5, s->server_random, 32);
    md5_final(&md5, out);
}

int sec_establish(rdp_sec *s, const uint8_t *enc_random, size_t len)
{
    uint8_t buf[SERVER_KEY_BYTES], dec[SERVER_KEY_BYTES];
    uint8_t pre[48], master[48], blob[48];
    size_t i;

    /* The wire value is modulus-sized plus 8 bytes of zero padding. */
    if (len < SERVER_KEY_BYTES)
        return -1;
    for (i = SERVER_KEY_BYTES; i < len; i++)
        if (enc_random[i])
            return -1;
    memcpy(buf, enc_random, SERVER_KEY_BYTES);
    if (rsa_modexp_le(dec, buf, server_privexp, SERVER_KEY_BYTES,
                      server_modulus, SERVER_KEY_BYTES))
        return -1;
    memcpy(s->client_random, dec, 32);

    memcpy(pre, s->client_random, 24);
    memcpy(pre + 24, s->server_random, 24);
    salted_hash(s, pre, "A", master);
    salted_hash(s, pre, "BB", master + 16);
    salted_hash(s, pre, "CCC", master + 32);
    salted_hash(s, master, "X", blob);
    salted_hash(s, master, "YY", blob + 16);
    salted_hash(s, master, "ZZZ", blob + 32);

    memcpy(s->mac_key, blob, 16);
    final_hash(s, blob + 16, s->enc_key_init);
    final_hash(s, blob + 32, s->dec_key_init);
    memcpy(s->enc_key, s->enc_key_init, 16);
    memcpy(s->dec_key, s->dec_key_init, 16);
    rc4_init(&s->enc_rc4, s->enc_key, 16);
    rc4_init(&s->dec_rc4, s->dec_key, 16);
    s->enc_count = s->dec_count = 0;
    s->ready = 1;
    return 0;
}

void sec_mac(const rdp_sec *s, const uint8_t *data, size_t len, uint8_t out[8])
{
    sha1_ctx sha;
    md5_ctx md5;
    uint8_t lenbuf[4], shasig[20], md5sig[16];

    lenbuf[0] = (uint8_t)len; lenbuf[1] = (uint8_t)(len >> 8);
    lenbuf[2] = (uint8_t)(len >> 16); lenbuf[3] = (uint8_t)(len >> 24);
    sha1_init(&sha);
    sha1_update(&sha, s->mac_key, 16);
    sha1_update(&sha, pad1, 40);
    sha1_update(&sha, lenbuf, 4);
    sha1_update(&sha, data, len);
    sha1_final(&sha, shasig);
    md5_init(&md5);
    md5_update(&md5, s->mac_key, 16);
    md5_update(&md5, pad2, 48);
    md5_update(&md5, shasig, 20);
    md5_final(&md5, md5sig);
    memcpy(out, md5sig, 8);
}

/* MS-RDPBCGR 5.3.7.1: refresh a key after 4096 packets. */
static void update_key(const uint8_t init[16], uint8_t key[16], rc4_ctx *rc4)
{
    sha1_ctx sha;
    md5_ctx md5;
    uint8_t shasig[20];
    rc4_ctx tmp;

    sha1_init(&sha);
    sha1_update(&sha, init, 16);
    sha1_update(&sha, pad1, 40);
    sha1_update(&sha, key, 16);
    sha1_final(&sha, shasig);
    md5_init(&md5);
    md5_update(&md5, init, 16);
    md5_update(&md5, pad2, 48);
    md5_update(&md5, shasig, 20);
    md5_final(&md5, key);
    rc4_init(&tmp, key, 16);
    rc4_crypt(&tmp, key, 16);
    rc4_init(rc4, key, 16);
}

void sec_encrypt(rdp_sec *s, uint8_t *data, size_t len)
{
    if (s->enc_count == 4096) {
        update_key(s->enc_key_init, s->enc_key, &s->enc_rc4);
        s->enc_count = 0;
    }
    rc4_crypt(&s->enc_rc4, data, len);
    s->enc_count++;
}

void sec_decrypt(rdp_sec *s, uint8_t *data, size_t len)
{
    if (s->dec_count == 4096) {
        update_key(s->dec_key_init, s->dec_key, &s->dec_rc4);
        s->dec_count = 0;
    }
    rc4_crypt(&s->dec_rc4, data, len);
    s->dec_count++;
}
