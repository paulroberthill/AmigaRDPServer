/* Checks crypto primitives against known-answer vectors from
 * tests/crypto_vectors.py (generated with Python's hashlib / pow). */
#include <stdio.h>
#include <string.h>
#include "../src/crypto.h"

static int fails;

static void hex(char *out, const uint8_t *p, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++)
        sprintf(out + 2 * i, "%02x", p[i]);
}

static void check(const char *what, const uint8_t *got, size_t n, const char *want)
{
    char buf[1024];
    hex(buf, got, n);
    if (strcmp(buf, want)) {
        printf("FAIL %s\n  got  %s\n  want %s\n", what, buf, want);
        fails++;
    } else
        printf("ok   %s\n", what);
}

static void unhex(uint8_t *out, const char *s)
{
    while (*s) {
        unsigned v;
        sscanf(s, "%2x", &v);
        *out++ = (uint8_t)v;
        s += 2;
    }
}

#include "crypto_vectors.h"

int main(void)
{
    uint8_t out[256], buf[1000];
    md5_ctx m;
    sha1_ctx s;
    rc4_ctx r;
    size_t i;

    for (i = 0; i < sizeof(buf); i++)
        buf[i] = (uint8_t)(i * 7 + 3);

    for (i = 0; i < sizeof(hash_lens) / sizeof(hash_lens[0]); i++) {
        char name[64];
        md5_init(&m);
        md5_update(&m, buf, hash_lens[i] / 2);
        md5_update(&m, buf + hash_lens[i] / 2, hash_lens[i] - hash_lens[i] / 2);
        md5_final(&m, out);
        sprintf(name, "md5 len %d", hash_lens[i]);
        check(name, out, 16, md5_want[i]);
        sha1_init(&s);
        sha1_update(&s, buf, hash_lens[i]);
        sha1_final(&s, out);
        sprintf(name, "sha1 len %d", hash_lens[i]);
        check(name, out, 20, sha1_want[i]);
    }

    rc4_init(&r, (const uint8_t *)"Key", 3);
    memcpy(out, "Plaintext", 9);
    rc4_crypt(&r, out, 9);
    check("rc4 'Key'/'Plaintext'", out, 9, "bbf316e8d940af0ad3");

    for (i = 0; i < sizeof(rsa_vec) / sizeof(rsa_vec[0]); i++) {
        uint8_t n[256], b[256], e[256];
        char name[64];
        size_t len = strlen(rsa_vec[i].n) / 2, elen = strlen(rsa_vec[i].e) / 2;
        unhex(n, rsa_vec[i].n);
        unhex(b, rsa_vec[i].b);
        unhex(e, rsa_vec[i].e);
        rsa_modexp_le(out, b, e, elen, n, len);
        sprintf(name, "modexp %d bits #%d", (int)len * 8, (int)i);
        check(name, out, len, rsa_vec[i].want);
    }

    printf(fails ? "%d FAILED\n" : "all passed\n", fails);
    return fails != 0;
}
