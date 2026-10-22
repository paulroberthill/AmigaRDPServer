/*
 * RDP Standard Security (MS-RDPBCGR 5.3), 128-bit RC4 only.
 */
#ifndef RDP_SEC_H
#define RDP_SEC_H

#include <stdint.h>
#include <stddef.h>
#include "crypto.h"

typedef struct {
    uint8_t client_random[32];
    uint8_t server_random[32];
    uint8_t mac_key[16];
    uint8_t enc_key_init[16], enc_key[16];  /* server -> client */
    uint8_t dec_key_init[16], dec_key[16];  /* client -> server */
    rc4_ctx enc_rc4, dec_rc4;
    unsigned enc_count, dec_count;
    int ready;
} rdp_sec;

/*
 * Decrypt the client's encrypted random (little-endian, `len` bytes) with
 * the server private key and derive all session keys. Returns 0 on success.
 */
int sec_establish(rdp_sec *s, const uint8_t *enc_random, size_t len);

/* 8-byte MAC over plaintext data (non-salted, MS-RDPBCGR 5.3.6.1). */
void sec_mac(const rdp_sec *s, const uint8_t *data, size_t len, uint8_t out[8]);

/* In-place encrypt (server->client) / decrypt (client->server). */
void sec_encrypt(rdp_sec *s, uint8_t *data, size_t len);
void sec_decrypt(rdp_sec *s, uint8_t *data, size_t len);

#endif
