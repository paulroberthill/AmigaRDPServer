/* Server RSA key + signed proprietary certificate (see tools/genkey.py). */
#ifndef RDP_SERVERKEY_H
#define RDP_SERVERKEY_H

#include <stdint.h>

#define SERVER_KEY_BYTES 64   /* 512-bit RSA */

extern const uint8_t server_cert[];
extern const unsigned server_cert_len;
extern const uint8_t server_modulus[SERVER_KEY_BYTES];
extern const uint8_t server_privexp[SERVER_KEY_BYTES];

#endif
