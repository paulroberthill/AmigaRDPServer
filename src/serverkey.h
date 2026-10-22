/*
 * The server's RSA key and signed proprietary certificate (srvkey.c), set
 * at runtime with rdp_set_server_key() (see rdp.h).
 */
#ifndef RDP_SERVERKEY_H
#define RDP_SERVERKEY_H

#include <stdint.h>

#define SERVER_KEY_BYTES 64     /* 512-bit RSA */
#define SERVER_CERT_BYTES 184

extern uint8_t server_cert[SERVER_CERT_BYTES];
extern unsigned server_cert_len;    /* 0 until a key has been set */
extern uint8_t server_modulus[SERVER_KEY_BYTES];
extern uint8_t server_privexp[SERVER_KEY_BYTES];

#endif
