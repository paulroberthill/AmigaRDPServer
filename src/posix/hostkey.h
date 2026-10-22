/* Build-time server key for the Linux and native test hosts (generated
 * into hostkey.c by tools/genkey.py; the Amiga host makes its own). */
#ifndef RDP_HOSTKEY_H
#define RDP_HOSTKEY_H

#include <stdint.h>

extern const uint8_t host_key_modulus[64];
extern const uint8_t host_key_privexp[64];
extern const uint32_t host_key_exponent;

#endif
