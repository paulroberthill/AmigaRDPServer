/*
 * IFF FTXT (the Amiga clipboard's text format) packing and parsing.
 * Pure C with no AmigaOS calls, so it can be unit-tested anywhere.
 */
#ifndef RDP_FTXT_H
#define RDP_FTXT_H

#include <stddef.h>

/* Size of the IFF FORM FTXT holding `len` bytes of text. */
size_t ftxt_size(size_t len);

/* Write FORM FTXT { CHRS text } into out (ftxt_size(len) bytes). */
void ftxt_build(const char *text, size_t len, unsigned char *out);

/*
 * Extract the text of all CHRS chunks of a FORM FTXT into out (at most
 * cap bytes). Returns the text length, or -1 if `iff` is not FTXT.
 */
long ftxt_parse(const unsigned char *iff, size_t len, char *out, size_t cap);

#endif
