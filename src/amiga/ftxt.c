/* IFF FTXT packing and parsing: see ftxt.h. IFF is big-endian. */
#include <string.h>
#include "ftxt.h"

static void put_be32(unsigned char *p, unsigned long v)
{
    p[0] = (unsigned char)(v >> 24); p[1] = (unsigned char)(v >> 16);
    p[2] = (unsigned char)(v >> 8); p[3] = (unsigned char)v;
}

static unsigned long get_be32(const unsigned char *p)
{
    return ((unsigned long)p[0] << 24) | ((unsigned long)p[1] << 16) |
           ((unsigned long)p[2] << 8) | p[3];
}

size_t ftxt_size(size_t len)
{
    return 12 + 8 + len + (len & 1);
}

void ftxt_build(const char *text, size_t len, unsigned char *out)
{
    memcpy(out, "FORM", 4);
    put_be32(out + 4, (unsigned long)(4 + 8 + len + (len & 1)));
    memcpy(out + 8, "FTXT", 4);
    memcpy(out + 12, "CHRS", 4);
    put_be32(out + 16, (unsigned long)len);
    memcpy(out + 20, text, len);
    if (len & 1)
        out[20 + len] = 0;          /* chunks are padded to an even size */
}

long ftxt_parse(const unsigned char *iff, size_t len, char *out, size_t cap)
{
    size_t pos = 12, end, n = 0;

    if (len < 12 || memcmp(iff, "FORM", 4) || memcmp(iff + 8, "FTXT", 4))
        return -1;
    end = 8 + get_be32(iff + 4);
    if (end > len)
        end = len;                  /* truncated clip: use what is there */
    while (pos + 8 <= end) {
        unsigned long size = get_be32(iff + pos + 4);
        const unsigned char *data = iff + pos + 8;
        if (size > end - pos - 8)
            size = end - pos - 8;
        if (!memcmp(iff + pos, "CHRS", 4)) {
            size_t take = size < cap - n ? size : cap - n;
            memcpy(out + n, data, take);
            n += take;
        }
        pos += 8 + size + (size & 1);
    }
    return (long)n;
}
