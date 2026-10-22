/* Unit test for src/amiga/ftxt.c (runs natively and under vamos). */
#include <stdio.h>
#include <string.h>
#include "../src/amiga/ftxt.h"

#ifdef __amigaos__
unsigned long __stack = 65536;
#endif

static int fails;

static void check(const char *what, int ok)
{
    printf("%s %s\n", ok ? "ok  " : "FAIL", what);
    if (!ok)
        fails++;
}

int main(void)
{
    static unsigned char buf[4096];
    static char out[4096];
    /* A clip as another program might write it: two CHRS chunks (one odd
     * length, so padded), with an unknown chunk between them. */
    static const unsigned char multi[] = {
        'F','O','R','M', 0,0,0,36, 'F','T','X','T',
        'C','H','R','S', 0,0,0,3, 'a','b','c', 0,
        'F','O','N','T', 0,0,0,2, 1,2,
        'C','H','R','S', 0,0,0,2, 0xa3,'\n'
    };
    const char *text = "Hello \xa3 Amiga\nodd";
    size_t len = strlen(text), size = ftxt_size(len);
    long n;

    ftxt_build(text, len, buf);
    check("size includes pad byte for odd text", size == 20 + len + 1 && (size & 1) == 0);
    check("FORM header", !memcmp(buf, "FORM", 4) && !memcmp(buf + 8, "FTXT", 4) &&
          !memcmp(buf + 12, "CHRS", 4));
    check("FORM size is big-endian", buf[4] == 0 && buf[7] == (unsigned char)(size - 8));
    n = ftxt_parse(buf, size, out, sizeof(out));
    check("round trip", n == (long)len && !memcmp(out, text, len));

    n = ftxt_parse(multi, sizeof(multi), out, sizeof(out));
    check("several CHRS chunks, skipping others", n == 5 && !memcmp(out, "abc\xa3\n", 5));
    n = ftxt_parse(multi, sizeof(multi), out, 4);
    check("output capped", n == 4 && !memcmp(out, "abc\xa3", 4));
    check("not FTXT rejected", ftxt_parse((const unsigned char *)"FORMxxxxILBM", 12, out, 10) == -1);
    n = ftxt_parse(multi, 30, out, sizeof(out));
    check("truncated clip tolerated", n == 3);

    printf(fails ? "%d FAILED\n" : "all passed\n", fails);
    return fails != 0;
}
