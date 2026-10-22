/*
 * Prints generated server keys for tests/test_keygen.py to check with
 * Python's own big integers: "n_hex d_hex e" per line (little-endian hex).
 * Usage: test_keygen [count]
 */
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "../src/keygen.h"

#ifdef __amigaos__
unsigned long __stack = 65536;
#endif

static uint64_t state;   /* 64-bit on every platform (unsigned long is 32 on the Amiga) */

/* Test-only random source (not for real keys). */
static void rnd(void *ctx, uint8_t *out, size_t len)
{
    (void)ctx;
    while (len--) {
        state = state * 6364136223846793005ull + 1442695040888963407ull;
        *out++ = (uint8_t)(state >> 33);
    }
}

int main(int argc, char **argv)
{
    int count = argc > 1 ? atoi(argv[1]) : 3, i, j;

    state = (uint64_t)time(NULL);
    for (i = 0; i < count; i++) {
        uint8_t n[64], d[64];
        uint32_t e;
        clock_t t0 = clock();
        if (rsa512_generate(n, d, &e, rnd, NULL)) {
            printf("FAIL generation\n");
            return 1;
        }
        for (j = 0; j < 64; j++) printf("%02x", n[j]);
        printf(" ");
        for (j = 0; j < 64; j++) printf("%02x", d[j]);
        printf(" %lu %ld\n", (unsigned long)e, (long)((clock() - t0) * 1000 / CLOCKS_PER_SEC));
    }
    return 0;
}
