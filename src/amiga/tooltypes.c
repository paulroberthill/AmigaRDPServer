/* Workbench tool types as ReadArgs() input (see tooltypes.h). */
#include <stdlib.h>
#include <string.h>
#include "tooltypes.h"

static int lower(int c)
{
    return c >= 'A' && c <= 'Z' ? c + ('a' - 'A') : c;
}

static int space(int c)
{
    return c == ' ' || c == '\t';
}

/*
 * Is key[0..len) a keyword of the template? *sw is set if it is a switch.
 * Template entries look like "NAME/K/N", separated by commas.
 */
static int keyword(const char *template, const char *key, size_t len, int *sw)
{
    const char *t = template;

    while (*t) {
        const char *end = t + strcspn(t, ",");
        size_t n = strcspn(t, "/,");
        size_t i;

        if (n == len) {
            for (i = 0; i < len && lower((unsigned char)t[i]) == lower((unsigned char)key[i]); i++)
                ;
            if (i == len) {
                const char *s;
                *sw = 0;
                for (s = t + n; s < end; s++)
                    if (s[0] == '/' && lower((unsigned char)s[1]) == 's')
                        *sw = 1;
                return 1;
            }
        }
        t = *end ? end + 1 : end;
    }
    return 0;
}

char *tooltypes_to_args(const char *template, const char *const *types)
{
    size_t size = 2;
    const char *const *tt;
    char *out, *p;

    /* worst case: every character escaped, plus space, '=' and quotes */
    for (tt = types; *tt; tt++)
        size += 2 * strlen(*tt) + 4;
    out = p = malloc(size);
    if (!out)
        return NULL;

    for (tt = types; *tt; tt++) {
        const char *t = *tt, *eq = strchr(t, '='), *end;
        size_t len;
        int sw;

        /* key and value without surrounding spaces, as the Shell would see them */
        while (space(*t))
            t++;
        end = eq ? eq : t + strlen(t);
        while (end > t && space(end[-1]))
            end--;
        len = (size_t)(end - t);
        if (!len || !keyword(template, t, len, &sw))
            continue;
        if (p != out)
            *p++ = ' ';
        memcpy(p, t, len);
        p += len;
        if (eq && !sw) {
            const char *v = eq + 1;
            while (space(*v))
                v++;
            end = v + strlen(v);
            while (end > v && space(end[-1]))
                end--;
            *p++ = '=';
            *p++ = '"';
            for (; v < end; v++) {
                if (*v == '"' || *v == '*') {
                    *p++ = '*';
                    *p++ = *v;
                } else if (*v == '\n') {
                    *p++ = '*';
                    *p++ = 'N';
                } else {
                    *p++ = *v;
                }
            }
            *p++ = '"';
        }
    }
    *p++ = '\n';
    *p = 0;
    return out;
}
