/*
 * Unit test for src/amiga/tooltypes.c (runs natively and under vamos).
 * As 68k code it also feeds the result to dos.library ReadArgs() with
 * RDPServer's real template.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../src/amiga/tooltypes.h"

#ifdef __amigaos__
#include <dos/dos.h>
#include <dos/rdargs.h>
#include <proto/dos.h>
unsigned long __stack = 65536;
#endif

static int fails;

static void check(const char *what, int ok)
{
    printf("%s %s\n", ok ? "ok  " : "FAIL", what);
    if (!ok)
        fails++;
}

static void conv(const char *what, const char *const *types, const char *want)
{
    char *got = tooltypes_to_args(RDPSERVER_TEMPLATE, types);
    int ok = got && !strcmp(got, want);
    check(what, ok);
    if (!ok)
        printf("     got  [%s]\n     want [%s]\n", got ? got : "(null)", want);
    free(got);
}

#ifdef __amigaos__
/* Parse `types` with ReadArgs() as main.c does; 0 on success. */
static int readargs(const char *const *types, LONG *args)
{
    char *line = tooltypes_to_args(RDPSERVER_TEMPLATE, types);
    struct RDArgs *src = AllocDosObject(DOS_RDARGS, NULL), *rda;
    int rc = -1;

    memset(args, 0, 12 * sizeof(LONG));
    if (line && src) {
        src->RDA_Source.CS_Buffer = (UBYTE *)line;
        src->RDA_Source.CS_Length = strlen(line);
        src->RDA_Source.CS_CurChr = 0;
        src->RDA_Flags |= RDAF_NOPROMPT;
        rda = ReadArgs((STRPTR)RDPSERVER_TEMPLATE, args, src);
        if (rda) {
            rc = 0;
            /* check what we need before FreeArgs() releases the strings */
            if (args[5])
                strcpy(line, (const char *)args[5]);
            args[5] = args[5] ? (LONG)line : 0;
            FreeArgs(rda);
        }
    }
    if (src)
        FreeDosObject(DOS_RDARGS, src);
    if (rc)
        free(line);
    return rc;
}
#endif

int main(void)
{
    static const char *const none[] = { NULL };
    static const char *const basic[] = { "PORT=3390", "BPP=24", "NOBEEP", NULL };
    static const char *const other[] = {
        "DONOTWAIT", "(PORT=1)", "(NOBEEP)", "TOOLPRI=-1", "=x", "", "PORTS=2", "POR=3", NULL
    };
    static const char *const kase[] = { "port=1", "NoBeep", "Verbose=YES", NULL };
    static const char *const pw[] = { "PASSWORD=a b\"c*d", NULL };
    static const char *const empty[] = { "PASSWORD=", "INTERVAL", NULL };
    static const char *const spaces[] = {
        "PASSWORD=x ", " PORT = 3390\t", "NOBEEP ", "BPP=  ", "(SCAN=2) ", NULL
    };
    static const char *const inner[] = { "PASSWORD= a b ", NULL };

    conv("no tool types", none, "\n");
    conv("numbers and a switch", basic, "PORT=\"3390\" BPP=\"24\" NOBEEP\n");
    conv("unknown, disabled and look-alike tool types ignored", other, "\n");
    conv("keywords ignore case; switch value dropped", kase, "port=\"1\" NoBeep Verbose\n");
    conv("value with space, quote and star escaped", pw, "PASSWORD=\"a b*\"c**d\"\n");
    conv("empty value; keyword without value", empty, "PASSWORD=\"\" INTERVAL\n");
    conv("spaces around keywords and values ignored", spaces,
         "PASSWORD=\"x\" PORT=\"3390\" NOBEEP BPP=\"\"\n");
    conv("spaces inside a value kept", inner, "PASSWORD=\"a b\"\n");

#ifdef __amigaos__
    {
        static const char *const all[] = {
            "PORT=3390", "BPP=24", "INTERVAL=50", "SCAN=2", "NEGFAIL", "VERBOSE",
            "NOCOMPRESS", "NOCLIPBOARD", "NOBEEP", "NEWKEY", "(NOPASSWORD)", "DONOTWAIT", NULL
        };
        static const char *const bad_num[] = { "PORT=abc", NULL };
        LONG a[12];

        check("ReadArgs: all options", !readargs(all, a) &&
              a[0] && *(LONG *)a[0] == 3390 && a[1] && *(LONG *)a[1] == 24 &&
              a[2] && *(LONG *)a[2] == 50 && a[10] && *(LONG *)a[10] == 2 &&
              a[3] && a[4] && !a[5] && !a[6] && a[7] && a[8] && a[9] && a[11]);
        check("ReadArgs: escaped password", !readargs(pw, a) && a[5] &&
              !strcmp((const char *)a[5], "a b\"c*d"));
        free((void *)a[5]);
        check("ReadArgs: no tool types", !readargs(none, a) && !a[0] && !a[3] && !a[5]);
        {
            static const char *const trail[] = { "PASSWORD=x ", "PORT=3390 ", NULL };
            check("ReadArgs: trailing spaces dropped", !readargs(trail, a) && a[5] &&
                  !strcmp((const char *)a[5], "x") && a[0] && *(LONG *)a[0] == 3390);
            free((void *)a[5]);
        }
        check("ReadArgs: bad number rejected", readargs(bad_num, a) != 0);
    }
#endif

    printf(fails ? "%d FAILED\n" : "all passed\n", fails);
    return fails ? 1 : 0;
}
