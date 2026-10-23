/*
 * Workbench tool types as ReadArgs() input, so options given in the icon
 * are parsed and checked exactly like Shell arguments.
 * Pure C with no AmigaOS calls, so it can be unit-tested anywhere.
 */
#ifndef RDP_TOOLTYPES_H
#define RDP_TOOLTYPES_H

/* RDPServer's ReadArgs() template, shared with tests/test_tooltypes.c */
#define RDPSERVER_TEMPLATE \
    "PORT/K/N,BPP/K/N,INTERVAL/K/N,NEGFAIL/S,VERBOSE/S,PASSWORD/K,NOPASSWORD/S,NOCOMPRESS/S," \
    "NOCLIPBOARD/S,NOBEEP/S,SCAN/K/N,NEWKEY/S"

/*
 * Build a ReadArgs() command line (ending in "\n") from the NULL-terminated
 * tool type array `types`. Only tool types naming a keyword of `template`
 * are used, so other ones, and ones disabled Workbench-style with
 * parentheses, are ignored. Keyword matching ignores case. Values are
 * quoted; a switch (/S) keyword is passed without its value.
 * Returns a malloc()ed string, or NULL if out of memory.
 */
char *tooltypes_to_args(const char *template, const char *const *types);

#endif
