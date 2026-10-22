/*
 * DisplayBeep() patch: see beep.h.
 *
 * The patch runs in whatever task calls DisplayBeep(), so it is a small
 * self-contained stub copied into its own public memory, with its data
 * (task, signal mask, original vector) stored inside it. All it does is
 * Signal() our task and jump to the original DisplayBeep() with the
 * caller's registers intact. Keeping it out of our program's hunks means
 * it stays valid even if it cannot be unpatched when we quit.
 */
#include <exec/execbase.h>
#include <exec/memory.h>
#include <intuition/intuitionbase.h>
#include <proto/exec.h>
#include <proto/intuition.h>
#include <string.h>

#include "beep.h"

#define LVO_DisplayBeep (-96)

/* The stub, in Motorola syntax. Offsets of the data longs are fixed by
 * their position at the end: task at -12, mask at -8, original at -4. */
__asm__(
    "    .text\n"
    "    .even\n"
    "    .globl _beep_stub_start\n"
    "    .globl _beep_stub_end\n"
    "_beep_stub_start:\n"
    "    movem.l d0-d1/a0-a1/a6,-(sp)\n"
    "    move.l  bs_task(pc),d0\n"
    "    beq.s   1f\n"                      /* no task: just pass through */
    "    move.l  d0,a1\n"
    "    move.l  bs_mask(pc),d0\n"
    "    move.l  4.w,a6\n"
    "    jsr     -324(a6)\n"                /* Signal(a1 = task, d0 = mask) */
    "1:  movem.l (sp)+,d0-d1/a0-a1/a6\n"
    "    move.l  bs_orig(pc),-(sp)\n"
    "    rts\n"                             /* 'return' into the original */
    "bs_task: .long 0\n"
    "bs_mask: .long 0\n"
    "bs_orig: .long 0\n"
    "_beep_stub_end:\n");

extern const UBYTE beep_stub_start[], beep_stub_end[];

static UBYTE *stub;             /* installed copy */
static ULONG stub_size;

#define STUB_TASK(p) ((ULONG *)((p) + stub_size - 12))
#define STUB_MASK(p) ((ULONG *)((p) + stub_size - 8))
#define STUB_ORIG(p) ((ULONG *)((p) + stub_size - 4))

int beep_install(ULONG mask)
{
    APTR orig;

    stub_size = (ULONG)(beep_stub_end - beep_stub_start);
    stub = AllocMem(stub_size, MEMF_PUBLIC);
    if (!stub)
        return -1;
    memcpy(stub, beep_stub_start, stub_size);
    *STUB_TASK(stub) = (ULONG)FindTask(NULL);
    *STUB_MASK(stub) = mask;

    Forbid();
    orig = SetFunction((struct Library *)IntuitionBase, LVO_DisplayBeep,
                       (ULONG (*)())stub);
    *STUB_ORIG(stub) = (ULONG)orig;
    CacheClearU();              /* we wrote code: flush the 040/060 caches */
    Permit();
    return 0;
}

void beep_remove(void)
{
    APTR current;

    if (!stub)
        return;
    Forbid();
    current = SetFunction((struct Library *)IntuitionBase, LVO_DisplayBeep,
                          (ULONG (*)())*STUB_ORIG(stub));
    if (current != (APTR)stub) {
        /* Someone patched DisplayBeep() after us: put their patch back,
         * turn ours into a pass-through and leave it in memory for good. */
        SetFunction((struct Library *)IntuitionBase, LVO_DisplayBeep,
                    (ULONG (*)())current);
        *STUB_TASK(stub) = 0;
        CacheClearU();
        Permit();
        stub = NULL;
        return;
    }
    Permit();
    FreeMem(stub, stub_size);
    stub = NULL;
}
