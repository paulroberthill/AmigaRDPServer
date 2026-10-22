/*
 * Runs the DisplayBeep() patch stub from src/amiga/beep.c (68k only, under
 * vamos): it must Signal() the task stored in it, then continue into the
 * stored original routine with the caller's a0 (the Screen argument) intact.
 *
 * vamos's Signal() is a no-op, so ExecBase (address 4) is pointed at a fake
 * library for the call whose Signal entry (-324) records a1 and d0.
 */
#include <exec/types.h>
#include <dos/dos.h>
#include <proto/exec.h>
#include <stdio.h>
#include <string.h>

unsigned long __stack = 65536;

extern const UBYTE beep_stub_start[], beep_stub_end[];
static volatile ULONG orig_calls, orig_a0, sig_calls, sig_task, sig_mask;

/* Stands in for the original DisplayBeep(): records a0 and returns. */
__asm__(
    "    .text\n"
    "    .even\n"
    "_fake_orig:\n"
    "    addq.l  #1,_orig_calls\n"
    "    move.l  a0,_orig_a0\n"
    "    rts\n");
extern void fake_orig(void);

/* Call the stub with a0 = screen, as intuition would. */
static void call_stub(UBYTE *stub, ULONG screen)
{
    register ULONG a0 __asm__("a0") = screen;
    register UBYTE *a2 __asm__("a2") = stub;
    __asm__ volatile("jsr (%1)" : "+r"(a0) : "a"(a2) : "d0", "d1", "a1", "memory", "cc");
}

/* Fake exec Signal(a1 = task, d0 = mask): records its arguments. */
__asm__(
    "    .text\n"
    "    .even\n"
    "_fake_signal:\n"
    "    addq.l  #1,_sig_calls\n"
    "    move.l  a1,_sig_task\n"
    "    move.l  d0,_sig_mask\n"
    "    rts\n");
extern void fake_signal(void);

static UWORD fake_lib[200];         /* jump table below, "base" at the end */

/* Run the stub with ExecBase temporarily replaced by fake_lib. */
static void call_stub_fake_exec(UBYTE *stub, ULONG screen)
{
    volatile ULONG *execbase = (volatile ULONG *)4;
    UBYTE *base = (UBYTE *)fake_lib + sizeof(fake_lib);
    UWORD *jmp = (UWORD *)(base - 324);
    ULONG saved = *execbase;

    jmp[0] = 0x4ef9;                /* JMP abs.l fake_signal */
    jmp[1] = (UWORD)((ULONG)fake_signal >> 16);
    jmp[2] = (UWORD)(ULONG)fake_signal;
    CacheClearU();
    Disable();
    *execbase = (ULONG)base;
    call_stub(stub, screen);
    *execbase = saved;
    Enable();
}

int main(void)
{
    static UBYTE stub[64];
    ULONG size = (ULONG)(beep_stub_end - beep_stub_start);
    int fails = 0;

    memcpy(stub, beep_stub_start, size);
    *(ULONG *)(stub + size - 12) = (ULONG)FindTask(NULL);
    *(ULONG *)(stub + size - 8) = SIGBREAKF_CTRL_F;
    *(ULONG *)(stub + size - 4) = (ULONG)fake_orig;

    call_stub_fake_exec(stub, 0x12345678);
    printf("%s Signal(our task, CTRL_F) called once (calls %lu, task %s, mask %08lx)\n",
           sig_calls == 1 && sig_task == (ULONG)FindTask(NULL) && sig_mask == SIGBREAKF_CTRL_F
               ? "ok  " : "FAIL", (unsigned long)sig_calls,
           sig_task == (ULONG)FindTask(NULL) ? "ours" : "wrong", (unsigned long)sig_mask);
    fails += !(sig_calls == 1 && sig_task == (ULONG)FindTask(NULL) && sig_mask == SIGBREAKF_CTRL_F);
    printf("%s original called once with a0 intact (calls %lu, a0 %08lx)\n",
           orig_calls == 1 && orig_a0 == 0x12345678 ? "ok  " : "FAIL",
           (unsigned long)orig_calls, (unsigned long)orig_a0);
    fails += !(orig_calls == 1 && orig_a0 == 0x12345678);

    *(ULONG *)(stub + size - 12) = 0;           /* pass-through mode */
    call_stub_fake_exec(stub, 0xcafe0000);
    printf("%s pass-through: no Signal, original still called\n",
           sig_calls == 1 && orig_calls == 2 && orig_a0 == 0xcafe0000 ? "ok  " : "FAIL");
    fails += !(sig_calls == 1 && orig_calls == 2 && orig_a0 == 0xcafe0000);
    printf(fails ? "%d FAILED\n" : "all passed\n", fails);
    return fails != 0;
}
