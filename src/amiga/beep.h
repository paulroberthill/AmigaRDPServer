/*
 * Forward DisplayBeep() to the RDP client: intuition.library's
 * DisplayBeep() is patched so every call also signals our task.
 */
#ifndef RDP_BEEP_H
#define RDP_BEEP_H

#include <exec/types.h>

/* Install the patch; `mask` is signalled to the calling task on every
 * DisplayBeep(). Returns 0 on success. */
int beep_install(ULONG mask);

/* Remove the patch (or make it a pass-through if another program has
 * patched DisplayBeep() on top of it since). */
void beep_remove(void);

#endif
