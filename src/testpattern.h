/*
 * Animated 8-bit indexed test pattern that echoes input on screen.
 * Shared by the Linux host and the 68k pipe test harness.
 */
#ifndef RDP_TESTPATTERN_H
#define RDP_TESTPATTERN_H

#include <stdint.h>
#include "rdp.h"

/* Allocate a w x h pattern (at least 640x400); returns 0 on success. */
int tp_init(int w, int h);
uint8_t *tp_fb(void);
const uint8_t *tp_palette(void);

/* Redraw from scratch for a new session (may be NULL). */
void tp_reset(rdp_session *s);
/* Move the bouncing box one step. */
void tp_animate(void);

/* A middle click asks for a resize (640x512 <-> 800x600, standing in for
 * a screen switch). Returns 1 and the new size once per request. */
int tp_resize_requested(int *w, int *h);
/* Reallocate and redraw at a new size (at least 640x400). Returns 0. */
int tp_resize(int w, int h);
int tp_width(void);
int tp_height(void);
/* Incremented whenever the framebuffer changes. */
unsigned long tp_generation(void);
/* Fill in the input and clipboard callbacks. The pattern's clipboard
 * starts with TP_CLIP_TEXT; text from the client replaces it and is logged
 * (escaped) as "clipboard from client (N bytes): ...". */
void tp_set_callbacks(rdp_callbacks *cb);

#define TP_CLIP_TEXT "Hello from the Amiga \xa3""5\nLine 2\n"

#endif
