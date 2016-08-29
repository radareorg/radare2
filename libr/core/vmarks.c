/* radare - LGPL - Copyright 2009-2016 - pancake */

#include <r_core.h>

/* maybe move this into RCore */
static bool marks_init = false;
static ut64 marks[UT8_MAX + 1];

R_API void r_core_visual_mark_reset(RCore *core) {
	int i;
	marks_init = true;
	for (i = 0; i < UT8_MAX; i++) {
		marks[i] = UT64_MAX;
	}
}

R_API void r_core_visual_mark_dump(RCore *core) {
	int i;
	if (!marks_init) {
		return;
	}
	for (i = 0; i < UT8_MAX; i++) {
		if (marks[i] != UT64_MAX) {
			r_cons_printf ("fV %d 0x%"PFMT64x"\n", i, marks[i]);
		}
	}
}

R_API void r_core_visual_mark_set(RCore *core, ut8 ch, ut64 addr) {
	if (!marks_init) {
		r_core_visual_mark_reset(core);
	}
	marks[ch] = addr;
}

R_API void r_core_visual_mark(RCore *core, ut8 ch) {
	r_core_visual_mark_set (core, ch, core->offset);
}

R_API void r_core_visual_mark_seek(RCore *core, ut8 ch) {
	if (marks_init && marks[ch] != UT64_MAX) {
		r_core_seek (core, marks[ch], 1);
	}
}
