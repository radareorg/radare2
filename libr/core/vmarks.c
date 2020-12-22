/* radare - LGPL - Copyright 2009-2020 - pancake */

#include <r_core.h>


R_API void r_core_visual_mark_reset(RCore *core) {
	size_t i;
	for (i = 0; i < UT8_MAX; i++) {
		core->marks[i] = UT64_MAX;
	}
	core->marks_init = true;
}

R_API bool r_core_visual_mark_dump(RCore *core) {
	size_t i;
	if (!core->marks_init) {
		return false;
	}
	bool res = false;
	for (i = 0; i < UT8_MAX; i++) {
		if (core->marks[i] != UT64_MAX) {
			if (i > ASCII_MAX) {
				r_cons_printf ("fV %zu 0x%"PFMT64x"\n", i - ASCII_MAX - 1, core->marks[i]);
			} else {
				r_cons_printf ("fV %c 0x%"PFMT64x"\n", (char)i, core->marks[i]);
			}
			res = true;
		}
	}
	return res;
}

R_API void r_core_visual_mark_set(RCore *core, ut8 ch, ut64 addr) {
	if (!core->marks_init) {
		r_core_visual_mark_reset (core);
	}
	core->marks[ch] = addr;
}

R_API void r_core_visual_mark_del(RCore *core, ut8 ch) {
	if (!core->marks_init) {
		return;
	}
	core->marks[ch] = UT64_MAX;
}

R_API void r_core_visual_mark(RCore *core, ut8 ch) {
	if (IS_DIGIT (ch)) {
		ch += ASCII_MAX + 1;
	}
	r_core_visual_mark_set (core, ch, core->offset);
}

R_API void r_core_visual_mark_seek(RCore *core, ut8 ch) {
	if (core->marks_init && core->marks[ch] != UT64_MAX) {
		r_core_seek (core, core->marks[ch], true);
	}
}
