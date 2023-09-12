/* radare - LGPL - Copyright 2009-2023 - pancake */

#include <r_core.h>

R_API void r_core_vmark_reset(RCore *core) {
	r_return_if_fail (core);
	size_t i;
	for (i = 0; i < UT8_MAX; i++) {
		core->marks[i].addr = UT64_MAX;
	}
}

R_API bool r_core_vmark_dump(RCore *core) {
	r_return_val_if_fail (core, false);
	size_t i;
	bool res = false;
	for (i = 0; i < UT8_MAX; i++) {
		const ut64 markaddr = core->marks[i].addr;
		if (markaddr != UT64_MAX) {
			if (i > ASCII_MAX) {
				r_cons_printf ("fV %d 0x%"PFMT64x"\n", (int)(i - ASCII_MAX - 1), markaddr);
			} else {
				r_cons_printf ("fV %c 0x%"PFMT64x"\n", (char)i, markaddr);
			}
			res = true;
		}
	}
	return res;
}

R_API void r_core_vmark_set(RCore *core, ut8 ch, ut64 addr, int x, int y) {
	r_return_if_fail (core);
	VisualMark *vm = &core->marks[ch];
	vm->addr = addr;
	vm->x = x;
	vm->y = y;
}

R_API void r_core_vmark_del(RCore *core, ut8 ch) {
	r_return_if_fail (core);
	core->marks[ch].addr = UT64_MAX;
}

R_API void r_core_vmark(RCore *core, ut8 ch) {
	r_return_if_fail (core);
	if (IS_DIGIT (ch)) {
		ch += ASCII_MAX + 1;
	}
	r_core_vmark_set (core, ch, core->offset, 0, 0);
}

R_API void r_core_vmark_seek(RCore *core, ut8 ch, RAGraph *g) {
	r_return_if_fail (core);
	VisualMark *vm = &core->marks[ch];
	if (vm->addr != UT64_MAX) {
		r_core_seek (core, vm->addr, true);
		if (g) {
			g->need_reload_nodes = true;
			g->update_seek_on = NULL;
			g->force_update_seek = false;
			g->can->sx = vm->x;
			g->can->sy = vm->y;
		}
	}
}
