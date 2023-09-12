/* radare - LGPL - Copyright 2009-2023 - pancake */

#include <r_core.h>

// TODO: rename to RCore.vmark...()

R_API void r_core_visual_mark_reset(RCore *core) {
	r_return_if_fail (core);
	size_t i;
	for (i = 0; i < UT8_MAX; i++) {
		core->marks[i].addr = UT64_MAX;
	}
	core->marks_init = true;
}

R_API bool r_core_visual_mark_dump(RCore *core) {
	r_return_val_if_fail (core, false);
	size_t i;
	if (!core->marks_init) {
		return false;
	}
	bool res = false;
	for (i = 0; i < UT8_MAX; i++) {
		ut64 markaddr = core->marks[i].addr;
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

R_API void r_core_visual_mark_set(RCore *core, ut8 ch, ut64 addr) {
	r_return_if_fail (core);
	if (!core->marks_init) {
		r_core_visual_mark_reset (core);
	}
	core->marks[ch].addr = addr;
}

R_API void r_core_visual_mark_set2(RCore *core, ut8 ch, ut64 addr, int x, int y) {
	r_return_if_fail (core);
	if (!core->marks_init) {
		r_core_visual_mark_reset (core);
	}
	VisualMark *vm = &core->marks[ch];
	vm->addr = addr;
	vm->x = x;
	vm->y = y;
}

R_API void r_core_visual_mark_del(RCore *core, ut8 ch) {
	r_return_if_fail (core);
	if (!core->marks_init) {
		return;
	}
	core->marks[ch].addr = UT64_MAX;
}

R_API void r_core_visual_mark(RCore *core, ut8 ch) {
	r_return_if_fail (core);
	if (IS_DIGIT (ch)) {
		ch += ASCII_MAX + 1;
	}
	r_core_visual_mark_set (core, ch, core->offset);
}

R_API void r_core_visual_mark_seek(RCore *core, ut8 ch) {
	r_return_if_fail (core);
	ut64 markaddr = core->marks[ch].addr;
	if (core->marks_init && markaddr != UT64_MAX) {
		r_core_seek (core, markaddr, true);
	}
}

R_API void r_core_visual_mark_seek2(RCore *core, ut8 ch, RAGraph *g) {
	VisualMark *vm = &core->marks[ch];
	if (vm->addr != UT64_MAX) {
		r_core_seek (core, vm->addr, true);
		g->need_reload_nodes = true;
		g->update_seek_on = NULL;
		g->force_update_seek = false;
	//	agraph_update_seek (g, vm->addr, true);
		g->can->sx = vm->x;
		g->can->sy = vm->y;
	}
}
