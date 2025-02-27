/* radare - LGPL - Copyright 2009-2023 - pancake */

#include <r_core.h>

R_API void r_core_vmark_reset(RCore *core) {
	R_RETURN_IF_FAIL (core);
	size_t i;
	for (i = 0; i < UT8_MAX; i++) {
		core->marks[i].addr = UT64_MAX;
	}
}

R_API bool r_core_vmark_dump(RCore *core, int mode) {
	R_RETURN_VAL_IF_FAIL (core, false);
	size_t i;
	bool res = false;
	if (mode == 'v') {
		r_cons_printf ("  .-----[ vmarks ]-------------------------------------------------.\n");
	}
	int count = 0;
	for (i = 0; i < UT8_MAX; i++) {
		const ut64 markaddr = core->marks[i].addr;
		if (markaddr == UT64_MAX) {
			continue;
		}
		count++;
		if (mode == '*') {
			r_cons_printf ("fV %d 0x%"PFMT64x"\n", (int)i, markaddr);
		} else if (mode == 'v') {
			char *s = r_core_cmd_strf (core, "fd@0x%08"PFMT64x, markaddr);
			char *z = r_core_cmd_strf (core, "CC.@0x%08"PFMT64x, markaddr);
			r_str_trim (s);
			r_str_trim (z);
			char *r = NULL;
			if (*z) {
				// have comment
				r = r_str_newf ("%s ; %s", s, z);
				free (s);
				free (z);
			} else {
				r = s;
				free (z);
			}
			if (strlen (r) > 42) {
				r[42] = 0;
			}
			if (i > ASCII_MAX) {
				r_cons_printf ("  | ['\\x%02x] 0x%"PFMT64x"  %42s |  \n", (int)(i - ASCII_MAX - 1), markaddr, r);
			} else {
				r_cons_printf ("  | ['%c]   0x%"PFMT64x"  %-42s |  \n", (char)i, markaddr, r);
			}
			free (r);
		} else {
			if (i > ASCII_MAX) {
				r_cons_printf ("- [m\\x%02x] 0x%"PFMT64x"\n", (int)(i - ASCII_MAX - 1), markaddr);
			} else {
				r_cons_printf ("- [m%c]      0x%"PFMT64x"\n", (char)i, markaddr);
			}
		}
		res = true;
	}
	if (mode == 'v') {
		r_cons_printf ("  `----------------------------------------------------------------'\n");
		if (count == 0) {
			r_cons_clear00 ();
			r_cons_printf ("\nNo visual marks have been set.\n");
			r_cons_printf ("Use `m<KEY>` and then `'<KEY>` like in VIM\n");
			r_cons_any_key (NULL);
		}
	}
	return res;
}

R_API void r_core_vmark_set(RCore *core, ut8 ch, ut64 addr, int x, int y) {
	R_RETURN_IF_FAIL (core);
	VisualMark *vm = &core->marks[ch];
	vm->addr = addr;
	vm->x = x;
	vm->y = y;
}

R_API void r_core_vmark_del(RCore *core, ut8 ch) {
	R_RETURN_IF_FAIL (core);
	core->marks[ch].addr = UT64_MAX;
}

R_API void r_core_vmark(RCore *core, ut8 ch) {
	R_RETURN_IF_FAIL (core);
	if (isdigit (ch)) {
		ch += ASCII_MAX + 1;
	}
	r_core_vmark_set (core, ch, core->addr, 0, 0);
}

R_API void r_core_vmark_seek(RCore *core, ut8 ch, RAGraph *g) {
	R_RETURN_IF_FAIL (core);
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
