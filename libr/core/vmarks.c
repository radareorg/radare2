/* radare - LGPL - Copyright 2009-2026 - pancake */

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
		r_cons_printf (core->cons, "  .-----[ vmarks ]-------------------------------------------------.\n");
	}
	PJ *pj = NULL;
	if (mode == 'j') {
		pj = r_core_pj_new (core);
		pj_a (pj);
	}
	RStrBuf *sb = r_strbuf_new ("");
	ut32 count = 0;
	for (i = 0; i < UT8_MAX; i++) {
		const ut64 markaddr = core->marks[i].addr;
		if (markaddr == UT64_MAX) {
			continue;
		}
		count++;
		if (mode == '*') {
			r_strbuf_appendf (sb, "fv 0x%02x 0x%"PFMT64x"\n", (int)i, markaddr);
		} else if (mode == 'j') {
			pj_o (pj);
			pj_kn (pj, "ord", i);
			if (IS_PRINTABLE (i)) {
				char *chstr = r_str_newf ("%c", i);
				pj_ks (pj, "key", chstr);
				free (chstr);
			}
			pj_kn (pj, "addr", markaddr);
			pj_end (pj);
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
			char *msg;
			if (i > ASCII_MAX) {
				msg = r_str_newf ("  | ['\\x%02x] 0x%"PFMT64x, (int)(i - ASCII_MAX - 1), markaddr, r);
			} else {
				msg = r_str_newf ("  | ['%c]   0x%"PFMT64x, (char)i, markaddr, r);
			}
			r_strbuf_append (sb, msg);
			int left = 67 - strlen (msg);
			if (left > 0) {
				r_strbuf_pad (sb, ' ', left);
			}
			r_strbuf_append (sb, "|\n");
			free (r);
		} else {
			if (i > ASCII_MAX) {
				r_strbuf_appendf (sb, "- [m\\x%02x] 0x%"PFMT64x"\n", (int)(i - ASCII_MAX - 1), markaddr);
			} else {
				r_strbuf_appendf (sb, "- [m%c]      0x%"PFMT64x"\n", (char)i, markaddr);
			}
		}
		res = true;
	}
	if (pj) {
		pj_end (pj);
		char *s = pj_drain (pj);
		r_cons_println (core->cons, s);
		free (s);
	} else if (mode == 'v') {
		r_strbuf_appendf (sb, "  `----------------------------------------------------------------'\n");
		if (count == 0) {
			r_cons_clear00 (core->cons);
			r_cons_printf (core->cons, "\nNo visual marks have been set.\n");
			r_cons_printf (core->cons, "Use `m<KEY>` and then `'<KEY>` like in VIM\n");
			r_cons_any_key (core->cons, NULL);
		}
	}
	if (sb) {
		char *s = r_strbuf_drain (sb);
		r_cons_print (core->cons, s);
		free (s);
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

R_API ut64 r_core_vmark_get(RCore *core, ut8 ch) {
	R_RETURN_VAL_IF_FAIL (core, UT64_MAX);
	return core->marks[ch].addr;
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
