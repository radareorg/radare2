/* radare - LGPL - Copyright 2009-2026 - pancake */

// R2R db/cmd/cmd_fv
// R2R db/cmd/cmd_visual

#include <r_core_priv.h>

static char *vmark_line(RCore *core, int key) {
	ut64 addr = core->marks[key].addr;
	char *flag = r_core_cmd_strf (core, "fd@0x%08"PFMT64x, addr);
	char *comment = r_core_cmd_strf (core, "CC.@0x%08"PFMT64x, addr);
	r_str_trim (flag);
	r_str_trim (comment);
	char label[8];
	if (IS_PRINTABLE (key)) {
		snprintf (label, sizeof (label), "'%c", key);
	} else {
		snprintf (label, sizeof (label), "'\\x%02x", key);
	}
	char *line = r_str_newf ("[%s] 0x%08"PFMT64x"  %s%s%s", label, addr,
		r_str_get (flag), R_STR_ISNOTEMPTY (comment)? " ; ": "", r_str_get (comment));
	free (flag);
	free (comment);
	return line;
}

R_IPI int r_core_vmark_select(RCore *core, bool delete_mark) {
	RCons *cons = core->cons;
	char *lines[UT8_MAX + 1];
	int count = 0, from = 0, ret = -1;
	bool mouse = cons->mouse;
	int i;
	for (i = 0; i <= UT8_MAX; i++) {
		if (core->marks[i].addr == UT64_MAX) {
			continue;
		}
		char *line = vmark_line (core, i);
		if (!line) {
			goto beach;
		}
		r_str_replace_char (line, '\n', ' ');
		r_str_replace_char (line, '\r', ' ');
		r_str_replace_char (line, '\t', ' ');
		lines[count++] = line;
	}
	if (!count) {
		r_core_vmark_dump (core, 'v');
		return -1;
	}
	r_cons_enable_mouse (cons, r_config_get_b (core->config, "scr.wheel"));
	for (;;) {
		int height;
		int width = R_MAX (1, r_cons_get_size (cons, &height) - 1);
		height = R_MAX (1, height);
		int page = R_MIN (count, R_MAX (1, height - 2));
		from = R_MIN (from, R_MAX (0, count - page));
		int to = R_MIN (count, from + page);
		RStrBuf *frame = r_strbuf_new (NULL);
		if (height > 1) {
			r_strbuf_appendf (frame, "vmarks [%d-%d/%d] - %s\n", from + 1, to, count,
				delete_mark? "delete": "jump");
		}
		for (i = from; i < to; i++) {
			r_strbuf_append (frame, lines[i]);
			if (i + 1 < to || height > 2) {
				r_strbuf_append (frame, "\n");
			}
		}
		if (height > 2) {
			r_strbuf_append (frame, "Up/Down, wheel: scroll | PgUp/PgDn: page | key: select");
		}
		char *cropped = r_str_ansi_crop (r_strbuf_get (frame), 0, 0, width, height);
		r_strbuf_free (frame);
		if (!cropped) {
			break;
		}
		r_cons_clear00 (cons);
		r_cons_print (cons, cropped);
		r_cons_flush (cons);
		free (cropped);
		int ch = r_cons_readchar (cons);
		if (ch == -1) {
			break;
		}
		if (ch == 0x1b && !cons->input_state.readbuffer_length) {
			int next = r_cons_readchar_timeout (cons, 100);
			if (next == -1) {
				break;
			}
			char byte = next;
			if (!r_cons_readpush (cons, &byte, 1)) {
				break;
			}
		}
		bool navigation = ch == 0x1b || (ut8)ch == 0x9b;
#if R2__WINDOWS__
		navigation |= cons->is_arrow || cons->mouse_event;
#endif
		// Literal letters remain available as mark shortcuts.
		if (!navigation) {
			ret = (ut8)ch;
			break;
		}
		ch = r_cons_arrow_to_hjkl (cons, ch);
		int step = cons->mouse_event? R_CLAMP (r_config_get_i (core->config, "scr.wheel.speed"), 1, count): 1;
		switch (ch) {
		case 'j':
			from += R_MIN (step, count - 1 - from);
			break;
		case 'k':
			from = R_MAX (0, from - step);
			break;
		case 'J':
		case 'l':
			from += R_MIN (page, count - 1 - from);
			break;
		case 'K':
		case 'h':
			from = R_MAX (0, from - page);
			break;
		default:
			if (!cons->mouse_event) {
				goto beach;
			}
			break;
		}
	}
beach:
	if (cons->mouse != mouse) {
		r_cons_enable_mouse (cons, mouse);
	}
	for (i = 0; i < count; i++) {
		free (lines[i]);
	}
	return ret;
}

R_API void r_core_vmark_reset(RCore *core) {
	R_RETURN_IF_FAIL (core);
	size_t i;
	for (i = 0; i <= UT8_MAX; i++) {
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
		if (!pj) {
			return false;
		}
		pj_a (pj);
	}
	for (i = 0; i <= UT8_MAX; i++) {
		const ut64 markaddr = core->marks[i].addr;
		if (markaddr == UT64_MAX) {
			continue;
		}
		if (mode == '*') {
			r_cons_printf (core->cons, "fv 0x%02x 0x%"PFMT64x"\n", (int)i, markaddr);
		} else if (mode == 'j') {
			pj_o (pj);
			pj_kn (pj, "ord", i);
			if (IS_PRINTABLE (i)) {
				char chstr[2] = { (char)i, 0 };
				pj_ks (pj, "key", chstr);
			}
			pj_kn (pj, "addr", markaddr);
			pj_end (pj);
		} else if (mode == 'v') {
			char *msg = vmark_line (core, i);
			r_cons_printf (core->cons, "  | %-62.62s |\n", r_str_get (msg));
			free (msg);
		} else {
			if (!IS_PRINTABLE (i)) {
				r_cons_printf (core->cons, "- [m\\x%02x] 0x%"PFMT64x"\n", (int)i, markaddr);
			} else {
				r_cons_printf (core->cons, "- [m%c]      0x%"PFMT64x"\n", (char)i, markaddr);
			}
		}
		res = true;
	}
	if (pj) {
		pj_end (pj);
		r_cons_println (core->cons, pj_string (pj));
		pj_free (pj);
	} else if (mode == 'v') {
		r_cons_printf (core->cons, "  `----------------------------------------------------------------'\n");
		if (!res && r_cons_is_interactive (core->cons)) {
			r_cons_clear00 (core->cons);
			r_cons_printf (core->cons, "\nNo visual marks have been set.\n");
			r_cons_printf (core->cons, "Use `m<KEY>` and then `'<KEY>` like in VIM\n");
			r_cons_any_key (core->cons, NULL);
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

R_API ut64 r_core_vmark_get(RCore *core, ut8 ch) {
	R_RETURN_VAL_IF_FAIL (core, UT64_MAX);
	return core->marks[ch].addr;
}

R_API void r_core_vmark(RCore *core, ut8 ch) {
	R_RETURN_IF_FAIL (core);
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
