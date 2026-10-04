/* radare2 - LGPL - Copyright 2014-2026 - pancake, vane11ope */

static ut64 r_panels_parse_string_on_cursor(RCore *core, RPanel *panel, int idx) {
	if (!panel->model->cmdStrCache) {
		return UT64_MAX;
	}
	RStrBuf *buf = r_strbuf_new (NULL);
	char *s = panel->model->cmdStrCache;
	int l = 0;
	while (R_STR_ISNOTEMPTY (s) && l != idx) {
		if (*s == '\n') {
			l++;
		}
		s++;
	}
	while (R_STR_ISNOTEMPTY (s) && R_STR_ISNOTEMPTY (s + 1)) {
		if (*s == '0' && *(s + 1) == 'x') {
			r_strbuf_append_n (buf, s, 2);
			while (*s != ' ') {
				r_strbuf_append_n (buf, s, 1);
				s++;
			}
			ut64 ret = r_num_math (core->num, r_strbuf_get (buf));
			r_strbuf_free (buf);
			return ret;
		}
		s++;
	}
	r_strbuf_free (buf);
	return UT64_MAX;
}

static void r_panels_activate_cursor(RCore *core) {
	RPanels *panels = core->panels;
	RPanel *cur = r_panels_get_cur_panel (panels);
	bool normal = r_panels_is_normal_cursor_type (cur);
	bool abnormal = r_panels_is_abnormal_cursor_type (core, cur);
	if (normal || abnormal) {
		if (normal && cur->model->cache) {
			if (r_panels_show_status_yesno (core, 1, "You need to turn off cache to use cursor. Turn off now? (Y/n)")) {
				cur->model->cache = false;
				r_panels_set_cmd_str_cache (core, cur, NULL);
				(void)r_panels_show_status (core, "Cache is off and cursor is on");
				r_panels_set_cursor (core, !core->print->cur_enabled);
				cur->view->refresh = true;
				r_panels_reset_scroll_pos (cur);
			} else {
				(void)r_panels_show_status (core, "You can always toggle cache by \'&\' key");
			}
			return;
		}
		r_panels_set_cursor (core, !core->print->cur_enabled);
		cur->view->refresh = true;
	} else {
		(void)r_panels_show_status (core, "Cursor is not available for the current panel.");
	}
}

static void r_panels_fix_cursor_up(RCore *core) {
	RPrint *print = core->print;
	if (print->cur >= 0) {
		return;
	}
	int sz = r_core_visual_prevopsz (core, core->addr + print->cur);
	if (sz < 1) {
		sz = 1;
	}
	r_core_seek_delta (core, -sz);
	print->cur += sz;
	if (print->ocur != -1) {
		print->ocur += sz;
	}
}

static void r_panels_cursor_left(RCore *core) {
	RPanel *cur = r_panels_get_cur_panel (core->panels);
	RPrint *print = core->print;
	if (r_panels_check_panel_type (cur, "dr")
			|| r_panels_check_panel_type (cur, "px")) {
		if (print->cur > 0) {
			print->cur--;
			cur->model->addr--;
		}
	} else if (r_panels_check_panel_type (cur, "pd")) {
		print->cur--;
		r_panels_fix_cursor_up (core);
	} else {
		print->cur--;
	}
}

static void r_panels_fix_cursor_down(RCore *core) {
	RPrint *print = core->print;
	bool cur_is_visible = core->addr + print->cur + 32 < print->screen_bounds;
	if (!cur_is_visible) {
		int i;
		// XXX: ugly hack
		for (i = 0; i < 2; i++) {
			RAnalOp op;
			int sz = r_asm_disassemble (core->rasm, &op, core->block, 32);
			if (sz < 1) {
				sz = 1;
			}
			r_anal_op_fini (&op);
			r_core_seek_delta (core, sz);
			print->cur = R_MAX (print->cur - sz, 0);
			if (print->ocur != -1) {
				print->ocur = R_MAX (print->ocur - sz, 0);
			}
		}
	}
}

static void r_panels_cursor_right(RCore *core) {
	RPanel *cur = r_panels_get_cur_panel (core->panels);
	RPrint *print = core->print;
	if (r_panels_check_panel_type (cur, "px") && print->cur >= 15) {
		return;
	}
	print->cur++;
	if (r_panels_check_panel_type (cur, "dr")
			|| r_panels_check_panel_type (cur, "px")) {
		cur->model->addr++;
	} else if (r_panels_check_panel_type (cur, "pd")) {
		r_panels_fix_cursor_down (core);
	}
}

// copypasta from visual
static ut64 r_panels_insoff(RCore *core, int delta) {
	int minop = r_arch_info (core->anal->arch, R_ARCH_INFO_MINOP_SIZE);
	int maxop = r_arch_info (core->anal->arch, R_ARCH_INFO_MAXOP_SIZE);
	ut64 addr = core->addr + delta; // should be core->print->cur
	RAnalBlock *bb = r_anal_bb_from_offset (core->anal, addr - minop);
	if (bb) {
		ut64 res = r_anal_bb_opaddr_at (bb, addr - minop);
		if (res != UT64_MAX) {
			if (res < addr && addr - res <= maxop) {
				return res;
			}
		}
	}
	return addr;
}

static void r_panels_cursor_up(RCore *core) {
	prevOpcode (core);
	r_panels_fix_cursor_up (core);
}

static void r_panels_cursor_down(RCore *core) {
	nextOpcode (core);
}

static bool r_panels_handle_zoom_mode(RCore *core, const int key) {
	RPanels *panels = core->panels;
	r_cons_switchbuf (core->cons, false);
	switch (key) {
	case 'Q':
	case 'q':
	case 0x0d:
		r_panels_toggle_zoom_mode (core);
		break;
	case 'c':
	case 'C':
	case ';':
	case ' ':
	case '_':
	case '/':
	case '"':
	case 'A':
	case 'r':
	case '0':
	case '1':
	case '2':
	case '3':
	case '4':
	case '5':
	case '6':
	case '7':
	case '8':
	case '9':
	case 'u':
	case 'U':
	case 'b':
	case 'd':
	case 'n':
	case 'N':
	case 'g':
	case 'h':
	case 'j':
	case 'k':
	case 'J':
	case 'K':
	case 'l':
	case '.':
	case 'R':
	case 'p':
	case 'P':
	case 's':
	case 'S':
	case 't':
	case 'T':
	case 'x':
	case 'X':
	case ':':
	case '[':
	case ']':
	case '=':
	case 'm':
	case 'i':
		return false;
	case 9:
		r_panels_restore_panel_pos (panels->panel[panels->curnode]);
		r_panels_handle_tab_key (core, false);
		r_panels_save_panel_pos (panels->panel[panels->curnode]);
		r_panels_maximize_panel_size (panels);
		break;
	case 'Z':
		r_panels_restore_panel_pos (panels->panel[panels->curnode]);
		r_panels_handle_tab_key (core, true);
		r_panels_save_panel_pos (panels->panel[panels->curnode]);
		r_panels_maximize_panel_size (panels);
		break;
	case '?':
		r_panels_toggle_zoom_mode (core);
		r_panels_toggle_help (core);
		r_panels_toggle_zoom_mode (core);
		break;
	}
	return true;
}

static void r_panels_set_refresh_by_type(RCore *core, const char *cmd, bool clearCache) {
	RPanels *panels = core->panels;
	int i;
	for (i = 0; i < panels->n_panels; i++) {
		RPanel *p = r_panels_get_panel (panels, i);
		if (!r_panels_check_panel_type (p, cmd)) {
			continue;
		}
		p->view->refresh = true;
		if (clearCache) {
			r_panels_set_cmd_str_cache (core, p, NULL);
		}
	}
}

static char *r_panels_filter_arg(char *a) {
	r_str_filter (a, -1);
	char *r = r_str_escape (a);
	free (a);
	return r;
}

static bool r_panels_move_to_direction(RCore *core, Direction direction) {
	RPanels *panels = core->panels;
	RPanelPos *cp = &r_panels_get_cur_panel (panels)->view->pos;
	int cx0 = cp->x, cx1 = cp->x + cp->w - 1, cy0 = cp->y, cy1 = cp->y + cp->h - 1;
	int i;
	for (i = 0; i < panels->n_panels; i++) {
		RPanel *p = r_panels_get_panel (panels, i);
		RPanelPos *tp = &p->view->pos;
		int temp_x0 = tp->x, temp_x1 = tp->x + tp->w - 1;
		int temp_y0 = tp->y, temp_y1 = tp->y + tp->h - 1;
		switch (direction) {
		case 'h':
			if (temp_x1 == cx0 && !(temp_y1 <= cy0 || cy1 <= temp_y0)) {
				r_panels_set_curnode (core, i);
				return true;
			}
			break;
		case 'l':
			if (temp_x0 == cx1 && !(temp_y1 <= cy0 || cy1 <= temp_y0)) {
				r_panels_set_curnode (core, i);
				return true;
			}
			break;
		case 'k':
			if (temp_y1 == cy0 && !(temp_x1 <= cx0 || cx1 <= temp_x0)) {
				r_panels_set_curnode (core, i);
				return true;
			}
			break;
		case 'j':
			if (temp_y0 == cy1 && !(temp_x1 <= cx0 || cx1 <= temp_x0)) {
				r_panels_set_curnode (core, i);
				return true;
			}
			break;
		default:
			break;
		}
	}
	return false;
}

static void r_panels_toggle_window_mode(RCore *core) {
	RPanels *panels = core->panels;
	if (panels->mode != PANEL_MODE_WINDOW) {
		panels->prevMode = panels->mode;
		r_panels_set_mode (core, PANEL_MODE_WINDOW);
	} else {
		r_panels_set_mode (core, panels->prevMode);
		panels->prevMode = PANEL_MODE_DEFAULT;
	}
}

static void r_panels_resize_panel(RPanels *panels, Direction dir) {
	RPanel *cur = r_panels_get_cur_panel (panels);
	if (!cur) {
		return;
	}
	bool horiz = (dir == 'h' || dir == 'l');
	bool neg = (dir == 'h' || dir == 'k');
	int d = horiz ? PANEL_CONFIG_RESIZE_W : PANEL_CONFIG_RESIZE_H;
	int pmax = horiz ? panels->can->w : panels->can->h - PANEL_FOOTER_H;
	// offsets into RPanelPos for primary axis (pos/size) and secondary axis
	size_t op = horiz ? offsetof (RPanelPos, x) : offsetof (RPanelPos, y);
	size_t os = horiz ? offsetof (RPanelPos, w) : offsetof (RPanelPos, h);
	size_t sp = horiz ? offsetof (RPanelPos, y) : offsetof (RPanelPos, x);
	size_t ss = horiz ? offsetof (RPanelPos, h) : offsetof (RPanelPos, w);
	// current panel bounds: primary axis [cp0,cp1], secondary [cs0,cs1]
	int cp0 = PP (cur->view->pos, op);
	int cp1 = cp0 + PP (cur->view->pos, os) - 1;
	int cs0 = PP (cur->view->pos, sp);
	int cs1 = cs0 + PP (cur->view->pos, ss) - 1;
	int n = panels->n_panels;
	size_t sz = sizeof (RPanel *) * n;
	RPanel **t1 = malloc (sz), **t2 = malloc (sz), **t3 = malloc (sz), **t4 = malloc (sz);
	if (!t1 || !t2 || !t3 || !t4) {
		goto beach;
	}
	int n1 = 0, n2 = 0, n3 = 0, n4 = 0, i;
	for (i = 0; i < n; i++) {
		if (i == panels->curnode) {
			continue;
		}
		RPanel *p = r_panels_get_panel (panels, i);
		if (!p) {
			continue;
		}
		int tp0 = PP (p->view->pos, op);
		int tp1 = tp0 + PP (p->view->pos, os) - 1;
		int ts0 = PP (p->view->pos, sp);
		int ts1 = ts0 + PP (p->view->pos, ss) - 1;
		// fast path: exact neighbor on secondary axis, adjacent on primary
		if (ts0 == cs0 && ts1 == cs1) {
			if (neg && tp1 == cp0 && tp1 - d > tp0) {
				PP (p->view->pos, os) -= d;
				PP (cur->view->pos, op) -= d;
				PP (cur->view->pos, os) += d;
				p->view->refresh = true;
				cur->view->refresh = true;
				goto beach;
			}
			if (!neg && tp0 == cp1 && tp0 + d < tp1) {
				PP (p->view->pos, op) += d;
				PP (p->view->pos, os) -= d;
				PP (cur->view->pos, os) += d;
				p->view->refresh = true;
				cur->view->refresh = true;
				goto beach;
			}
		}
		bool sec_incl = (ts1 >= cs0 && cs1 >= ts1) || (ts0 >= cs0 && cs1 >= ts0);
		// t1: neighbors on leading edge
		if (tp1 == cp0 && sec_incl) {
			if (neg ? (tp1 - d > tp0) : (tp1 + d < cp1)) {
				t1[n1++] = p;
			}
		}
		// t3: neighbors on trailing edge
		if (tp0 == cp1 && sec_incl) {
			if (neg ? (tp0 - d > cp0) : (tp0 + d < tp1)) {
				t3[n3++] = p;
			}
		}
		// t2: same leading edge as cur
		if (tp0 == cp0) {
			if (neg ? (tp0 - d > 0) : (tp0 + d < tp1)) {
				t2[n2++] = p;
			}
		}
		// t4: same trailing edge as cur
		if (tp1 == cp1) {
			if (neg ? (tp1 - d > tp0) : (tp1 + d < pmax)) {
				t4[n4++] = p;
			}
		}
	}
	// for neg (h/k): try t1 first, fallback t3
	// for pos (l/j): try t3 first, fallback t1
	RPanel **ta, **tb, **tc, **td;
	int na, nb, nc, nd;
	if (neg) {
		ta = t1; na = n1; tb = t2; nb = n2;
		tc = t3; nc = n3; td = t4; nd = n4;
	} else {
		ta = t3; na = n3; tb = t4; nb = n4;
		tc = t1; nc = n1; td = t2; nd = n2;
	}
	if (na > 0) {
		for (i = 0; i < na; i++) {
			PP (ta[i]->view->pos, os) -= d;
			if (!neg) {
				PP (ta[i]->view->pos, op) += d;
			}
			ta[i]->view->refresh = true;
		}
		for (i = 0; i < nb; i++) {
			if (neg) {
				PP (tb[i]->view->pos, op) -= d;
			}
			PP (tb[i]->view->pos, os) += d;
			tb[i]->view->refresh = true;
		}
		PP (cur->view->pos, os) += d;
		if (neg) {
			PP (cur->view->pos, op) -= d;
		}
		cur->view->refresh = true;
	} else if (nc > 0) {
		for (i = 0; i < nc; i++) {
			PP (tc[i]->view->pos, os) += d;
			if (neg) {
				PP (tc[i]->view->pos, op) -= d;
			}
			tc[i]->view->refresh = true;
		}
		for (i = 0; i < nd; i++) {
			PP (td[i]->view->pos, os) -= d;
			if (!neg) {
				PP (td[i]->view->pos, op) += d;
			}
			td[i]->view->refresh = true;
		}
		PP (cur->view->pos, os) -= d;
		if (!neg) {
			PP (cur->view->pos, op) += d;
		}
		cur->view->refresh = true;
	}
beach:
	free (t1);
	free (t2);
	free (t3);
	free (t4);
}

static bool r_panels_handle_window_mode(RCore *core, const int key) {
	RPanels *panels = core->panels;
	RPanel *cur = r_panels_get_cur_panel (panels);
	r_cons_switchbuf (core->cons, false);
	switch (key) {
	case 'Q':
	case 'q':
	case 'w':
		r_panels_toggle_window_mode (core);
		break;
	case 0x0d:
		r_panels_toggle_zoom_mode (core);
		break;
	case 9: // tab
		r_panels_handle_tab_key (core, false);
		break;
	case 'Z': // shift-tab
		r_panels_handle_tab_key (core, true);
		break;
	case 'E':
		r_core_visual_colors (core);
		break;
	case 'e':
	{
		char *cmd = r_panels_show_status_input (core, "New command: ");
		if (R_STR_ISNOTEMPTY (cmd)) {
			replace_cmd (core, cmd, cmd);
		}
		free (cmd);
	}
		break;
	case 'h':
		if (r_config_get_b (core->config, "scr.cursor")) {
			core->cons->cpos.x--;
		} else {
			(void)r_panels_move_to_direction (core, 'h');
			if (panels->fun == PANEL_FUN_SNOW || panels->fun == PANEL_FUN_SAKURA) {
				r_panels_reset_snow (panels);
			}
		}
		break;
	case 'j':
		if (r_config_get_b (core->config, "scr.cursor")) {
			core->cons->cpos.y++;
		} else {
			(void)r_panels_move_to_direction (core, 'j');
			if (panels->fun == PANEL_FUN_SNOW || panels->fun == PANEL_FUN_SAKURA) {
				r_panels_reset_snow (panels);
			}
		}
		break;
	case 'k':
		if (r_config_get_b (core->config, "scr.cursor")) {
			core->cons->cpos.y--;
		} else {
			(void)r_panels_move_to_direction (core, 'k');
			if (panels->fun == PANEL_FUN_SNOW || panels->fun == PANEL_FUN_SAKURA) {
				r_panels_reset_snow (panels);
			}
		}
		break;
	case 'l':
		if (core->print->cur_enabled) {
			core->cons->cpos.x++;
		} else {
			(void)r_panels_move_to_direction (core, 'l');
			if (panels->fun == PANEL_FUN_SNOW || panels->fun == PANEL_FUN_SAKURA) {
				r_panels_reset_snow (panels);
			}
		}
		break;
	case 'H':
	case 'L':
	case 'J':
	case 'K':
		if (r_config_get_b (core->config, "scr.cursor")) {
			if (key == 'H' || key == 'L') {
				core->cons->cpos.x += 5;
			} else {
				core->cons->cpos.y += (key == 'J') ? 5 : -5;
			}
		} else {
			r_cons_switchbuf (core->cons, false);
			r_panels_resize_panel (panels, key | 0x20);
		}
		break;
	case 'n':
		create_panel_input (core, cur, PANEL_LAYOUT_VERTICAL, NULL);
		break;
	case 'N':
		create_panel_input (core, cur, PANEL_LAYOUT_HORIZONTAL, NULL);
		break;
	case 'X':
		r_panels_dismantle_del_panel (core, cur, panels->curnode);
		break;
	case '"':
	case ':':
	case ';':
	case '/':
	case 'd':
	case 'b':
	case 'p':
	case 'P':
	case 't':
	case 'T':
	case '?':
	case '|':
	case '-':
		return false;
	}
	return true;
}

static bool r_panels_handle_cursor_mode(RCore *core, const int key) {
	RPanel *cur = r_panels_get_cur_panel (core->panels);
	RPrint *print = core->print;
	char *db_val;
	if (r_panels_check_panel_type (cur, "xc") && cur->model->directionCb
			&& (key == 'h' || key == 'j' || key == 'k' || key == 'l')) {
		cur->model->directionCb (core, key);
		return true;
	}
	switch (key) {
	case ':':
	case ';':
	case 'd':
	case 'h':
	case 'j':
	case 'k':
	case 'J':
	case 'K':
	case 'l':
	case 'm':
	case 'Z':
	case '"':
	case 9:
		return false;
	case 'g':
		cur->view->curpos = 0;
		r_panels_reset_scroll_pos (cur);
		cur->view->refresh = true;
		break;
	case ']':
		if (r_panels_check_panel_type (cur, "xc")) {
			const int cols = r_config_get_i (core->config, "hex.cols");
			r_config_set_i (core->config, "hex.cols", cols + 1);
		} else {
			const int cmtcol = r_config_get_i (core->config, "asm.cmt.col");
			r_config_set_i (core->config, "asm.cmt.col", cmtcol + 2);
		}
		cur->view->refresh = true;
		break;
	case '[':
		if (r_panels_check_panel_type (cur, "xc")) {
			const int cols = r_config_get_i (core->config, "hex.cols");
			r_config_set_i (core->config, "hex.cols", cols - 1);
 		} else {
			int cmtcol = r_config_get_i (core->config, "asm.cmt.col");
			if (cmtcol > 2) {
				r_config_set_i (core->config, "asm.cmt.col", cmtcol - 2);
			}
		}
		cur->view->refresh = true;
		break;
	case 'Q':
	case 'q':
	case 'c':
		r_panels_set_cursor (core, !print->cur_enabled);
		cur->view->refresh = true;
		break;
	case 'w':
		r_panels_toggle_window_mode (core);
		r_panels_set_cursor (core, false);
		cur->view->refresh = true;
		break;
	case 'i':
		insert_value (core, 'x');
		break;
	case 'I':
		insert_value (core, 'a');
		break;
	case '*':
		if (r_panels_check_panel_type (cur, "pd")) {
			r_core_cmdf (core, "dr PC=0x%08"PFMT64x, core->addr + print->cur);
			r_panels_set_panel_addr (core, cur, core->addr + print->cur);
		}
		break;
	case '-':
		db_val = r_panels_search_db (core, "Breakpoints");
		if (r_panels_check_panel_type (cur, db_val)) {
			cursor_del_breakpoints(core, cur);
			free (db_val);
			break;
		}
		free (db_val);
		return false;
	case 'x':
		handle_refs (core, cur, r_panels_parse_string_on_cursor (core, cur, cur->view->curpos));
		break;
	case 0x0d:
		jmp_to_cursor_addr (core, cur);
		break;
	case 'b':
		set_breakpoints_on_cursor (core, cur);
		break;
	case 'H':
		cur->view->curpos = cur->view->sy;
		cur->view->refresh = true;
		break;
	}
	return true;
}

static bool r_panels_check_func(RCore *core) {
	RAnalFunction *fun = r_anal_get_fcn_in (core->anal, core->addr, R_ANAL_FCN_TYPE_NULL);
	if (!fun) {
		r_cons_message (core->cons, "Not in a function. Type 'df' to define it here");
		return false;
	}
	if (r_list_empty (fun->bbs)) {
		r_cons_message (core->cons, "No basic blocks in this function. You may want to use 'afb+'.");
		return false;
	}
	return true;
}

static void r_panels_call_visual_graph(RCore *core) {
	if (!r_panels_check_func (core)) {
		return;
	}
	RPanels *panels = core->panels;
	r_cons_canvas_free (panels->can);
	panels->can = NULL;
	int ocolor = r_config_get_i (core->config, "scr.color");
	r_core_visual_graph (core, NULL, NULL, true);
	r_config_set_i (core->config, "scr.color", ocolor);
	int h, w = r_panels_get_size (core, &h);
	panels->can = r_panels_create_new_canvas (core, w, h);
}

static void r_panels_hudstuff(RCore *core) {
	RPanels *panels = core->panels;
	RPanel *cur = r_panels_get_cur_panel (panels);
	r_core_visual_hudstuff (core);

	if (r_panels_check_panel_type (cur, "pd")) {
		r_panels_set_panel_addr (core, cur, core->addr);
	} else {
		int i;
		for (i = 0; i < panels->n_panels; i++) {
			RPanel *panel = r_panels_get_panel (panels, i);
			if (r_panels_check_panel_type (panel, "pd")) {
				r_panels_set_panel_addr (core, panel, core->addr);
				break;
			}
		}
	}
}

static void r_panels_undo_seek(RCore *core) {
	RPanel *cur = r_panels_get_cur_panel (core->panels);
	if (!r_panels_check_panel_type (cur, "pd")) {
		return;
	}
	RIOUndos *undo = r_io_sundo (core->io, core->addr);
	if (undo) {
		r_core_visual_seek_animation (core, undo->off);
		r_panels_set_panel_addr (core, cur, core->addr);
	}
}

static void r_panels_redo_seek(RCore *core) {
	RPanel *cur = r_panels_get_cur_panel (core->panels);
	if (!r_panels_check_panel_type (cur, "pd")) {
		return;
	}
	RIOUndos *undo = r_io_sundo_redo (core->io);
	if (undo) {
		r_core_visual_seek_animation (core, undo->off);
		r_panels_set_panel_addr (core, cur, core->addr);
	}
}

static void handlePrompt(RCore *core, RPanels *panels) {
	RCons *cons = core->cons;
	RConsEvent resize = cons->event_resize;
	void *event_data = cons->event_data;
	cons->event_resize = NULL;
	r_panels_bottom_panel_line (core);
	r_core_visual_prompt_input (core);
	cons->event_resize = NULL;
	cons->event_data = event_data;
	cons->event_resize = resize;
	int h, w = r_panels_get_size (core, &h);
	r_panels_resize_layout (panels, w, h);
	int i;
	for (i = 0; i < panels->n_panels; i++) {
		RPanel *p = r_panels_get_panel (panels, i);
		if (p && r_panels_check_panel_type (p, "pd")) {
			r_panels_set_panel_addr (core, p, core->addr);
			break;
		}
	}
}

static int add_cmd_panel(void *user) {
	RCore *core = (RCore *)user;
	if (!r_panels_check_panel_num (core)) {
		return 0;
	}
	RPanelsMenu *menu = core->panels->panels_menu;
	RPanelsMenuItem *parent = menu->history[menu->depth - 1];
	RPanelsMenuItem *child = parent->sub[parent->selectedIndex];
	char *cmd = r_panels_search_db (core, child->name);
	if (!cmd) {
		return 0;
	}
	r_panels_adjust_and_add_panel (core, child->name, cmd);
	r_panels_set_mode (core, PANEL_MODE_DEFAULT);
	free (cmd);
	menu->n_refresh = 0; // close the menu bar
	return 0;
}

static void handleComment(RCore *core) {
	RPanel *p = r_panels_get_cur_panel (core->panels);
	if (!r_panels_check_panel_type (p, "pd")) {
		return;
	}
	char buf[4095];
	char *cmd = NULL;
	r_line_set_prompt (core->cons->line, "[Comment]> ");
	if (r_cons_fgets (core->cons, buf, sizeof (buf), 0, NULL) > 0) {
		ut64 addr, orig;
		addr = orig = core->addr;
		if (core->print->cur_enabled) {
			addr += core->print->cur;
			r_core_seek (core, addr, false);
			r_core_cmdf (core, "s 0x%"PFMT64x, addr);
		}
		if (!strcmp (buf, "-")) {
			cmd = strdup ("CC-");
		} else {
			char *arg = r_panels_filter_arg (strdup (buf));
			switch (buf[0]) {
			case '-':
				cmd = r_str_newf ("'CC-%s", arg);
				break;
			case '!':
				cmd = strdup ("CC!");
				break;
			default:
				cmd = r_str_newf ("'CC %s", arg);
				break;
			}
			free (arg);
		}
		if (cmd) {
			r_core_cmd0 (core, cmd);
		}
		if (core->print->cur_enabled) {
			r_core_seek (core, orig, true);
		}
		free (cmd);
	}
	r_panels_set_refresh_by_type (core, p->model->cmd, true);
}

static void direction_default_cb(void *user, int direction) {
	RCore *core = (RCore *)user;
	RPanel *cur = r_panels_get_cur_panel (core->panels);
	cur->view->refresh = true;
	switch (direction) {
	case 'h':
		if (cur->view->sx > 0) {
			cur->view->sx--;
		}
		break;
	case 'l':
		if (cur->view->sx < MAX_CANVAS_SIZE) {
			cur->view->sx++;
		}
		break;
	case 'k':
		if (cur->view->sy > 0) {
			cur->view->sy--;
		}
		break;
	case 'j':
		if (cur->view->sy < MAX_CANVAS_SIZE) {
			cur->view->sy++;
		}
		break;
	}
}

static void direction_disassembly_cb(void *user, int direction) {
	RCore *core = (RCore *)user;
	RPanels *panels = core->panels;
	RPanel *cur = r_panels_get_cur_panel (panels);
	if (cur->model->cache) {
		direction_default_cb (user, direction);
		return;
	}
	int cols = core->print->cols;
	cur->view->refresh = true;
	switch (direction) {
	case 'h':
		if (core->print->cur_enabled) {
			r_panels_cursor_left (core);
			r_core_block_read (core);
			r_panels_set_panel_addr (core, cur, core->addr);
		} else if (panels->mode == PANEL_MODE_ZOOM) {
			cur->model->addr--;
		} else if (cur->view->sx > 0) {
			cur->view->sx--;
		}
		break;
	case 'l':
		if (core->print->cur_enabled) {
			r_panels_cursor_right (core);
			r_core_block_read (core);
			r_panels_set_panel_addr (core, cur, core->addr);
		} else if (panels->mode == PANEL_MODE_ZOOM) {
			cur->model->addr++;
		} else {
			cur->view->sx++;
		}
		break;
	case 'k':
		core->addr = cur->model->addr;
		if (core->print->cur_enabled) {
			r_panels_cursor_up (core);
			r_core_block_read (core);
			r_panels_set_panel_addr (core, cur, core->addr);
		} else {
			r_core_visual_disasm_up (core, &cols);
			r_core_seek_delta (core, -cols);
			r_panels_set_panel_addr (core, cur, core->addr);
		}
		break;
	case 'j':
		core->addr = cur->model->addr;
		if (core->print->cur_enabled) {
			r_panels_cursor_down (core);
			r_core_block_read (core);
			r_panels_set_panel_addr (core, cur, core->addr);
		} else {
			RAnalOp op;
			r_core_visual_disasm_down (core, &op, &cols);
			r_core_seek (core, core->addr + cols, true);
			r_panels_set_panel_addr (core, cur, core->addr);
			r_anal_op_fini (&op);
		}
		break;
	}
}

static void direction_graph_cb(void *user, int direction) {
	RCore *core = (RCore *)user;
	RPanels *panels = core->panels;
	RPanel *cur = r_panels_get_cur_panel (panels);
	if (cur->model->cache) {
		direction_default_cb (user, direction);
		return;
	}
	cur->view->refresh = true;
	const int speed = r_config_get_i (core->config, "graph.scroll") * 2;
	switch (direction) {
	case 'h':
		if (cur->view->sx > 0) {
			cur->view->sx -= speed;
		}
		break;
	case 'l':
		cur->view->sx +=  speed;
		break;
	case 'k':
		if (cur->view->sy > 0) {
			cur->view->sy -= speed;
		}
		break;
	case 'j':
		cur->view->sy += speed;
		break;
	}
}

static void direction_register_cb(void *user, int direction) {
	RCore *core = (RCore *)user;
	RPanels *panels = core->panels;
	RPanel *cur = r_panels_get_cur_panel (panels);
	int cols = core->dbg->options.regcols;
	cols = cols > 0 ? cols : 3;
	cur->view->refresh = true;
	switch (direction) {
	case 'h':
		if (core->print->cur_enabled) {
			r_panels_cursor_left (core);
		} else if (cur->view->sx > 0) {
			cur->view->sx--;
			cur->view->refresh = true;
		}
		break;
	case 'l':
		if (core->print->cur_enabled) {
			r_panels_cursor_right (core);
		} else {
			cur->view->sx++;
			cur->view->refresh = true;
		}
		break;
	case 'k':
		if (core->print->cur_enabled) {
			int tmp = core->print->cur;
			tmp -= cols;
			if (tmp >= 0) {
				core->print->cur = tmp;
			}
		}
		break;
	case 'j':
		if (core->print->cur_enabled) {
			core->print->cur += cols;
		}
		break;
	}
}

static void direction_stack_cb(void *user, int direction) {
	RCore *core = (RCore *)user;
	RPanels *panels = core->panels;
	RPanel *cur = r_panels_get_cur_panel (panels);
	int cols = r_config_get_i (core->config, "hex.cols");
	if (cols < 1) {
		cols = 16;
	}
	cur->view->refresh = true;
	switch (direction) {
	case 'h':
		if (core->print->cur_enabled) {
			r_panels_cursor_left (core);
		} else if (cur->view->sx > 0) {
			cur->view->sx--;
			cur->view->refresh = true;
		}
		break;
	case 'l':
		if (core->print->cur_enabled) {
			r_panels_cursor_right (core);
		} else {
			cur->view->sx++;
			cur->view->refresh = true;
		}
		break;
	case 'k':
		{
			ut64 delta = r_config_get_i (core->config, "stack.delta");
			if (cur->model->addr >= (ut64)cols && delta <= UT64_MAX - (ut64)cols) {
				r_config_set_i (core->config, "stack.delta", delta + cols);
				cur->model->addr -= cols;
			}
		}
		break;
	case 'j':
		{
			ut64 delta = r_config_get_i (core->config, "stack.delta");
			if (delta >= (ut64)cols && cur->model->addr <= UT64_MAX - (ut64)cols) {
				r_config_set_i (core->config, "stack.delta", delta - cols);
				cur->model->addr += cols;
			}
		}
		break;
	}
}

static void direction_hexdump_cb(void *user, int direction) {
	RCore *core = user;
	RPanel *panel = r_panels_get_cur_panel (core->panels);
	if (panel->model->cache) {
		direction_default_cb (user, direction);
		return;
	}
	const int cols = R_MAX (core->print->cols, 2);
	int delta;
	switch (direction) {
	case 'h': delta = -1; break;
	case 'l': delta = 1; break;
	case 'k': delta = -cols; break;
	case 'j': delta = cols; break;
	default: return;
	}
	RPrint *print = core->print;
	print->ocur = -1;
	if (print->cur_enabled) {
		st64 next = (st64)print->cur + delta;
		int rows = R_MAX (panel->view->pos.h - 3 - (print->cols >= 2 && (print->flags & R_PRINT_FLAGS_HEADER)), 1);
		if (next < 0) {
			ut64 step = R_MIN (panel->model->addr, cols);
			panel->model->addr -= step;
			next += (st64)step;
		} else if (next / cols >= rows && panel->model->addr <= UT64_MAX - cols) {
			panel->model->addr += cols;
			next -= cols;
		}
		print->cur = R_MIN (R_MAX (next, 0), INT_MAX);
		panel->view->curpos = print->cur;
	} else if (delta < 0) {
		panel->model->addr -= R_MIN (panel->model->addr, -delta);
	} else {
		panel->model->addr += R_MIN (UT64_MAX - panel->model->addr, delta);
	}
	panel->view->refresh = true;
}

static void direction_panels_cursor_cb(void *user, int direction) {
	RCore *core = (RCore *)user;
	RPanels *panels = core->panels;
	RPanel *cur = r_panels_get_cur_panel (panels);
	cur->view->refresh = true;
	const int THRESHOLD = cur->view->pos.h / 3;
	int sub;
	switch (direction) {
	case 'h':
		if (core->print->cur_enabled) {
			break;
		}
		if (cur->view->sx > 0) {
			cur->view->sx -= r_config_get_i (core->config, "graph.scroll");
		}
		break;
	case 'l':
		if (core->print->cur_enabled) {
			break;
		}
		cur->view->sx += r_config_get_i (core->config, "graph.scroll");
		break;
	case 'k':
		if (core->print->cur_enabled) {
			if (cur->view->curpos > 0) {
				cur->view->curpos--;
			}
			if (cur->view->sy > 0) {
				sub = cur->view->curpos - cur->view->sy;
				if (sub < 0) {
					cur->view->sy--;
				}
			}
		} else {
			if (cur->view->sy > 0) {
				cur->view->curpos -= 1;
				cur->view->sy -= 1;
			}
		}
		break;
	case 'j':
		core->addr = cur->model->addr;
		if (core->print->cur_enabled) {
			cur->view->curpos++;
			sub = cur->view->curpos - cur->view->sy;
			if (sub > THRESHOLD) {
				cur->view->sy++;
			}
		} else {
			cur->view->curpos += 1;
			cur->view->sy += 1;
		}
		break;
	}
}

static void jmp_to_cursor_addr(RCore *core, RPanel *panel) {
	ut64 addr = r_panels_parse_string_on_cursor (core, panel, panel->view->curpos);
	if (addr == UT64_MAX) {
		return;
	}
	core->addr = addr;
	update_disassembly_or_open (core);
}

static void set_breakpoints_on_cursor(RCore *core, RPanel *panel) {
	if (!r_config_get_b (core->config, "cfg.debug")) {
		return;
	}
	if (r_panels_check_panel_type (panel, "pd")) {
		r_core_cmdf (core, "dbs 0x%08"PFMT64x, core->addr + core->print->cur);
		panel->view->refresh = true;
	}
}

static ut64 r_panels_edit_addr(RCore *core) {
	RPanel *panel = r_panels_get_cur_panel (core->panels);
	RPrint *print = core->print;
	int offset = 0;
	if (print->cur_enabled) {
		offset = print->ocur < 0? print->cur: R_MIN (print->cur, print->ocur);
	}
	return panel->model->addr + R_MAX (offset, 0);
}

static bool r_panels_write_hex(RCore *core, const char *hex) {
	int nibbles = r_hex_str_is_valid (hex);
	if (nibbles < 1 || (nibbles & 1)) {
		R_LOG_ERROR ("Expected complete hex byte pairs");
		return false;
	}
	size_t size;
	ut8 *bytes = r_hex_str2bin_dup (hex, &size);
	if (!bytes) {
		return false;
	}
	bool written = r_core_write_at (core, r_panels_edit_addr (core), bytes, size);
	free (bytes);
	if (written) {
		r_panels_set_refresh_all (core, true, false);
	}
	return written;
}

static void insert_value(RCore *core, int wat) {
	ut64 addr = r_panels_edit_addr (core);
	RIOMap *map = r_io_map_get_at (core->io, addr);
	bool writable = core->io->va? map && (map->perm & R_PERM_W)
		: core->io->desc && (core->io->desc->perm & R_PERM_W);
	if (!writable && !r_config_get_b (core->config, "io.cache")) {
		if (!r_panels_show_status_yesno (core, 1, "File is read-only. Enable io.cache for editing? (Y/n)")) {
			return;
		}
		r_config_set_b (core->config, "io.cache", true);
	}
	if (wat == 'a') {
		r_core_visual_asm (core, addr);
		r_panels_set_refresh_all (core, true, false);
	} else if (wat == 'x') {
		const char *hex = r_cons_visual_readln (core->cons, "overwrite hex: ", NULL);
		if (R_STR_ISNOTEMPTY (hex)) {
			r_panels_write_hex (core, hex);
		}
	}
}

static void cursor_del_breakpoints(RCore *core, RPanel *panel) {
	RListIter *iter;
	RBreakpointItem *b;
	int i = 0;
	r_list_foreach (core->dbg->bp->bps, iter, b) {
		if (panel->view->curpos == i++) {
			r_bp_del (core->dbg->bp, b->addr);
		}
	}
}

static void set_addr_by_type(RCore *core, const char *cmd, ut64 addr) {
	RPanels *panels = core->panels;
	int i;
	for (i = 0; i < panels->n_panels; i++) {
		RPanel *p = r_panels_get_panel (panels, i);
		if (!r_panels_check_panel_type (p, cmd)) {
			continue;
		}
		r_panels_set_panel_addr (core, p, addr);
	}
}

static void handle_refs(RCore *core, RPanel *panel, ut64 tmp) {
	if (tmp != UT64_MAX) {
		core->addr = tmp;
	}
	int key = r_panels_show_status(core, "xrefs:x refs:X ");
	switch (key) {
	case 'x':
		(void)r_core_visual_refs (core, true, false);
		break;
	case 'X':
		(void)r_core_visual_refs (core, false, false);
		break;
	default:
		break;
	}
	if (r_panels_check_panel_type (panel, "pd")) {
		r_panels_set_panel_addr (core, panel, core->addr);
	} else {
		set_addr_by_type (core, "pd", core->addr);
	}
}

static void add_vmark(RCore *core) {
	char *msg = r_str_newf (R_CONS_CLEAR_LINE"Set shortcut key for 0x%"PFMT64x": ", core->addr);
	int ch = r_panels_show_status (core, msg);
	free (msg);
	r_core_vmark (core, ch);
}

static void handle_vmark(RCore *core) {
	RPanel *cur = r_panels_get_cur_panel (core->panels);
	if (!r_panels_check_panel_type (cur, "pd")) {
		return;
	}
	RCons *cons = core->cons;
	int act = r_panels_show_status (core, "Visual Mark  s:set -:remove \':use: ");
	switch (act) {
	case 's':
		add_vmark (core);
		break;
	case '-':
		r_cons_gotoxy (core->cons, 0, 0);
		if (r_core_vmark_dump (core, 0)) {
			r_cons_printf (cons, R_CONS_CLEAR_LINE"Remove a shortcut key from the list\n");
			r_cons_flush (cons);
			r_cons_set_raw (cons, true);
			int ch = r_cons_readchar (cons);
			r_core_vmark_del (core, ch);
		}
		break;
	case '\'':
		r_cons_gotoxy (core->cons, 0, 0);
		if (r_core_vmark_dump (core, 0)) {
			r_cons_flush (cons);
			r_cons_set_raw (cons, true);
			int ch = r_cons_readchar (core->cons);
			r_core_vmark_seek (core, ch, NULL);
			r_panels_set_panel_addr (core, cur, core->addr);
		}
	}
}

static void set_dcb(RCore *core, RPanel *p) {
	if (r_panels_is_abnormal_cursor_type (core, p)) {
		p->model->directionCb = direction_panels_cursor_cb;
		return;
	}
	if ((p->model->cache && p->model->cmdStrCache) || p->model->readOnly) {
		p->model->directionCb = direction_default_cb;
		return;
	}
	if (!p->model->cmd) {
		return;
	}
	if (r_panels_check_panel_type (p, "agf")) {
		p->model->directionCb = direction_graph_cb;
		return;
	}
	if (r_panels_check_panel_type (p, "px")) {
		p->model->directionCb = direction_stack_cb;
	} else if (r_panels_check_panel_type (p, "pd")) {
		p->model->directionCb = direction_disassembly_cb;
	} else if (r_panels_check_panel_type (p, "dr")
			|| r_panels_check_panel_type (p, "dr fpu;drf")
			|| r_panels_check_panel_type (p, "drm")
			|| r_panels_check_panel_type (p, "drmy")) {
		p->model->directionCb = direction_register_cb;
	} else if (r_panels_check_panel_type (p, "xc")) {
		p->model->directionCb = direction_hexdump_cb;
	} else {
		p->model->directionCb = direction_default_cb;
	}
}

static void panel_breakpoint(RCore *core) {
	RPanel *cur = r_panels_get_cur_panel (core->panels);
	if (r_panels_check_panel_type (cur, "pd")) {
		r_core_cmd (core, "dbs $$", 0);
		cur->view->refresh = true;
	}
}

static void panel_continue(RCore *core) {
	r_core_cmd (core, "dc", 0);
}

static bool handle_console(RCore *core, RPanel *panel, const int key) {
	if (!r_panels_check_panel_type (panel, "cat $console")) {
		return false;
	}
	r_cons_switchbuf (core->cons, false);
	switch (key) {
	case 'i':
		{
			char *prompt = r_str_newf ("[0x%08"PFMT64x"]) ", core->addr);
			const char *cmd = r_cons_visual_readln (core->cons, prompt, NULL);
			if (R_STR_ISNOTEMPTY (cmd)) {
				if (!strcmp (cmd, "clear")) {
					r_core_cmd0 (core, ":>$console");
				} else {
					r_core_cmdf (core, "?e %s %s>>$console", prompt, cmd);
					r_core_cmdf (core, "%s >>$console", cmd);
				}
			}
			free (prompt);
			panel->view->refresh = true;
		}
		return true;
	case 'l':
		r_core_cmd0 (core, ":>$console");
		panel->view->refresh = true;
		return true;
	default:
		// add more things later
		break;
	}
	return false;
}

// copypasta from visual
static void prevOpcode(RCore *core) {
	RPrint *p = core->print;
	ut64 addr = 0;
	ut64 opaddr = r_panels_insoff (core, core->print->cur);
	if (r_core_prevop_addr (core, opaddr, 1, &addr)) {
		const int delta = opaddr - addr;
		p->cur -= delta;
	} else {
		p->cur -= 4;
	}
}

static void nextOpcode(RCore *core) {
	RAnalOp *aop = r_core_anal_op (core, core->addr + core->print->cur, R_ARCH_OP_MASK_BASIC);
	RPrint *p = core->print;
	if (aop) {
		p->cur += aop->size;
		r_anal_op_free (aop);
	} else {
		p->cur += 4;
	}
}
