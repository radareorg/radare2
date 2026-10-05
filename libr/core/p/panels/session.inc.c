/* radare2 - LGPL - Copyright 2014-2026 - pancake, vane11ope */

static void panels_process(RCore *core, RPanels *panels) {
	if (!panels) {
		return;
	}
	int i, okey, key;
	RPanelsRoot *panels_root = core->panels_root;
	RPanels *prev;
	prev = core->panels;
	core->panels = panels;
	r_panels_seek_all (core, core->addr);
	panels->autoUpdate = true;
	int h, w = r_panels_get_size (core, &h);
	if (panels->can) {
		r_panels_resize_layout (panels, w, h);
		(void)r_cons_canvas_resize (panels->can, w, h);
	} else {
		panels->can = r_panels_create_new_canvas (core, w, h);
	}
	r_panels_set_refresh_all (core, false, true);

	r_cons_switchbuf (core->cons, false);

	int originCursor = core->print->cur;
	core->print->cur = 0;
	core->print->cur_enabled = false;
	core->print->col = 0;

	bool originVmode = core->vmode;
	core->vmode = true;

	bool o_interactive = r_cons_is_interactive (core->cons);
	r_cons_set_interactive (core->cons, true);
	r_core_visual_showcursor (core, false);
repeat:
	r_cons_enable_mouse (core->cons, true);
	core->panels = panels;
	core->cons->event_resize = NULL; // avoid running old event with new data
	core->cons->event_data = core;
	core->cons->event_resize = (RConsEvent) r_panels_do_panels_refreshQueued;
	r_panels_layout_refresh (core);
	RPanel *cur = r_panels_get_cur_panel (panels);
	r_cons_set_raw (core->cons, true);
	if (panels->fun == PANEL_FUN_SNOW || panels->fun == PANEL_FUN_SAKURA) {
		if (panels->mode == PANEL_MODE_MENU) {
			panels->fun = PANEL_FUN_NOFUN;
			r_panels_reset_snow (panels);
			goto repeat;
		}
		okey = r_cons_readchar_timeout (core->cons, 300);
		if (okey == -1) {
			cur->view->refresh = true;
			goto repeat;
		}
	} else {
		okey = r_cons_readchar (core->cons);
	}

	key = r_cons_arrow_to_hjkl (core->cons, okey);
virtualmouse:
	if (r_panels_handle_mouse (core, &key)) {
		if (panels_root->root_state != DEFAULT) {
			goto exit;
		}
		goto repeat;
	}

	const bool wheel_event = core->cons->mouse_event && !core->cons->drag_event &&
		(key == 'h' || key == 'j' || key == 'k' || key == 'l');
	if (wheel_event && panels->mode != PANEL_MODE_MENU) {
		if (cur->model->directionCb) {
			r_cons_switchbuf (core->cons, false);
			r_panels_wheel_direction (core, cur, key);
		}
		goto repeat;
	}
	if (wheel_event && (key == 'h' || key == 'l')) {
		goto repeat;
	}

	r_cons_switchbuf (core->cons, true);

	if (panels->mode == PANEL_MODE_MENU) {
		handle_menu (core, key);
		if (r_panels_check_root_state (core, QUIT) ||
				r_panels_check_root_state (core, ROTATE)) {
			goto exit;
		}
		goto repeat;
	}

	if (core->print->cur_enabled) {
		if (r_panels_handle_cursor_mode (core, key)) {
			goto repeat;
		}
	}

	if (panels->mode == PANEL_MODE_ZOOM) {
		if (r_panels_handle_zoom_mode (core, key)) {
			goto repeat;
		}
	}

	if (panels->mode == PANEL_MODE_WINDOW) {
		if (r_panels_handle_window_mode (core, key)) {
			goto repeat;
		}
	}

	if (r_panels_check_panel_type (cur, "pd") && '0' < key && key <= '9') {
		ut8 ch = key;
		r_core_visual_jump (core, ch);
		r_panels_set_panel_addr (core, cur, core->addr);
		goto repeat;
	}

	const char *cmd;
	RConsCanvas *can = panels->can;
	if (handle_console (core, cur, key)) {
		goto repeat;
	}
	switch (key) {
	case 'u':
		r_panels_undo_seek (core);
		break;
	case 'U':
		r_panels_redo_seek (core);
		break;
	case 'p':
		r_panels_rotate_panels (core, false);
		break;
	case 'P':
		r_panels_rotate_panels (core, true);
		break;
	case '.':
		if (r_panels_check_panel_type (cur, "pd")) {
			ut64 addr = r_debug_reg_get (core->dbg, "PC");
			if (addr && addr != UT64_MAX) {
				r_core_seek (core, addr, true);
			} else {
				addr = r_num_get (core->num, "entry0");
				if (addr && addr != UT64_MAX) {
					r_core_seek (core, addr, true);
				}
			}
			r_panels_set_panel_addr (core, cur, core->addr);
		} else if (!strcmp (cur->model->title, "Stack")) {
			r_config_set_i (core->config, "stack.delta", 0);
		}
		break;
	case '?':
		r_panels_toggle_help (core);
		break;
	case 'b':
		r_core_visual_browse (core, NULL);
		break;
	case ';':
		handleComment (core);
		break;
	case '$':
		if (core->print->cur_enabled) {
			r_core_cmdf (core, "dr PC=$$+%d", core->print->cur);
		} else {
			r_core_call (core, "dr PC=$$");
		}
		break;
	case 's':
		panel_single_step_in (core);
		if (r_panels_check_panel_type (cur, "pd")) {
			r_panels_set_panel_addr (core, cur, core->addr);
		}
		break;
	case 'S':
		panel_single_step_over (core);
		if (r_panels_check_panel_type (cur, "pd")) {
			r_panels_set_panel_addr (core, cur, core->addr);
		}
		break;
	case ' ':
		r_panels_call_visual_graph (core);
		break;
	case ':':
		handlePrompt(core, panels);
		if (r_panels_sync_seek (cur)) {
			r_panels_set_panel_addr (core, cur, core->addr);
		}
		break;
	case 'c':
		r_panels_activate_cursor (core);
		break;
	case 'C':
		{
			int color = r_config_get_i (core->config, "scr.color");
			if (++color > 2) {
				color = 0;
			}
			r_config_set_i (core->config, "scr.color", color);
			can->color = color;
			r_panels_set_refresh_all (core, true, false);
		}
		break;
	case 'r':
		if (r_config_get_i (core->config, "asm.hint.call")) {
			r_config_toggle (core->config, "asm.hint.call");
			r_config_set_b (core->config, "asm.hint.jmp", true);
		} else if (r_config_get_i (core->config, "asm.hint.jmp")) {
			r_config_toggle (core->config, "asm.hint.jmp");
			r_config_set_b (core->config, "asm.hint.emu", true);
		} else if (r_config_get_i (core->config, "asm.hint.emu")) {
			r_config_toggle (core->config, "asm.hint.emu");
			r_config_set_b (core->config, "asm.hint.lea", true);
		} else if (r_config_get_i (core->config, "asm.hint.lea")) {
			r_config_toggle (core->config, "asm.hint.lea");
			r_config_set_b (core->config, "asm.hint.call", true);
		} else {
			r_config_set_b (core->config, "asm.hint.call", true);
		}
		break;
	case 'R':
		if (r_config_get_b (core->config, "scr.randpal")) {
			r_core_call (core, "ecr");
		} else {
			r_core_call (core, "ecn");
		}
		r_panels_do_panels_refresh (core);
		break;
	case 'a':
		panels->autoUpdate = r_panels_show_status_yesno (core, 1, "Auto update On? (Y/n)");
		break;
	case 'A':
		{
			const int ocur = core->print->cur_enabled;
			r_core_visual_asm (core, core->addr);
			core->print->cur_enabled = ocur;
		}
		break;
	case 'd':
		r_core_visual_define (core, "", 0);
		break;
	case 'D':
		replace_cmd (core, "Disassembly", "pd");
		break;
	case 'j':
		if (r_config_get_b (core->config, "scr.cursor")) {
			core->cons->cpos.y++;
			core->print->cur++;
		} else if (core->print->cur_enabled) {
			RPanel *cp = r_panels_get_cur_panel (core->panels);
			if (cp) {
				if (cur->model->directionCb) {
					cur->model->directionCb (core, 'j');
					break;
				} else {
					direction_panels_cursor_cb (core, 'j');
				}
			}
			nextOpcode (core);
		} else {
			if (cur->model->directionCb) {
				r_cons_switchbuf (core->cons, false);
				cur->model->directionCb (core, 'j');
			}
		}
		break;
	case 'k':
		if (r_config_get_b (core->config, "scr.cursor")) {
			core->cons->cpos.y--;
		} else if (core->print->cur_enabled) {
			RPanel *cp = r_panels_get_cur_panel (core->panels);
			if (cp) {
				if (strstr (cp->model->cmd, "pd")) {
					if (cur->model->directionCb) {
						cur->model->directionCb (core, 'k');
						break;
					}
					int op = cp->view->curpos;
					prevOpcode (core);
					if (op == cp->view->curpos) {
						cp->view->curpos--;
						prevOpcode (core);
					}
				} else {
					direction_panels_cursor_cb (core, 'k');
				}
			}
		} else if (cur->model->directionCb) {
			prevOpcode (core);
			r_cons_switchbuf (core->cons, false);
			cur->model->directionCb (core, 'k');
		}
		break;
	case 'K':
		if (r_config_get_b (core->config, "scr.cursor")) {
			core->cons->cpos.y -= 5;
		} else {
			r_cons_switchbuf (core->cons, false);
			if (cur->model->directionCb) {
				for (i = 0; i < r_panels_get_cur_panel (panels)->view->pos.h / 2 - 6; i++) {
					cur->model->directionCb (core, 'k');
				}
			} else {
				if (core->print->cur_enabled) {
					size_t i;
					for (i = 0; i < 4; i++) {
						prevOpcode (core);
					}
				}
			}
		}
		break;
	case 'J':
		if (r_config_get_b (core->config, "scr.cursor")) {
			core->cons->cpos.y += 5;
		} else {
			r_cons_switchbuf (core->cons, false);
			if (cur->model->directionCb) {
				for (i = 0; i < r_panels_get_cur_panel (panels)->view->pos.h / 2 - 6; i++) {
					cur->model->directionCb (core, 'j');
				}
			} else {
				if (core->print->cur_enabled) {
					size_t i;
					for (i = 0; i < 4; i++) {
						nextOpcode (core);
					}
				}
			}
		}
		break;
	case 'H':
		if (r_config_get_b (core->config, "scr.cursor")) {
			core->cons->cpos.x -= 5;
		} else {
			r_cons_switchbuf (core->cons, false);
			if (cur->model->directionCb) {
				for (i = 0; i < r_panels_get_cur_panel (panels)->view->pos.w / 3; i++) {
					cur->model->directionCb (core, 'h');
				}
			}
		}
		break;
	case 'L':
		if (r_config_get_b (core->config, "scr.cursor")) {
			core->cons->cpos.x += 5;
		} else {
			r_cons_switchbuf (core->cons, false);
			if (cur->model->directionCb) {
				for (i = 0; i < r_panels_get_cur_panel (panels)->view->pos.w / 3; i++) {
					cur->model->directionCb (core, 'l');
				}
			}
		}
		break;
	case 'f':
		r_panels_set_filter (core, cur);
		break;
	case 'F':
		r_panels_reset_filter (core, cur);
		break;
	case '_':
		r_panels_hudstuff (core);
		break;
	case '\\':
		r_core_visual_hud (core);
		break;
	case '"':
		r_cons_switchbuf (core->cons, false);
		r_panels_create_modal (core, cur);
		if (r_panels_check_root_state (core, ROTATE)) {
			goto exit;
		}
		break;
	case 'O':
		handle_print_rotate (core);
		break;
	case 'n':
		if (r_panels_check_panel_type (cur, "pd")) {
			r_core_seek_next (core, r_config_get (core->config, "scr.nkey"));
			r_panels_set_panel_addr (core, cur, core->addr);
		}
		break;
	case 'N':
		if (r_panels_check_panel_type (cur, "pd")) {
			r_core_seek_previous (core, r_config_get (core->config, "scr.nkey"));
			r_panels_set_panel_addr (core, cur, core->addr);
		}
		break;
	case 'x':
		handle_refs (core, cur, UT64_MAX);
		break;
	case 'X':
		r_panels_dismantle_del_panel (core, cur, panels->curnode);
		break;
	case 9: // TAB
		r_panels_handle_tab_key (core, false);
		break;
	case 'Z': // SHIFT-TAB
		r_panels_handle_tab_key (core, true);
		break;
	case 'M':
		handle_vmark (core);
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
	case 'm':
		r_panels_set_mode (core, PANEL_MODE_MENU);
		r_panels_clear_panels_menu (core);
		r_panels_get_cur_panel (panels)->view->refresh = true;
		break;
	case 'g':
		if (!r_panels_sync_seek (cur)) {
			r_core_seek (core, cur->model->addr, true);
		}
		r_core_visual_showcursor (core, true);
		r_core_visual_offset (core);
		r_core_visual_showcursor (core, false);
		r_panels_set_panel_addr (core, cur, core->addr);
		break;
	case 'G':
		{
			const char *hl = r_config_get (core->config, "scr.highlight");
			if (hl) {
				ut64 addr = r_num_math (core->num, hl);
				r_panels_set_panel_addr (core, cur, addr);
				// r_io_sundo_push (core->io, addr, false); // doesnt seems to work
			}
		}
		break;
	case 'h':
		if (r_config_get_b (core->config, "scr.cursor")) {
			core->cons->cpos.x--;
			core->print->cur--;
		} else if (core->print->cur_enabled) {
			cur->model->directionCb (core, 'h');
			RPanel *cp = r_panels_get_cur_panel (core->panels);
			if (cp) {
				core->cons->cpos.x--;
				cp->view->curpos--;
			}
		} else if (cur->model->directionCb) {
			r_cons_switchbuf (core->cons, false);
			cur->model->directionCb (core, 'h');
		}
		break;
	case 'l':
		if (r_config_get_b (core->config, "scr.cursor")) {
			core->cons->cpos.x++;
		} else if (cur->model->directionCb) {
			cur->model->directionCb (core, 'l');
			r_cons_switchbuf (core->cons, false);
		} else if (core->print->cur_enabled) {
			core->print->cur++;
		}
		break;
	case 'v':
		r_core_visual_anal (core, NULL);
		break;
	case 'V':
		r_panels_call_visual_graph (core);
		break;
	case ']':
		if (r_panels_check_panel_type (cur, "xc")) {
			r_config_set_i (core->config, "hex.cols", r_config_get_i (core->config, "hex.cols") + 1);
		} else {
			int cmtcol = r_config_get_i (core->config, "asm.cmt.col");
			r_config_set_i (core->config, "asm.cmt.col", cmtcol + 2);
		}
		cur->view->refresh = true;
		break;
	case '[':
		if (r_panels_check_panel_type (cur, "xc")) {
			r_config_set_i (core->config, "hex.cols", r_config_get_i (core->config, "hex.cols") - 1);
		} else {
			int cmtcol = r_config_get_i (core->config, "asm.cmt.col");
			if (cmtcol > 2) {
				r_config_set_i (core->config, "asm.cmt.col", cmtcol - 2);
			}
		}
		cur->view->refresh = true;
		break;
	case '/':
		r_core_cmd0 (core, "?i highlight;e scr.highlight=`yp`");
		break;
	case 'z':
		if (panels->curnode > 0) {
			r_panels_swap_panels (panels, 0, panels->curnode);
			r_panels_set_curnode (core, 0);
		}
		break;
	case '`':
		if (cur->model->rotateCb) {
			cur->model->rotateCb (core, false); // || true
			cur->view->refresh = true;
		}
		break;
	case 'i':
		insert_value (core, 'x');
		break;
	case 'I':
		insert_value (core, 'a');
		break;
	case 'o':
		{
			const char *s = "hexdump\n" \
				"esil\n" \
				"comments\n" \
				"analyze function\n" \
				"analyze program\n" \
				"bytes\n" \
				"address\n" \
				"disasm\n" \
				"entropy\n";
			char *format = r_cons_hud_line_string (core->cons, s);
			if (format) {
				if (!strcmp (format, "hexdump")) {
					replace_cmd (core, "px", "px");
				} else if (!strcmp (format, "analyze function")) {
					r_core_call (core, "af");
					r_core_call (core, "aaef");
				} else if (!strcmp (format, "analyze program")) {
					r_core_call (core, "aaa");
				} else if (!strcmp (format, "address")) {
					r_config_toggle (core->config, "asm.addr");
				} else if (!strcmp (format, "esil")) {
					r_config_toggle (core->config, "asm.esil");
				} else if (!strcmp (format, "bytes")) {
					r_config_toggle (core->config, "asm.bytes");
				} else if (!strcmp (format, "comments")) {
					r_config_toggle (core->config, "asm.comments");
				} else if (!strcmp (format, "disasm")) {
					replace_cmd (core, "pd", "pd");
				} else if (!strcmp (format, "entropy")) {
					replace_cmd (core, "p=e 100", "p=e 100");
				}
				free (format);
			}
		}
		return;
	case 't':
		r_panels_open_tab_menu (core);
		break;
	case 'T':
		if (panels_root->n_panels > 1) {
			r_panels_set_root_state (core, DEL);
			goto exit;
		}
		break;
	case 'w':
		r_panels_toggle_window_mode (core);
		break;
	case 'W':
		r_panels_move_panel_to_dir (core, cur, panels->curnode);
		break;
	case 0x0d: // "\\n"
		if (r_config_get_b (core->config, "scr.cursor")) {
			key = 0;
			r_cons_set_click (core->cons, core->cons->cpos.x, core->cons->cpos.y);
			goto virtualmouse;
		} else {
			r_panels_toggle_zoom_mode (core);
		}
		break;
	case '|':
		{
			RPanel *p = r_panels_get_cur_panel (panels);
			r_panels_split_panel (core, p, p->model->title, p->model->cmd, true);
			break;
		}
	case '-':
		{
			RPanel *p = r_panels_get_cur_panel (panels);
			r_panels_split_panel (core, p, p->model->title, p->model->cmd, false);
			break;
		}
	case '*':
		if (r_panels_check_func (core)) {
			r_cons_canvas_free (can);
			panels->can = NULL;
			replace_cmd (core, "Decompiler", "pdc");
			int h, w = r_panels_get_size (core, &h);
			panels->can = r_panels_create_new_canvas (core, w, h);
		}
		break;
	case '(':
		if (panels->fun != PANEL_FUN_SNOW && panels->fun != PANEL_FUN_SAKURA) {
			//TODO: Refactoring the FUN if bored af
			panels->fun = PANEL_FUN_SNOW;
			// panels->fun = PANEL_FUN_SAKURA;
		} else {
			panels->fun = PANEL_FUN_NOFUN;
			r_panels_reset_snow (panels);
		}
		break;
	case ')':
		rotate_asmemu (core, r_panels_get_cur_panel (panels));
		break;
	case '&':
		r_panels_toggle_cache (core, r_panels_get_cur_panel (panels));
		break;
	case '=':
		r_panels_open_frame_menu (core);
		break;
	case R_CONS_KEY_F1:
		cmd = r_config_get (core->config, "key.f1");
		if (R_STR_ISNOTEMPTY (cmd)) {
			(void)r_core_cmd0 (core, cmd);
		}
		break;
	case R_CONS_KEY_F2:
		cmd = r_config_get (core->config, "key.f2");
		if (R_STR_ISNOTEMPTY (cmd)) {
			(void)r_core_cmd0 (core, cmd);
		} else {
			panel_breakpoint (core);
		}
		break;
	case R_CONS_KEY_F3:
		cmd = r_config_get (core->config, "key.f3");
		if (R_STR_ISNOTEMPTY (cmd)) {
			(void)r_core_cmd0 (core, cmd);
		}
		break;
	case R_CONS_KEY_F4:
		cmd = r_config_get (core->config, "key.f4");
		if (R_STR_ISNOTEMPTY (cmd)) {
			(void)r_core_cmd0 (core, cmd);
		}
		break;
	case R_CONS_KEY_F5:
		cmd = r_config_get (core->config, "key.f5");
		if (R_STR_ISNOTEMPTY (cmd)) {
			(void)r_core_cmd0 (core, cmd);
		}
		break;
	case R_CONS_KEY_F6:
		cmd = r_config_get (core->config, "key.f6");
		if (R_STR_ISNOTEMPTY (cmd)) {
			(void)r_core_cmd0 (core, cmd);
		}
		break;
	case R_CONS_KEY_F7:
		cmd = r_config_get (core->config, "key.f7");
		if (R_STR_ISNOTEMPTY (cmd)) {
			(void)r_core_cmd0 (core, cmd);
		} else {
			panel_single_step_in (core);
			if (r_panels_check_panel_type (cur, "pd")) {
				r_panels_set_panel_addr (core, cur, core->addr);
			}
		}
		break;
	case R_CONS_KEY_F8:
		cmd = r_config_get (core->config, "key.f8");
		if (R_STR_ISNOTEMPTY (cmd)) {
			(void)r_core_cmd0 (core, cmd);
		} else {
			panel_single_step_over (core);
			if (r_panels_check_panel_type (cur, "pd")) {
				r_panels_set_panel_addr (core, cur, core->addr);
			}
		}
		break;
	case R_CONS_KEY_F9:
		cmd = r_config_get (core->config, "key.f9");
		if (R_STR_ISNOTEMPTY (cmd)) {
			(void)r_core_cmd0 (core, cmd);
		} else {
			if (r_panels_check_panel_type (cur, "pd")) {
				panel_continue (core);
				r_panels_set_panel_addr (core, cur, core->addr);
			}
		}
		break;
	case R_CONS_KEY_F10:
		cmd = r_config_get (core->config, "key.f10");
		if (R_STR_ISNOTEMPTY (cmd)) {
			(void)r_core_cmd0 (core, cmd);
		}
		break;
	case R_CONS_KEY_F11:
		cmd = r_config_get (core->config, "key.f11");
		if (R_STR_ISNOTEMPTY (cmd)) {
			(void)r_core_cmd0 (core, cmd);
		}
		break;
	case R_CONS_KEY_F12:
		cmd = r_config_get (core->config, "key.f12");
		if (R_STR_ISNOTEMPTY (cmd)) {
			(void)r_core_cmd0 (core, cmd);
		}
		break;
	case 'Q':
		r_panels_set_root_state (core, QUIT);
		goto exit;
	case '!':
		core->visual.fromVisual = true;
	case 'q':
	case -1: // EOF
		r_panels_set_root_state (core, DEL);
		if (core->panels_root->n_panels < 2) {
			if (r_config_get_i (core->config, "scr.demo")) {
				demo_end (core, can);
			}
		}
		goto exit;
	default:
		break;
	}
	goto repeat;
exit:
	if (!originVmode) {
		r_core_visual_showcursor (core, true);
	}
	core->cons->event_resize = NULL;
	core->cons->event_data = NULL;
	core->print->cur = originCursor;
	core->print->cur_enabled = false;
	core->print->col = 0;
	core->vmode = originVmode;
	core->panels = prev;
	r_cons_set_interactive (core->cons, o_interactive);
}

static void init_new_panels_root(RCore *core) {
	RPanelsRoot *panels_root = core->panels_root;
	RPanels *panels = r_panels_new (core);
	if (!panels) {
		return;
	}
	RPanels *prev = core->panels;
	core->panels = panels;
	panels_root->panels[panels_root->n_panels++] = panels;
	if (!init_panels_menu (core)) {
		panels_root->panels[--panels_root->n_panels] = NULL;
		r_panels_free_partial (panels);
		core->panels = prev;
		return;
	}
	if (!r_panels_alloc (core, panels)) {
		panels_root->panels[--panels_root->n_panels] = NULL;
		r_panels_free_partial (panels);
		core->panels = prev;
		return;
	}
	init_all_dbs (core);
	r_panels_set_mode (core, PANEL_MODE_DEFAULT);
	create_default_panels (core);
	r_panels_layout (core, panels);
	core->panels = prev;
}

static bool panels_root(RCore *core, RPanelsRoot *panels_root) {
	core->visual.fromVisual = core->vmode;
	r_config_set_b (core->config, "scr.wheel", true);
	if (!panels_root) {
		panels_root = R_NEW0 (RPanelsRoot);
		core->panels_root = panels_root;
		panels_root->panels = calloc (sizeof (RPanels *), PANEL_NUM_LIMIT);
		panels_root->n_panels = 0;
		panels_root->cur_panels = 0;
		panels_root->pdc_caches = sdb_new0 ();
		panels_root->cur_pdc_cache = NULL;
		r_panels_set_root_state (core, DEFAULT);
		init_new_panels_root (core);
	} else {
		if (!panels_root->n_panels) {
			panels_root->n_panels = 0;
			panels_root->cur_panels = 0;
			init_new_panels_root (core);
		}
		const char *pdc_now = r_config_get (core->config, "cmd.pdc");
		if (sdb_exists (panels_root->pdc_caches, pdc_now)) {
			panels_root->cur_pdc_cache = sdb_ptr_get (panels_root->pdc_caches, pdc_now, 0);
		} else {
			Sdb *sdb = sdb_new0();
			sdb_ptr_set (panels_root->pdc_caches, strdup (pdc_now), sdb, 0);
			panels_root->cur_pdc_cache = sdb;
		}
	}
	RPanels *panels = panels_root->panels[panels_root->cur_panels];
	const char *layout = r_config_get (core->config, "scr.layout");
	if (!R_STR_ISEMPTY (layout)) {
		RPanels *prev = core->panels;
		core->panels = panels;
		if (!r_core_panels_load (core, layout)) {
			create_default_panels (core);
			r_panels_layout (core, panels);
		}
		core->panels = prev;
	}
	int maxpage = r_config_get_i (core->config, "scr.maxpage");
	r_config_set_i (core->config, "scr.maxpage", 0);
	r_cons_set_raw (core->cons, true);
	while (panels_root->n_panels) {
		r_panels_set_root_state (core, DEFAULT);
		panels_process (core, panels_root->panels[panels_root->cur_panels]);
		if (r_panels_check_root_state (core, DEL)) {
			r_panels_del_panels (core);
		}
		if (r_panels_check_root_state (core, QUIT)) {
			break;
		}
	}
	r_config_set_i (core->config, "scr.maxpage", maxpage);
	if (core->visual.fromVisual) {
		r_core_visual (core, "");
	} else {
		r_cons_enable_mouse (core->cons, false);
	}
	return true;
}
