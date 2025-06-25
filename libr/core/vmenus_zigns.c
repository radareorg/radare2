/* radare - LGPL - Copyright 2019-2025 - pancake */

#include <r_core.h>

typedef struct {
	ut64 addr;
	ut64 faddr;
	RAnalFunction *fcn;
	int pos; // related to columns
	int cur; // current row selected
	RList *columns;
	RCore *core;
	bool canLeft;
	bool canRight;
} RCoreVisualViewZigns;

static R_TH_LOCAL const char *cur_name = NULL;

static char *print_item(void *_core, void *_item, bool selected) {
	RSignItem *item = _item;
	int i;
	int bytes_mask = 0;
	int bytes_size = item->bytes->size;
	//  int bytes_null = bytes_size - bytes_mask;
	if (item->bytes->mask) {
		for (i = 0; i < bytes_size;i++) {
			if (item->bytes->mask[i]) {
				bytes_mask++;
			}
		}
	}
	if (selected && item->name) {
		cur_name = strdup (item->name);
	}
	return r_str_newf ("%c 0x%08"PFMT64x" bytes=%d/%d %20s\n", selected?'>':' ',
		item->addr, bytes_mask, bytes_size, item->name);
}

static RList *__signs(RCoreVisualViewZigns *status, ut64 addr, bool update) {
	RCore *core = status->core;
	return r_sign_get_list (core->anal);
}

R_API int __core_visual_view_zigns_update(RCore *core, RCoreVisualViewZigns *status) {
	RCons *cons = core->cons;
	int h, w = r_kons_get_size (cons, &h);
	r_kons_clear00 (cons);
	int colh = h -2;
	int colw = w -1;
	RList *col0 = __signs (status, status->addr, true);
	char *col0str = r_str_widget_list (core, col0, colh, status->cur, print_item);

	char *title = r_str_newf ("[r2-visual-signatures] 0x%08"PFMT64x" 0x%08"PFMT64x, status->addr, status->faddr);
	if (title) {
		r_cons_print_at (cons, title, 0, 0, w - 1, 2);
		free (title);
	}
	r_cons_print_at (cons, col0str, 0, 2, colw, colh);
	r_list_free (col0);
	r_kons_flush (core->cons);
	return 0;
}

R_API int r_core_visual_view_zigns(RCore *core) {
	RCoreVisualViewZigns status = {0};
	status.core = core;
	status.addr = core->addr;
	status.fcn = NULL;

	while (true) {
		__core_visual_view_zigns_update (core, &status);
		int ch = r_cons_readchar (core->cons);
		if (ch == -1 || ch == 4) {
			return true;
		}
		ch = r_cons_arrow_to_hjkl (core->cons, ch); // get ESC+char, return 'hjkl' char
		switch (ch) {
		case 'g':
			r_core_cmd0 (core, "zg");
			break;
		case 'h':
			if (status.canLeft) {
				if (status.pos) {
					status.addr = status.faddr;
				}
				status.pos = 1;
				status.cur = 0;
			}
			break;
		case 'l':
			if (status.canRight) {
				if (status.pos) {
					status.addr = status.faddr;
				}
				status.pos = 2;
				status.cur = 0;
			}
			break;
		case 'd':
			if (cur_name && *cur_name) {
				r_sign_delete (core->anal, cur_name);
				R_FREE (cur_name);
			}
			break;
		case 'J':
			status.cur += 10;
			break;
		case 'K':
			if (status.cur > 10) {
				status.cur -= 10;
			} else {
				status.cur = 0;
			}
			break;
		case '.':
			status.pos = 0;
			break;
		case 9:
		case ' ':
		case '\r':
		case '\n':
			if (status.pos) {
				r_core_seek (core, status.faddr, true);
			} else {
				r_core_seek (core, status.addr, true);
			}
			return true;
			break;
		case '_':
			r_core_cmd0 (core, "z*~...");
			break;
		case 'j':
			status.cur++;
			break;
		case 'k':
			if (status.cur > 0) {
				status.cur--;
			} else {
				status.cur = 0;
			}
			break;
		case '?':
			r_kons_clear00 (core->cons);
			r_kons_printf (core->cons,
			"vbz: Visual Zignatures:\n\n"
			" jkJK  - scroll up/down\n"
			" d     - delete current signature\n"
			" g     - regenerate signatures\n"
			" q     - quit this visual mode\n"
			" _     - enter the hud\n"
			" :     - enter command\n");
			r_kons_flush (core->cons);
			r_cons_any_key (core->cons, NULL);
			break;
		case 'q':
			R_FREE (cur_name);
			return false;
		case ':': // TODO: move this into a separate helper function
			{
			char cmd[1024] = {0};
			r_kons_show_cursor (core->cons, true);
			r_kons_set_raw (core->cons, 0);
			r_line_set_prompt (core->cons->line, ":> ");
			if (r_cons_fgets (core->cons, cmd, sizeof (cmd), 0, NULL) < 0) {
				cmd[0] = '\0';
			}
			cmd[sizeof (cmd) - 1] = 0;
			r_core_cmd_task_sync (core, cmd, 1);
			r_kons_set_raw (core->cons, 1);
			r_kons_show_cursor (core->cons, false);
			if (cmd[0]) {
				r_cons_any_key (core->cons, NULL);
			}
			r_kons_clear (core->cons);
			}
			break;
		}
	}
	return false;
}
