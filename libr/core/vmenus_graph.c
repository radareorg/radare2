/* radare - LGPL - Copyright 2019 - pancake */

#include <r_core.h>

// find a better name and move to r_util or r_cons?
R_API char *r_str_widget_list(void *user, RList *list, int rows, int cur, PrintItemCallback cb) {
	void *item, *curItem = NULL;
	RStrBuf *sb = r_strbuf_new ("");
	RListIter *iter;
	int count = 0;
	int skip = 0;
	if (cur > (rows / 2)) {
		skip = cur - (rows / 2);
	}
	r_list_foreach (list, iter, item) {
		if (cur == count) {
			curItem = item;
		}
		if (rows >= 0) {
			if (skip > 0) {
				skip--;
			} else {
				char *line = cb (user, item, cur == count);
				if (line) {
					r_strbuf_appendf (sb, "%s", line);
					free (line);
				}
				rows--;
				if (rows == 0) {
					break;
				}
			}
		}
		count++;
	}
	// return curItem;
	return r_strbuf_drain (sb);
}

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
} RCoreVisualViewGraph;

typedef struct {
	ut64 addr;
	RAnalFunction *fcn;
	int pos; // related to columns
	int cur; // current row selected
	RList *columns;
} RCoreVisualViewGraphColumn;

typedef struct {
	ut64 addr;
	const char *name;
} RCoreVisualViewGraphItem;

static char *print_item (void *_core, void *_item, bool selected) {
	RCoreVisualViewGraphItem *item = _item;
	if (item->name && *item->name) {
		return r_str_newf ("%c %s\n", selected?'>':' ', item->name);
	}
	return r_str_newf ("%c 0x%08"PFMT64x"\n", selected?'>':' ', item->addr);
}

static RList *__xrefs(RCoreVisualViewGraph *status, ut64 addr, bool update) {
	RCore *core = status->core;
	RList *r = r_list_newf (free);
	RListIter *iter;
	RAnalRef *ref;
	RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, addr, 0);
	if (!fcn) {
		return r;
	}
	RList *xrefs = r_anal_fcn_get_xrefs (core->anal, fcn);
	r_list_foreach (xrefs, iter, ref) {
		if (ref->type != 'C') {
			continue;
		}
		RCoreVisualViewGraphItem *item = R_NEW0 (RCoreVisualViewGraphItem);
		RFlagItem *f = r_flag_get_at (core->flags, ref->addr, 0);
		item->addr = ref->addr;
		item->name = f? f->name: NULL;
		RAnalFunction *rf = r_anal_get_fcn_in (core->anal, ref->addr, 0);
		if (rf) {
			item->name = rf->name;
		}
		r_list_append (r, item);
		if (update && r_list_length (r) == status->cur) {
			fcn = r_anal_get_fcn_in (core->anal, item->addr, 0);
			status->addr = item->addr;
			status->faddr = item->addr;
			status->fcn = fcn;
		}
	}
	return r;
}

static RList *__refs(RCoreVisualViewGraph *status, ut64 addr, bool update) {
	RCore *core = status->core;
	RList *r = r_list_newf (free);
	RListIter *iter;
	RAnalRef *ref;
	RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, addr, 0);
	if (!fcn) {
		return r;
	}
	RList *refs = r_anal_fcn_get_refs (core->anal, fcn);
	r_list_foreach (refs, iter, ref) {
		if (ref->type != 'C') {
			continue;
		}
		RCoreVisualViewGraphItem *item = R_NEW0 (RCoreVisualViewGraphItem);
		RFlagItem *f = r_flag_get_at (core->flags, ref->addr, 0);
		item->addr = ref->addr;
		item->name = f? f->name: NULL;
		RAnalFunction *rf = r_anal_get_fcn_in (core->anal, ref->addr, 0);
		if (rf) {
			item->name = rf->name;
		}
		r_list_append (r, item);
		if (update && r_list_length (r) == status->cur) {
			fcn = r_anal_get_fcn_in (core->anal, item->addr, 0);
			status->addr = item->addr;
			status->faddr = item->addr;
			status->fcn = fcn;
		}
	}
	return r;
}

static RList *__fcns(RCoreVisualViewGraph *status, ut64 addr, bool update) {
	RCore *core = status->core;
	RList *r = r_list_newf (free);
	RListIter *iter;
	RAnalFunction *fcn;
	r_list_foreach (core->anal->fcns, iter, fcn) {
		if (update && r_list_length (r) == status->cur) {
			status->addr = fcn->addr;
			status->fcn = fcn;
		}
		RCoreVisualViewGraphItem *item = R_NEW0 (RCoreVisualViewGraphItem);
		item->addr = fcn->addr;
		item->name = fcn->name;
		r_list_append (r, item);
	}
	return r; // core->anal->fcns;
}

R_API int __core_visual_view_graph_update(RCore *core, RCoreVisualViewGraph *status) {
	int h, w = r_cons_get_size (&h);
	const int colw = w / 4;
	const int colh = h / 2;
	const int colx = w / 3;
	r_cons_clear00 ();
	RList *col0 = NULL, *col1 = NULL, *col2 = NULL;
	switch (status->pos) {
	case 0:
		col1 = __fcns (status, status->addr, true);
		col0 = __xrefs (status, status->addr, false);
		col2 = __refs (status, status->addr, false);
		status->faddr = status->addr;
		break;
	case 1: // xrefs
		{
			ut64 oaddr = status->addr;
			col1 = __xrefs (status, status->addr, true);
			RCoreVisualViewGraphItem *item = r_list_get_n (col1, status->cur);
			if (item) {
				col0 = __xrefs (status, item->addr, false);
				col2 = __refs (status, item->addr, false);
			}
			status->addr = oaddr;
		}
		break;
	case 2: // refs
		{
			ut64 oaddr = status->addr;
			col1 = __refs (status, status->addr, true);
			RCoreVisualViewGraphItem *item = r_list_get_n (col1, status->cur);
			if (item) {
				col0 = __xrefs (status, item->addr, false);
				col2 = __refs (status, item->addr, false);
			}
			status->addr = oaddr;
		}
		break;
	}
	char *col0str = r_str_widget_list (core, col0, colh, 0, print_item);
	char *col1str = r_str_widget_list (core, col1, colh, status->cur, print_item);
	char *col2str = r_str_widget_list (core, col2, colh, 0, print_item);

	status->canLeft = !r_list_empty (col0);
	status->canRight = !r_list_empty (col2);

	ut64 addr = status->pos ? status->faddr: status->addr;

	char *title = r_str_newf ("[r2-visual-browser] 0x%08"PFMT64x" 0x%08"PFMT64x, status->addr, status->faddr);
	if (title) {
		r_cons_strcat_at (title, 0, 0, w - 1, 2);
		free (title);
	}
	r_cons_strcat_at (col0str, 0, 2, colw, colh);
	r_cons_strcat_at (col1str, colx, 2, colw*2, colh);
	r_cons_strcat_at (col2str, colx * 2, 2, colw, colh);
	char *output = r_core_cmd_strf (core, "pd %d @e:asm.flags=0@ 0x%08"PFMT64x"; pds 256 @ 0x%08"PFMT64x"\n",
		32, addr);
	int disy = colh + 2;
	r_cons_strcat_at (output, 10, disy, w, h-disy);
	free (output);
	r_list_free (col0);
	r_list_free (col1);
	r_list_free (col2);
	r_cons_flush();
	return 0;
}

R_API int r_core_visual_view_graph(RCore *core) {
	RCoreVisualViewGraph status = {0};
	status.core = core;
	status.addr = core->offset;
	status.fcn = NULL;

	while (true) {
		__core_visual_view_graph_update (core, &status);
		int ch = r_cons_readchar ();
		if (ch == -1 || ch == 4) {
			return true;
		}
		ch = r_cons_arrow_to_hjkl (ch); // get ESC+char, return 'hjkl' char
		switch (ch) {
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
		case 'J':
			status.cur+=10;
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
				r_core_seek (core, status.faddr, 1);
			} else {
				r_core_seek (core, status.addr, 1);
			}
			return true;
			break;
		case '_':
			r_core_visual_hudstuff (core);
			status.addr = core->offset;
			status.fcn = r_anal_get_fcn_at (core->anal, status.addr, 0);
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
			r_cons_clear00 ();
			r_cons_printf (
			"vbg: Visual Browser (Code) Graph:\n\n"
			" jkJK  - scroll up/down\n"
			" hl    - move to the left/right panel\n"
			" q     - quit this visual mode\n"
			" _     - enter the hud\n"
			" .     - go back to the initial function list view\n"
			" :     - enter command\n");
			r_cons_flush ();
			r_cons_any_key (NULL);
			break;
		case 'q':
			return false;
		case ':': // TODO: move this into a separate helper function
			{
			char cmd[1024];
			r_cons_show_cursor (true);
			r_cons_set_raw (0);
			cmd[0]='\0';
			r_line_set_prompt (":> ");
			if (r_cons_fgets (cmd, sizeof (cmd)-1, 0, NULL) < 0) {
				cmd[0] = '\0';
			}
			r_core_cmd_task_sync (core, cmd, 1);
			r_cons_set_raw (1);
			r_cons_show_cursor (false);
			if (cmd[0]) {
				r_cons_any_key (NULL);
			}
			r_cons_clear ();
			}
			break;
		}
	}
	return false;
}
