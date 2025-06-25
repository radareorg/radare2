/* radare - LGPL - Copyright 2019-2025 - pancake */

#include <r_core.h>
#include <r_vec.h>

R_VEC_TYPE(RVecAnalRef, RAnalRef);

#define SORT_ADDRESS 0
#define SORT_NAME 1

// find a better name and move to r_util or r_cons?
R_API char *r_str_widget_list(void *user, RList *list, int rows, int cur, PrintItemCallback cb) {
	void *item;
	RStrBuf *sb = r_strbuf_new ("");
	RListIter *iter;
	int count = 0;
	int skip = 0;
	if (cur > (rows / 2)) {
		skip = cur - (rows / 2);
	}
	r_list_foreach (list, iter, item) {
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
	return r_strbuf_drain (sb);
}

typedef struct {
	ut64 addr;
	RAnalFunction *fcn;
	int cur; // current row selected
	int cur_sort; // holds current sort
	RCore *core;
	RList *mainCol;
	RList *xrefsCol;
	RList *refsCol;
} RCoreVisualViewGraph;

typedef struct {
	ut64 addr;
	const char *name;
	RAnalFunction *fcn;
} RCoreVisualViewGraphItem;

static char *print_item(void *_core, void *_item, bool selected) {
	RCoreVisualViewGraphItem *item = _item;
	if (item->name && *item->name) {
		if (false && item->fcn && item->addr > item->fcn->addr) {
			st64 delta = item->addr - item->fcn->addr;
			return r_str_newf ("%c %s+0x%"PFMT64x"\n", selected?'>':' ', item->name, delta);
		} else {
			return r_str_newf ("%c %s\n", selected?'>':' ', item->name);
		}
	}
	return r_str_newf ("%c 0x%08"PFMT64x"\n", selected?'>':' ', item->addr);
}

static RList *__xrefs(RCore *core, ut64 addr) {
	RList *r = r_list_newf (free);
	RVecAnalRef *xrefs = r_anal_xrefs_get (core->anal, addr);
	if (!xrefs) {
		return r;
	}

	RAnalRef *ref;
	R_VEC_FOREACH (xrefs, ref) {
		if (ref->type != 'C') {
			continue;
		}

		RCoreVisualViewGraphItem *item = R_NEW0 (RCoreVisualViewGraphItem);
		RFlagItem *f = r_flag_get_at (core->flags, ref->addr, 0);
		item->addr = ref->addr;
		item->name = f? f->name: NULL;
		RAnalFunction *rf = r_anal_get_fcn_in (core->anal, ref->addr, 0);
		item->fcn = rf;
		if (rf) {
			item->name = rf->name;
		}
		r_list_append (r, item);
	}

	RVecAnalRef_free (xrefs);
	return r;
}

static RList *__refs(RCore *core, ut64 addr) {
	RList *r = r_list_newf (free);
	RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, addr, 0);
	if (!fcn) {
		return r;
	}

	RVecAnalRef *refs = r_anal_function_get_refs (fcn);
	if (!refs) {
		return r;
	}

	RAnalRef *ref;
	R_VEC_FOREACH (refs, ref) {
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
			item->fcn = rf;
		}
		r_list_append (r, item);
	}

	RVecAnalRef_free (refs);
	return r;
}

static RList *__fcns(RCore *core) {
	RList *r = r_list_newf (free);
	RListIter *iter;
	RAnalFunction *fcn;
	r_list_foreach (core->anal->fcns, iter, fcn) {
		RCoreVisualViewGraphItem *item = R_NEW0 (RCoreVisualViewGraphItem);
		item->addr = fcn->addr;
		item->name = fcn->name;
		item->fcn = fcn;
		r_list_append (r, item);
	}
	return r; // core->anal->fcns;
}

static void __seek_cursor(RCoreVisualViewGraph *status) {
	ut64 target = 0;
	if (status->fcn) {
		target = status->fcn->addr;
	} else {
		target = status->addr;
	}

	RListIter *iter;
	RCoreVisualViewGraphItem *item;
	int cur = 0;
	r_list_foreach (status->mainCol, iter, item) {
		if (target == item->addr) {
			status->cur = cur;
		}
		cur++;
	}
	return;
}

static int cmpaddr(const void *_a, const void *_b) {
	const RCoreVisualViewGraphItem *a = _a, *b = _b;
	return a->addr - b->addr;
}

static int cmpname(const void *_a, const void *_b) {
	const RCoreVisualViewGraphItem *a = _a, *b = _b;
	if (!a || !b || !a->name || !b->name) {
		return 0;
	}
	return (int)strcmp (a->name, b->name);
}

static void __sort(RCoreVisualViewGraph *status, RList *list) {
	R_RETURN_IF_FAIL (status && list);
	RListComparator cmp = (status->cur_sort == SORT_ADDRESS)? cmpaddr: cmpname;
	list->sorted = false;
	r_list_sort (list, cmp);
}

static void __toggleSort(RCoreVisualViewGraph *status) {
	R_RETURN_IF_FAIL (status);
	status->cur_sort = (status->cur_sort == SORT_ADDRESS)? SORT_NAME: SORT_ADDRESS;
	__sort (status, status->mainCol);
	__sort (status, status->refsCol);
	__sort (status, status->xrefsCol);
	__seek_cursor (status);
}

static void __reset_status(RCoreVisualViewGraph *status) {
	status->addr = status->core->addr;
	status->fcn = r_anal_get_function_at (status->core->anal, status->addr);

	status->mainCol = __fcns (status->core);
	__sort (status, status->mainCol);
	__seek_cursor (status);

	return;
}

static void __sync_status_with_cursor(RCoreVisualViewGraph *status) {
	RCoreVisualViewGraphItem *item = r_list_get_n (status->mainCol, status->cur);
	if (!item) {
		r_list_free (status->mainCol);
		__reset_status (status);
		return;
	}

	status->addr = item->addr;
	status->fcn = item->fcn;

	// Update xrefs and refs columns based on selected element in fcns column
	if (status->fcn && status->fcn->addr) {
		status->xrefsCol = __xrefs (status->core, status->fcn->addr);
		status->refsCol = __refs (status->core, status->fcn->addr);
	} else {
		status->xrefsCol = __xrefs (status->core, status->addr);
		status->refsCol = r_list_newf (free);
	}
	__sort (status, status->xrefsCol);
	__sort (status, status->refsCol);
}

R_API int __core_visual_view_graph_update(RCore *core, RCoreVisualViewGraph *status) {
	RCons *cons = core->cons;
	int h, w = r_cons_get_size (cons, &h);
	const int colw = w / 4;
	const int colh = h / 2;
	const int colx = w / 3;
	r_cons_clear00 (core->cons);

	char *xrefsColstr = r_str_widget_list (core, status->xrefsCol, colh, 0, print_item);
	char *mainColstr = r_str_widget_list (core, status->mainCol, colh, status->cur, print_item);
	char *refsColstr = r_str_widget_list (core, status->refsCol, colh, 0, print_item);

	/* if (r_list_empty (status->xrefsCol) && r_list_empty (status->refsCol)) { */
	/* 	// We've found ourselves in a bad state, reset the view */
		/* r_list_free (status->mainCol); */
	/* 	__reset_status (status); */
	/* } */

	char *title = r_str_newf ("[r2-visual-browser] addr=0x%08"PFMT64x" faddr=0x%08"PFMT64x, status->addr, status->fcn ? status->fcn->addr : 0);
	if (title) {
		r_cons_print_at (cons, title, 0, 0, w - 1, 2);
		free (title);
	}
	r_cons_print_at (cons, xrefsColstr, 0, 2, colw, colh);
	r_cons_print_at (cons, mainColstr, colx, 2, colw*2, colh);
	r_cons_print_at (cons, refsColstr, colx * 2, 2, colw, colh);

	char *output = r_core_cmd_strf (core, "pd %d @e:asm.flags=0@ 0x%08"PFMT64x"; pds 256 @ 0x%08"PFMT64x,
		32, status->addr, status->addr);
	int disy = colh + 2;
	r_cons_print_at (cons, output, 10, disy, w, h - disy);
	free (output);
	r_cons_flush (cons);

	free (xrefsColstr);
	free (mainColstr);
	free (refsColstr);
	return 0;
}

R_API int r_core_visual_view_graph(RCore *core) {
	RCoreVisualViewGraph status = {0};
	status.core = core;
	status.cur_sort = SORT_NAME;
	__reset_status (&status);
	__sync_status_with_cursor (&status);
	RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, status.addr, 0);
	if (fcn) {
		status.addr = fcn->addr;
		status.fcn = fcn;
	}
	while (true) {
		__core_visual_view_graph_update (core, &status);
		int ch = r_cons_readchar (core->cons);
		if (ch == -1 || ch == 4) {
			return true;
		}
		ch = r_cons_arrow_to_hjkl (core->cons, ch); // get ESC+char, return 'hjkl' char
		switch (ch) {
		case 'h':
			if (!r_list_empty (status.xrefsCol)) {
				status.cur = 0;
				r_list_free (status.mainCol);
				r_list_free (status.refsCol);
				status.mainCol = status.xrefsCol;

				__sync_status_with_cursor (&status);
			}
			break;
		case 'l':
			if (!r_list_empty (status.refsCol)) {
				status.cur = 0;
				r_list_free (status.mainCol);
				r_list_free (status.xrefsCol);
				status.mainCol = status.refsCol;

				__sync_status_with_cursor (&status);
			}
			break;
		case 'J':
			{
				status.cur += 10;
				int length = r_list_length (status.mainCol);
				if (status.cur >= length) {
					status.cur = length-1;
				}
				r_list_free (status.xrefsCol);
				r_list_free (status.refsCol);
				__sync_status_with_cursor (&status);
			}
			break;
		case 'K':
			if (status.cur > 10) {
				status.cur -= 10;
			} else {
				status.cur = 0;
			}
			r_list_free (status.xrefsCol);
			r_list_free (status.refsCol);
			__sync_status_with_cursor (&status);
			break;
		case '.':
			// reset view and seek status->cur to current function
			r_list_free (status.mainCol);
			__reset_status (&status);
			break;
		case 9:
		case ' ':
		case '\r':
		case '\n':
			{
				RCoreVisualViewGraphItem *item = r_list_get_n (status.mainCol, status.cur);
				if (item) {
					r_core_seek (core, item->addr, true);
				}
			}
			return true;
			break;
		case '_':
			r_core_visual_hudstuff (core);
			r_list_free (status.mainCol);
			r_list_free (status.xrefsCol);
			r_list_free (status.refsCol);
			__reset_status (&status);
			__sync_status_with_cursor (&status);
			break;
		case 'r':
			r_list_free (status.mainCol);
			r_list_free (status.xrefsCol);
			r_list_free (status.refsCol);
			__reset_status (&status);
			__sync_status_with_cursor (&status);
			break;
		case 'j':
			{
				status.cur++;
				int length = r_list_length (status.mainCol);
				if (status.cur >= length) {
					status.cur = length-1;
				}
				r_list_free (status.xrefsCol);
				r_list_free (status.refsCol);
				__sync_status_with_cursor (&status);
			}
			break;
		case 'k':
			if (status.cur > 0) {
				status.cur--;
			} else {
				status.cur = 0;
			}
			r_list_free (status.xrefsCol);
			r_list_free (status.refsCol);
			__sync_status_with_cursor (&status);
			break;
		case '?':
			r_cons_clear00 (core->cons);
			r_kons_printf (core->cons,
			"vbg: Visual Browser (Code) Graph:\n\n"
			" jkJK  - scroll up/down\n"
			" hl    - move to the left/right panel\n"
			" q     - quit this visual mode\n"
			" _     - enter the hud\n"
			" .     - go back to the initial function list view\n"
			" :     - enter command\n");
			r_cons_flush (core->cons);
			r_cons_any_key (core->cons, NULL);
			break;
		case '/':
			{
				char cmd[1024];
				r_cons_show_cursor (core->cons, true);
				r_cons_set_raw (core->cons, 0);
				cmd[0] = '\0';
				r_line_set_prompt (core->cons->line, ":> ");
				if (r_cons_fgets (core->cons, cmd, sizeof (cmd), 0, NULL) < 0) {
					cmd[0] = '\0';
				}
				r_config_set (core->config, "scr.highlight", cmd);
				// r_core_cmd_task_sync (core, cmd, 1);
				r_cons_set_raw (core->cons, 1);
				r_cons_show_cursor (core->cons, false);
				r_cons_clear (core->cons);
			}
			break;
		case 'q':
			return false;
		case ':': // TODO: move this into a separate helper function
			{
			char cmd[1024];
			r_cons_show_cursor (core->cons, true);
			r_cons_set_raw (core->cons, 0);
			cmd[0]='\0';
			r_line_set_prompt (core->cons->line, ":> ");
			if (r_cons_fgets (core->cons, cmd, sizeof (cmd), 0, NULL) < 0) {
				cmd[0] = '\0';
			}
			r_core_cmd0 (core, cmd);
			//r_core_cmd_task_sync (core, cmd, 1);
			r_cons_set_raw (core->cons, 1);
			r_cons_show_cursor (core->cons, false);
			if (cmd[0]) {
				r_cons_any_key (core->cons, NULL);
			}
			r_cons_clear (core->cons);
			}
			break;
		case '!': {
			__toggleSort (&status);
		} break;
		}
	}
	return false;
}
