/* radare - LGPL - Copyright 2024-2025 - pancake */

typedef struct {
	char *name;
	char *data;
	char *type;
	char *cmnd;
} RIUWidget;

typedef struct {
	RCore *core;
	RList *items;
	int cur;
	char *title;
} RIU;

static void riu_item_free(RIUWidget *w) {
	if (R_LIKELY (w)) {
		free (w->name);
		free (w->data);
		free (w->type);
		free (w->cmnd);
		free (w);
	}
}

static RIUWidget *riu_item(const char *n, const char *v, const char *t, const char *c) {
	RIUWidget *w = R_NEW (RIUWidget);
	if (R_LIKELY (w)) {
		w->name = strdup (n);
		w->data = strdup (v);
		w->type = strdup (t);
		w->cmnd = strdup (c);
	}
	return w;
}

static RIU *riu_new(RCore *core, const char *input) {
	RList *list = r_list_newf ((RListFree)riu_item_free);
	RIU *riu = R_NEW0 (RIU);
	riu->title = strdup ("...");

	const char *p = input;
	const char *p_n = p;
	const char *p_b = p;
	while (*p) {
		switch (*p) {
		case '(':
			p_b = p + 1;
			break;
		case ')':
			{
				char *name = r_str_ndup (p_n, p_b - p_n - 1);
				char *args = r_str_ndup (p_b, p - p_b);
				RList *largs = r_str_split_list (args, ",", 0);
				char *type = strdup (r_str_get (r_list_get_n (largs, 0)));
				char *cmnd = strdup (r_str_get (r_list_get_n (largs, 1)));
				char *data = strdup (r_str_get (r_list_get_n (largs, 2)));
				if (*type == 't') {
					riu->title = strdup (name);
				} else {
					RIUWidget *item = riu_item (name, data, type, cmnd);
					r_list_append (list, item);
				}
				free (name);
				free (type);
				free (cmnd);
				free (data);
				r_list_free (largs);
				p_b = NULL;
				p_n = NULL;
			}
			break;
		case ' ':
			if (!p_b) {
				p_n = p;
			}
			break;
		}
		p++;
	}

	r_cons_set_raw (core->cons, true);
	riu->items = list;
	riu->core = core;
	return riu;
}

static void riu_render(RIU *riu) {
	RCore *core = riu->core;
	RCons *cons = core->cons;
	RListIter *iter;
	RIUWidget *w;
	r_cons_clear00 (cons);
	r_cons_printf (cons, "\n.---------------------------------------.\n");
	r_cons_printf (cons, "| [q] %18s                |\n", r_str_get (riu->title));
	r_cons_printf (cons, "|---------------------------------------'\n");
	int n = 0;
	bool havebuttons = false;
	r_list_foreach (riu->items, iter, w) {
		const char ch = (n == riu->cur)? '>' : '-';
		switch (*w->type) {
		case 'b': // button
			if (!havebuttons) {
				r_cons_printf (cons, "|\n");
				havebuttons = true;
			}
			r_cons_printf (cons, "|  %c [ %s ]\n", ch, w->name);
			break;
		case 'r': // run
			r_cons_printf (cons, "|  %c %s (%s)\n", ch, w->name, w->cmnd);
			r_core_cmd0 (core, w->cmnd);
			break;
		default:
			r_cons_printf (cons, "|  %c %10s : %s\n", ch, w->name, w->data);
			break;
		}
		n++;
	}
	r_kons_print (cons, "`---------------------------------------'\n");
	r_cons_flush (cons);
}

static bool riu_input(RIU *riu) {
	int ch = r_cons_readchar (riu->core->cons);
	ch = r_cons_arrow_to_hjkl (riu->core->cons, ch);
	switch (ch) {
	case 'q':
		return false;
	case 'j':
		if (riu->cur < r_list_length (riu->items) - 1) {
			riu->cur++;
		}
		break;
	case 'J':
		riu->cur = r_list_length (riu->items) - 1;
		break;
	case 'k':
		if (riu->cur > 0) {
			riu->cur--;
		}
		break;
	case 'K':
		riu->cur = 0;
		break;
	case '\r':
	case '\n':
	case ' ':
		// activate!
		{
			RIUWidget *w = r_list_get_n (riu->items, riu->cur);
			if (!w) {
				break;
			}
			if (w->type[0] == 'b') {
				r_core_cmd0 (riu->core, w->cmnd);
				r_core_cmdf (riu->core, "'k riu=%s", w->name);
				return false;
			}
			r_cons_set_raw (riu->core->cons, false);
			char *res = r_core_cmd_str (riu->core, w->cmnd);
			r_str_trim (res);
			free (w->data);
			w->data = res;
			r_core_cmdf (riu->core, "'k riu.%s=%s", w->name, w->data);
			r_cons_set_raw (riu->core->cons, true);
		}
		break;
	}
	return true;
}

static void riu_free(RIU *riu) {
	r_cons_set_raw (riu->core->cons, false);
	if (riu) {
		r_list_free (riu->items);
		free (riu);
	}
}
