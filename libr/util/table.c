/* radare - LGPL - Copyright 2019-2021 - pancake */

#include <r_util/r_table.h>
#include "r_cons.h"

// cant do that without globals because RList doesnt have void *user :(
static int Gnth = 0;
static RListComparator Gcmp = NULL;

static int sortString(const void *a, const void *b) {
	return strcmp (a, b);
}

static int sortNumber(const void *a, const void *b) {
	return r_num_get (NULL, a) - r_num_get (NULL, b);
}

// maybe just index by name instead of exposing those symbols as global
static RTableColumnType r_table_type_string = { "string", sortString };
static RTableColumnType r_table_type_number = { "number", sortNumber };
static RTableColumnType r_table_type_bool = { "bool", sortNumber };

R_API RTableColumnType *r_table_type (const char *name) {
	if (!strcmp (name, "bool")) {
		return &r_table_type_bool;
	}
	if (!strcmp (name, "boolean")) {
		return &r_table_type_bool;
	}
	if (!strcmp (name, "string")) {
		return &r_table_type_string;
	}
	if (!strcmp (name, "number")) {
		return &r_table_type_number;
	}
	return NULL;
}

// TODO: unused for now, maybe good to call after filter :?
static void __table_adjust(RTable *t) {
	RListIter *iter, *iter2;
	RTableColumn *col;
	RTableRow  *row;
	r_list_foreach (t->cols, iter, col) {
		int itemLength = r_str_len_utf8_ansi (col->name) + 1;
		col->width = itemLength;
	}
	r_list_foreach (t->rows, iter, row) {
		const char *item;
		int ncol = 0;
		r_list_foreach (row->items, iter2, item) {
			int itemLength = r_str_len_utf8_ansi (item) + 1;
			RTableColumn *c = r_list_get_n (t->cols, ncol);
			if (c) {
				c->width = R_MAX (c->width, itemLength);
			}
			ncol ++;
		}
	}
}

R_API void r_table_row_free(void *_row) {
	RTableRow *row = _row;
	r_list_free (row->items);
	free (row);
}

R_API void r_table_column_free(void *_col) {
	RTableColumn *col = _col;
	free (col->name);
	free (col);
}

R_API RTableRow *r_table_row_clone(RTableRow *row) {
	RTableRow *r = r_table_row_new (r_list_newf (free));
	RListIter *iter;
	char *word;
	r_list_foreach (row->items, iter, word) {
		r_list_append (r->items, strdup (word));
	}
	return r;
}

R_API RTableColumn *r_table_column_clone(RTableColumn *col) {
	RTableColumn *c = R_NEW0 (RTableColumn);
	if (!c) {
		return NULL;
	}
	memcpy (c, col, sizeof (*c));
	c->name = strdup (c->name);
	return c;
}

R_API RTable *r_table_new(const char *name) {
	RTable *t = R_NEW0 (RTable);
	if (t) {
		t->showHeader = true;
		t->name = strdup (name);
		t->cols = r_list_newf (r_table_column_free);
		t->rows = r_list_newf (r_table_row_free);
		t->showSum = false;
	}
	return t;
}

R_API void r_table_free(RTable *t) {
	if (!t) {
		return;
	}
	r_list_free (t->cols);
	r_list_free (t->rows);
	free (t->name);
	free (t);
}

R_API void r_table_add_column(RTable *t, RTableColumnType *type, const char *name, int maxWidth) {
	RTableColumn *c = R_NEW0 (RTableColumn);
	if (c) {
		c->name = strdup (name);
		c->maxWidth = maxWidth;
		c->type = type;
		int itemLength = r_str_len_utf8_ansi (name) + 1;
		c->width = itemLength;
		r_list_append (t->cols, c);
		c->total = -1;
	}
}

R_API RTableRow *r_table_row_new(RList *items) {
	RTableRow *row = R_NEW (RTableRow);
	row->items = items;
	return row;
}

static bool __addRow(RTable *t, RList *items, const char *arg, int col) {
	int itemLength = r_str_len_utf8_ansi (arg) + 1;
	RTableColumn *c = r_list_get_n (t->cols, col);
	if (c) {
		c->width = R_MAX (c->width, itemLength);
		r_list_append (items, strdup (arg));
		return true;
	}
	return false;
}

R_API void r_table_add_row_list(RTable *t, RList *items) {
	r_return_if_fail (t && items);
	RTableRow *row = r_table_row_new (items);
	r_list_append (t->rows, row);
	// throw warning if not enough columns defined in header
	t->totalCols = R_MAX (t->totalCols, r_list_length (items));
}

R_API void r_table_set_columnsf(RTable *t, const char *fmt, ...) {
	va_list ap;
	va_start (ap, fmt);
	RTableColumnType *typeString = r_table_type ("string");
	RTableColumnType *typeNumber = r_table_type ("number");
	RTableColumnType *typeBool = r_table_type ("bool");
	const char *name;
	const char *f = fmt;
	for (;*f;f++) {
		name = va_arg (ap, const char *);
		if (!name) {
			break;
		}
		switch (*f) {
		case 'b':
			r_table_add_column (t, typeBool, name, 0);
			break;
		case 's':
		case 'z':
			r_table_add_column (t, typeString, name, 0);
			break;
		case 'i':
		case 'd':
		case 'n':
		case 'x':
		case 'X':
			r_table_add_column (t, typeNumber, name, 0);
			break;
		default:
			eprintf ("Invalid format string char '%c', use 's' or 'n'\n", *f);
			break;
		}
	}
	va_end(ap);
}

R_API void r_table_add_rowf(RTable *t, const char *fmt, ...) {
	va_list ap;
	va_start (ap, fmt);
	RList *list = r_list_newf (free);
	const char *f = fmt;
	const char *arg = NULL;
	for (; *f; f++) {
		switch (*f) {
		case 's':
		case 'z':
			arg = va_arg (ap, const char *);
			r_list_append (list, strdup (r_str_get (arg)));
			break;
		case 'b':
			r_list_append (list, r_str_new (r_str_bool (va_arg (ap, int))));
			break;
		case 'i':
		case 'd':
			r_list_append (list, r_str_newf ("%d", va_arg (ap, int)));
			break;
		case 'n':
			r_list_append (list, r_str_newf ("%"PFMT64d, va_arg (ap, ut64)));
			break;
		case 'u':
			r_list_append (list, r_num_units (NULL, 32, va_arg (ap, ut64)));
			break;
		case 'x':
		case 'X':
			{
				ut64 n = va_arg (ap, ut64);
				if (n == UT64_MAX) {
					if (*f == 'X') {
						r_list_append (list, strdup ("----------"));
					} else {
						r_list_append (list, strdup ("-1"));
					}
				} else {
					if (*f == 'X') {
						r_list_append (list, r_str_newf ("0x%08"PFMT64x, n));
					} else {
						r_list_append (list, r_str_newf ("0x%"PFMT64x, n));
					}
				}
			}
			break;
		default:
			eprintf ("Invalid format string char '%c', use 's' or 'n'\n", *f);
			break;
		}
	}
	va_end (ap);
	r_table_add_row_list (t, list);
}

R_API void r_table_add_row(RTable *t, const char *name, ...) {
	va_list ap;
	va_start (ap, name);
	int col = 0;
	RList *items = r_list_newf (free);
	__addRow (t, items, name, col++);
	for (;;) {
		const char *arg = va_arg (ap, const char *);
		if (!arg) {
			break;
		}
		__addRow (t, items, arg, col);
		// TODO: assert if number of columns doesnt match t->cols
		col++;
	}
	va_end (ap);
	RTableRow *row = r_table_row_new (items);
	r_list_append (t->rows, row);
	// throw warning if not enough columns defined in header
	t->totalCols = R_MAX (t->totalCols, r_list_length (items));
}

// import / export

static int __strbuf_append_col_aligned_fancy(RTable *t, RStrBuf *sb, RTableColumn *col, char *str) {
	RCons *cons = (RCons *) t->cons;
	const char *v_line = (cons && (cons->use_utf8 ||  cons->use_utf8_curvy)) ? RUNE_LINE_VERT : "|";
	int ll = r_strbuf_length (sb);
	switch (col->align) {
	case R_TABLE_ALIGN_LEFT:
		r_strbuf_appendf (sb, "%s %-*s ", v_line, col->width, str);
		break;
	case R_TABLE_ALIGN_RIGHT:
		r_strbuf_appendf (sb, "%s %*s ", v_line, col->width, str);
		break;
	case R_TABLE_ALIGN_CENTER:
		{
			int len = r_str_len_utf8 (str);
			int pad = (col->width - len) / 2;
			int left = col->width - (pad * 2 + len);
			r_strbuf_appendf (sb, "%s %-*s ", v_line, pad, " ");
			r_strbuf_appendf (sb, "%-*s ", pad + left, str);
			break;
		}
	}
	return r_strbuf_length (sb) - ll;
}

static void __computeTotal(RTable *t) {
	RTableRow *row;
	RListIter *iter, *iter2;
	r_list_foreach (t->rows, iter, row) {
		char *item;
		int c = 0;
		r_list_foreach (row->items, iter2, item) {
			RTableColumn *col = r_list_get_n (t->cols, c);
			if (!r_str_cmp (col->type->name, "number", r_str_ansi_len ("number")) && r_str_isnumber (item)) {
				if (col->total < 0) {
					col->total = 0;
				}
				col->total += sdb_atoi(item);
			}
			c++;
		}
	}
}

R_API char *r_table_tofancystring(RTable *t) {
	if (r_list_length (t->cols) == 0) {
		return strdup ("");
	}
	RStrBuf *sb = r_strbuf_new ("");
	RTableRow *row;
	RTableColumn *col;
	RCons *cons = (RCons *)t->cons;
	RListIter *iter, *iter2;
	bool useUtf8 = (cons && cons->use_utf8);
	bool useUtf8Curvy = (cons && cons->use_utf8_curvy);
	const char *v_line = useUtf8 || useUtf8Curvy ? RUNE_LINE_VERT : "|";
	const char *h_line = useUtf8 || useUtf8Curvy ? RUNE_LINE_HORIZ : "-";
	const char *l_intersect = useUtf8 || useUtf8Curvy ? RUNE_LINE_VERT : ")";
	const char *r_intersect = useUtf8 || useUtf8Curvy ? RUNE_LINE_VERT : "(";
	const char *tl_corner = useUtf8 ? (useUtf8Curvy ? RUNE_CURVE_CORNER_TL : RUNE_CORNER_TL) : ".";
	const char *tr_corner = useUtf8 ? (useUtf8Curvy ? RUNE_CURVE_CORNER_TR : RUNE_CORNER_TR) : ".";
	const char *bl_corner = useUtf8 ? (useUtf8Curvy ? RUNE_CURVE_CORNER_BL : RUNE_CORNER_BL) : "`";
	const char *br_corner = useUtf8 ? (useUtf8Curvy ? RUNE_CURVE_CORNER_BR : RUNE_CORNER_BR) : "'";
	__table_adjust (t);

	r_list_foreach (t->cols, iter, col) {
		__strbuf_append_col_aligned_fancy (t, sb, col, col->name);
	}
	int len = r_str_len_utf8_ansi (r_strbuf_get (sb)) - 1;
	int maxlen = len;
	char *h_line_str = r_str_repeat (h_line, maxlen);
	{
		char *s = r_str_newf ("%s%s%s\n", tl_corner, h_line_str, tr_corner);
		r_strbuf_prepend (sb, s);
		free (s);
	}

	r_strbuf_appendf (sb, "%s\n%s%s%s\n", v_line, l_intersect, h_line_str, r_intersect);
	r_list_foreach (t->rows, iter, row) {
		char *item;
		int c = 0;
		r_list_foreach (row->items, iter2, item) {
			RTableColumn *col = r_list_get_n (t->cols, c);
			if (col) {
				int l = __strbuf_append_col_aligned_fancy (t, sb, col, item);
				len = R_MAX (len, l);
			}
			c++;
		}
		r_strbuf_appendf (sb, "%s\n", v_line);
	}

	if (t->showSum) {
		char tmp[64];
		__computeTotal (t);
		r_strbuf_appendf (sb, "%s%s%s\n", l_intersect, h_line_str, r_intersect);
		r_list_foreach (t->cols, iter, col) {
			char *num = col->total == -1 ? "" : sdb_itoa (col->total, tmp, 10);
			int l = __strbuf_append_col_aligned_fancy (t, sb, col, num);
			len = R_MAX (len, l);
		}
		r_strbuf_appendf (sb, "%s\n", v_line);
	}
	r_strbuf_appendf (sb, "%s%s%s\n", bl_corner, h_line_str, br_corner);
	free (h_line_str);
	return r_strbuf_drain (sb);
}

static int __strbuf_append_col_aligned(RStrBuf *sb, RTableColumn *col, const char *str, bool nopad) {
	int ll = r_strbuf_length (sb);
	if (nopad) {
		r_strbuf_appendf (sb, "%s", str);
	} else {
		char *pad = "";
		int padlen = 0;
		int len1 = r_str_len_utf8 (str);
		int len2 = r_str_len_utf8_ansi (str);
		if (len1 > len2) {
			if (len2 < col->width) {
				padlen = col->width - len2;
			}
		}
		switch (col->align) {
		case R_TABLE_ALIGN_LEFT:
			pad = r_str_repeat (" ", padlen);
			r_strbuf_appendf (sb, "%-*s%s", col->width, str, pad);
			free (pad);
			break;
		case R_TABLE_ALIGN_RIGHT:
			pad = r_str_repeat (" ", padlen);
			r_strbuf_appendf (sb, "%s%*s ", pad, col->width, str);
			free (pad);
			break;
		case R_TABLE_ALIGN_CENTER:
			{
				int pad = (col->width - len2) / 2;
				int left = col->width - (pad * 2 + len2);
				r_strbuf_appendf (sb, "%-*s", pad, " ");
				r_strbuf_appendf (sb, "%-*s ", pad + left, str);
				break;
			}
		}
	}
	return r_strbuf_length (sb) - ll;
}

R_API char *r_table_tostring(RTable *t) {
	if (!t) { // guard
		return strdup ("");
	}
	if (t->showR2) {
		return r_table_tor2cmds (t);
	}
	if (t->showSQL) {
		return r_table_tosql (t);
	}
	if (t->showCSV) {
		return r_table_tocsv (t);
	}
	if (t->showJSON) {
		char *s = r_table_tojson (t);
		char *q = r_str_newf ("%s\n", s);;
		free (s);
		return q;
	}
	if (t->showFancy) {
		return r_table_tofancystring (t);
	}
	return r_table_tosimplestring (t);
}

R_API char *r_table_tosimplestring(RTable *t) {
	RStrBuf *sb = r_strbuf_new ("");
	RTableRow *row;
	RTableColumn *col;
	RListIter *iter, *iter2;
	RCons *cons = (RCons *) t->cons;
	const char *h_line = (cons && (cons->use_utf8 || cons->use_utf8_curvy)) ? RUNE_LONG_LINE_HORIZ : "-";
	__table_adjust (t);
	int maxlen = 0;
	if (t->showHeader) {
		r_list_foreach (t->cols, iter, col) {
			bool nopad = !iter->n;
			int ll = __strbuf_append_col_aligned (sb, col, col->name, nopad);
			maxlen = R_MAX (maxlen, ll);
		}
		int len = r_str_len_utf8_ansi (r_strbuf_get (sb));
		char *l = r_str_repeat (h_line, R_MAX (maxlen, len));
		if (l) {
			r_strbuf_appendf (sb, "\n%s\n", l);
			free (l);
		}
	}
	r_list_foreach (t->rows, iter, row) {
		char *item;
		int c = 0;
		r_list_foreach (row->items, iter2, item) {
			bool nopad = !iter2->n;
			RTableColumn *col = r_list_get_n (t->cols, c);
			if (col) {
				(void)__strbuf_append_col_aligned (sb, col, item, nopad);
			}
			c++;
		}
		r_strbuf_append (sb, "\n");
	}
	if (t->showSum) {
		char tmp[64];
		__computeTotal (t);
		if (maxlen > 0) {
			char *l = r_str_repeat (h_line, maxlen);
			if (l) {
				r_strbuf_appendf (sb, "\n%s\n", l);
				free (l);
			}
		}
		r_list_foreach (t->cols, iter, col) {
			bool nopad = !iter->n;
			(void)__strbuf_append_col_aligned (sb, col, sdb_itoa (col->total, tmp, 10), nopad);
		}
	}
	return r_strbuf_drain (sb);
}

R_API char *r_table_tor2cmds(RTable *t) {
	RStrBuf *sb = r_strbuf_new ("");
	RTableRow *row;
	RTableColumn *col;
	RListIter *iter, *iter2;

	r_strbuf_appendf (sb, ",h ");
	r_list_foreach (t->cols, iter, col) {
		char fmt = col->type == &r_table_type_string? 's': 'x';
		r_strbuf_appendf (sb, "%c", fmt);
	}
	r_list_foreach (t->cols, iter, col) {
		r_strbuf_appendf (sb, " %s",  col->name);
	}
	r_strbuf_append (sb, "\n");

	r_list_foreach (t->rows, iter, row) {
		char *item;
		int c = 0;
		r_strbuf_appendf (sb, ",r");
		r_list_foreach (row->items, iter2, item) {
			RTableColumn *col = r_list_get_n (t->cols, c);
			if (col) {
				r_strbuf_appendf (sb, " %s", item);
			}
			c++;
		}
		r_strbuf_append (sb, "\n");
	}
	return r_strbuf_drain (sb);
}

R_API char *r_table_tosql(RTable *t) {
	r_return_val_if_fail (t, NULL);
	RStrBuf *sb = r_strbuf_new ("");
	RTableRow *row;
	RTableColumn *col;
	RListIter *iter, *iter2;

	const char *table_name = R_STR_ISEMPTY (t->name)? "r2": t->name;
	r_strbuf_appendf (sb, "CREATE TABLE %s (", table_name);
	bool primary_key = true;
	r_list_foreach (t->cols, iter, col) {
		const char *type = col->type == &r_table_type_string? "VARCHAR": "NUMERIC(20)";
		const char *comma = iter->n? ", ": "";
		const char *pkey = primary_key? " PRIMARY KEY": "";
		char *s = r_str_escape_sql (col->name);
		r_strbuf_appendf (sb, "%s %s%s%s", s, type, pkey, comma);
		free (s);
		primary_key = false;
	}
	r_strbuf_appendf (sb, ");\n");

	r_list_foreach (t->rows, iter, row) {
		const char *item;
		int c = 0;
		r_strbuf_appendf (sb, "INSERT INTO %s (", table_name);
		r_list_foreach (t->cols, iter2, col) {
			const char *comma = iter2->n? ", ": "";
			char *s = r_str_escape_sql (col->name);
			r_strbuf_appendf (sb, "%s%s", s, comma);
			free (s);
		}
		r_strbuf_append (sb, ") VALUES (");
		r_list_foreach (row->items, iter2, item) {
			RTableColumn *col = r_list_get_n (t->cols, c);
			if (col) {
				const char *comma = iter2->n? ", ": "";
				if (col->type == &r_table_type_string) {
					char *s = r_str_escape_sql (item);
					r_strbuf_appendf (sb, "'%s'%s", s, comma);
					free (s);
				} else {
					r_strbuf_appendf (sb, "%s%s", item, comma);
				}
			}
			c++;
		}
		r_strbuf_append (sb, ");\n");
	}
	return r_strbuf_drain (sb);
}

R_API char *r_table_tocsv(RTable *t) {
	RStrBuf *sb = r_strbuf_new ("");
	RTableRow *row;
	RTableColumn *col;
	RListIter *iter, *iter2;
	if (t->showHeader) {
		const char *comma = "";
		r_list_foreach (t->cols, iter, col) {
			if (strchr (col->name, ',')) {
				// TODO. escaped string?
				r_strbuf_appendf (sb, "%s\"%s\"", comma, col->name);
			} else {
				r_strbuf_appendf (sb, "%s%s", comma, col->name);
			}
			comma = ",";
		}
		r_strbuf_append (sb, "\n");
	}
	r_list_foreach (t->rows, iter, row) {
		char *item;
		int c = 0;
		const char *comma = "";
		r_list_foreach (row->items, iter2, item) {
			RTableColumn *col = r_list_get_n (t->cols, c);
			if (col) {
				if (strchr (col->name, ',')) {
					r_strbuf_appendf (sb, "%s\"%s\"", comma, col->name);
				} else {
					r_strbuf_appendf (sb, "%s%s", comma, item);
				}
				comma = ",";
			}
			c++;
		}
		r_strbuf_append (sb, "\n");
	}
	return r_strbuf_drain (sb);
}

R_API char *r_table_tojson(RTable *t) {
	PJ *pj = pj_new ();
	RTableRow *row;
	RListIter *iter, *iter2;
	pj_a (pj);
	r_list_foreach (t->rows, iter, row) {
		char *item;
		int c = 0;
		pj_o (pj);
		r_list_foreach (row->items, iter2, item) {
			RTableColumn *col = r_list_get_n (t->cols, c);
			if (col) {
				if (col->type == &r_table_type_number) {
					ut64 n = r_num_get (NULL, item);
					if (n) {
						pj_kn (pj, col->name, n);
					} else if (*item && *item != '0') {
						pj_ks (pj, col->name, item);
					}
				} else {
					if (*item) {
						pj_ks (pj, col->name, item);
					}
				}
			}
			c++;
		}
		pj_end (pj);
	}
	pj_end (pj);
	return pj_drain (pj);
}

R_API void r_table_filter(RTable *t, int nth, int op, const char *un) {
	r_return_if_fail (t && un);
	RTableRow *row;
	RListIter *iter, *iter2;
	ut64 uv = r_num_math (NULL, un);
	ut64 sum = 0;
	int page = 0, page_items = 0;
	size_t lrow = 0;
	if (op == 't') {
		size_t ll = r_list_length (t->rows);
		if (ll > uv) {
			uv = ll - uv;
		}
	}
	if (op == 'p') {
		sscanf (un, "%d/%d", &page, &page_items);
		if (page < 1) {
			page = 1;
		}
		if (!ST32_MUL_OVFCHK (page, page_items)) {
			lrow = page_items * (page - 1);
			uv = page_items * (page);
		}
	}
	size_t nrow = 0;
	r_list_foreach_safe (t->rows, iter, iter2, row) {
		const char *nn = r_list_get_n (row->items, nth);
		ut64 nv = r_num_math (NULL, nn);
		bool match = true;
		switch (op) {
		case 'p':
			nrow++;
			if (nrow < lrow) {
				match = false;
			}
			if (nrow > uv) {
				match = false;
			}
			break;
		case 't':
			nrow++;
			if (nrow < uv) {
				match = false;
			}
			break;
		case 'h':
			nrow++;
			if (nrow > uv) {
				match = false;
			}
			break;
		case '+':
			// "sum"
			sum += nv;
			match = false;
			break;
		case '>':
			match = (nv > uv);
			break;
		case '<':
			match = (nv < uv);
			break;
		case '=':
			if (nv == 0) {
				match = !strcmp (nn, un);
			} else {
				match = (nv == uv);
			}
			break;
		case '!':
			if (nv == 0) {
				match = strcmp (nn, un);
			} else {
				match = (nv != uv);
			}
			break;
		case '~':
			match = strstr (nn, un) != NULL;
			break;
		case 's':
			match = strlen (nn) == atoi (un);
			break;
		case 'l':
			match = strlen (nn) > atoi (un);
			break;
		case 'L':
			match = strlen (nn) < atoi (un);
			break;
		case '\0':
			break;
		}
		if (!match) {
			r_list_delete (t->rows, iter);
		}
	}
	if (op == '+') {
		r_table_add_rowf (t, "u", sum);
	}
}

static int cmp(const void *_a, const void *_b) {
	RTableRow *a = (RTableRow*)_a;
	RTableRow *b = (RTableRow*)_b;
	const char *wa = r_list_get_n (a->items, Gnth);
	const char *wb = r_list_get_n (b->items, Gnth);
	int res = Gcmp (wa, wb);
	return res;
}

R_API void r_table_sort(RTable *t, int nth, bool dec) {
	RTableColumn *col = r_list_get_n (t->cols, nth);
	if (col) {
		Gnth = nth;
		if (col->type && col->type->cmp) {
			Gcmp = col->type->cmp;
			t->rows->sorted = false; //force sorting
			r_list_sort (t->rows, cmp);
			if (dec) {
				r_list_reverse (t->rows);
			}
		}
		Gnth = 0;
		Gcmp = NULL;
	}
}

static int cmplen(const void *_a, const void *_b) {
	RTableRow *a = (RTableRow*)_a;
	RTableRow *b = (RTableRow*)_b;
	const char *wa = r_list_get_n (a->items, Gnth);
	const char *wb = r_list_get_n (b->items, Gnth);
	int res = strlen (wa) - strlen (wb);
	return res;
}

R_API void r_table_sortlen(RTable *t, int nth, bool dec) {
	RTableColumn *col = r_list_get_n (t->cols, nth);
	if (col) {
		Gnth = nth;
		t->rows->sorted = false; //force sorting
		r_list_sort (t->rows, cmplen);
		if (dec) {
			r_list_reverse (t->rows);
		}
		Gnth = 0;
	}
}

static int r_rows_cmp(RList *lhs, RList *rhs, RList *cols, int nth) {
	RListIter *iter_lhs;
	RListIter *iter_rhs;
	RListIter *iter_col;
	RTableColumn *item_col;

	void *item_lhs;
	void *item_rhs;
	int tmp;
	int i = 0;

	for (iter_lhs = lhs->head, iter_rhs = rhs->head, iter_col = cols->head;
		iter_lhs && iter_rhs && iter_col;
		iter_lhs = iter_lhs->n, iter_rhs = iter_rhs->n, iter_col = iter_col->n) {

		item_lhs = iter_lhs->data;
		item_rhs = iter_rhs->data;
		item_col = iter_col->data;

		if (nth == -1 || i == nth) {
			tmp = item_col->type->cmp (item_lhs, item_rhs);

			if (tmp) {
				return tmp;
			}
		}

		i++;
	}

	if (iter_lhs) {
		return 1;
	}

	if (iter_rhs) {
		return -1;
	}

	return 0;
}

R_API void r_table_uniq(RTable *t) {
	r_table_group (t, -1, NULL);
}

R_API void r_table_group(RTable *t, int nth, RTableSelector fcn) {
	RListIter *iter;
	RListIter *tmp;
	RTableRow *row;

	RListIter *iter_inner;
	RTableRow *uniq_row;

	RList *rows = t->rows;

	r_list_foreach_safe (rows, iter, tmp, row) {
		for (iter_inner = rows->head;
			iter_inner && iter_inner != iter;
			iter_inner = iter_inner->n) {

			uniq_row = iter_inner->data;

			if (!r_rows_cmp (uniq_row->items, row->items, t->cols, nth)) {
				if (fcn) {
					fcn (uniq_row, row, nth);
				}
				r_list_delete (rows, iter);
				break;
			}
		}
	}
}

R_API int r_table_column_nth(RTable *t, const char *name) {
	RListIter *iter;
	RTableColumn *col;
	int n = 0;
	r_list_foreach (t->cols, iter, col) {
		if (!strcmp (name, col->name)) {
			return n;
		}
		n++;
	}
	return -1;
}

static int __resolveOperation(const char *op) {
	if (!strcmp (op, "gt")) {
		return '>';
	}
	if (!strcmp (op, "lt")) {
		return '<';
	}
	if (!strcmp (op, "eq")) {
		return '=';
	}
	if (!strcmp (op, "ne")) {
		return '!';
	}
	return -1;
}

static void __table_column_free(void *_col) {
	RTableColumn *col = (RTableColumn*)_col;
	free (col);
}

R_API void r_table_columns(RTable *t, RList *col_names) {
	// 1 bool per OLD column to indicate whether it should be freed (masked out)
	bool *free_cols = malloc (sizeof (bool) * r_list_length (t->cols));
	if (!free_cols) {
		return;
	}
	size_t i;
	for (i = 0; i < r_list_length (t->cols); i++) {
		free_cols[i] = true;
	}

	// 1 value per NEW column to indicate from which OLD column to take the info from and whether to dup it
	struct col_source {
		int oldcol;
		bool dup;
	} *col_sources = calloc (r_list_length (col_names), sizeof (struct col_source));
	if (!col_sources) {
		free (free_cols);
		return;
	}

	// First create the plan which new columns to take from which old, which ones to dup or free.
	RListIter *it;
	const char *col_name;
	size_t new_count = 0;
	r_list_foreach (col_names, it, col_name) {
		int fc = r_table_column_nth (t, col_name);
		if (fc < 0) {
			continue;
		}
		col_sources[new_count].oldcol = fc;
		col_sources[new_count].dup = !free_cols[fc]; // if we already used the same old column for another new column before, we must dup it for all following!
		free_cols[fc] = false;
		new_count++;
	}

	RTableRow *row;
	r_list_foreach (t->rows, it, row) {
		RList *old_items = row->items;
		RList *new_items = r_list_newf (free);
		for (i = 0; i < new_count; i++) {
			char *item = r_list_get_n (old_items, col_sources[i].oldcol);
			if (!item) {
				continue;
			}
			if (col_sources[i].dup) {
				item = strdup (item);
			}
			r_list_append (new_items, item);
		}
		row->items = new_items;

		// Free dropped items
		char *item;
		i = 0;
		RListIter *fit;
		r_list_foreach (old_items, fit, item) {
			if (free_cols[i]) {
				free (item);
			}
			i++;
		}
		old_items->free = NULL;
		r_list_free (old_items);
	}

	RList *old_cols = t->cols;
	RList *new_cols = r_list_newf (r_table_column_free);
	for (i = 0; i < new_count; i++) {
		RTableColumn *col = r_list_get_n (old_cols, col_sources[i].oldcol);
		if (!col) {
			continue;
		}
		if (col_sources[i].dup) {
			col = r_table_column_clone (col);
		}
		r_list_append (new_cols, col);
	}
	t->cols = new_cols;

	// Free dropped columns
	RTableColumn *col;
	i = 0;
	r_list_foreach (old_cols, it, col) {
		if (free_cols[i]) {
			r_table_column_free (col);
		}
		i++;
	}
	old_cols->free = NULL;
	r_list_free (old_cols);

	free (col_sources);
	free (free_cols);
}

R_API void r_table_filter_columns(RTable *t, RList *list) {
	const char *col;
	RListIter *iter;
	RList *cols = t->cols;
	t->cols = r_list_newf (__table_column_free);
	r_list_foreach (list, iter, col) {
		int ncol = r_table_column_nth (t, col);
		if (ncol != -1) {
			RTableColumn *c = r_list_get_n (cols, ncol);
			if (c) {
				r_table_add_column (t, c->type, col, 0);
			}
		}
	}
}

R_API const char *r_table_help(void) {
	return \
		"RTableQuery> comma separated. 'c' stands for column name.\n"
		" c/sort/inc     sort rows by given colname\n"
		" c/sortlen/inc  sort rows by strlen()\n"
		" c/cols/c1/c2   only show selected columns\n"
		" c/gt/0x800     grep rows matching col0 > 0x800\n"
		" c/lt/0x800     grep rows matching col0 < 0x800\n"
		" c/eq/0x800     grep rows matching col0 == 0x800\n"
		" c/ne/0x800     grep rows matching col0 != 0x800\n"
		" */uniq         get the first row of each that col0 is unique\n"
		" */head/10      same as | head -n 10\n"
		" */tail/10      same as | tail -n 10\n"
		" */page/1/10    show the first 10 rows (/page/2/10 will show the 2nd)\n"
		" c/str/warn     grep rows matching col(name).str(warn)\n"
		" c/strlen/3     grep rows matching strlen(col) == X\n"
		" c/minlen/3     grep rows matching strlen(col) > X\n"
		" c/maxlen/3     grep rows matching strlen(col) < X\n"
		" c/sum          sum all the values of given column\n"
		" :r2            .tostring() == .tor2()         # supports import/export\n"
		" :csv           .tostring() == .tocsv()        # supports import/export\n"
		" :fancy         .tostring() == .tofancystring()\n"
		" :json          .tostring() == .tojson()\n"
		" :simple        simple table output without lines\n"
		" :sql           .tostring() == .tosql() # export table contents in SQL statements\n"
		" :quiet         do not print column names header\n";
}

static bool __table_special(RTable *t, const char *columnName) {
	if (*columnName != ':') {
		return false;
	}
	if (!strcmp (columnName, ":quiet")) {
		t->showHeader = true;
	} else if (!strcmp (columnName, ":fancy")) {
		t->showFancy = true;
	} else if (!strcmp (columnName, ":sql")) {
		t->showSQL = true;
	} else if (!strcmp (columnName, ":simple")) {
		t->showFancy = false;
	} else if (!strcmp (columnName, ":r2")) {
		t->showR2 = true;
	} else if (!strcmp (columnName, ":csv")) {
		t->showCSV = true;
	} else if (!strcmp (columnName, ":json")) {
		t->showJSON = true;
	} else {
		return false;
	}
	return true;
}

R_API bool r_table_query(RTable *t, const char *q) {
	r_return_val_if_fail (t, false);
	q = r_str_trim_head_ro (q);
	// TODO support parenthesis and (or)||
	// split by "&&" (or comma) -> run .filter on each
	// addr/gt/200,addr/lt/400,addr/sort/dec,offset/sort/inc
	if (!q || !*q) {
		__table_adjust (t);
		return true;
	}
	if (*q == '?') {
		const char *th = r_table_help ();
		eprintf ("%s\n", th);
		return false;
	}

	RListIter *iter;
	char *qq = strdup (q);
	RList *queries = r_str_split_list (qq, ",",  0);
	char *query;
	r_list_foreach (queries, iter, query) {
		RList *q = r_str_split_list (query, "/", 2);
		const char *columnName = r_list_get_n (q, 0);
		const char *operation = r_list_get_n (q, 1);
		const char *operand = r_list_get_n (q, 2);
		if (__table_special (t, columnName)) {
			continue;
		}
		int col = r_table_column_nth (t, columnName);
		if (col == -1) {
			if (columnName == NULL && strcmp (operation, "uniq")) {
				eprintf ("Invalid column name (%s) for (%s)\n", columnName, query);
			} else if (columnName) {
				if (*columnName == '[') {
					col = atoi (columnName + 1);
				}
			}
		}
		if (!operation) {
			break;
		}
		if (!strcmp (operation, "sort")) {
			r_table_sort (t, col, operand && !strcmp (operand, "dec"));
		} else if (!strcmp (operation, "uniq")) {
			r_table_group (t, col, NULL);
		} else if (!strcmp (operation, "sortlen")) {
			r_table_sortlen (t, col, operand && !strcmp (operand, "dec"));
		} else if (!strcmp (operation, "join")) {
			// TODO: implement join operation with other command's tables
		} else if (!strcmp (operation, "sum")) {
			char *op = strdup (r_str_get (operand));
			RList *list = r_str_split_list (op, "/", 0);
			r_list_prepend (list, strdup (columnName));
			r_table_columns (t, list); // select/reorder columns
			r_list_free (list);
			r_table_filter (t, 0, '+', op);
			free (op);
		} else if (!strcmp (operation, "strlen")) {
			if (operand) {
				r_table_filter (t, col, 's', operand);
			}
		} else if (!strcmp (operation, "minlen")) {
			if (operand) {
				r_table_filter (t, col, 'l', operand);
			}
		} else if (!strcmp (operation, "maxlen")) {
			if (operand) {
				r_table_filter (t, col, 'L', operand);
			}
		} else if (!strcmp (operation, "page")) {
			if (operand) {
				r_table_filter (t, col, 'p', operand);
			}
		} else if (!strcmp (operation, "tail")) {
			if (operand) {
				r_table_filter (t, col, 't', operand);
			}
		} else if (!strcmp (operation, "head")) {
			if (operand) {
				r_table_filter (t, col, 'h', operand);
			}
		} else if (!strcmp (operation, "str")) {
			if (operand) {
				r_table_filter (t, col, '~', operand);
			}
		} else if (!strcmp (operation, "cols")) {
			char *op = strdup (r_str_get (operand));
			RList *list = r_str_split_list (op, "/", 0);
			r_list_prepend (list, strdup (columnName));
			r_table_columns (t, list); // select/reorder columns
			r_list_free (list);
			free (op);
		// TODO	r_table_filter_columns (t, q);
		} else {
			int op = __resolveOperation (operation);
			if (op == -1) {
				eprintf ("Invalid operation (%s)\n", operation);
			} else {
				r_table_filter (t, col, op, operand);
			}
		}
		r_list_free (q);
	}
	r_list_free (queries);
	free (qq);
	__table_adjust (t);
	return true;
}

R_API bool r_table_align(RTable *t, int nth, int align) {
	RTableColumn *col = r_list_get_n (t->cols, nth);
	if (col) {
		col->align = align;
		return true;
	}
	return false;
}

R_API void r_table_hide_header (RTable *t) {
	t->showHeader = false;
}

R_API void r_table_visual_list(RTable *table, RList *list, ut64 seek, ut64 len, int width, bool va) {
	ut64 mul, min = -1, max = -1;
	RListIter *iter;
	RListInfo *info;
	RCons *cons = (RCons *) table->cons;
	table->showHeader = false;
	const char *h_line = cons->use_utf8 ? RUNE_LONG_LINE_HORIZ : "-";
	const char *block = cons->use_utf8 ? UTF_BLOCK : "#";
	int j, i;
	width -= 80;
	if (width < 1) {
		width = 30;
	}

	r_table_set_columnsf (table, "sssssss", "No.", "offset", "blocks", "offset", "perms", "extra", "name");
	r_list_foreach (list, iter, info) {
		if (min == -1 || info->pitv.addr < min) {
			min = info->pitv.addr;
		}
		if (max == -1 || info->pitv.addr + info->pitv.size > max) {
			max = info->pitv.addr + info->pitv.size;
		}
	}
	mul = (max - min) / width;
	if (min != -1 && mul > 0) {
		i = 0;
		r_list_foreach (list, iter, info) {
			RStrBuf *buf = r_strbuf_new ("");
			for (j = 0; j < width; j++) {
				ut64 pos = min + j * mul;
				ut64 npos = min + (j + 1) * mul;
				const char *arg = (info->pitv.addr < npos && (info->pitv.addr + info->pitv.size) > pos)
					? block: h_line;
				r_strbuf_append (buf, arg);
			}
			char *b = r_strbuf_drain (buf);
			if (va) {
				r_table_add_rowf (table, "sssssss",
					sdb_fmt ("%d%c", i, r_itv_contain (info->vitv, seek) ? '*' : ' '),
					sdb_fmt ("0x%"PFMT64x, info->vitv.addr),
					b,
					sdb_fmt ("0x%"PFMT64x, r_itv_end (info->vitv)),
					(info->perm != -1)? r_str_rwx_i (info->perm) : "",
					(info->extra)?info->extra : "",
					(info->name)?info->name :"");
			} else {
				r_table_add_rowf (table, "sssssss", sdb_fmt ("%d%c", i, r_itv_contain (info->pitv, seek) ? '*' : ' '),
					sdb_fmt ("0x%"PFMT64x, info->pitv.addr), b,
					sdb_fmt ("0x%"PFMT64x, r_itv_end (info->pitv)),
					(info->perm != -1)? r_str_rwx_i (info->perm) : "",(info->extra)?info->extra : "", (info->name)?info->name :"");
			}
			free (b);
			i++;
		}
		RStrBuf *buf = r_strbuf_new ("");
		/* current seek */
		if (i > 0 && len != 0) {
			if (seek == UT64_MAX) {
				seek = 0;
			}
			for (j = 0; j < width; j++) {
				r_strbuf_append (buf,((j * mul) + min >= seek &&
						     (j * mul) + min <= seek + len) ? "^" : h_line);
			}
			r_table_add_rowf (table, "sssssss", "=>", sdb_fmt ("0x%08"PFMT64x, seek),
					r_strbuf_drain (buf), sdb_fmt ("0x%08"PFMT64x, seek + len), "", "", "");
		} else {
			r_strbuf_free (buf);
		}
	}
}

R_API RTable *r_table_clone(const RTable *t) {
	RTable *o = r_table_new (t->name);
	RTableColumn *col;
	RTableRow *row;
	RListIter *iter;
	r_list_foreach (t->cols, iter, col) {
		r_list_append (o->rows, r_table_column_clone (col));
	}
	r_list_foreach (t->rows, iter, row) {
		r_list_append (o->rows, r_table_row_clone (row));
	}
	return o;
}

#if 0
// TODO: to be implemented

R_API RTable *r_table_push(RTable *t) {
	// TODO: implement
	return NULL;
}

R_API RTable *r_table_pop(RTable *t) {
	// TODO: implement
	return NULL;
}

R_API void r_table_fromjson(RTable *t, const char *csv) {
	//  TODO
}

R_API void r_table_fromcsv(RTable *t, const char *csv) {
	//  TODO
}

R_API char *r_table_tohtml(RTable *t) {
	// TODO
	return NULL;
}

R_API void r_table_transpose(RTable *t) {
	// When the music stops rows will be cols and cols... rows!
}

R_API void r_table_format(RTable *t, int nth, RTableColumnType *type) {
	// change the format of a specific column
	// change imm base, decimal precission, ...
}

// to compute sum result of all the elements in a column
R_API ut64 r_table_reduce(RTable *t, int nth) {
	// When the music stops rows will be cols and cols... rows!
	return 0;
}
#endif
