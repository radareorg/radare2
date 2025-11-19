/* radare - LGPL - Copyright 2019-2025 - pancake */

#include <r_util/r_table.h>
#include <r_core.h>
#include <r_cons.h>

#define READ_SHOW_FLAG(t, bitflag) (((t)->showMode & bitflag) != 0)
#define WRITE_SHOW_FLAG(t, bitflag, condition) \
	if ((condition) == true) { \
		(t)->showMode |= bitflag; \
	} else { \
		(t)->showMode &= ~bitflag; \
	}

#define SHOULD_SHOW_HEADER(t) READ_SHOW_FLAG(t, SHOW_HEADER)
#define SHOULD_SHOW_FANCY(t) READ_SHOW_FLAG(t, SHOW_FANCY)
#define SHOULD_SHOW_SQL(t) READ_SHOW_FLAG(t, SHOW_SQL)
#define SHOULD_SHOW_JSON(t) READ_SHOW_FLAG(t, SHOW_JSON)
#define SHOULD_SHOW_CSV(t) READ_SHOW_FLAG(t, SHOW_CSV)
#define SHOULD_SHOW_TSV(t) READ_SHOW_FLAG(t, SHOW_TSV)
#define SHOULD_SHOW_HTML(t) READ_SHOW_FLAG(t, SHOW_HTML)
#define SHOULD_SHOW_R2(t) READ_SHOW_FLAG(t, SHOW_R2)
#define SHOULD_SHOW_SUM(t) READ_SHOW_FLAG(t, SHOW_SUM)

#define SET_SHOW_HEADER(t, condition) WRITE_SHOW_FLAG(t, SHOW_HEADER, condition)
#define SET_SHOW_FANCY(t, condition) WRITE_SHOW_FLAG(t, SHOW_FANCY, condition)
#define SET_SHOW_SQL(t, condition) WRITE_SHOW_FLAG(t, SHOW_SQL, condition)
#define SET_SHOW_JSON(t, condition) WRITE_SHOW_FLAG(t, SHOW_JSON, condition)
#define SET_SHOW_CSV(t, condition) WRITE_SHOW_FLAG(t, SHOW_CSV, condition)
#define SET_SHOW_TSV(t, condition) WRITE_SHOW_FLAG(t, SHOW_TSV, condition)
#define SET_SHOW_HTML(t, condition) WRITE_SHOW_FLAG(t, SHOW_HTML, condition)
#define SET_SHOW_R2(t, condition) WRITE_SHOW_FLAG(t, SHOW_R2, condition)
#define SET_SHOW_SUM(t, condition) WRITE_SHOW_FLAG(t, SHOW_SUM, condition)

// cant do that without globals because RList doesnt have void *user :(
// R2_590 wrap RList in a struct that also has a void* user field
static R_TH_LOCAL int Gnth = 0;
static R_TH_LOCAL RListComparator Gcmp = NULL;


R_API RListInfo *r_listinfo_new(const char *name, RInterval pitv, RInterval vitv, int perm, const char *extra) {
	RListInfo *info = R_NEW (RListInfo);
	info->name = name ? strdup (name) : NULL;
	info->pitv = pitv;
	info->vitv = vitv;
	info->perm = perm;
	info->extra = extra ? strdup (extra) : NULL;
	return info;
}

static void r_listinfo_fini(RListInfo *info) {
	free (info->name);
	free (info->extra);
}

R_API void r_listinfo_free(RListInfo *info) {
	if (info) {
		r_listinfo_fini (info);
		free (info);
	}
}
static int sortString(const void *a, const void *b) {
	return strcmp (a, b);
}

static int sortNumber(const void *a, const void *b) {
	return r_num_get (NULL, a) - r_num_get (NULL, b);
}

static int sortFloat(const void *a, const void *b) {
	double fa = strtod ((const char *) a, NULL);
	double fb = strtod ((const char *) b, NULL);
	return (int)((fa * 100) - (fb * 100));
}

// maybe just index by name instead of exposing those symbols as global
static RTableColumnType r_table_type_string = { "string", sortString };
static RTableColumnType r_table_type_number = { "number", sortNumber };
static RTableColumnType r_table_type_bool = { "bool", sortNumber };
static RTableColumnType r_table_type_float = { "float", sortFloat };

R_API RTableColumnType *r_table_type(const char *name) {
	if (r_str_startswith (name, "bool")) {
		return &r_table_type_bool;
	}
	if (!strcmp (name, "string")) {
		return &r_table_type_string;
	}
	if (!strcmp (name, "number")) {
		return &r_table_type_number;
	}
	if (!strcmp (name, "float")) {
		return &r_table_type_float;
	}
	return NULL;
}

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
				if (t->maxColumnWidth > 0) {
					c->width = R_MIN (t->maxColumnWidth, c->width);
				}
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
	if (_col) {
		RTableColumn *col = _col;
		free (col->name);
		free (col);
	}
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
	R_RETURN_VAL_IF_FAIL (col, NULL);
	RTableColumn *c = R_NEW0 (RTableColumn);
	memcpy (c, col, sizeof (*c));
	c->name = strdup (c->name);
	return c;
}

R_API RTable *r_table_new(const char *name) {
	RTable *t = R_NEW0 (RTable);
	t->name = strdup (name);
	t->cols = r_list_newf (r_table_column_free);
	t->rows = r_list_newf (r_table_row_free);
	t->maxColumnWidth = 32;
	t->wrapColumns = false;
	SET_SHOW_HEADER (t, true);
	SET_SHOW_SUM (t, false);
	return t;
}

R_API void r_table_set_width(RTable *t, int maxColumnWidth, bool wrap) {
	R_RETURN_IF_FAIL (t);
	t->maxColumnWidth = maxColumnWidth;
	t->wrapColumns = wrap;
}

R_API void r_table_free(RTable *t) {
	if (R_LIKELY (t)) {
		r_list_free (t->cols);
		r_list_free (t->rows);
		free (t->name);
		free (t);
	}
}

R_API void r_table_add_column(RTable *t, RTableColumnType *type, const char *name, int maxWidth) {
	RTableColumn *c = R_NEW0 (RTableColumn);
	c->name = strdup (name);
	c->maxWidth = maxWidth;
	c->type = type;
	int itemLength = r_str_len_utf8_ansi (name) + 1;
	c->width = itemLength;
	r_list_append (t->cols, c);
	c->total = -1;
}

R_API RTableRow *r_table_row_new(RList *items) {
	R_RETURN_VAL_IF_FAIL (items, NULL);
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

static void wrap_items(RTable *t, RList *items) {
	if (t->wrapColumns && t->maxColumnWidth > 0) {
		char *item;
		RListIter *iter;
		r_list_foreach (items, iter, item) {
			int itemLength = r_str_len_utf8_ansi (item);
			if (itemLength + 3 > t->maxColumnWidth) {
				char *p = (char *)r_str_ansi_chrn (item, t->maxColumnWidth - 3);
				strcpy (p, "..");
			}
		}
	}
}

R_API void r_table_add_row_list(RTable *t, RList *items) {
	R_RETURN_IF_FAIL (t && items);
	RTableRow *row = r_table_row_new (items);
	wrap_items (t, items);
	r_list_append (t->rows, row);
	// throw warning if not enough columns defined in header
	t->totalCols = R_MAX (t->totalCols, r_list_length (items));
}

R_API void r_table_set_columnsf(RTable *t, const char *fmt, ...) {
	R_RETURN_IF_FAIL (t && fmt);
	va_list ap;
	va_start (ap, fmt);
	RTableColumnType *typeString = r_table_type ("string");
	RTableColumnType *typeNumber = r_table_type ("number");
	RTableColumnType *typeFloat = r_table_type ("float");
	RTableColumnType *typeBool = r_table_type ("bool");
	const char *name;
	const char *f = fmt;
	for (; *f; f++) {
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
		case 'f':
			r_table_add_column (t, typeFloat, name, 0);
			break;
		case 'i':
		case 'd':
		case 'n':
		case 'x':
		case 'X':
			r_table_add_column (t, typeNumber, name, 0);
			break;
		default:
			R_LOG_ERROR ("Invalid format string char '%c', use 's' or 'n'", *f);
			break;
		}
	}
	va_end (ap);
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
		case 'f':
			r_list_append (list, r_str_newf ("%.03lf", va_arg (ap, double)));
			break;
		case 'b':
			r_list_append (list, strdup (r_str_bool (va_arg (ap, int))));
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
			R_LOG_ERROR ("Invalid format string char '%c', use 's' or 'n'", *f);
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
	wrap_items (t, items);
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
		}
		break;
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
			if (r_str_startswith (col->type->name, "number") && r_str_isnumber (item)) {
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

	if (SHOULD_SHOW_SUM (t)) {
		char tmp[SDB_NUM_BUFSZ];
		__computeTotal (t);
		r_strbuf_appendf (sb, "%s%s%s\n", l_intersect, h_line_str, r_intersect);
		r_list_foreach (t->cols, iter, col) {
			char *num = col->total == -1 ? "" : sdb_itoa (col->total, 10, tmp, sizeof (tmp));
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
		int len = r_str_len_utf8_ansi (str);
		int padlen = (len < col->width)? col->width - len: 0;
		switch (col->align) {
		case R_TABLE_ALIGN_LEFT:
			pad = r_str_repeat (" ", col->width - len);
			r_strbuf_append (sb, str);
			r_strbuf_append (sb, pad);
			free (pad);
			break;
		case R_TABLE_ALIGN_RIGHT:
			pad = r_str_repeat (" ", padlen);
			r_strbuf_append (sb, pad);
			r_strbuf_append (sb, str);
			r_strbuf_append (sb, " ");
			free (pad);
			break;
		case R_TABLE_ALIGN_CENTER:
			{
				int pad = (col->width - len) / 2;
				int left = col->width - pad - len;
				r_strbuf_appendf (sb, "%-*s", pad, " ");
				r_strbuf_appendf (sb, "%s ", str);
				r_strbuf_appendf (sb, "%-*s", left, " ");
				break;
			}
		}
	}
	return r_strbuf_length (sb) - ll;
}

R_API char *r_table_tostring(RTable *t) {
	R_RETURN_VAL_IF_FAIL (t, NULL);
	if (SHOULD_SHOW_R2 (t)) {
		return r_table_tor2cmds (t);
	}
	if (SHOULD_SHOW_SQL (t)) {
		return r_table_tosql (t);
	}
	if (SHOULD_SHOW_TSV (t)) {
		return r_table_totsv (t);
	}
	if (SHOULD_SHOW_CSV (t)) {
		return r_table_tocsv (t);
	}
	if (SHOULD_SHOW_HTML (t)) {
		return r_table_tohtml (t);
	}
	if (SHOULD_SHOW_JSON (t)) {
		char *s = r_table_tojson (t);
		char *q = r_str_newf ("%s\n", s);
		free (s);
		return q;
	}
	if (SHOULD_SHOW_FANCY (t)) {
		return r_table_tofancystring (t);
	}
	return r_table_tosimplestring (t);
}

static bool nopad_trailing(RListIter *iter) {
	while (iter->n) {
		iter = iter->n;
		char *next_item = iter->data;
		if (R_STR_ISNOTEMPTY (next_item)) {
			return false;
		}
	}
	return true;
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
	if (SHOULD_SHOW_HEADER (t)) {
		r_list_foreach (t->cols, iter, col) {
			bool nopad = !iter->n;
			int ll = __strbuf_append_col_aligned (sb, col, col->name, nopad);
			maxlen = R_MAX (maxlen, ll);
		}
		int len = r_str_len_utf8_ansi (r_strbuf_get (sb));
		char *l = r_str_repeat (h_line, R_MAX (maxlen, len));
		if (R_LIKELY (l)) {
			r_strbuf_appendf (sb, "\n%s\n", l);
			free (l);
		}
	}
	r_list_foreach (t->rows, iter, row) {
		char *item;
		int c = 0;
		r_list_foreach (row->items, iter2, item) {
			bool nopad = nopad_trailing (iter2);
			RTableColumn *col = r_list_get_n (t->cols, c);
			if (R_LIKELY (col)) {
				(void)__strbuf_append_col_aligned (sb, col, item, nopad);
			}
			c++;
		}
		r_strbuf_append (sb, "\n");
	}
	if (SHOULD_SHOW_SUM (t)) {
		char tmp[SDB_NUM_BUFSZ];
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
			char *num = col->total == -1 ? "" : sdb_itoa (col->total, 10, tmp, sizeof (tmp));
			(void)__strbuf_append_col_aligned (sb, col, num, nopad);
		}
	}
	return r_strbuf_drain (sb);
}

R_API char *r_table_tor2cmds(RTable *t) {
	RStrBuf *sb = r_strbuf_new ("");
	RTableRow *row;
	RTableColumn *col;
	RListIter *iter, *iter2;

	r_strbuf_append (sb, ",h ");
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
		r_strbuf_append (sb, ",r");
		r_list_foreach (row->items, iter2, item) {
			RTableColumn *col = r_list_get_n (t->cols, c);
			if (col) {
				r_strbuf_append (sb, " ");
				r_strbuf_append (sb, item);
			}
			c++;
		}
		r_strbuf_append (sb, "\n");
	}
	return r_strbuf_drain (sb);
}

R_API char *r_table_tosql(RTable *t) {
	R_RETURN_VAL_IF_FAIL (t, NULL);
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
	r_strbuf_append (sb, ");\n");

	r_list_foreach (t->rows, iter, row) {
		const char *item;
		int c = 0;
		r_strbuf_appendf (sb, "INSERT INTO %s (", table_name);
		r_list_foreach (t->cols, iter2, col) {
			char *s = r_str_escape_sql (col->name);
			r_strbuf_append (sb, s);
			if (iter2->n) {
				r_strbuf_append (sb, ", ");
			}
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

static char *tocsv(RTable *t, const char *sep) {
	RStrBuf *sb = r_strbuf_new ("");
	RTableRow *row;
	RTableColumn *col;
	RListIter *iter, *iter2;
	if (SHOULD_SHOW_HEADER (t)) {
		const char *comma = "";
		r_list_foreach (t->cols, iter, col) {
			if (strchr (col->name, *sep)) {
				// TODO. escaped string?
				r_strbuf_appendf (sb, "%s\"%s\"", comma, col->name);
			} else {
				r_strbuf_appendf (sb, "%s%s", comma, col->name);
			}
			comma = sep;
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
				if (strchr (col->name, *sep)) {
					r_strbuf_appendf (sb, "%s\"%s\"", comma, col->name);
				} else {
					r_strbuf_appendf (sb, "%s%s", comma, item);
				}
				comma = sep;
			}
			c++;
		}
		r_strbuf_append (sb, "\n");
	}
	return r_strbuf_drain (sb);
}

R_API char *r_table_totsv(RTable *t) {
	return tocsv (t, "\t");
}

R_API char *r_table_tocsv(RTable *t) {
	return tocsv (t, ",");
}

R_API char *r_table_tohtml(RTable *t) {
	PJ *pj = pj_new ();
	RTableRow *row;
	RListIter *iter, *iter2;
	pj_a (pj);
	RStrBuf *sb = r_strbuf_new ("");
	r_strbuf_append (sb, "<table>\n");
	// TODO: add th
	r_list_foreach (t->rows, iter, row) {
		char *item;
		r_strbuf_append (sb, "  <tr>\n");
		r_list_foreach (row->items, iter2, item) {
			r_strbuf_appendf (sb, "    <td>%s</td>\n", item);
		}
		r_strbuf_append (sb, "  </tr>\n");
	}
	r_strbuf_append (sb, "</table>\n");
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
	R_RETURN_IF_FAIL (t && un);
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
			uv = ((ut64)page_items) * page;
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
		case 'S':
			nrow++;
			match = (nrow > uv);
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
				match = (nn && un && !strcmp (nn, un));
			} else {
				match = (nv == uv);
			}
			break;
		case '!':
			if (nv == 0) {
				match = (!nn || !un || strcmp (nn, un));
			} else {
				match = (nv != uv);
			}
			break;
		case '$':
			match = !nn || !un || strstr (nn, un) == NULL;
			break;
		case '~':
			match = nn&&un&&strstr (nn, un);
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
			t->rows->sorted = false; // force sorting
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
	size_t old_col_count = r_list_length (t->cols);
	bool *used_cols = calloc (old_col_count, sizeof (bool));
	if (!used_cols) {
		return;
	}

	size_t max_new = r_list_length (col_names);
	struct col_source {
		int oldcol;
		bool dup;
	} *plan = calloc (max_new, sizeof (struct col_source));
	if (!plan) {
		free (used_cols);
		return;
	}

	RListIter *iter;
	const char *col_name;
	size_t plan_size = 0;
	size_t plan_idx;
	size_t idx;
	size_t col_idx;
	r_list_foreach (col_names, iter, col_name) {
		int oldcol = r_table_column_nth (t, col_name);
		if (oldcol < 0) {
			continue;
		}
		plan[plan_size].oldcol = oldcol;
		plan[plan_size].dup = used_cols[oldcol];
		used_cols[oldcol] = true;
		plan_size++;
	}

	RTableRow *row;
	r_list_foreach (t->rows, iter, row) {
		RList *old_items = row->items;
		RList *new_items = r_list_newf (free);
		for (plan_idx = 0; plan_idx < plan_size; plan_idx++) {
			char *item = r_list_get_n (old_items, plan[plan_idx].oldcol);
			if (!item) {
				continue;
			}
			if (plan[plan_idx].dup) {
				item = strdup (item);
			}
			r_list_append (new_items, item);
		}
		row->items = new_items;

		char *item;
		idx = 0;
		RListIter *fit;
		r_list_foreach (old_items, fit, item) {
			if (!used_cols[idx]) {
				free (item);
			}
			idx++;
		}
		old_items->free = NULL;
		r_list_free (old_items);
	}

	RList *old_cols = t->cols;
	RList *new_cols = r_list_newf (r_table_column_free);
	for (plan_idx = 0; plan_idx < plan_size; plan_idx++) {
		RTableColumn *col = r_list_get_n (old_cols, plan[plan_idx].oldcol);
		if (!col) {
			continue;
		}
		if (plan[plan_idx].dup) {
			col = r_table_column_clone (col);
		}
		r_list_append (new_cols, col);
	}
	t->cols = new_cols;

	RTableColumn *col;
	col_idx = 0;
	r_list_foreach (old_cols, iter, col) {
		if (!used_cols[col_idx]) {
			r_table_column_free (col);
		}
		col_idx++;
	}
	old_cols->free = NULL;
	r_list_free (old_cols);

	free (plan);
	free (used_cols);
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
		" */skip/10      skip the first 10 rows\n"
		" */tail/10      same as | tail -n 10\n"
		" */page/1/10    show the first 10 rows (/page/2/10 will show the 2nd)\n"
		" c/str/warn     grep rows matching col(name).str(warn)\n"
		" c/nostr/warn   grep rows not matching col(name).str(warn)\n"
		" c/strlen/3     grep rows matching strlen(col) == X\n"
		" c/minlen/3     grep rows matching strlen(col) > X\n"
		" c/maxlen/3     grep rows matching strlen(col) < X\n"
		" c/sum          sum all the values of given column\n"
		" :r2            .tostring() == .tor2()         # supports import/export\n"
		" :csv           .tostring() == .tocsv()        # supports import/export\n"
		" :tsv           .tostring() == .totsv()        # supports import/export\n"
		" :fancy         .tostring() == .tofancystring()\n"
		" :html          .tostring() == .tohtml()\n"
		" :json          .tostring() == .tojson()\n"
		" :simple        simple table output without lines\n"
		" :sql           .tostring() == .tosql() # export table contents in SQL statements\n"
		" :header        show column headers (see :quiet and :noheader)\n"
		" :quiet         do not print column names header\n";
}

static bool __table_special(RTable *t, const char *columnName) {
	if (*columnName != ':') {
		return false;
	}
	if (!strcmp (columnName, ":quiet")) {
		SET_SHOW_HEADER (t, false);
		SET_SHOW_FANCY (t, false);
	} else if (r_str_startswith (columnName, ":nohead")) {
		SET_SHOW_HEADER (t, false);
	} else if (r_str_startswith (columnName, ":head")) {
		SET_SHOW_HEADER (t, true);
	} else if (!strcmp (columnName, ":fancy")) {
		SET_SHOW_HEADER (t, true);
		SET_SHOW_FANCY (t, true);
	} else if (!strcmp (columnName, ":sql")) {
		SET_SHOW_SQL (t, true);
		SET_SHOW_HEADER (t, false);
	} else if (!strcmp (columnName, ":simple")) {
		SET_SHOW_HEADER (t, false);
		SET_SHOW_FANCY (t, true);
	} else if (!strcmp (columnName, ":r2")) {
		SET_SHOW_R2 (t, true);
	} else if (!strcmp (columnName, ":csv")) {
		SET_SHOW_CSV (t, true);
	} else if (!strcmp (columnName, ":html")) {
		SET_SHOW_HTML (t, true);
	} else if (!strcmp (columnName, ":tsv")) {
		SET_SHOW_TSV (t, true);
	} else if (!strcmp (columnName, ":json")) {
		SET_SHOW_JSON (t, true);
	} else {
		return false;
	}
	return true;
}

R_API bool r_table_query(RTable *t, const char *q) {
	R_RETURN_VAL_IF_FAIL (t, false);
	q = r_str_trim_head_ro (q);
	// TODO support parenthesis and (or)||
	// split by "&&" (or comma) -> run .filter on each
	// addr/gt/200,addr/lt/400,addr/sort/dec,offset/sort/inc
	if (!q || !*q) {
		__table_adjust (t);
		return true;
	}
	if (*q == '?' || r_str_endswith (q, ":help")) {
		const char *th = r_table_help ();
		eprintf ("%s\n", th);
		return false;
	}

	RListIter *iter;
	char *qq = strdup (q);
	RList *queries = r_str_split_list (qq, ",",  0);
	char *query;
	r_list_foreach (queries, iter, query) {
		RList *q = r_str_split_list (query, "/", 3);
		const char *columnName = r_list_get_n (q, 0);
		const char *operation = r_list_get_n (q, 1);
		const char *operand = r_list_get_n (q, 2);
		if (__table_special (t, columnName)) {
			r_list_free (q);
			continue;
		}
		int col = r_table_column_nth (t, columnName);
		if (col == -1) {
			if (columnName == NULL && strcmp (operation, "uniq")) {
				R_LOG_ERROR ("Invalid column name (%s) for (%s)", columnName, query);
			} else if (columnName) {
				if (*columnName == '[') {
					col = atoi (columnName + 1);
				}
			}
		}
		if (!operation) {
			r_list_free (q);
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
		} else if (!strcmp (operation, "skip")) {
			if (operand) {
				r_table_filter (t, col, 'S', operand);
			}
		} else if (!strcmp (operation, "head")) {
			if (operand) {
				r_table_filter (t, col, 'h', operand);
			}
		} else if (!strcmp (operation, "nostr")) {
			if (operand) {
				r_table_filter (t, col, '$', operand);
			}
		} else if (!strcmp (operation, "str")) {
			if (operand) {
				r_table_filter (t, col, '~', operand);
			}
		} else if (!strcmp (operation, "cols")) {
			char *op = strdup (r_str_get (operand));
			RList *list = r_str_split_list (op, "/", 0);
			r_list_prepend (list, (char *)columnName);
			r_table_columns (t, list); // select/reorder columns
			r_list_free (list);
			free (op);
		// TODO	r_table_filter_columns (t, q);
		} else {
			int op = __resolveOperation (operation);
			if (op == -1) {
				R_LOG_ERROR ("Invalid table operation (%s)", operation);
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

R_API void r_table_hide_header(RTable *t) {
	SET_SHOW_HEADER (t, false);
}

typedef struct r_table_visual_state_t TableVisualState;
typedef int (*RenderTableRows)(RTable *table, TableVisualState *state);

typedef struct r_table_visual_state_t {
	ut64 min;
	ut64 mul;
	int width;
	ut64 seek;
	ut64 len;
	bool va;
	RenderTableRows render_fn;
	void *user;
} TableVisualState;

static void r_table_visual_row(RTable *table, const RListInfo *info, int i, TableVisualState *state) {
	RCons *cons = (RCons *) table->cons;
	const ut64 min = state->min;
	const ut64 mul = state->mul;
	const ut64 seek = state->seek;
	const int width = state->width;
	const bool va = state->va;
	const char *block = cons->use_utf8 ? R_UTF8_BLOCK : "#";
	const char *h_line = cons->use_utf8 ? RUNE_LONG_LINE_HORIZ : "-";
	RStrBuf *buf = r_strbuf_new ("");
	int j;
	for (j = 0; j < width; j++) {
		ut64 pos = min + j * mul;
		ut64 npos = min + (j + 1) * mul;
		const char *arg = (info->pitv.addr < npos && (info->pitv.addr + info->pitv.size) > pos)
			? block: h_line;
		r_strbuf_append (buf, arg);
	}
	r_strf_var (a0, 64, "%d%c", i, (va
		? r_itv_contain (info->vitv, seek)
		: r_itv_contain (info->pitv, seek))? '*' : ' ');
	r_strf_var (a1, 64, "0x%08"PFMT64x, va
		? info->vitv.addr: info->pitv.addr);
	r_strf_var (a2, 64, "0x%08"PFMT64x, va
		? r_itv_end (info->vitv): r_itv_end (info->pitv));
	char *b = r_strbuf_drain (buf);

	r_table_add_rowf (table, "sssssss",
		a0, a1, b, a2,
		(info->perm != -1)? r_str_rwx_i (info->perm) : "",
		(info->extra)?info->extra : "",
		(info->name)?info->name :"");

	free (b);
}

static void r_table_visual_current_seek(RTable *table, TableVisualState *state) {
	const int width = state->width;
	const ut64 mul = state->mul;
	const ut64 min = state->min;
	const ut64 seek = state->seek;
	const ut64 len = state->len;
	RCons *cons = (RCons *) table->cons;
	const char *h_line = cons->use_utf8 ? RUNE_LONG_LINE_HORIZ : "-";
	RStrBuf *buf = r_strbuf_new ("");
	int j;
	for (j = 0; j < width; j++) {
		r_strbuf_append (buf,((j * mul) + min >= seek && (j * mul) + min <= seek + len) ? "^" : h_line);
	}
	r_strf_var (a0, 64, "0x%08"PFMT64x, seek);
	r_strf_var (a1, 64, "0x%08"PFMT64x, seek + len);
	char *b = r_strbuf_drain (buf);
	r_table_add_rowf (table, "sssssss", "=>", a0, b, a1, "", "", "");
	free (b);
}

static void r_table_visual(RTable *table, TableVisualState *state) {
	const ut64 min = state->min;
	const ut64 mul = state->mul;
	const ut64 len = state->len;

	SET_SHOW_HEADER (table, false);
	r_table_set_columnsf (table, "sssssss", "No.", "offset", "blocks", "offset", "perms", "extra", "name");
	if (min != -1 && mul > 0) {
		int i = state->render_fn (table, state);
		/* current seek */
		if (i > 0 && len != 0) {
			r_table_visual_current_seek (table, state);
		}
	}
}

static inline int render_table_rows_from_list(RTable *table, TableVisualState *state) {
	int i = 0;

	RList *list = state->user;
	RListIter *iter;
	RListInfo *info;
	r_list_foreach (list, iter, info) {
		r_table_visual_row (table, info, i, state);
		i++;
	}

	return i;
}

R_API void r_table_visual_list(RTable *table, RList *list, ut64 seek, ut64 len, int width, bool va) {
	width -= 80;
	if (width < 1) {
		width = 30;
	}

	ut64 min = -1;
	ut64 max = -1;
	RListIter *iter;
	RListInfo *info;
	r_list_foreach (list, iter, info) {
		if (min == -1 || info->pitv.addr < min) {
			min = info->pitv.addr;
		}
		if (max == -1 || info->pitv.addr + info->pitv.size > max) {
			max = info->pitv.addr + info->pitv.size;
		}
	}

	const ut64 mul = (max - min) / width;
	TableVisualState state = {
		.min = min,
		.mul = mul,
		.width = width,
		.seek = seek == UT64_MAX ? 0 : seek,
		.len = len,
		.va = va,
		.render_fn = render_table_rows_from_list,
		.user = list,
	};
	r_table_visual (table, &state);
}

R_VEC_TYPE_WITH_FINI(RVecListInfo, RListInfo, r_listinfo_fini);

static inline int render_table_rows_from_vec(RTable *table, TableVisualState *state) {
	int i = 0;

	RVecListInfo *vec = state->user;
	RListInfo *info;
	R_VEC_FOREACH (vec, info) {
		r_table_visual_row (table, info, i, state);
		i++;
	}

	return i;
}

R_API void r_table_visual_vec(RTable *table, RVecListInfo* vec, ut64 seek, ut64 len, int width, bool va) {
	width -= 80;
	if (width < 1) {
		width = 30;
	}

	ut64 min = -1;
	ut64 max = -1;
	RListInfo *info;
	R_VEC_FOREACH (vec, info) {
		if (min == -1 || info->pitv.addr < min) {
			min = info->pitv.addr;
		}
		if (max == -1 || info->pitv.addr + info->pitv.size > max) {
			max = info->pitv.addr + info->pitv.size;
		}
	}

	const ut64 mul = (max - min) / width;
	TableVisualState state = {
		.min = min,
		.mul = mul,
		.width = width,
		.seek = seek == UT64_MAX ? 0 : seek,
		.len = len,
		.va = va,
		.render_fn = render_table_rows_from_vec,
		.user = vec,
	};
	r_table_visual (table, &state);
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

R_API void r_table_fromtsv(RTable *t, const char *csv) {
}

R_API void r_table_fromcsv(RTable *t, const char *csv) {
	//  TODO
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
