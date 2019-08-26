/* radare - LGPL - Copyright 2019 - pancake */

#include <r_util/r_table.h>

// cant do that without globals because RList doesnt have void *user :(
static bool Ginc = false;
static int Gnth = 0;
static RListComparator Gcmp = NULL;

static int sortString(const void *a, const void *b) {
	return strcmp (a, b);
}

static int sortNumber(const void *a, const void *b) {
	return r_num_get (NULL, a) - r_num_get (NULL, b);
}

// maybe just index by name instead of exposing those symbols as global
R_API RTableColumnType r_table_type_string = { "string", sortString };
R_API RTableColumnType r_table_type_number = { "number", sortNumber };

// TODO: unused for now, maybe good to call after filter :?
static void __table_adjust(RTable *t) {
	RListIter *iter, *iter2;
	RTableColumn *col;
	RTableRow  *row;
	r_list_foreach (t->cols, iter, col) {
		col->width = 0;
	}
	r_list_foreach (t->rows, iter, row) {
		const char *item;
		int ncol = 0;
		r_list_foreach (row->items, iter2, item) {
			int itemLength = r_str_len_utf8 (item) + 1;
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
	free (row);
}

R_API void r_table_column_free(void *_col) {
	RTableColumn *col = _col;
	free (col->name);
	free (col);
}

R_API RTable *r_table_new() {
	RTable *t = R_NEW0 (RTable);
	t->showHeader = true;
	t->cols = r_list_newf (r_table_column_free);
	t->rows = r_list_newf (r_table_row_free);
	return t;
}

R_API void r_table_free(RTable *t) {
	r_list_free (t->cols);
	r_list_free (t->rows);
	free (t);
}

R_API void r_table_add_column(RTable *t, RTableColumnType *type, const char *name, int maxWidth) {
	RTableColumn *c = R_NEW0 (RTableColumn);
	if (c) {
		c->name = strdup (name);
		c->maxWidth = maxWidth;
		c->type = type;
		int itemLength = r_str_len_utf8 (name) + 1;
		c->width = itemLength;
		r_list_append (t->cols, c);
	}
}

R_API RTableRow *r_table_row_new(RList *items) {
	RTableRow *row = R_NEW (RTableRow);
	row->items = items;
	return row;
}

static bool addRow (RTable *t, RList *items, const char *arg, int col) {
	int itemLength = r_str_len_utf8 (arg) + 1;
	RTableColumn *c = r_list_get_n (t->cols, col);
	if (c) {
		c->width = R_MAX (c->width, itemLength);
		r_list_append (items, strdup (arg));
		return true;
	}
	return false;
}

R_API void r_table_add_row(RTable *t, const char *name, ...) {
	va_list ap;
	va_start (ap, name);
	int col = 0;
	RList *items = r_list_newf (free);
	addRow (t, items, name, col++);
	for (;;) {
		const char *arg = va_arg (ap, const char *);
		if (!arg) {
			break;
		}
		addRow (t, items, arg, col);
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

R_API char *r_table_tofancystring(RTable *t) {
	RStrBuf *sb = r_strbuf_new ("");
	RTableRow *row;
	RTableColumn *col;
	RListIter *iter, *iter2;
	
	r_list_foreach (t->cols, iter, col) {
		r_strbuf_appendf (sb, "| %*s ", col->width, col->name);
	}
	int len = r_strbuf_length (sb) - 1;
	{
		char *s = r_str_newf (".%s.\n", r_str_pad ('-', len));
		r_strbuf_prepend (sb, s);
		free (s);
	}

	r_strbuf_appendf (sb, "|\n)%s(\n", r_str_pad ('-', len));
	r_list_foreach (t->rows, iter, row) {
		char *item;
		int c = 0;
		r_list_foreach (row->items, iter2, item) {
			RTableColumn *col = r_list_get_n (t->cols, c);
			if (col) {
				r_strbuf_appendf (sb, "| %*s ", col->width, item);
			}
			c++;
		}
		r_strbuf_append (sb, "|\n");
	}
	r_strbuf_appendf (sb, "`%s'\n", r_str_pad ('-', len));
	return r_strbuf_drain (sb);
}

R_API char *r_table_tostring(RTable *t) {
	RStrBuf *sb = r_strbuf_new ("");
	RTableRow *row;
	RTableColumn *col;
	RListIter *iter, *iter2;
	if (t->showHeader) {
		r_list_foreach (t->cols, iter, col) {
			r_strbuf_appendf (sb, "%*s", col->width, col->name);
		}
		int len = r_strbuf_length (sb);
		r_strbuf_appendf (sb, "\n%s\n", r_str_pad ('-', len));
	}
	r_list_foreach (t->rows, iter, row) {
		char *item;
		int c = 0;
		r_list_foreach (row->items, iter2, item) {
			RTableColumn *col = r_list_get_n (t->cols, c);
			if (col) {
				r_strbuf_appendf (sb, "%*s", col->width, item);
			}
			c++;
		}
		r_strbuf_append (sb, "\n");
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
				pj_ks (pj, col->name, item);
			}
			c++;
		}
		pj_end (pj);
	}
	pj_end (pj);
	return pj_drain (pj);
}

R_API void r_table_filter(RTable *t, int nth, int op, const char *un) {
	RTableRow *row;
	RListIter *iter, *iter2;
	ut64 uv = r_num_get (NULL, un);
	r_list_foreach_safe (t->rows, iter, iter2, row) {
		const char *nn = r_list_get_n (row->items, nth);
		ut64 nv = r_num_get (NULL, nn);
		bool match = true;
		switch (op) {
		case '>':
			match = (nv > uv);
			break;
		case '<':
			match = (nv < uv);
			break;
		case '=':
			match = (nv == uv);
			break;
		case '!':
			match = (nv == uv);
			break;
		case '~':
			match = strstr (nn, un) != NULL;
		case '\0':
			break;
		}
		if (!match) {
			r_list_delete (t->rows, iter);
		}
	}
}

static int cmp(const void *_a, const void *_b) {
	RTableRow *a = (RTableRow*)_a;
	RTableRow *b = (RTableRow*)_b;
	const char *wa = r_list_get_n (a->items, Gnth);
	const char *wb = r_list_get_n (b->items, Gnth);
	int res = Gcmp (wa, wb);
	if (Ginc) {
		res = -res;
	}
	return res;
}

R_API void r_table_sort(RTable *t, int nth, bool inc) {
	RTableColumn *col = r_list_get_n (t->cols, nth);
	if (col) {
		Ginc = inc;
		Gnth = nth;
		Gcmp = col->type->cmp;
		r_list_sort (t->rows, cmp);
		Gnth = Ginc = 0;
		Gcmp = NULL;
	}
}

static int __columnByName(RTable *t, const char *name) {
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

R_API void r_table_filter_columns(RTable *t, RList *list) {
	const char *col;
	RListIter *iter;
	RList *cols = t->cols;
	t->cols = r_list_newf (__table_column_free);
	r_list_foreach (list, iter, col) {
		int ncol = __columnByName(t, col);
		if (ncol != -1) {
			RTableColumn *c = r_list_get_n (cols, ncol);
			if (c) {
				//c->width = R_MAX (c->width, itemLength);
				r_table_add_column (t, c->type, col, 0);
			}
		}
	}
}

R_API void r_table_query(RTable *t, const char *q) {
	// TODO support parenthesis and (or)||
	// split by "&&" (or comma) -> run .filter on each
	// addr/gt/200,addr/lt/400,addr/sort/dec,offset/sort/inc
	RListIter *iter;
	char *qq = strdup (q);
	RList *queries = r_str_split_list (qq, ",");
	char *query;
	r_list_foreach (queries, iter, query) {
		RList *q = r_str_split_list (query, "/");
		const char *columnName = r_list_get_n (q, 0);
		const char *operation = r_list_get_n (q, 1);
		const char *operand = r_list_get_n (q, 2);
		int col = __columnByName (t, columnName);
		if (col == -1) {
			if (*columnName == '[') {
				col = atoi (columnName + 1);
			} else {
				eprintf ("Invalid column name (%s)\n", columnName);
			}
		}
		if (!operation) {
			break;
		}
		if (!strcmp (operation, "sort")) {
			r_table_sort (t, col, operand && !strcmp (operand, "dec"));
		} else if (!strcmp (operation, "cols")) {
			//eprintf ("(%s)\n", q);
		// TODO	r_table_filter_columns (t, q);
		} else if (!strcmp (operation, "quiet")) {
			t->showHeader = false;
		} else if (!strcmp (operation, "graph")) {
		// TODO	r_table_rendergraph(t, q);
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
}

#if 0
// TODO: to be implemented
R_API RTable *r_table_clone(RTable *t) {
	// TODO: implement
	return NULL;
}

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

R_API void r_table_columns(RTable *t, const char *name, ...) {
	va_list ap;
	va_start (ap, fmt);
	r_list_free (t->cols);
	t->cols = r_list_newf (__table_column_free);
	for (;;) {
		const char *n = va_arg (ap, const char *);
		if (!n) {
			break;
		}
	}
        va_end (ap);
}
#endif
