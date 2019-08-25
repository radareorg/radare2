/* radare - LGPL - Copyright 2019 - pancake */

#include <r_util.h>


typedef struct {
	const char *name;
	RListComparator cmp;
} RTableType;

static int sortString(const void *a, const void *b) {
	return strcmp (a, b);
}

static int sortNumber(const void *a, const void *b) {
	return r_num_get (NULL, a) - r_num_get (NULL, b);
}

RTableType r_table_type_string = { "string", sortString };
RTableType r_table_type_number = { "string", sortNumber };

typedef struct {
	char *name;
	RTableType *type;
	int align; // left, right, center (TODO: unused)
	int width; // computed
	int maxWidth;
	bool forceUppercase;
} RTableColumn;

typedef struct {
	// TODO: use RVector
	RList *items;
} RTableRow;

typedef struct {
	RList *rows;
	RList *cols;
	int totalCols;
	bool showHeader;
	bool adjustedCols;
} RTable;

// adjust column width
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
			int itemLength = r_str_len_utf8 (item);
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

R_API void r_table_add_column(RTable *t, RTableType *type, const char *name, int maxWidth) {
	RTableColumn *c = R_NEW0 (RTableColumn);
	if (c) {
		c->name = strdup (name);
		c->maxWidth = maxWidth;
		c->type = type;
		int itemLength = r_str_len_utf8 (name);
		c->width = itemLength + 1;
		r_list_append (t->cols, c);
	}
}

#if 0
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
R_API RTableRow *r_table_row_new(RList *items) {
	RTableRow *row = R_NEW (RTableRow);
	row->items = items;
	return row;
}

static bool addRow (RTable *t, RList *items, const char *arg, int col) {
	int itemLength = r_str_len_utf8 (arg);
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

// XXX deprecate?
R_API char *r_table_drain(RTable *t) {
	char *res = r_table_tostring (t);
	r_table_free (t);
	return res;
}

R_API char *r_table_tohtml(RTable *t) {
	// TODO
}

R_API void r_table_transpose(RTable *t) {
	// When the music stops rows will be cols and cols... rows!
}

R_API void r_table_format(RTable *t, int nth, RTableColumnType) {
	// change the format of a specific column
	// change imm base, decimal precission, ...
}

// to compute sum result of all the elements in a column
R_API ut64 r_table_reduce(RTable *t, int nth) {
	// When the music stops rows will be cols and cols... rows!
}

R_API char *r_table_tojson(RTable *t) {
	PJ *pj = pj_new ();
	RTableRow *row;
	RTableColumn *col;
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

R_API void r_table_fromjson(RTable *t, const char *csv) {
	//  TODO
}

R_API void r_table_fromcsv(RTable *t, const char *csv) {
	//  TODO
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

R_API void r_table_sort(RTable *t, int nth, int dir) {
	
}

R_API void r_table_query(RTable *t, const char *q) {
	// addr>200&&addr<400&&is_global&&name~test&&type=bind
	// query: [addr]>200&&[addr]<400&&[]
	// we need a syntax to do sorting
	// TODO support parenthesis and (or)||
	// split by "&&" (or comma) -> run .filter on each
	// call .sort() multiple times if needed for different columns
	// addr/gt/200,addr/lt/400,addr/sort/dec,offset/sort/inc
}
