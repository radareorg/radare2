/* radare - LGPL - Copyright 2019 - pancake */

#include <r_util.h>

typedef struct {
	char *name;
	RTableSort type;
	int width; // computed
	int maxWidth;
} RTableColumn;

typedef struct {
	// TODO: use RVector
	RList *items;
} RTableRow;

typedef struct {
	RList *rows;
	RList *cols;
	bool showHeaders;
	bool adjustedCols;
} RTable;

typedef enum {
	// JUST USE THE CALLBACKS
	R_TABLE_COLUMN_TYPE_STRING,
	R_TABLE_COLUMN_TYPE_NUMBER,
} RTableColumnType

// adjust column width
static void __table_adjust(RTable *t) {
	RListIter *iter, *iter2;
	RTableColumn *col;
	r_list_foreach (t->cols, iter, col) {
		col->width = 0;
	}
	r_list_foreach (t->rows, iter, row) {
		const char *item;
		int ncol = 0;
		r_list_foreach (row, iter2, item) {
			int itemLength = r_str_len_utf8 (item);
			ncol ++;
			col->
		}
	}
}

R_API RTable *r_table_new() {
	RTable *t = R_NEW0 (RTable);
	return t;
}

R_API void r_table_free(RTable *t) {
	free (t);
}

R_API RTable *r_table_clone(RTable *t) {
	// TODO: implement
	return NULL;
}

R_API void r_table_add_column(RTable *t, const char *name, int maxwidth) {
	RTableColumn *tc = R_NEW0 (RTableColumn);
	tc->name = strdup (name);
	tc->maxwidth = maxwidth;
	r_list_append (t->cols, tc);
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

R_API void r_table_add_row(RTable *t, const char *name, ...) {
	int itemLength = r_str_len_utf8 (item);
	// TODO: assert if number of columns doesnt match t->cols
}

R_API char *r_table_tostring(RTable *t) {
	RTableRow *row;
	RListIter *iter;
	if (t->showHeader) {
		r_list_foreach (t->cols, iter, row) {
		}
	}
	r_list_foreach (t->rows, iter, row) {
	}
}

// import / export
R_API char *r_table_drain(RTable *t) {
	char *res = r_table_tostring (t);
	r_table_free (t);
	return res;
}

R_API char *r_table_tojson(RTable *t) {
	PJ *pj
}
R_API void r_table_fromcsv(RTable *t, const char *csv) {
	//  TODO
}

R_API void r_table_filter(RTable *t) {
}

R_API void r_table_sort(RTable *t, int nth) {

}

R_API int r_table_type_string(void *a, void *b) {
}

R_API int r_table_type_number(void *a, void *b) {
}

main() {
	RTable *t = r_table_new ();

	r_table_add_column (t, "Action", 0, r_table_type_string);
	r_table_add_column (t, "Target", 1, r_table_type_number);

	r_table_add_row (t, "hello", "world");

	r_table_free (t);
}
