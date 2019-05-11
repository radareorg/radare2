/* radare - Copyright 2009-2019 */
#include "r_list.h"
#include "r_types.h"
#include "r_core.h"

#define R_COLUMN_TYPE_FLOAT 1
#define R_COLUMN_TYPE_CHAR 2
#define R_COLUMN_TYPE_STR 3
#define R_COLUMN_TYPE_INT 4

typedef struct r_core_table_t {
	RList/*<RCoreColumn>*/ *columns;
	int num_of_cols;
	int num_of_rows;
	bool show_header;
	bool show_outline;
} RCoreTable;


typedef struct r_core_column_t {
	char *header;
	int type;
	RList/*<type>*/ *data;
	int width;
} RCoreColumn;

static char *get_fms (int type) {
	switch (type) {
		case R_COLUMN_TYPE_CHAR: return " %c ";
		case R_COLUMN_TYPE_INT: return " %*d ";
		case R_COLUMN_TYPE_STR: return " %.*s ";
		case R_COLUMN_TYPE_FLOAT: return " %.*f ";
	}
}

R_API void r_table_insert_column (RCoreTable *table, RCoreColumn *column) {
	r_list_append (table->columns, column);
	table->num_of_cols += 1;
}

R_API void r_core_draw_table (RCore *core, RCoreTable *table) {
	RList *columns = table->columns;
	RListIter *iter;
	RCoreColumn *column;
	// Print headers
	r_list_foreach (columns, iter, column) {
		printf ("%.*s", column->header);
	}
	printf ("\n");

	// print the data now
	for (int i = 0; i < table->num_of_rows; ++i) {
		r_list_foreach (columns, iter, column) {
			printf (get_fms(column->type), column->width, column->data[i]); 
		}
	}
}
