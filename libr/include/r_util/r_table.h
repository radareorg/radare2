#ifndef R_UTIL_TABLE_H
#define R_UTIL_TABLE_H

#include <r_util.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	const char *name;
	RListComparator cmp;
} RTableColumnType;

typedef struct {
	char *name;
	RTableColumnType *type;
	int align; // left, right, center (TODO: unused)
	int width; // computed
	int maxWidth;
	bool forceUppercase;
	int total;
} RTableColumn;

typedef struct {
	char *name;
	RInterval pitv;
	RInterval vitv;
	int perm;
	char *extra;
} RListInfo;

enum {
	R_TABLE_ALIGN_LEFT,
	R_TABLE_ALIGN_RIGHT,
	R_TABLE_ALIGN_CENTER
};

typedef struct {
	// TODO: use RVector
	RList *items;
} RTableRow;

typedef struct {
	char *name;
	RList *rows;
	RList *cols;
	int totalCols;
	bool showHeader;
	bool showFancy;
	bool showSQL;
	bool showJSON;
	bool showCSV;
	bool showR2;
	bool showSum;
	bool adjustedCols;
	void *cons;
} RTable;

typedef void (*RTableSelector)(RTableRow *acc, RTableRow *new_row, int nth);

R_API void r_table_row_free(void *_row);
R_API void r_table_column_free(void *_col);
R_API RTableColumn *r_table_column_clone(RTableColumn *col);
R_API RTableColumnType *r_table_type(const char *name);
R_API RTable *r_table_new(const char *name);
R_API RTable *r_table_clone(const RTable *t);
R_API void r_table_free(RTable *t);
R_API int r_table_column_nth(RTable *t, const char *name);
R_API void r_table_add_column(RTable *t, RTableColumnType *type, const char *name, int maxWidth);
R_API void r_table_set_columnsf(RTable *t, const char *fmt, ...);
R_API RTableRow *r_table_row_new(RList *items);
R_API void r_table_add_row(RTable *t, const char *name, ...);
R_API void r_table_add_rowf(RTable *t, const char *fmt, ...);
R_API void r_table_add_row_list(RTable *t, RList *items);
R_API char *r_table_tofancystring(RTable *t);
R_API char *r_table_tosimplestring(RTable *t);
R_API char *r_table_tostring(RTable *t);
R_API char *r_table_tosql(RTable *t);
R_API char *r_table_tocsv(RTable *t);
R_API char *r_table_tor2cmds(RTable *t);
R_API char *r_table_tojson(RTable *t);
R_API const char *r_table_help(void);
R_API void r_table_filter(RTable *t, int nth, int op, const char *un);
R_API void r_table_sort(RTable *t, int nth, bool inc);
R_API void r_table_uniq(RTable *t);
R_API void r_table_group(RTable *t, int nth, RTableSelector fcn);
R_API bool r_table_query(RTable *t, const char *q);
R_API void r_table_hide_header(RTable *t);
R_API bool r_table_align(RTable *t, int nth, int align);
R_API void r_table_visual_list(RTable *table, RList* list, ut64 seek, ut64 len, int width, bool va);
R_API RTable *r_table_push(RTable *t);
R_API RTable *r_table_pop(RTable *t);
R_API void r_table_fromjson(RTable *t, const char *csv);
R_API void r_table_fromcsv(RTable *t, const char *csv);
R_API char *r_table_tohtml(RTable *t);
R_API void r_table_transpose(RTable *t);
R_API void r_table_format(RTable *t, int nth, RTableColumnType *type);
R_API ut64 r_table_reduce(RTable *t, int nth);
R_API void r_table_columns(RTable *t, RList *cols); // const char *name, ...);

#ifdef __cplusplus
}
#endif

#endif
