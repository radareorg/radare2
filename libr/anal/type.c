/* radare - LGPL - Copyright 2012 - Anton Kochkov */

#include <r_anal.h>
#include "cparse/lexglb.h"

// TOTHINK: Right now we are loading types in RList
// but may be better to add argument RAnal *a, to
// do target-specific stuff (e.g. endianess, longiness, etc)

void *cdataParseAlloc(void *(*mallocProc)(size_t));
void *cdataParseFree(void *p, void (*freeProc)(void *));
extern FILE *yyin;
typedef struct yy_buffer_state *YY_BUFFER_STATE;
extern int yylex(void);
extern YY_BUFFER_STATE yy_scan_string(const char*);
extern void yy_delete_buffer(YY_BUFFER_STATE);

R_API RAnalType *r_anal_type_new() {
	return R_NEW0 (RAnalType);
}

R_API RList *r_anal_type_list_new() {
	return r_list_new ();
}

R_API void r_anal_type_add(RAnal *a, RAnalType *t) {
	if (t) r_list_append (a->types, (void *)t);
}

R_API void r_anal_type_del(RAnal *a, const char* name) {
	RListIter *t;
	RAnalType *m;

	r_list_foreach (a->types, t, m) {
		if (!strcmp (name, m->name))
			r_list_delete (a->types, t);
	}
}

R_API RAnalType *r_anal_type_free(RAnalType *t) {
	free (t);
	return NULL;
}

R_API void r_anal_type_list(RAnal *a, short category, short enabled) {
	// List all types by category: var/struct/unions/pointers
}

R_API RAnalType *r_anal_type_find(RAnal *a, const char *name) {
	RListIter *t;
	RAnalType *m;
	r_list_foreach (a->types, t, m) {
		if (!strcmp (name, m->name))
			return m;
	}
	return NULL;
}

R_API const char* r_anal_type_to_str(RAnal *a, RAnalType *t) {
	return "<none>";
}

// TODO: Add types to RList instead or RAnalType
R_API RAnalType *r_anal_str_to_type(RAnal *a, const char* type) {
	int yv;
	RAnalType *tTree = NULL;

	void *pParser = cdataParseAlloc (malloc);
	yy_scan_string (type);
	while ((yv = yylex ()) != 0) {
		cdataParse (pParser, yv, yylval, tTree);
	}
	cdataParse (pParser, 0, yylval, tTree);
	cdataParseFree (pParser, free);
	// TODO: Parse whole tree and split top-level members
	// and place them into RList;
	return NULL;
}

// TODO: Add types to RList instead of RAnalType
R_API RAnalType *r_anal_type_loadfile(RAnal *a, const char *path) {
	FILE *cfile;
	void *pParser;
	char buf[4096];
	int n, yv, yylval = 0;
	RAnalType *tTree = NULL;

	cfile = fopen (path, "ro");
	if (!cfile)
		return NULL;
	// TODO: use r_file_slurp ?
	pParser = cdataParseAlloc (malloc);
	while ((n = fread (buf, 1, sizeof (buf), cfile)) > 0) {
		buf[n] = '\0';
		yy_scan_string (buf);
		while ((yv = yylex ()) != 0) {
			cdataParse (pParser, yv, yylval, tTree);
		}
	}
	fclose (cfile);
	cdataParse (pParser, 0, yylval, tTree);
	cdataParseFree (pParser, free);
	// TODO: Parse whole tree and split top-level members
	// and place them into RList;
	// TODO: insert '.filename' field for all elements in this tree
	return tTree;
}
