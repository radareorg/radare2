/* radare - LGPL - Copyright 2012 - Anton Kochkov */

#include <r_anal.h>
#include "cparse/lexglb.h"

void *cdataParseAlloc(void *(*mallocProc)(size_t));
void *cdataParseFree(void *p, void (*freeProc)(void *));
extern FILE *yyin;
typedef struct yy_buffer_state *YY_BUFFER_STATE;
extern int yylex(void);
extern YY_BUFFER_STATE yy_scan_string(const char*);
extern void yy_delete_buffer(YY_BUFFER_STATE);

R_API RAnalType *r_anal_type_new() {
	RAnalType *t = R_NEW(RAnalType);
	return t;
}

R_API RList *r_anal_type_list_new() {
	RList *t = r_list_new ();
	return t;
}

R_API void r_anal_type_add(RList *l, RAnalType *t) {
	if ((l != NULL) && (l->head != NULL) && (l->tail != NULL)) {
		RListIter *r = NULL;
		r = r_list_append(l, (void *)t);
	}
}

R_API void r_anal_type_del(RList *l, const char* name) {
	RListIter *t = l->head;
	RAnalType *m = NULL;

	while (t->n != t->tail) {
		m = (RAnalType *)t->data;
		if (!strncmp(name, m->name, strlen(name))) {
			r_list_delete(l, t);
		}
		t = t->n;
	}
}

R_API RAnalType *r_anal_type_free(RAnalType *t) {
	free(t);
	return t;
}

R_API void r_anal_type_list(RList *t, short category, short enabled) {
	// List all types by category: var/struct/unions/pointers
}

R_API RAnalType *r_anal_type_find(char *name) {
	RListIter *t = core->anal->head;
	RAnalType *m = NULL;

	while (t->n != core->anal->tail) {
		m = (RAnalTYpe *)t->data;
		if (!strncmp(name, m->name, strlen(name))) {
			return m;
		}
		t = t->n;
	}
	return NULL;
}

R_API char* r_anal_type_to_str(RAnal *a, RAnalType *t) {
	return "<none>";
}

// TODO: Add types to RList instead or RAnalType
R_API RAnalType *r_anal_str_to_type(RAnal *a, const char* type) {
	int yv;
	RAnalType *tTree = NULL;

	void *pParser = cdataParseAlloc(malloc);
	yy_scan_string(type);
	while ((yv = yylex()) != 0) {
		cdataParse(pParser, yv, yylval, tTree);
	}
	cdataParse(pParser, 0, yylval, tTree);
	cdataParseFree(pParser, free);
	// TODO: Parse whole tree and split top-level members
	// and place them into RList;
	return NULL;
}

// TODO: Add types to RList instead of RAnalType
R_API RAnalType *r_anal_type_loadfile(RAnal *a, const char *path) {
	FILE *cfile;
	int n;
	int yv, yylval = 0;
	char buf[4096];
	RAnalType *tTree = NULL;

	void *pParser = cdataParseAlloc(malloc);
	cfile = fopen(path, "ro");
	while ((n = fread(buf, 1, sizeof(buf), cfile)) > 0) {
		buf[n] = '\0';
		yy_scan_string(buf);
		while ((yv = yylex()) != 0) {
			cdataParse(pParser, yv, yylval, tTree);
		}
	}
	fclose(cfile);
	cdataParse(pParser, 0, yylval, tTree);
	cdataParseFree(pParser, free);
	// TODO: Parse whole tree and split top-level members
	// and place them into RList;
	// TODO: insert '.filename' field for all elements in this tree
	return tTree;
}
