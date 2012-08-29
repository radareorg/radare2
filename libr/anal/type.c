/* radare - LGPL - Copyright 2012 - Anton Kochkov */

#include <r_anal.h>
#include "cparse/lexglb.h"
#include "cparse/cdata.h"

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
	RAnalType *type = R_NEW0 (RAnalType);
	type->name = "<root>";
	return type;
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

static const char *analtype(ushort t) {
	switch (t) {
	// XXX: these types are in cparse/cdata.h
	case R_ANAL_TYPE_VOID:
		return "void";
	case R_ANAL_TYPE_FLOAT:
		return "float";
	case R_ANAL_TYPE_DOUBLE:
		return "double";
	case R_ANAL_TYPE_LONGLONG:
		return "long long";
	case R_ANAL_TYPE_SHORT:
		return "short";
	case R_ANAL_TYPE_CHAR:
		return "char";
	case R_ANAL_TYPE_INT:
		return "int";
	}
	return "<unknown>";
}

R_API char* r_anal_type_to_str(RAnal *a, RAnalType *t, const char *sep) {
	char *tmp, buf[1000];
	if (!t) return NULL;
	buf[0] = '\0';
	switch (t->type) {
	case R_ANAL_TYPE_FUNCTION:
		tmp = r_anal_type_to_str (a, t->custom.f->args, ", ");
		sprintf (buf, "function %s %s(%s);",
			analtype (t->custom.f->rets), t->custom.f->name, tmp);
		free (tmp);
		break;
	case R_ANAL_TYPE_STRUCT:
		tmp = r_anal_type_to_str (a, t->custom.s->items, "; ");
		// TODO: iterate over all elements in struct
		sprintf (buf, "struct %s { %s };", t->custom.f->name, tmp);
		free (tmp);
		break;
	case R_ANAL_TYPE_UNION:
	case R_ANAL_TYPE_ARRAY:
	case R_ANAL_TYPE_POINTER:
	case R_ANAL_TYPE_VARIABLE:
	{
		int custom = t->custom.v->type;
		int type = R_ANAL_UNMASK_TYPE (custom);
		int sign = R_ANAL_UNMASK_SIGN (sign);
		switch (type) {
		case R_ANAL_VAR_TYPE_BYTE:
			sprintf(buf, "%s %s", sign?"char":"ut8", t->custom.v->name);
			break;
		case R_ANAL_VAR_TYPE_WORD:
			sprintf(buf, "%s %s", sign?"int":"unsigned int", t->custom.v->name);
			break;
		case R_ANAL_VAR_TYPE_DWORD:
			sprintf(buf, "%s %s", sign?"int":"ut32", t->custom.v->name);
			break;
		}
		while (t->next) {
			char *p = r_anal_type_to_str (a, t->next, sep);
			strcat (buf, sep);
			strcat (buf, p);
			free (p);
			t = t->next;
		}
	}
		break;
	default:
		break;
	}
	if (!*buf) strcpy (buf, "<oops>");
	// XXX: control overflow in buf
	return strdup (buf);
}

// TODO: Add types to RList instead or RAnalType
R_API RAnalType *r_anal_str_to_type(RAnal *a, const char* type) {
	char *tmp;
	int yv;
	RAnalType *tTree = R_NEW0 (RAnalType); //NULL;

	void *pParser = cdataParseAlloc (malloc);
	yy_scan_string (type);
	while ((yv = yylex ()) != 0) {
		cdataParse (pParser, yv, yylval, tTree);
	}
	cdataParse (pParser, 0, yylval, tTree);
	cdataParseFree (pParser, free);
	// TODO: Parse whole tree and split top-level members
	// and place them into RList;

	while (tTree->next) {
		RAnalType *t = tTree->next;
		tmp = r_anal_type_to_str (a, t, "; ");
		eprintf ("-> (%s)\n", tmp);
		free (tmp);
		tTree = tTree->next;

	}
	return NULL;
}

// TODO: Add types to RList instead of RAnalType
R_API RAnalType *r_anal_type_loadfile(RAnal *a, const char *path) {
	char *tmp;
	void *pParser;
	char buf[4096];
	int n, yv, yylval = 0;
	RAnalType *tTree = NULL;
	FILE *cfile = fopen (path, "r");
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
	while (tTree->next) {
		RAnalType *t = tTree->next;
		tmp = r_anal_type_to_str (a, t, "; ");
		eprintf ("-> (%s)\n", tmp);
		free (tmp);
		tTree = tTree->next;

	}
	return tTree;
}
