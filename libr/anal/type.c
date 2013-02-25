/* radare - LGPL - Copyright 2012 - Anton Kochkov */

#include <r_anal.h>
#include "cparse/lexglb.h"
#include "cparse/cdata.h"
#include "cparse/pp.h"

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

static const char *analtype(ut16 t) {
	switch (t) {
	case R_ANAL_VAR_TYPE_VOID:
		return "void";
	case R_ANAL_VAR_TYPE_BYTE:
		return "byte";
	case R_ANAL_VAR_TYPE_WORD:
		return "word";
	case R_ANAL_VAR_TYPE_DWORD:
		return "dword";
	case R_ANAL_VAR_TYPE_QWORD:
		return "qword";
	case R_ANAL_VAR_TYPE_FLOAT:
		return "float";
	case R_ANAL_VAR_TYPE_DOUBLE:
		return "double";
	case R_ANAL_VAR_TYPE_LONGLONG:
		return "long long";
	case R_ANAL_VAR_TYPE_LONG:
		return "long";
	case R_ANAL_VAR_TYPE_SHORT:
		return "short";
	case R_ANAL_VAR_TYPE_CHAR:
		return "char";
	case R_ANAL_VAR_TYPE_INT:
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
		sprintf (buf, "struct %s { %s };", t->custom.s->name, tmp);
		free (tmp);
		break;
	case R_ANAL_TYPE_UNION:
		tmp = r_anal_type_to_str (a, t->custom.u->items, "; ");
		sprintf (buf, "union %s { %s };", t->custom.u->name, tmp);
	case R_ANAL_TYPE_ARRAY:
	case R_ANAL_TYPE_POINTER:
	{
		int custom = t->custom.p->type;
		int type = R_ANAL_UNMASK_TYPE (custom);
		int sign = R_ANAL_UNMASK_SIGN (custom);
		switch (type) {
		case R_ANAL_VAR_TYPE_BYTE:
			sprintf(buf, "%s *%s", sign?"byte":"ut8", t->custom.p->name);
			break;
		case R_ANAL_VAR_TYPE_WORD:
			sprintf(buf, "%s *%s", sign?"word":"ut16", t->custom.p->name);
			break;
		case R_ANAL_VAR_TYPE_DWORD:
			sprintf(buf, "%s *%s", sign?"dword":"ut32", t->custom.p->name);
			break;
		case R_ANAL_VAR_TYPE_QWORD:
			sprintf(buf, "%s *%s", sign?"qword":"ut64", t->custom.p->name);
			break;
		case R_ANAL_VAR_TYPE_CHAR:
			sprintf(buf, "%s *%s", sign?"char":"unsigned char", t->custom.p->name);
			break;
		case R_ANAL_VAR_TYPE_SHORT:
			sprintf(buf, "%s *%s", sign?"short":"unsigned short", t->custom.p->name);
			break;
		case R_ANAL_VAR_TYPE_INT:
			sprintf(buf, "%s *%s", sign?"int":"unsigned int", t->custom.p->name);
			break;
		case R_ANAL_VAR_TYPE_LONG:
			sprintf(buf, "%s *%s", sign?"long":"unsigned long", t->custom.p->name);
			break;
		case R_ANAL_VAR_TYPE_LONGLONG:
			sprintf(buf, "%s *%s", sign?"long long":"unsigned long long", t->custom.p->name);
			break;
		case R_ANAL_VAR_TYPE_FLOAT:
			sprintf(buf, "%s *%s", sign?"float":"unsigned float", t->custom.p->name);
			break;
		case R_ANAL_VAR_TYPE_DOUBLE:
			sprintf(buf, "%s *%s", sign?"double":"unsigned double", t->custom.p->name);
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

	case R_ANAL_TYPE_VARIABLE:
	{
		int custom = t->custom.v->type;
		int type = R_ANAL_UNMASK_TYPE (custom);
		int sign = R_ANAL_UNMASK_SIGN (custom);
		switch (type) {
		case R_ANAL_VAR_TYPE_BYTE:
			sprintf(buf, "%s %s", sign?"byte":"ut8", t->custom.v->name);
			break;
		case R_ANAL_VAR_TYPE_WORD:
			sprintf(buf, "%s %s", sign?"word":"ut16", t->custom.v->name);
			break;
		case R_ANAL_VAR_TYPE_DWORD:
			sprintf(buf, "%s %s", sign?"dword":"ut32", t->custom.v->name);
			break;
		case R_ANAL_VAR_TYPE_QWORD:
			sprintf(buf, "%s %s", sign?"qword":"ut64", t->custom.v->name);
			break;
		case R_ANAL_VAR_TYPE_CHAR:
			sprintf(buf, "%s %s", sign?"char":"unsigned char", t->custom.v->name);
			break;
		case R_ANAL_VAR_TYPE_SHORT:
			sprintf(buf, "%s %s", sign?"short":"unsigned short", t->custom.v->name);
			break;
		case R_ANAL_VAR_TYPE_INT:
			sprintf(buf, "%s %s", sign?"int":"unsigned int", t->custom.v->name);
			break;
		case R_ANAL_VAR_TYPE_LONG:
			sprintf(buf, "%s %s", sign?"long":"unsigned long", t->custom.v->name);
			break;
		case R_ANAL_VAR_TYPE_LONGLONG:
			sprintf(buf, "%s %s", sign?"long long":"unsigned long long", t->custom.v->name);
			break;
		case R_ANAL_VAR_TYPE_FLOAT:
			sprintf(buf, "%s %s", sign?"float":"unsigned float", t->custom.v->name);
			break;
		case R_ANAL_VAR_TYPE_DOUBLE:
			sprintf(buf, "%s %s", sign?"double":"unsigned double", t->custom.v->name);
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

#if HAVE_CPARSE
// TODO: Add types to RList instead or RAnalType
R_API RAnalType *r_anal_str_to_type(RAnal *a, const char* type) {
	RAnalType *tTree = R_NEW0 (RAnalType);
	RAnalType *t = NULL;
	char *tmp_type = NULL;
	void *pParser;
	char *tmp;
	int yv;

	/* Preprocess buffer first */
	tmp_type = cparsepp_buf (type);

	/* Parse preprocessed buffer then */
	pParser = cdataParseAlloc (malloc);
	yy_scan_string (tmp_type);
	while ((yv = yylex ()) != 0) {
		cdataParse (pParser, yv, yylval, &tTree);
	}
	cdataParse (pParser, 0, yylval, &tTree);
	cdataParseFree (pParser, free);
	// TODO: Parse whole tree and split top-level members
	// and place them into RList;

	t = tTree;
	while (t) {
		tmp = r_anal_type_to_str (a, t, "; ");
		eprintf ("-> (%s)\n", tmp);
		free (tmp);
		t = t->next;
	}
	return tTree;
}

// TODO: Add types to RList instead of RAnalType
R_API RAnalType *r_anal_type_loadfile(RAnal *a, const char *path) {
	int n, yv, yylval = 0;
	RAnalType *tTree = R_NEW0 (RAnalType);
	RAnalType *t = NULL;
	char *tmp, *tmp_path;
	char buf[4096];
	void *pParser;
	FILE *cfile;

	/* Preprocess file first */
	if (!r_file_mkstemp ("r2pp", &tmp_path)) {
		eprintf ("Cannot create temporary file\n");
		return NULL;
	}
	cparsepp_file (path, tmp_path);

	/* Parse preprocessed file then */
	if (!(cfile = r_sandbox_fopen (tmp_path, "r"))) {
		free (tmp_path);
		return NULL;
	}
	// TODO: use r_file_slurp ?
	pParser = cdataParseAlloc (malloc);
	while ((n = fread (buf, 1, sizeof (buf), cfile)) > 0) {
		buf[n] = '\0';
		yy_scan_string (buf);
		while ((yv = yylex ()) != 0) {
			cdataParse (pParser, yv, yylval, &tTree);
		}
	}
	cdataParse (pParser, 0, yylval, &tTree);
	fclose (cfile);

	cdataParseFree (pParser, free);

	/* Remove tmp file */
	r_file_rm (tmp_path);
	free (tmp_path);

	// TODO: Parse whole tree and split top-level members
	// and place them into RList;
	// TODO: insert '.filename' field for all elements in this tree
	t = tTree;
	while (t) {
		tmp = r_anal_type_to_str (a, t, "; ");
		eprintf ("-> (%s)\n", tmp);
		free (tmp);
		t = t->next;
	}
	return tTree;
}
#else
R_API RAnalType *r_anal_str_to_type(RAnal *a, const char* type) {
	return NULL;
}
R_API RAnalType *r_anal_type_loadfile(RAnal *a, const char *path) {
	return NULL;
}
#endif

/* if value is null, undefine, if value is "" , defined*/
/* numeric values are parsed from strings */
R_API void r_anal_type_define (RAnal *anal, const char *key, const char *value) {
	// TODO: store in RPair
}

R_API void r_anal_type_header (RAnal *anal, const char *hdr) {
}
