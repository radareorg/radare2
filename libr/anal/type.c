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

/*
typedef struct r_meta_function_t {
	int stackframe;
	RMetaType ret;
	RMetaType *arg[16]; // Just references to already registered data types
	// when we remove a type, we must ensure no function meta signature claims for it
} RMetaFunction;
*/
/*
R_API RMetaType *r_meta_type_new() {
	RMetaType *type = R_NEW (RMetaType);
	//
	return type;
}
*/

R_API RAnalType *r_anal_type_new() {
	RAnalType *t = R_NEW(RAnalType);
	return NULL;
}

R_API void r_anal_type_del() {
}

R_API void r_anal_type_cleanup() {
}

R_API void r_anal_type_free(RAnalType *t) {
	free(t);
}

R_API void r_anal_type_list() {
}

R_API RAnalType *r_anal_type_find(char *name) {

}

R_API char* r_anal_type_to_string(char* name) {

}

R_API RAnalType *r_anal_type_loadfile(char *path) {
	FILE *cfile;
	int n;
	int yv;
	char buf[4096];

	void *pParser = cdataParseAlloc(malloc);
	cfile = fopen(path, "ro");
	while ((n = fread(buf, 1, sizeof(buf), cfile)) > 0) {
		buf[n] = '\0';
		yy_scan_string(buf);
		while ((yv = yylex()) != 0) {
			cdataParse(pParser, yv, yylval);
		}
	}
	fclose(cfile);
	cdataParse(pParser, 0, yylval);
	cdataParseFree(pParser, free);
}

R_API RAnalType *r_anal_type_loadstring(char *buf) {
	return NULL;
}
