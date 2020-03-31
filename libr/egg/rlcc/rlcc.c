/* Radare Language Code Compiler */

#include <mpc.h>
#define eprintf(x,y...) fprintf(stderr,x,##y)

static int isComment(mpc_ast_t *node) {
	if (!strcmp (node->tag, "comment|regex")) {
		return 1;
	}
	if (!strcmp (node->tag, "linecomment|regex")) {
		return 1;
	}
	return 0;
}

static int isInlineAssembly(mpc_ast_t *node) {
	if (!strcmp (node->tag, "asm|regex")) {
		return 1;
	}
	return 0;
}

static int isStatement(mpc_ast_t *node) {
	if (!strcmp (node->tag, "stmt|>")) {
		return 1;
	}
	return 0;
}

static int isSigdef(mpc_ast_t *node) {
	if (!strcmp (node->tag, "sigdef|>")) {
		return 1;
	}
	return 0;
}

static int isProcedure(mpc_ast_t *node) {
	if (!strcmp (node->tag, "procedure|>")) {
		return 1;
	}
	return 0;
}

static void processNode (mpc_ast_t *node) {
	if (isStatement(node)) {
		int i, narg = 0;
		const char *args[32];
		for (i=0 ; i<node->children_num; i++) {
			const char *tag = node->children[i]->tag;
			const char *val = node->children[i]->contents;
			if (strcmp (tag, "char")) {
				printf ("TAG (%s) = (%s)\n", tag, val);
				args[narg++] = val;
			}
		}
		printf ("; CALL WITH %d ARGS\n", narg);
	} else if (isProcedure (node)) {
		int i, j;
		const char *name = node->children[0]->contents;
		printf ("%s:\n", name);
		for (i=0 ; i<node->children_num; i++) {
			if (!strcmp (node->children[i]->tag, "body|>")) {
				node = node->children[i];
				for (i=0 ; i<node->children_num; i++) {
					if (!strcmp (node->children[i]->tag, "stmt|>")) {
						processNode (node->children[i]);
					} else {
						eprintf ("UNK %s\n", node->children[i]->tag);
					}
				}
				break;
			}
		}
	} else if (isSigdef (node)) {
		if (node->children_num>4) {
			const char *name = node->children[0]->contents;
			const char *type = node->children[2]->contents;
			const char *size = node->children[4]->contents;
			if (!strcmp (type, "alias")) {
				printf (".equ %s,%s\n", name, size);
			} else if (!strcmp (type, "syscall")) {
				printf ("; TODO: register syscall %s number %s\n", name, size);
			} else if (!strcmp (type, "global")) {
				printf ("; TODO: global \n");
			} else {
				printf ("; UNKNOWN EXPRESISON: NAME = '%s' ", name);
				printf ("TYPE = '%s' ", type);
				printf ("SIZE = '%s'\n", size);
			}
		}
	} else if (isComment (node)) {
		char *s = strdup (node->contents + 2);
		int len = strlen (s);
		if (node->contents[1] == '*') {
			s[len-2] = 0;
		}
		while (s) {
			char *nl = strchr (s, '\n');
			if (nl) {
				*nl = 0;
				printf ("; %s\n", s);
				s = nl + 1;
			} else {
				printf ("; %s\n", s);
				s = NULL;
			}
		}
		free (s);
	} else if (isInlineAssembly (node)) {
		printf ("%s\n", node->contents+1);
	}
}

int main(int argc, char **argv) {
	mpc_parser_t* Ident     = mpc_new("ident");
	mpc_parser_t* Number    = mpc_new("number");
	mpc_parser_t* Character = mpc_new("character");
	mpc_parser_t* String    = mpc_new("string");
	mpc_parser_t* Factor    = mpc_new("factor");
	mpc_parser_t* Term      = mpc_new("term");
	mpc_parser_t* Lexp      = mpc_new("lexp");
	mpc_parser_t* Stmt      = mpc_new("stmt");
	mpc_parser_t* Exp       = mpc_new("exp");
	mpc_parser_t* Vartype   = mpc_new("vartype");
	mpc_parser_t* Typeident = mpc_new("typeident");
	mpc_parser_t* Decls     = mpc_new("decls");
	mpc_parser_t* Args      = mpc_new("args");
	mpc_parser_t* Body      = mpc_new("body");
	mpc_parser_t* Comment   = mpc_new("comment");
	mpc_parser_t* Linecomment   = mpc_new("linecomment");
	mpc_parser_t* Asm = mpc_new("asm");
	mpc_parser_t* Procedure = mpc_new("procedure");
	mpc_parser_t* CProcedure = mpc_new("cprocedure");
	mpc_parser_t* Sigdef    = mpc_new("sigdef");
	mpc_parser_t* Sigbody   = mpc_new("sigbody");
	mpc_parser_t* Includes  = mpc_new("includes");
	mpc_parser_t* Smallc    = mpc_new("smallc");

	mpc_err_t* err = mpca_lang(MPCA_LANG_DEFAULT,
			" ident     : /[a-zA-Z_][a-zA-Z0-9_]*/ ;                           \n"
			" number    : /[0-9]+/ ;                                           \n"
			" character : /'.'/ ;                                              \n"
			" string    : /\"(\\\\.|[^\"])*\"/ ;                               \n"
			"                                                                  \n"
			" factor    : '(' <lexp> ')'                                       \n"
			"           | <number>                                             \n"
			"           | <character>                                          \n"
			"           | <string>                                             \n"
			"           | <ident> '(' <lexp>? (',' <lexp>)* ')'                \n"
			"           | <ident> ;                                            \n"
			"                                                                  \n"
			" term      : <factor> (('*' | '/' | '%') <factor>)* ;             \n"
			" lexp      : <term> (('+' | '-') <term>)* ;                       \n"
			"                                                                  \n"
			" stmt      : '{' <stmt>* '}'                                      \n"
			"           | \"while\" '(' <exp> ')' <stmt>                       \n"
			"           | \"if\"    '(' <exp> ')' <stmt>                       \n"
			"           | <ident> '=' <lexp> ';'                               \n"
			"           | \"print\" '(' <lexp>? ')' ';'                        \n"
			"           | \"return\" <lexp>? ';'                               \n"
			"           | <ident> '(' (<number>|<ident>|<string>)? (',' (<string>|<number>|<ident>))* ')' ';' ;        \n"
			"                                                                  \n"
			" exp       : <lexp> '>' <lexp>                                    \n"
			"           | <lexp> '<' <lexp>                                    \n"
			"           | <lexp> \">=\" <lexp>                                 \n"
			"           | <lexp> \"<=\" <lexp>                                 \n"
			"           | <lexp> \"!=\" <lexp>                                 \n"
			"           | <lexp> \"==\" <lexp> ;                               \n"
			"                                                                  \n"
			" vartype   : (\"int\" | \"char\") ;                               \n"
			" typeident : <vartype> <ident> ;                                  \n"
			" decls     : (<typeident> ';')* ;                                 \n"
			" args      : <typeident>? (',' <typeident>)* ;                    \n"
			" body      : '{' <decls> <stmt>* '}' ;                            \n"
			" comment   : /\\/\\*([^\\*])*\\*\\// ;                            \n"
			" linecomment : /\\/\\/([^\\n])*/ ;                                \n"
			" asm       : /\\:([^\\n])*/ ;                                \n"
			" procedure : <ident> '@' \"global\" '(' <number>? ')' <body> ; \n"
			" cprocedure : <vartype> <ident> '(' <args> ')' <body> ; \n"
			" sigdef    : <ident> '@' <ident> '(' <number> ')' ';' ; \n"
			" sigbody   : '@' <ident> '(' <number> ')' ';' ; \n"
			" includes  : (\"#include\" <string>)* ;                           \n"
			" smallc    : /^/ (<comment>|<asm>|<linecomment>|<sigdef>|<sigbody>|<procedure>|<cprocedure>)* <includes> <decls> /$/ ; \n",
		Ident, Number, Character, String, Factor, Term, Lexp, Stmt, Exp,
		Vartype, Typeident, Decls, Args, Body, Comment, Linecomment, Asm, Procedure, CProcedure,
		Sigdef, Sigbody, Includes, Smallc, NULL);

	if (err != NULL) {
		mpc_err_print (err);
		mpc_err_delete (err);
		exit(1);
	}

#if 1
	if (argc > 1) {

		mpc_result_t r;
		if (mpc_parse_contents(argv[1], Smallc, &r)) {
			mpc_ast_print_to(r.output, stderr);
			{
				int i;
				mpc_ast_t *root = r.output;
				for (i=0; i< root->children_num; i++) {
					mpc_ast_t *node = root->children[i];
					eprintf ("; TAG = %s    (%s)\n", node->tag, node->contents);
					processNode (node);
				}
			}
			mpc_ast_delete(r.output);
		} else {
			mpc_err_print(r.error);
			mpc_err_delete(r.error);
		}

	} else {

		mpc_result_t r;
		if (mpc_parse_pipe("<stdin>", stdin, Smallc, &r)) {
			mpc_ast_print(r.output);
			mpc_ast_delete(r.output);
		} else {
			mpc_err_print(r.error);
			mpc_err_delete(r.error);
		}
	}
#endif

	mpc_cleanup(17, Ident, Number, Character, String, Factor, Term, Lexp, Stmt, Exp,
			Vartype, Typeident, Decls, Args, Body, Comment, Procedure, CProcedure,
			Sigdef, Includes, Smallc);

	return 0;

}

