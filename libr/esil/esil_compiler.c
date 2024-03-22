/* radare - LGPL - Copyright 2024 - pancake */

#include <r_esil.h>

typedef struct {
	REsil *esil;
	bool available;
	const char *tok;
	const char *cur;
	RList *sb;
	RList *program;
	Sdb *db;
	bool comment;
	int deftoken;
	char *token;
	bool error;
	int line;
} ParseState;

R_API REsilCompiler *r_esil_compiler_new(void) {
	REsilCompiler *ec = R_NEW0 (REsilCompiler);
	return ec;
}

R_API void r_esil_compiler_use(REsilCompiler *ec, REsil *esil) {
	R_RETURN_IF_FAIL (ec);
	ec->esil = esil;
}

static ParseState *ps_new(REsilCompiler *ec, const char *expr) {
	ParseState *ps = R_NEW0 (ParseState);
	ps->esil = ec->esil;
	ps->cur = expr;
	ps->tok = expr;
	ps->available = true;
	ps->db = sdb_new0 ();
	ps->sb = r_list_newf (free);
	ps->program = r_list_newf (free);
	ps->line = 1;
	return ps;
}

static void ps_free(ParseState *ps) {
	sdb_free (ps->db);
	r_list_free (ps->program);
	r_list_free (ps->sb);
	free (ps);
}

static char peek(ParseState *ps) {
	char ch = ps->cur[0];
	if (ch == 0) {
		ps->available = false;
	}
	ps->cur++;
	return ch;
}

static bool is_invalid_token(const char *token) {
	const char t0 = *token;
	switch (t0) {
	case '(':
	case ')':
	case ':':
	case ';':
		return true;
	}
	return false;
}

static void sep(ParseState *ps) {
	int toklen = ps->cur - ps->tok - 1;
	char *s = r_str_ndup (ps->tok, toklen);
	if (!strcmp (s, "(")) {
		ps->comment = true;
	} else if (!strcmp (s, ")")) {
		if (ps->comment) {
			ps->comment = false;
		} else {
			R_LOG_ERROR ("Closing a comment when its not open");
		}
	} else if (!strcmp (s, ":")) {
		if (ps->deftoken) {
			R_LOG_ERROR ("Cannot start defining a token twice");
		} else {
			ps->deftoken = 1;
		}
	} else if (!strcmp (s, ";")) {
		char *a = r_str_list_join (ps->sb, ",");
		r_str_trim (a);
		sdb_set (ps->db, ps->token, a, 0);
		R_LOG_DEBUG ("Define '%s' = '%s'", ps->token, a);
		free (a);
		r_list_free (ps->sb);
		ps->sb = r_list_newf (free);
		ps->deftoken = 0;
	} else {
		if (is_invalid_token (s)) {
			R_LOG_ERROR ("invalid token '%s' at line %d", s, ps->line);
			ps->error = true;
		}
		if (ps->deftoken == 1) {
			// allocate new token
			free (ps->token);
			ps->token = strdup (s);
			ps->deftoken = 2;
		} else if (ps->comment) {
			// do nothing
		} else {
			char *resolve = sdb_get (ps->db, s, 0);
			if (ps->deftoken) {
				char *token = resolve? resolve: strdup (s);
				if (*token) {
					r_list_append (ps->sb, token);
				} else {
					free (token);
				}
			} else {
				if (resolve) {
					r_str_trim (resolve);
					r_list_append (ps->program, resolve);
				} else {
					if (ps->esil && isupper (*s)) {
						// check if its a valid esil keyword
						REsilOp *eop = ht_pp_find (ps->esil->ops, s, NULL);
						if (eop) {
						} else {
							R_LOG_WARN ("Invalid operation '%s' at line %d", s, ps->line);
						}
					}
					r_str_trim (s);
					if (*s) {
						r_list_append (ps->program, strdup (s));
					}
				}
			}
		}
	}
	R_LOG_DEBUG ("%c TOKEN = %d %s", (ps->comment? '#':' '), toklen, s);
	free (s);
	ps->tok = ps->cur;
}

R_API void r_esil_compiler_parse(REsilCompiler *ec, const char *expr) {
	ParseState *ps = ps_new (ec, expr);
	R_RETURN_IF_FAIL (ec);
	R_LOG_DEBUG ("PARSE '%s'", expr);
	// parse a space separated list of tokens
	for (;ps->available && !ps->error;) {
		switch (peek (ps)) {
		case '\n':
			ps->line ++;
		case 0:
		case '\t':
		case ' ':
			sep (ps);
			break;
		}
	}
	free (ec->final);
	ec->final = r_str_list_join (ps->program, ",");
	ps_free (ps);
}

R_API char *r_esil_compiler_tostring(REsilCompiler *ec) {
	return ec->final;
}

R_API void r_esil_compiler_free(REsilCompiler *ec) {
	free (ec);
}

#if 0
int main(int argc, char **argv) {
	// const char code[] = "( my macro ) : ADD + ; 1 1 ADD rax :=";
// 	r_log_set_level (10);
	const char *code = r_file_slurp (argv[1], NULL);
	REsilCompiler *ec = r_esil_compiler_new ();
	r_esil_compiler_parse (ec, code);
	char *s = r_esil_compiler_tostring (ec);
	eprintf ("%s\n", s);
	free (s);
	r_esil_compiler_free (ec);
}
#endif
