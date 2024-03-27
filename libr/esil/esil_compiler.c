/* radare - LGPL - Copyright 2024 - pancake */

#include <r_esil.h>
#include <r_anal.h>

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

static ParseState *ps_new(REsilCompiler *ec) {
	ParseState *ps = R_NEW0 (ParseState);
	ps->esil = ec->esil;
	ps->available = true;
	ps->db = sdb_new0 ();
	ps->sb = r_list_newf (free);
	ps->program = r_list_newf (free);
	ps->line = 1;
	return ps;
}

static void ps_init(ParseState *ps, const char *expr) {
	ps->cur = expr;
	ps->tok = expr;
}

static void ps_free(ParseState *ps) {
	sdb_free (ps->db);
	r_list_free (ps->program);
	r_list_free (ps->sb);
	free (ps);
}

/////////////

R_API REsilCompiler *r_esil_compiler_new(void) {
	REsilCompiler *ec = R_NEW0 (REsilCompiler);
	ParseState *ps = ps_new (ec);
	ec->priv = (void *)ps;
	return ec;
}

R_API void r_esil_compiler_reset(REsilCompiler *ec) {
	R_RETURN_IF_FAIL (ec);
	ps_free (ec->priv);
	ec->priv = ps_new (ec);
}

R_API void r_esil_compiler_use(REsilCompiler *ec, REsil *esil) {
	R_RETURN_IF_FAIL (ec);
	ec->esil = esil;
}

static char peek(ParseState *ps) {
	char ch = ps->cur[0];
	ps->available = (ch != 0);
	ps->cur++;
	return ch;
}

static inline bool is_invalid_token(const char *token) {
	const char t0 = *token;
	return t0 && strchr ("():;", t0);
}

static bool checkword(ParseState *ps, const char *s) {
	if (*s && ps->esil) {
		if (*s == '$' || isdigit (*s)) {
			// internal flag or number
		} else {
			RAnal *anal = ps->esil->anal;
			// check if its a valid esil keyword
			REsilOp *eop = ht_pp_find (ps->esil->ops, s, NULL);
			if (eop) {
			} else {
				RRegItem *ri = r_reg_get (anal->reg, s, -1);
				if (ri) {
					r_unref (ri);
				} else {
					const char *type = islower (*s)? "register": "operation";
					R_LOG_ERROR ("Invalid %s '%s' at line %d", type, s, ps->line);
					ps->error = true;
				}
			}
			// must be a valid register name for the currnet arch
		}
	}
	return !ps->error;
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
		} else if (ps->deftoken == 1) {
			// allocate new token
			free (ps->token);
			ps->token = strdup (s);
			ps->deftoken = 2;
		} else if (ps->comment) {
			// do nothing
		} else if (*s) {
			bool uses_token = true;
			if (!ps->deftoken) {
				if (!strcmp (s, "{DUP2}")) {
					uses_token = false;
					char *a = r_list_pop (ps->program);
					char *b = r_list_pop (ps->program);
					r_list_push (ps->program, strdup (a));
					r_list_push (ps->program, strdup (b));
					r_list_push (ps->program, strdup (a));
					r_list_push (ps->program, strdup (b));
					free (a);
					free (b);
				}
			}
			if (uses_token) {
				r_str_trim (s);
				char *resolve = sdb_get (ps->db, s, 0);
				RList *target = ps->deftoken? ps->sb: ps->program;
				if (resolve) {
					r_list_append (target, resolve);
				} else {
					checkword (ps, s);
					r_list_append (target, strdup (s));
				}
			}
		}
	}
	R_LOG_DEBUG ("%c TOKEN = %d %s", (ps->comment? '#':' '), toklen, s);
	free (s);
	ps->tok = ps->cur;
}

R_API char *r_esil_compiler_unparse(REsilCompiler *ec, const char *expr) {
	ParseState *ps = ec->priv;
	sdb_query (ps->db, "*");
	// TODO
	// parse esil expression and return an esil source
	// 1. replace commas with spaces
	// 2. check every word on every sub exression
	// 3. if that matches then prepend the token definition source with comments
	// 4. and replace subexpression with token name
	return NULL;
}

R_API bool r_esil_compiler_parse(REsilCompiler *ec, const char *expr) {
	R_RETURN_VAL_IF_FAIL (ec && expr, false);
	ParseState *ps = ec->priv;
	ps_init (ps, expr);
	R_LOG_DEBUG ("PARSE '%s'", expr);
	// parse a space separated list of tokens
	for (; ps->available && !ps->error; ) {
		switch (peek (ps)) {
		case '\n':
			ps->line ++;
			// passthrough
		case 0:
		case '\t':
		case ' ':
			sep (ps);
			break;
		}
	}
	free (ec->str);
	ec->str = r_str_list_join (ps->program, ",");
	return !ps->error;
}

R_API char *r_esil_compiler_tostring(REsilCompiler *ec) {
	R_RETURN_VAL_IF_FAIL (ec, NULL);
	return ec->str;
}

R_API void r_esil_compiler_free(REsilCompiler *ec) {
	if (ec) {
		ParseState *ps = ec->priv;
		ps_free (ps);
		free (ec);
	}
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
