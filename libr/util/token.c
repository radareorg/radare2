/* radare - LGPL - Copyright 2007-2021 - pancake */

#if 0
Very simple code parser in C
============================

Takes a string representing the code and runs a callback everytime a token is found

r_codetok ("string", callback, &userdata);
#endif

#include <r_util.h>

static const char *tokentypes[] = {
	"none", "intn", "flot", "word", "hash", "strn", "cmnt", "math", "grup", "begin", "end", NULL
};


R_API RTokenizer *r_tokenizer_new(void) {
	RTokenizer *t = R_NEW0 (RTokenizer);
	return t;
}

static bool is_token_begin(RTokenizer *tok, char ch) {
	return !(IS_WHITESPACE (ch) || ch == '\n');
}

static bool end_token(RTokenizer *tok) {
	const char* tt = tokentypes[tok->type];
	const int tok_len = (size_t)(tok->end - tok->begin);
	const char* tok_buf = tok->buf + tok->begin;
	const char *r = r_str_pad (' ', tok->indent * 4);
	if (tok->cb) {
		return tok->cb (tok);
	}
	eprintf ("[%s]%s%.*s%c", tt, r, tok_len, tok_buf, 10);
	return true;
}

static bool start_token(RTokenizer *tok, char ch) {
	switch (ch) {
	case '\'':
	case '"':
		tok->type = R_TOKEN_STRING;
		tok->ch = ch;
		return true;
	case '/':
		tok->type = R_TOKEN_COMMENT;
		break;
	case '(':
	case '{':
	case '[':
		tok->indent ++;
		tok->type = R_TOKEN_GROUP;
		return false;
	case ')':
	case '}':
	case ']':
		tok->indent --;
		tok->type = R_TOKEN_GROUP;
		return false;
	case '#':
		tok->type = R_TOKEN_HASH;
		return true;
	case '<':
	case '>':
	case '=':
	case '+':
	case '-':
	case '*':
	case '?':
	case '|':
	case '&':
	case '%':
	case '^':
	case ':':
	case ';':
	case ',':
	case '.':
		tok->type = R_TOKEN_MATH;
		return false;
	}
	if (isalpha (ch)) {
		tok->type = R_TOKEN_WORD;
	}
	if (ch >= '0' && ch <= '9') {
		tok->type = R_TOKEN_INT;
	}
	return false;
}

static bool is_token_char(RTokenizer *tok, char ch) {
	switch (tok->type) {
	case R_TOKEN_BEGIN:
	case R_TOKEN_END:
		return false;
	case R_TOKEN_NONE:
		// ERROR
		return false;
	case R_TOKEN_HASH:
		return (isdigit (ch) || ch == '#' || ch == '_') || (isalpha (ch) && !IS_WHITESPACE (ch));
	case R_TOKEN_COMMENT:
		if (tok->end-tok->begin == 0) {
			if (ch != '/') {
				tok->type = R_TOKEN_MATH;
				return false;
			}
		}
		return (ch != '\n');
	case R_TOKEN_WORD:
		return (isdigit (ch) || ch == '#' || ch == '_') || (isalpha (ch) && !IS_WHITESPACE (ch));
	case R_TOKEN_INT:
		if (ch == 'x') {
			tok->hex = true;
			return true;
		}
		if (ch == '.') {
			tok->type = R_TOKEN_FLOAT;
			return true;
		}
		if (tok->hex) {
			if (ch >= 'a' && ch <= 'f') {
				return true;
			}
			if (ch >= 'A' && ch <= 'F') {
				return true;
			}
		}
		return ch >= '0' && ch <= '9';
	case R_TOKEN_FLOAT:
		return isdigit (ch) || ch == 'f'; // XXX 'f' is the last char
	case R_TOKEN_STRING:
		if (tok->escape) {
			tok->escape = false;
		} else {
			if (ch == tok->ch) {
				return false;
			}
			if (ch == '\\') {
				tok->escape = true;
			}
		}
		return true;
	case R_TOKEN_GROUP:
	case R_TOKEN_MATH:
		// those are one char tokens
		return false;
	}
	return false;
}

R_API void r_str_tokenize(const char *buf, RTokenizerCallback cb, void *user) {
	eprintf ("tokenize(%s)%c", buf, 10);
	RTokenizer *tok = R_NEW0 (RTokenizer);
	tok->cb = cb;
	tok->user = user;
	size_t i = 0;
	size_t len = strlen (buf);
	tok->buf = buf;

	tok->type = R_TOKEN_BEGIN;
	end_token (tok);

	while (i < len) {
		tok->hex = false;
		tok->type = R_TOKEN_NONE;
		while (i < len && !is_token_begin (tok, buf[i])) {
			i++;
		}
		if (i == len) {
			break;
		}
		tok->ch = buf[i];
		tok->begin = i;
		tok->end = i;
		if (start_token (tok, buf[i])) {
			tok->begin++;
			i++;
		}
		while (i < len && is_token_char (tok, buf[i])) {
			i++;
			tok->end = i;
		}
		if (tok->type == R_TOKEN_GROUP) {
			tok->end = i;
			i++;
		} else if (tok->type == R_TOKEN_MATH) {
			i++;
			tok->end = i;
		} else {
			tok->end = i;
		}
		if (tok->type == R_TOKEN_STRING) {
			i++;
		}
		if (tok->type != R_TOKEN_NONE) {
			end_token (tok);
		} else {
			i++;
		}
	}
	tok->type = R_TOKEN_END;
	end_token (tok);
}

typedef struct {
	char* word;
	int parlevel;
	bool inswitch;
	bool incase;
	bool inassign;
	bool inreturn;
	RList *args;
	char *s;
	PJ *pj;
} Data;


static void indent(RTokenizer *tok) {
	Data *data = tok->user;
	int n = 2 * ((tok->type == R_TOKEN_GROUP)? (tok->indent-1): tok->indent);
	if (data->incase) {
		n++;
	}
	eprintf ("%s", r_str_pad (' ', n));
}

bool callback(RTokenizer *tok) {
	Data *data = tok->user;
	switch (tok->type) {
	case R_TOKEN_NONE:
	case R_TOKEN_COMMENT:
		break;
	case R_TOKEN_HASH:
		{
			char *h = r_str_ndup (tok->buf + tok->begin, tok->end - tok->begin);
			if (data->pj) {
			} else {
				eprintf ("DIRECTIVE (%s)%c", h, 10);
			}
			free (h);
		}
		break;
	case R_TOKEN_WORD:
		free (data->word);
		data->word = r_str_ndup (tok->buf + tok->begin, tok->end - tok->begin);
		// eprintf ("WORD (%s)%c", data->word, 10);
		if (data->incase ) {
			// eprintf ("CASE WORD (%s)%c", data->word, 10);
			break;
			data->incase = false;
		}
		if (!strcmp (data->word, "case")) {
			R_FREE (data->word);
			data->incase = true;
			break;	
		}
		if (!strcmp (data->word, "default")) {
			break;	
		}
		if (!strcmp (data->word, "return")) {
			if (data->pj) {
				pj_o (data->pj);
				pj_ks (data->pj, "node", "return");
			} else {
				indent (tok);
				eprintf ("RETURN%c",10);
			}
			R_FREE (data->s);
			data->inreturn = true;
			return false;
		}
		if (!strcmp (data->word, "break")) {
			break;	
		}
		if (data->s) {
			data->s = r_str_append (data->s, " ");
		}
		data->s = r_str_appendlen (data->s, tok->buf + tok->begin, tok->end - tok->begin);
		// eprintf ("WORD(%s)%c", data->word, 10);
		break;
	case R_TOKEN_STRING:
		{ char *word = r_str_ndup (tok->buf + tok->begin, tok->end - tok->begin);
			//	eprintf ("STRING(%s)%c", word, 10);
			free (word);
		}
		if (data->s) {
			data->s = r_str_append (data->s, " ");
		}
		data->s = r_str_appendlen (data->s, tok->buf + tok->begin, tok->end - tok->begin);
		break;
	case R_TOKEN_GROUP:
		if (data->inassign) {
			break;
		}
		switch (tok->ch) {
		case '}':
			R_FREE (data->s);
			pj_end (data->pj);
			pj_end (data->pj);
			break;
		}
		if (tok->ch == ')') {
			data->parlevel--;
			data->s = r_str_appendlen (data->s, tok->buf + tok->begin, tok->end - tok->begin);
			if (data->args) {
				r_list_append (data->args, data->s);
				data->s = NULL;
				char *arg;
				RListIter *iter;
				r_list_foreach (data->args, iter, arg) {
					if (arg) {
						eprintf ("%s", r_str_pad (' ', (tok->indent +1)* 2));
						eprintf (" - %s%c", arg, 10);
						if (data->pj) {
							char *lz = (char *)r_str_rchr (arg, NULL, ' ');
							if (lz) {
								*lz++ = 0;
								pj_o (data->pj);
								pj_ks (data->pj, "name", lz);
								pj_ks (data->pj, "type", arg);
								pj_end (data->pj);
							} else {
								pj_s (data->pj, arg);
								pj_s (data->pj, arg);
							}
						}
					}
				}
				r_list_free (data->args);
				data->args = NULL;
				if (data->pj) {
					pj_end(data->pj);
				}
			}
		} else if (tok->ch == '{') {
			if (data->word) {
				if (!strcmp (data->word, "else")) {
					indent (tok);
					eprintf ("ELSE %d%c", tok->indent, 10);
					r_list_free (data->args);
					data->args = NULL;
					R_FREE (data->s);
				}
			}
			pj_ka (data->pj, "body");
		} else if (tok->ch == '(') {
			data->parlevel++;
			if (data->word) {
				if ( !strcmp (data->word, "if")) {
					indent (tok);
					eprintf ("IF %d%c", tok->indent, 10);
				} else if ( !strcmp (data->word, "switch")) {
					data->inswitch = true;
					indent (tok);
					eprintf ("SWITCH%c", 10);
					R_FREE (data->word);
				} else {
					if (tok->indent == 1) {
						if (data->pj) {
							pj_ko (data->pj, data->word);
							pj_ks (data->pj, "type", "symbol");
							pj_ks (data->pj, "name", data->word);
							pj_ka (data->pj, "args");
						} else {
							eprintf ("FUNC (%s)%c", data->word, 10);
						}
					} else {
						if (data->pj) {
							pj_o (data->pj);
							pj_ks (data->pj, "type", "call");
							pj_ks (data->pj, "name", data->word);
							pj_ka (data->pj, "args");
						} else {
							indent (tok);
							eprintf ("CALL (%s)%c", data->word, 10);
						}
					}
				}
			}
			R_FREE (data->s);
			if (data->word) {
				data->args = r_list_newf (free);
			}
			R_FREE (data->word);
		}
		break;
	case R_TOKEN_INT:
	case R_TOKEN_FLOAT:
		if (data->incase || data->inassign) {
			R_FREE (data->word);
			data->s = r_str_appendlen (data->s, tok->buf + tok->begin, tok->end - tok->begin);
			data->incase = false;
			//			data->inassign = false;
			break;
		} else {
			if (!data->s) {
				data->s = r_str_ndup (tok->buf + tok->begin, tok->end - tok->begin);
			}
		}
		if (data->incase) {
			char *s = r_str_ndup (tok->buf + tok->begin, tok->end - tok->begin);
			// data->s = r_str_appendlen (data->s, tok->buf + tok->begin, tok->end - tok->begin);
			indent (tok);
			eprintf ("CASE (%s)%c", s, 10);
			data->incase = false;
			R_FREE (data->word);
		}
		// fallthru
	case R_TOKEN_MATH:
		if (data->incase) {
			data->incase = false;
			R_FREE (data->word);
		}
		switch (tok->ch) {
		case '=':
			// eprintf ("PAR %d %c", data->parlevel, 10);
			if (data->parlevel == 0) {
				indent(tok);
				eprintf ("ASSIGN (%s)%c", data->word, 10);
				data->inassign = true;
				if (data->word && data->pj) {
					pj_o (data->pj);
					pj_ks (data->pj, "node", "assign");
					pj_ks (data->pj, "var", data->word);
				}
				R_FREE (data->word);
				R_FREE (data->s);
			}
			break;
		case ':':
			if (data->word) {
				// eprintf ("CASE %s%c", data->word, 10);
				break;
			}
		case ';':
			if (data->inreturn) {
				indent(tok);
				eprintf ("-- ARG (%s)%c", data->s, 10);
				if (data->pj) {
					pj_ks (data->pj, "value", data->s);
					pj_end (data->pj);
				}
			}
			if (data->inassign) {
				indent(tok);
				eprintf ("-- ARG (%s)%c", data->s, 10);
				data->inassign = false;
				if (data->pj) {
					pj_ks (data->pj, "value", data->s);
					pj_end (data->pj);
				}
			}
			R_FREE (data->word);
			break;
		case '*':
		case '+':
		case '-':
		case '%':
		case '&':
		case '|':
		case '<':
		case '>':
			R_FREE (data->word);
			data->s = r_str_appendlen (data->s, tok->buf + tok->begin, tok->end - tok->begin);
			break;
		case ',':
			if (data->s) {
				if (data->args) {
					r_list_append (data->args, data->s);
				}
				data->s = NULL;
			}
			R_FREE (data->word);
			break;
		}
		// eprintf ("ARG%c%c",tok->ch, 10);
		break;
	case R_TOKEN_BEGIN:
	case R_TOKEN_END:
		// free the data
		eprintf ("DONE%c", 10);
		break;
	}
	return true;
}

R_API char *r_str_tokenize_json(const char *buf) {
	Data data = {0};
	data.pj = pj_new ();
	pj_o (data.pj);
	r_str_tokenize (buf, (RTokenizerCallback)callback, &data);
	pj_end (data.pj);
	data.pj->level = 0; // force level 0 to permit invalid jsons for now
	char *o = pj_drain (data.pj);
	char *p = r_str_newf ("%s%c", o, 10);
	free (o);
	return p;
}

#if 0
//
int main() {
	tokenize("Hello World", NULL, NULL);
	tokenize("hello('this', 33, true);", NULL, NULL);
	tokenize(
		" // hello world this is very new\n"
		" int main(int argc, char **argv) {\n"
		"  printf (\"Hello %s\", \"world\");}\n"
		" }\n"
		, NULL, NULL
		);
	Data data = {0};
	char *s = r_file_slurp ("a.c", NULL);
	data.pj = pj_new ();;
	pj_o (data.pj);
	tokenize (s, callback, &data);
	pj_end (data.pj);
	char *o = pj_drain (data.pj);
	printf ("%s%c", o, 10);
	free (o);
	free (s);
}
#endif
