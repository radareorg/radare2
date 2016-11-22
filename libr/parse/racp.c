/* radare - LGPL - Copyright 2013-2016 - pancake, oddcoder */

#include "r_util.h"
#include "r_types.h"
enum LEXTYPES {
	R_RACP_ERROR,
	R_RACP_COMPLETED,
	R_RACP_BINARY,
	R_RACP_HEX,
	R_RACP_OCTAL,
	R_RACP_DECIMAL,
	R_RACP_MATH,
	R_RACP_INDIRECTION,
	R_RACP_RESERVED,
	R_RACP_IDENTIFIER,
	R_RACP_PUNCTUATION,
	R_RACP_ASSIGN
};
typedef struct racp_lexer {
	RDualBuf b;
	int type;
	int old_type;
}RLex;
R_API int r_parse_is_c_file(const char *file) {
	const char *ext = r_str_lchr (file, '.');
	if (ext) {
		ext = ext + 1;
		if (!strcmp (ext, "cparse")
		||  !strcmp (ext, "c")
		||  !strcmp (ext, "h")) {
			return true;
		}
	}
	return false;
}
char *racp_get_next_token(RLex *lex) { //lexical analyser, finite state machine simulation
	char *start, *current;
	int status = 0,  counter = 0;
	char *reservedwords[] = {
		"__attribute__",
		"const",
		"extern",
		"register",
		"static",
		"volatile",
		"struct",
		"enum",
		"union",
		"typedef",
		NULL
	};
	while (1) {
		//lets parse the whole thing
		if (++counter > 1024) {
			eprintf ("identifiers are not allowed to exceed 1024 character\n");
			return NULL;
		}
		switch (status) {
		case 0:
			start = r_dualbuf_next_charp (&lex->b);
			current = start;
			if (isspace (*current)) {
				counter = 0;
				continue;
			}
			switch (*current) {
			case EOF:
				lex->type = R_RACP_COMPLETED;
				return NULL;
			case '0':
				status = 1;
				continue;
			case '+':
			case '-':
			case '%':
				status = 10;
				continue;
			case '*':
				if (lex->type != R_RACP_IDENTIFIER) {
					status = 10;
					continue;
				}
				status = 13;
				continue;
			case '=':
				status = 18;
				continue;
			case '/':
				status = 19;
				continue;
			case '[':
			case ']':
			case '(':
			case ')':
			case ';':
			case ',':
			case '{':
			case '}':
				status = 17;
				continue;
			case '_':
				status = 15;
				continue;
			}
			if (isalpha (*current)) {
				status = 15;
				continue;
			}
			if (isdigit (*current)) {
				status = 11;
				continue;
			}
			eprintf ("unexpected character '%c'\n", *current);
			lex->type = R_RACP_ERROR;
			return NULL;
		case 1:
			current = r_dualbuf_next_charp (&lex->b);
			switch (*current) {
			case 'x':
			case 'X':
				status = 5;
				continue;
			case 'b':
			case 'B':
				status = 2;
				continue;
			}
			if (*current >='0' && *current <= '7') {
				status = 8;
				continue;
			}
			eprintf ("Unexpected character '%c'\n", *current);
			lex->type = R_RACP_ERROR;
			return NULL;
		case 2:
			current = r_dualbuf_next_charp (&lex->b);
			if (*current =='0' || *current == '1') {
				status = 3;
				continue;
			}
			eprintf ("Expected binary digit\n");
			lex->type = R_RACP_ERROR;
			return NULL;
		case 3:
			current = r_dualbuf_next_charp (&lex->b);
			if (*current == '0' || *current == '1') {
				status = 3;
				continue;
			}
			status = 4;
			continue;
		case 4:
			current = r_dualbuf_prev_charp (&lex->b);
			lex->type = R_RACP_BINARY;
			return r_dualbuf_retrieve_tok (&lex->b, start, current);
		case 5:
			current = r_dualbuf_next_charp (&lex->b);
			if (isdigit(*current) || (*current >= 'A' && *current <= 'F') || (*current >= 'a' && *current <= 'f')) {
				status = 6;
				continue;
			}
			eprintf ("Expected hexdecimal digit\n");
			lex->type = R_RACP_ERROR;
			return NULL;
		case 6:
			current = r_dualbuf_next_charp(&lex->b);
			if (isdigit(*current) || (*current >= 'A' && *current <= 'F') || (*current >= 'a' && *current <= 'f')) {
				status = 6;
				continue;
			}
			status = 7;
			continue;
		case 7:
			current = r_dualbuf_prev_charp (&lex->b);
			lex->type = R_RACP_HEX;
			return r_dualbuf_retrieve_tok (&lex->b, start, current);
		case 8:
			current = r_dualbuf_next_charp (&lex->b);
			if (*current >= '0' && *current <='7') {
				status = 8;
				continue;
			}
			status = 9;
			continue;
		case 9:
			current = r_dualbuf_prev_charp (&lex->b);
			lex->type = R_RACP_OCTAL;
			return r_dualbuf_retrieve_tok (&lex->b, start, current);
		case 10:
			lex->type = R_RACP_MATH;
			return r_dualbuf_retrieve_tok (&lex->b, start, current);
		case 11:
			current = r_dualbuf_next_charp (&lex->b);
			if (isdigit (*current)) {
				status = 11;
				continue;
			}
			status = 12;
			continue;
		case 12:
			current = r_dualbuf_prev_charp (&lex->b);
			lex->type = R_RACP_DECIMAL;
			return r_dualbuf_retrieve_tok (&lex->b, start, current);
		case 13:
			current = r_dualbuf_next_charp (&lex->b);
			if (*current == '*') {
				status = 13;
				continue;
			}
			status = 14;
			continue;
		case 14:
			current = r_dualbuf_prev_charp (&lex->b);
			lex->type = R_RACP_INDIRECTION;
			return r_dualbuf_retrieve_tok (&lex->b, start, current);
		case 15:
			current = r_dualbuf_next_charp (&lex->b);
			if (isalnum (*current) || *current == '_') {
				status = 15;
				continue;
			}
			status = 16;
			continue;
		case 16: {
			int i;
			current = r_dualbuf_prev_charp (&lex->b);
			char * tok = r_dualbuf_retrieve_tok (&lex->b, start, current);
			for (i = 0; reservedwords[i]; i++) {
				if (!strcmp (tok, reservedwords[i])) {
					lex->type = R_RACP_RESERVED;
					return tok;
				}
			}
			lex->type = R_RACP_IDENTIFIER;
			return tok;
		}
		case 17:
			lex->type = R_RACP_PUNCTUATION;
			return r_dualbuf_retrieve_tok (&lex->b, start, current);
		case 18:
			lex->type = R_RACP_ASSIGN;
			return r_dualbuf_retrieve_tok (&lex->b, start, current);
		case 19:
			current = r_dualbuf_next_charp (&lex->b);
			if (*current == '/') {
				status = 20;
				continue;
			}
			if (*current == '*') {
				status = 21;
				continue;
			}
			status = 23;
			continue;
		case 20:
			current = r_dualbuf_next_charp (&lex->b);
			counter = 0;
			if (*current =='\n') {
				status = 0;
			}
			continue;
		case 21:
			current = r_dualbuf_next_charp (&lex->b);
			counter = 0;
			if (*current == '*') {
				status = 22;
			}
			continue;
		case 22:
			current = r_dualbuf_next_charp (&lex->b);
			counter = 0;
			if (*current == '/') {
				status = 0;
				continue;
			}
			if (*current == '*') {
				continue;
			}
			status = 21;
			continue;
		case 23:
			current = r_dualbuf_prev_charp (&lex->b);
			lex->type = R_RACP_MATH;
			return r_dualbuf_retrieve_tok (&lex->b, start, current);
		}
	}
	lex->type = R_RACP_COMPLETED;
	return NULL;
}
R_API char *r_parse_c_file(const char *path) {
	RLex lex;
	FILE *f = fopen (path, "r");
	if (!f) {
		eprintf ("failed to open the file\n");
		return NULL;
	}
	r_dualbuf_init (&lex.b, f);
	char *tok;
	while(1) {
		tok = racp_get_next_token (&lex);
		if (lex.type == R_RACP_ERROR) {
			eprintf ("Error: Parsing stopped\n");
		}
		if (tok == NULL) {
			break;
		}
		switch (lex.type) {
		case R_RACP_BINARY:
			eprintf ("%s is binary number\n", tok);
			break;
		case R_RACP_HEX:
			eprintf ("%s is hex number\n", tok);
			break;
		case R_RACP_OCTAL:
			eprintf ("%s is octal number\n", tok);
			break;
		case R_RACP_DECIMAL:
			eprintf ("%s is decimal number\n", tok);
			break;
		case R_RACP_INDIRECTION:
			eprintf ("%s is pointer\n", tok);
			break;
		case R_RACP_RESERVED:
			eprintf ("%s is reserved word\n", tok);
			break;
		case R_RACP_IDENTIFIER:
			eprintf ("%s is identifier\n", tok);
			break;
		case R_RACP_PUNCTUATION:
			eprintf ("%s is symbol\n", tok);
			break;
		case R_RACP_ASSIGN:
			eprintf ("%s is and equal\n", tok);
			break;
		case R_RACP_MATH:
			eprintf ("%s is math operation\n", tok);
			break;
		}
		free (tok);
	}
	r_dualbuf_destroy (&lex.b);
	fclose (f);
	return NULL;
}

R_API char *r_parse_c_string(const char *code) {
	return NULL;
}
