#include <tree_sitter/parser.h>
#include <ctype.h>
#include <stdio.h>
#include <string.h>

#define CMD_IDENTIFIER_MAX_LENGTH 32

enum TokenType {
	CMD_IDENTIFIER,
	HELP_COMMAND,
	FILE_DESCRIPTOR,
	EQ_SEP_CONCAT,
	CONCAT,
	CONCAT_BRACE,
	CONCAT_PF_DOT,
};

void *tree_sitter_r2cmd_external_scanner_create() {
	return NULL;
}

void tree_sitter_r2cmd_external_scanner_destroy(void *payload) {
}

unsigned tree_sitter_r2cmd_external_scanner_serialize(void *payload, char *buffer) {
	return 0;
}

void tree_sitter_r2cmd_external_scanner_deserialize(void *payload, const char *buffer, unsigned length) {
}

static bool is_pf_cmd(const char *s) {
	return (strcmp (s, "pfo") && !strncmp (s, "pf", 2)) || !strcmp (s, "Cf");
}

static bool is_env_cmd(const char *s) {
	return !strncmp (s, "env", 3);
}

static bool is_at_cmd(const char *s) {
	return s[0] == '@';
}

static bool is_comment(const char *s) {
	return !strncmp (s, "/*", 2) || !strcmp (s, "#");
}

static bool is_special_start(const int32_t ch) {
	return ch == '*' || ch == '(' || ch == '@' || ch == '|' || ch == '>' ||
		ch == '.' || ch == '|' || ch == '%' || ch == '~' || ch == '&';
}

static bool is_start_of_command(const int32_t ch) {
	return isalpha (ch) || ch == '$' || ch == '?' || ch == ':' || ch == '+' || ch == '-'
		|| ch == '#' || ch == ',' || ch == '=' || ch == '/' || ch == '_' || ch == '\\'
		|| is_special_start (ch);
}

static bool is_mid_command(const char *res, int len, const int32_t ch) {
	if (res[0] == '#') {
		if (len == 1) {
			return ch == '!' || ch == '?';
		}
		return ch == '?';
	}
	return isalnum (ch) || ch == '$' || ch == '?' || ch == '.' || ch == '!' ||
		ch == ':' || ch == '+' || ch == '=' || ch == '/' || ch == '*' ||
		ch == '-' || ch == ',' || ch == '&' || (is_at_cmd (res) && ch == '@');
}

static bool is_concat(const int32_t ch) {
	return ch != '\0' && !isspace(ch) && ch != '#' && ch != '@' &&
		ch != '|' && ch != '>' && ch != ';' &&
		ch != ')' && ch != '`' && ch != '~' && ch != '\\';
}

static bool is_concat_brace(const int32_t ch) {
	return is_concat(ch) && ch != '}' && ch != '{';
}

static bool is_concat_pf_dot(const int32_t ch) {
	return is_concat(ch) && ch != '=';
}

static bool is_concat_eq_sep(const int32_t ch) {
	return is_concat(ch) && ch != '=';
}

static bool is_recursive_help(int id_len, const int32_t before_last_ch, const int32_t last_ch) {
	return id_len >= 2 && before_last_ch == '?' && last_ch == '*';
}

static bool scan_number(TSLexer *lexer, const bool *valid_symbols) {
	if (!valid_symbols[FILE_DESCRIPTOR]) {
		return false;
	}

	// skip spaces at the beginning
	while (isspace (lexer->lookahead)) {
		lexer->advance (lexer, true);
	}

	if (!isdigit (lexer->lookahead)) {
		return false;
	}
	lexer->advance (lexer, false);
	for (;;) {
		if (isdigit (lexer->lookahead)) {
			lexer->advance (lexer, false);
		} else if (lexer->lookahead != '>') {
			return false;
		} else {
			break;
		}
	}
	if (lexer->lookahead == '>') {
		lexer->result_symbol = FILE_DESCRIPTOR;
		return true;
	}
	return false;
}

bool tree_sitter_r2cmd_external_scanner_scan(void *payload, TSLexer *lexer, const bool *valid_symbols) {
	// FIXME: /* in the shell should become a multiline comment
	if (valid_symbols[CONCAT] && is_concat (lexer->lookahead)) {
		lexer->result_symbol = CONCAT;
		return true;
	} else if (valid_symbols[CONCAT_BRACE] && is_concat_brace (lexer->lookahead)) {
		lexer->result_symbol = CONCAT_BRACE;
		return true;
	} else if (valid_symbols[CONCAT_PF_DOT] && is_concat_pf_dot (lexer->lookahead)) {
		lexer->result_symbol = CONCAT_PF_DOT;
		return true;
	} else if (valid_symbols[EQ_SEP_CONCAT] && is_concat_eq_sep (lexer->lookahead)) {
		lexer->result_symbol = EQ_SEP_CONCAT;
		return true;
	}
	if (valid_symbols[CMD_IDENTIFIER] || valid_symbols[HELP_COMMAND]) {
		char res[CMD_IDENTIFIER_MAX_LENGTH + 1];
		int i_res = 0;

		while (isspace (lexer->lookahead)) {
			lexer->advance (lexer, true);
		}

		if (!is_start_of_command (lexer->lookahead)) {
			return false;
		}
		res[i_res++] = lexer->lookahead;
		lexer->advance (lexer, false);
		while (i_res < CMD_IDENTIFIER_MAX_LENGTH && is_mid_command (res, i_res, lexer->lookahead)) {
			res[i_res++] = lexer->lookahead;
			lexer->advance (lexer, false);
                }
		res[i_res] = '\0';
		if (is_comment (res)) {
			return false;
		}
		// ?? is not considered an help command, just a regular one
		if ((res[i_res - 1] == '?' && strcmp (res, "??")) || (i_res >= 2 && is_recursive_help (i_res, res[i_res - 2], res[i_res - 1]))) {
			if (i_res == 1) {
				return false;
			}
			lexer->result_symbol = HELP_COMMAND;
		} else {
			if (is_special_start (res[0]) || is_pf_cmd (res) || is_env_cmd (res) || is_at_cmd (res) || !valid_symbols[CMD_IDENTIFIER]) {
				return false;
			}
			lexer->result_symbol = CMD_IDENTIFIER;
		}
		return true;
	}
	if (valid_symbols[FILE_DESCRIPTOR]) {
		return scan_number (lexer, valid_symbols);
	}
	return false;
}
