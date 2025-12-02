#include <r_util.h>
#include "arch.h"

static ut64 parse_size(char *s, char **end) {
	if (*s == '.') {
		return strtoul (s + 1, end, 10);
	}
	char *has_dot = strchr (s, '.');
	if (has_dot) {
		*has_dot++ = 0;
		ut64 a = strtoul (s, end, 0) << 3;
		ut64 b = strtoul (has_dot, end, 0);
		return a + b;
	}
	return strtoul (s, end, 0) << 3;
}

gdb_reg_t *parse_def(char **tok) {
	char *end = NULL;
	gdb_reg_t *r = R_NEW0 (gdb_reg_t);
	r_str_ncpy (r->name, tok[1], sizeof (r->name));
	r->size = parse_size (tok[2], &end);
	if (*end != '\0' || !r->size) {
		free (r);
		return NULL;
	}
	if (R_STR_ISEMPTY (tok[3]) || !strcmp (tok[3], "?")) {
		free (r);
		return NULL;
	}
	r->offset = parse_size (tok[3], &end);
	return r;
}

#define PARSER_MAX_TOKENS 8
gdb_reg_t *arch_parse_reg_profile(const char *reg_profile) {
	char *tok[PARSER_MAX_TOKENS] = { 0 };
	char tmp[128];
	int i, j, l;
	const char *p = reg_profile;
	RList *gdb_regs_list = r_list_newf (free);
	RListIter *iter;
	gdb_reg_t *reg;

	// Line number
	l = 0;
	// For every line
	do {
		// Increment line number
		l++;
		// Skip comment lines
		if (*p == '#') {
			const char *q = p;
			while (*q != '\n') {
				q++;
			}
			p = q;
			continue;
		}
		j = 0;
		// For every word
		while (*p) {
			// Skip the whitespace
			while (*p == ' ' || *p == '\t') {
				p++;
			}
			// EOL?
			if (*p == '\n') {
				break;
			}
			if (*p == '#') {
				// Place the rest of the line in the token if a comment is encountered
				for (i = 0; *p != '\n'; p++) {
					if (i < sizeof (tmp) - 1) {
						tmp[i++] = *p;
					}
				}
			} else {
				// Save all characters up to a space/tab
				// Use isgraph instead of isprint because the latter considers ' ' printable
				for (i = 0; isgraph ((const unsigned char)*p) && i < sizeof (tmp) - 1;) {
					tmp[i++] = *p++;
				}
			}
			tmp[i] = '\0';
			// Limit the number of tokens
			if (j > PARSER_MAX_TOKENS - 1) {
				break;
			}
			// Save the token
			tok[j++] = strdup (tmp);
		}
		// Empty line, eww
		if (j) {
			// Do the actual parsing
			char *first = tok[0];
			// Check whether it's defining an alias or a register
			if (*first != '=') {
				reg = parse_def (tok);
				// Warn the user if something went wrong
				if (!reg) {
					R_LOG_ERROR ("%s: gdb_regs: Parse error @ line %d", __func__, l);
					for (i = 0; i < j; i++) {
						free (tok[i]);
					}
					// Clean up
					r_list_free (gdb_regs_list);
					return NULL;
				}
				r_list_append (gdb_regs_list, reg);
			}
			// Clean up
			for (i = 0; i < j; i++) {
				free (tok[i]);
			}
		}
	} while (*p++);

	gdb_reg_t *gdb_regs = malloc ((r_list_length (gdb_regs_list) + 1) * sizeof (gdb_reg_t));
	if (!gdb_regs) {
		return NULL;
	}
	i = 0;
	r_list_foreach (gdb_regs_list, iter, reg) {
		memcpy (gdb_regs + i, reg, sizeof (gdb_reg_t));
		i++;
	}
	memset (gdb_regs + i, 0, sizeof (gdb_reg_t));

	r_list_free (gdb_regs_list);
	return gdb_regs;
}
