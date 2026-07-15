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

static gdb_reg_t *parse_def(char **tok) {
	char *end = NULL;
	gdb_reg_t *r = R_NEW0 (gdb_reg_t);
	r_str_ncpy (r->name, tok[1], sizeof (r->name));
	r->size = parse_size (tok[2], &end);
	if (!*end && r->size && !R_STR_ISEMPTY (tok[3]) && strcmp (tok[3], "?")) {
		r->offset = parse_size (tok[3], &end);
		if (!*end) {
			return r;
		}
	}
	free (r);
	return NULL;
}

#define PARSER_MAX_TOKENS 8

static void free_tokens(char **tok, int count) {
	int i;
	for (i = 0; i < count; i++) {
		free (tok[i]);
		tok[i] = NULL;
	}
}

gdb_reg_t *arch_parse_reg_profile(const char *reg_profile) {
	char *tok[PARSER_MAX_TOKENS] = { 0 };
	char tmp[128];
	int i, j = 0, l;
	if (!reg_profile) {
		return NULL;
	}
	const char *p = reg_profile;
	RList *gdb_regs_list = r_list_newf (free);
	if (!gdb_regs_list) {
		return NULL;
	}
	RListIter *iter;
	gdb_reg_t *reg;

	for (l = 1; *p; l++) {
		j = 0;
		while (*p && *p != '\n') {
			// Skip the whitespace
			while (*p == ' ' || *p == '\t') {
				p++;
			}
			if (!*p || *p == '\n') {
				break;
			}
			if (*p == '#') {
				while (*p && *p != '\n') {
					p++;
				}
				break;
			}
			if (j >= PARSER_MAX_TOKENS) {
				while (*p && *p != '\n') {
					p++;
				}
				break;
			}
			// Use isgraph instead of isprint because the latter considers ' ' printable
			for (i = 0; *p && isgraph ((ut8)*p) && i < sizeof (tmp) - 1; i++) {
				tmp[i] = *p++;
			}
			if (!i) {
				p++;
				continue;
			}
			tmp[i] = '\0';
			while (*p && isgraph ((ut8)*p)) {
				p++;
			}
			if (!(tok[j++] = strdup (tmp))) {
				goto fail;
			}
		}
		if (j) {
			if (*tok[0] != '=') {
				reg = j < 4 ? NULL : parse_def (tok);
				if (!reg) {
					R_LOG_ERROR ("%s: gdb_regs: Parse error @ line %d", __func__, l);
					goto fail;
				}
				r_list_append (gdb_regs_list, reg);
			}
			free_tokens (tok, j);
		}
		if (*p == '\n') {
			p++;
		}
	}

	gdb_reg_t *gdb_regs = R_NEWS0 (gdb_reg_t, r_list_length (gdb_regs_list) + 1);
	if (!gdb_regs) {
		goto fail;
	}
	i = 0;
	r_list_foreach (gdb_regs_list, iter, reg) {
		memcpy (gdb_regs + i, reg, sizeof (gdb_reg_t));
		i++;
	}
	r_list_free (gdb_regs_list);
	return gdb_regs;
fail:
	free_tokens (tok, j);
	r_list_free (gdb_regs_list);
	return NULL;
}
