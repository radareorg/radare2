/* radare - LGPL - Copyright 2009-2016 - pancake */

#include <r_reg.h>
#include <r_util.h>
#include <r_lib.h>

static const char *parse_alias(RReg *reg, char **tok, const int n) {
	if (n == 2) {
		int role = r_reg_get_name_idx (tok[0] + 1);
		return r_reg_set_name (reg, role, tok[1])
			? NULL : "Invalid alias";
	}
	return "Invalid syntax";
}

// Sizes prepended with a dot are expressed in bits
// strtoul with base 0 allows the input to be in decimal/octal/hex format

static ut64 parse_size(char *s, char **end) {
	ut64 r = 0;
	if (*s == '.') {
		r = strtoul (s + 1, end, 10);
	} else {
		char *has_dot = strchr (s, '.');
		if (has_dot) {
			*has_dot = 0;
			r = strtoul (s, end, 0) << 3;
			r += strtoul (has_dot + 1, end, 0);
		} else {
			r = strtoul (s, end, 0) << 3;
		}
	}
	return r;
}

static const char *parse_def(RReg *reg, char **tok, const int n) {
	RRegItem *item;
	char *end;
	int type;

	if (n != 5 && n != 6)
		return "Invalid syntax";

	type = r_reg_type_by_name (tok[0]);
	if (type < 0) {
		return "Invalid register type";
	}

	item = R_NEW0 (RRegItem);
	if (!item) return "Unable to allocate memory";

	item->type = type;
	item->name = strdup (tok[1]);
	// All the numeric arguments are strictly checked
	item->size = parse_size (tok[2], &end);
	if (*end != '\0' || !item->size) {
		r_reg_item_free (item);
		return "Invalid size";
	}
	item->offset = parse_size (tok[3], &end);
	if (*end != '\0') {
		r_reg_item_free (item);
		return "Invalid offset";
	}
	item->packed_size = parse_size (tok[4], &end);
	if (*end != '\0') {
		r_reg_item_free (item);
		return "Invalid packed size";
	}

	// Dynamically update the list of supported bit sizes
	reg->bits |= item->size;

	// This is optional
	if (n == 6)
		item->flags = strdup (tok[5]);

	// Don't allow duplicate registers
	if (r_reg_get (reg, item->name, R_REG_TYPE_ALL)) {
		r_reg_item_free (item);
		return "Duplicate register definition";
	}
	/* Hack to put flags in the same arena as gpr */
	if (type == R_REG_TYPE_FLG) {
		type = R_REG_TYPE_GPR;
	}

	r_list_append (reg->regset[item->type].regs, item);

	// Update the overall profile size
	if (item->offset + item->size > reg->size) {
		reg->size = item->offset + item->size;
	}
	return NULL;
}

#define PARSER_MAX_TOKENS 8

R_API int r_reg_set_profile_string(RReg *reg, const char *str) {
	char *tok[PARSER_MAX_TOKENS];
	char tmp[128];
	int i, j, l;
	const char *p = str;

	if (!reg || !str)
		return false;

	// Same profile, no need to change
	if (reg->reg_profile_str && !strcmp (reg->reg_profile_str, str))
		return true;

	// we should reset all the arenas before setting the new reg profile
	r_reg_arena_pop (reg);
	// Purge the old registers
	r_reg_free_internal (reg, true);

	// Cache the profile string
	reg->reg_profile_str = strdup (str);

	// Line number
	l = 0;
	// For every line
	do {
		// Increment line number
		l++;
		// Skip comment lines
		if (*p == '#') {
			const char *q = p;
			while (*q != '\n')
				q++;
			reg->reg_profile_cmt = r_str_concatlen (
				reg->reg_profile_cmt, p, (int)(q - p) + 1);
			p = q;
			continue;
		}
		j = 0;
		// For every word
		while (*p) {
			// Skip the whitespace
			while (*p == ' ' || *p == '\t')
				p++;
			// Skip the rest of the line is a comment is encountered
			if (*p == '#') {
				while (*p != '\n')
					p++;
			}
			// EOL ?
			if (*p == '\n')
				break;
			// Gather a handful of chars
			// Use isgraph instead of isprint because the latter considers ' ' printable
			for (i = 0; isgraph ((const unsigned char)*p) && i < sizeof (tmp) - 1;) {
				tmp[i++] = *p++;
			}
			tmp[i] = '\0';
			// Limit the number of tokens
			if (j > PARSER_MAX_TOKENS - 1)
				break;
			// Save the token
			tok[j++] = strdup (tmp);
		}
		// Empty line, eww
		if (j) {
			// Do the actual parsing
			char *first = tok[0];
			// Check whether it's defining an alias or a register
			const char *r = (*first == '=')
				? parse_alias (reg, tok, j)
				: parse_def (reg, tok, j);
			// Clean up
			for (i = 0; i < j; i++)
				free (tok[i]);
			// Warn the user if something went wrong
			if (r) {
				eprintf ("%s: Parse error @ line %d (%s)\n",
					__FUNCTION__, l, r);
				//eprintf ("(%s)\n", str);
				// Clean up
				r_reg_free_internal (reg, false);
				return false;
			}
		}
	} while (*p++);

	// Align to byte boundary if needed
	if (reg->size & 7) {
		reg->size += 8 - (reg->size & 7);
	}
	reg->size >>= 3; // bits to bytes (divide by 8)
	r_reg_fit_arena (reg);

	// dup the last arena to allow regdiffing
	r_reg_arena_push (reg);
	r_reg_reindex (reg);
	// reset arenas
	return true;
}

R_API int r_reg_set_profile(RReg *reg, const char *profile) {
	int ret;
	char *base, *file;
	char *str = r_file_slurp (profile, NULL);
	if (!str) {
		base = r_sys_getenv (R_LIB_ENV);
		if (base) {
			file = r_str_concat (base, profile);
			str = r_file_slurp (file, NULL);
			free (file);
		}
	}

	if (!str) {
		eprintf ("r_reg_set_profile: Cannot find '%s'\n", profile);
		return false;
	}

	ret = r_reg_set_profile_string (reg, str);
	free (str);
	return ret;
}
