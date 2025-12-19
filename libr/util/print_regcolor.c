/* radare2 - LGPL - Copyright 2007-2025 - pancake */

#include <r_util/r_print.h>
#include <r_util/r_str.h>
#include <r_anal.h>

static bool reg_rainbow_enabled(RPrint *print) {
	if (!print) {
		return false;
	}
	if (print->coreb.cfgGetB) {
		return print->coreb.cfgGetB (print->coreb.core, "scr.color.regs");
	}
	return false;
}

static bool is_not_token(const char p) {
	if (isalpha (p & 0xff) || isdigit (p & 0xff)) {
		return true;
	}
	switch (p) {
	case '.':
	case '_':
		return true;
	}
	return false;
}

static bool token_name(const char *p, char *name, size_t name_sz) {
	if (!p || !name || name_sz < 2) {
		return false;
	}
	p = r_str_trim_head_ro (p);
	while (*p == '%' || *p == '$') {
		p++;
	}
	p = r_str_trim_head_ro (p);
	if (!isalpha (*p & 0xff) && *p != '_') {
		return false;
	}
	size_t n = 0;
	while (p[n] && is_not_token (p[n])) {
		n++;
	}
	if (n < 1 || n >= name_sz) {
		return false;
	}
	memcpy (name, p, n);
	name[n] = '\0';
	return true;
}

static bool is_reg_stopword(const char *s) {
	static const char *words[] = {
		"byte", "word", "dword", "qword", "tbyte", "tword",
		"oword", "xmmword", "ymmword", "zmmword",
		"ptr", "short", "near", "far",
		NULL
	};
	int i;
	for (i = 0; words[i]; i++) {
		if (!strcmp (s, words[i])) {
			return true;
		}
	}
	return false;
}

static int reg_item_cmp(const RRegItem *a, const RRegItem *b) {
	const int offa = (a->offset * 16) + a->size;
	const int offb = (b->offset * 16) + b->size;
	if (offa != offb) {
		return (offa > offb) - (offa < offb);
	}
	if (a->type != b->type) {
		return (a->type > b->type) - (a->type < b->type);
	}
	return strcmp (a->name, b->name);
}

static int reg_item_rank(RReg *reg, const RRegItem *item) {
	int rank = 0;
	int i;
	RListIter *iter;
	RRegItem *r;
	for (i = 0; i < R_REG_TYPE_LAST; i++) {
		r_list_foreach (reg->regset[i].regs, iter, r) {
			if (r == item) {
				continue;
			}
			if (reg_item_cmp (r, item) < 0) {
				rank++;
			}
		}
	}
	return rank;
}

static int reg_palette_add_unique(const char **colors, int n, int max, const char *color) {
	if (n < 0 || n >= max || R_STR_ISEMPTY (color) || !strcmp (color, Color_RESET) || !strcmp (color, Color_RESET_NOBG)) {
		return n;
	}
	int i;
	for (i = 0; i < n; i++) {
		if (!strcmp (colors[i], color)) {
			return n;
		}
	}
	colors[n++] = color;
	return n;
}

static int reg_palette_colors(RConsPrintablePalette *pal, const char **colors, int max) {
	int n = 0;
	if (!pal || !colors || max < 1) {
		return 0;
	}
	// Prefer core semantic palette entries; avoid BG-only entries.
	n = reg_palette_add_unique (colors, n, max, pal->call);
	n = reg_palette_add_unique (colors, n, max, pal->jmp);
	n = reg_palette_add_unique (colors, n, max, pal->cjmp);
	n = reg_palette_add_unique (colors, n, max, pal->cmp);
	n = reg_palette_add_unique (colors, n, max, pal->mov);
	n = reg_palette_add_unique (colors, n, max, pal->nop);
	n = reg_palette_add_unique (colors, n, max, pal->push);
	n = reg_palette_add_unique (colors, n, max, pal->pop);
	n = reg_palette_add_unique (colors, n, max, pal->crypto);
	n = reg_palette_add_unique (colors, n, max, pal->ret);
	n = reg_palette_add_unique (colors, n, max, pal->trap);
	n = reg_palette_add_unique (colors, n, max, pal->swi);
	n = reg_palette_add_unique (colors, n, max, pal->num);
	n = reg_palette_add_unique (colors, n, max, pal->flag);
	n = reg_palette_add_unique (colors, n, max, pal->label);
	n = reg_palette_add_unique (colors, n, max, pal->args);
	n = reg_palette_add_unique (colors, n, max, pal->comment);
	n = reg_palette_add_unique (colors, n, max, pal->fname);
	n = reg_palette_add_unique (colors, n, max, pal->floc);
	n = reg_palette_add_unique (colors, n, max, pal->fline);
	n = reg_palette_add_unique (colors, n, max, pal->other);
	n = reg_palette_add_unique (colors, n, max, pal->var_name);
	n = reg_palette_add_unique (colors, n, max, pal->var_type);
	n = reg_palette_add_unique (colors, n, max, pal->var_addr);
	return n;
}

R_IPI bool r_print_reg_rainbow_enabled(RPrint *print) {
	return reg_rainbow_enabled (print);
}

R_IPI char *r_print_reg_rainbow_color(RPrint *print, const char *p) {
	if (!print || !reg_rainbow_enabled (print) || !print->consb.cons || !print->reg || !print->get_register) {
		return NULL;
	}
	char regname[64];
	if (!token_name (p, regname, sizeof (regname))) {
		return NULL;
	}
	if (is_reg_stopword (regname)) {
		return NULL;
	}
	RRegItem *item = print->get_register (print->reg, regname, R_REG_TYPE_ALL);
	if (!item) {
		return NULL;
	}
	const int rank = reg_item_rank (print->reg, item);
	r_unref (item);
	RCons *cons = print->consb.cons;
	if (!cons || !cons->context) {
		return NULL;
	}
	const char *colors[64];
	const int colors_sz = reg_palette_colors (&cons->context->pal, colors, (int)R_ARRAY_SIZE (colors));
	if (colors_sz < 1) {
		return NULL;
	}
	const int base = rank % colors_sz;
	const int variant = rank / colors_sz;
	const char *color = colors[base];
	if (variant & 1) {
		return r_str_newf ("%s%s", Color_BOLD, color);
	}
	return strdup (color);
}

