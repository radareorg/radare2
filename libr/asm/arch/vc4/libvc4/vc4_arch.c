#ifndef _GNU_SOURCE
#define _GNU_SOURCE         /* See feature_test_macros(7) */
#endif
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <inttypes.h>
#include <assert.h>
#include <ctype.h>

#include "vc4.h"

static int vc4_isopcode(char ch)
{
	return strchr("01?!abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ", ch) != NULL;
}

static struct vc4_decode_table *vc4_read_table(char ch, const char *s)
{
	struct vc4_decode_table *t = (struct vc4_decode_table *)malloc(sizeof(struct vc4_decode_table));
	char *d;

	t->next = NULL;
	t->code = ch;
	t->count = 0;

	while (*s) {
		while (isspace(*s)) {
			s++;
			if (!*s) {
				assert(t->count > 0);
				return t;
			}
		}

		if (*s != '"') {
			fprintf(stderr, "No opening quote in table! [%c]\n", *s);
			abort();
		}
		s++;
		d = t->tab[t->count];
		while (*s && *s != '"')
			*d++ = *s++;
		*d = 0;

		if (*s != '"') {
			fprintf(stderr, "No closing quote in table! [%c]\n", *s);
			abort();
		}
		s++;

		t->count++;

		while (isspace(*s)) {
			s++;
		}

		if (!*s)
			return t;

		if (*s != ',') {
			fprintf(stderr, "No comma in table! [%d:%s]\n", *s, s);
			abort();
		}
		s++;
	}

	return t;
}

static int vc4_remove_comment(char *p)
{
	int in_quote = 0;
	int empty = 1;
	char *start = p;

	while (*p) {
		if (*p == '\"') {
			in_quote ^= 1;
			empty = 0;
		} else if (*p == '#' && !in_quote) {
			*p = 0;
			return empty;
		} else if (!isspace(*p)) {
			empty = 0;
		}
		p++;
	}
	while (p > start && isspace(p[-1])) {
		*--p = 0;
	}
	return empty;
}

static int match_c(const char *src, const char *o_fmt, char *c0)
{
	char fmt[256];
	int r;
	int len = -1;

	strcpy(fmt, o_fmt);
	strcat(fmt, "%n");

	r = sscanf(src, fmt, c0, &len);

	return (r >= 1) && (len > 0) && ((size_t)len == strlen(src));
}

static int match_cc(const char *src, const char *o_fmt, char *c0, char *c1)
{
	char fmt[256];
	int r;
	int len = 0;

	strcpy(fmt, o_fmt);
	strcat(fmt, "%n");

	r = sscanf(src, fmt, c0, c1, &len);

	return (r >= 2) && (len > 0) && ((size_t)len == strlen(src));
}

static int match_sc(const char *src, const char *o_fmt, char *s0, char *c0)
{
	char fmt[256];
	int r;
	int len = -1;

	strcpy(fmt, o_fmt);
	strcat(fmt, "%n");

	r = sscanf(src, fmt, s0, c0, &len);

	return (r >= 2) && (len > 0) && ((size_t)len == strlen(src));
}

static int match_scc(const char *src, const char *o_fmt, char *s0, char *c0, char *c1)
{
	char fmt[256];
	int r;
	int len = -1;

	strcpy(fmt, o_fmt);
	strcat(fmt, "%n");

	r = sscanf(src, fmt, s0, c0, c1, &len);

	return (r >= 3) && (len > 0) && ((size_t)len == strlen(src));
}

uint32_t vc4_op_get_val_width(const struct vc4_opcode *op, char code)
{
	uint32_t width;

	assert(op != NULL);

	if (code >= 'a' && code <= 'z')
		width = op->vals_lc[code - 'a'].length;
	else if (code >= 'A' && code <= 'Z')
		width = op->vals_uc[code - 'A'].length;
	else
		assert(0);

	return width;
}

static void vc4_classify_param(const struct vc4_opcode *op, struct vc4_param *par)
{
	char ch;
	char ch2;
	char extra[32];
	size_t width;

	if (match_c(par->txt, "r%%i{%c}", &ch) ||
	    match_c(par->txt, "r%%d{%c}", &ch)) {

		assert(ch >= 'a' && ch <= 'z');
		width = vc4_op_get_val_width(op, ch);
		assert(width == 4 || width == 5);
		if (width == 4) {
			par->type = vc4_p_reg_0_15;
		} else {
			par->type = vc4_p_reg_0_31;
		}
		par->reg_width = width;
		par->reg_code = ch;

	} else if (match_cc(par->txt, "r%%i{%c} shl #%%i{%c}", &ch, &ch2) ||
		   match_cc(par->txt, "r%%d{%c} shl #%%i{%c}", &ch, &ch2)) {

		assert(ch >= 'a' && ch <= 'z');
		assert(ch2 >= 'a' && ch2 <= 'z');
		width = op->vals_lc[ch - 'a'].length;
		assert(width == 5);
		par->type = vc4_p_reg_shl;
		par->reg_width = width;
		par->reg_code = ch;

		width = op->vals_lc[ch2 - 'a'].length;
		assert(width >= 1);
		par->num_width = width;
		par->num_code = ch2;

	} else if (match_cc(par->txt, "r%%i{%c} shl #%%i{%c+1}", &ch, &ch2) ||
		   match_cc(par->txt, "r%%d{%c} shl #%%i{%c+1}", &ch, &ch2) ||
		   match_cc(par->txt, "r%%i{%c} shl %%d{%c+1}", &ch, &ch2) ||
		   match_cc(par->txt, "r%%d{%c} shl %%d{%c+1}", &ch, &ch2)) {

		assert(ch >= 'a' && ch <= 'z');
		assert(ch2 >= 'a' && ch2 <= 'z');
		width = op->vals_lc[ch - 'a'].length;
		assert(width == 5);
		par->type = vc4_p_reg_shl_p1;
		par->reg_width = width;
		par->reg_code = ch;

		width = op->vals_lc[ch2 - 'a'].length;
		assert(width >= 1);
		par->num_width = width;
		par->num_code = ch2;

	} else if (match_cc(par->txt, "#%%i{%c} shl #%%i{%c+1}", &ch, &ch2) ||
		   match_cc(par->txt, "#%%d{%c} shl #%%i{%c+1}", &ch, &ch2) ||
		   match_cc(par->txt, "#%%i{%c} shl %%d{%c+1}", &ch, &ch2) ||
		   match_cc(par->txt, "#%%d{%c} shl %%d{%c+1}", &ch, &ch2)) {

		assert(ch >= 'a' && ch <= 'z');
		assert(ch2 >= 'a' && ch2 <= 'z');
		width = op->vals_lc[ch - 'a'].length;
		par->type = vc4_p_num_u_shl_p1;
		par->reg_width = width;
		par->reg_code = ch;

		width = op->vals_lc[ch2 - 'a'].length;
		assert(width >= 1);
		par->num_width = width;
		par->num_code = ch2;

	} else if (match_cc(par->txt, "r%%i{%c} lsr #%%i{%c}", &ch, &ch2) ||
		   match_cc(par->txt, "r%%d{%c} lsr #%%i{%c}", &ch, &ch2)) {

		assert(ch >= 'a' && ch <= 'z');
		assert(ch2 >= 'a' && ch2 <= 'z');
		width = op->vals_lc[ch - 'a'].length;
		assert(width == 5);
		par->type = vc4_p_reg_lsr;
		par->reg_width = width;
		par->reg_code = ch;

		width = op->vals_lc[ch2 - 'a'].length;
		assert(width >= 1);
		par->num_width = width;
		par->num_code = ch2;

	} else if (match_cc(par->txt, "r%%i{%c} lsr #%%i{%c+1}", &ch, &ch2) ||
		   match_cc(par->txt, "r%%d{%c} lsr #%%i{%c+1}", &ch, &ch2) ||
		   match_cc(par->txt, "r%%i{%c} lsr #%%d{%c+1}", &ch, &ch2) ||
		   match_cc(par->txt, "r%%d{%c} lsr #%%d{%c+1}", &ch, &ch2) ||
		   match_cc(par->txt, "r%%i{%c} lsr %%i{%c+1}", &ch, &ch2) ||
		   match_cc(par->txt, "r%%d{%c} lsr %%i{%c+1}", &ch, &ch2) ||
		   match_cc(par->txt, "r%%i{%c} lsr %%d{%c+1}", &ch, &ch2) ||
		   match_cc(par->txt, "r%%d{%c} lsr %%d{%c+1}", &ch, &ch2)) {

		assert(ch >= 'a' && ch <= 'z');
		assert(ch2 >= 'a' && ch2 <= 'z');
		width = op->vals_lc[ch - 'a'].length;
		assert(width == 5);
		par->type = vc4_p_reg_lsr_p1;
		par->reg_width = width;
		par->reg_code = ch;

		width = op->vals_lc[ch2 - 'a'].length;
		assert(width >= 1);
		par->num_width = width;
		par->num_code = ch2;

	} else if (match_cc(par->txt, "#%%i{%c} lsr #%%i{%c+1}", &ch, &ch2) ||
		   match_cc(par->txt, "#%%d{%c} lsr #%%i{%c+1}", &ch, &ch2) ||
		   match_cc(par->txt, "#%%i{%c} lsr #%%d{%c+1}", &ch, &ch2) ||
		   match_cc(par->txt, "#%%d{%c} lsr #%%d{%c+1}", &ch, &ch2) ||
		   match_cc(par->txt, "#%%i{%c} lsr %%i{%c+1}", &ch, &ch2) ||
		   match_cc(par->txt, "#%%d{%c} lsr %%i{%c+1}", &ch, &ch2) ||
		   match_cc(par->txt, "#%%i{%c} lsr %%d{%c+1}", &ch, &ch2) ||
		   match_cc(par->txt, "#%%d{%c} lsr %%d{%c+1}", &ch, &ch2)) {

		assert(ch >= 'a' && ch <= 'z');
		assert(ch2 >= 'a' && ch2 <= 'z');
		width = op->vals_lc[ch - 'a'].length;
		par->type = vc4_p_num_u_lsr_p1;
		par->reg_width = width;
		par->reg_code = ch;

		width = op->vals_lc[ch2 - 'a'].length;
		assert(width >= 1);
		par->num_width = width;
		par->num_code = ch2;

	} else if (match_cc(par->txt, "#%%i{%c} shl #%%i{%c+1}", &ch, &ch2) ||
		   match_cc(par->txt, "#%%d{%c} shl #%%i{%c+1}", &ch, &ch2)) {

		assert(ch >= 'a' && ch <= 'z');
		assert(ch2 >= 'a' && ch2 <= 'z');
		width = op->vals_lc[ch - 'a'].length;
		assert(width == 5);
		if (ch == 'i' || ch == 'o') {
			par->type = vc4_p_num_s_shl_p1;
		} else {
			par->type = vc4_p_num_u_shl_p1;
		}
		par->reg_width = width;
		par->reg_code = ch;

		width = op->vals_lc[ch2 - 'a'].length;
		assert(width >= 1);
		par->num_width = width;
		par->num_code = ch2;

	} else if (match_c(par->txt, "r%%i{%c} shl 8", &ch) ||
		   match_c(par->txt, "r%%d{%c} shl 8", &ch)) {

		assert(ch >= 'a' && ch <= 'z');
		width = op->vals_lc[ch - 'a'].length;
		assert(width == 5);
		par->type = vc4_p_reg_shl_8;
		par->reg_width = width;
		par->reg_code = ch;

	} else if (match_c(par->txt, "r%%d{%c*8}", &ch)) {

		assert(ch >= 'a' && ch <= 'z');
		width = op->vals_lc[ch - 'a'].length;
		assert(width == 2);
		par->type = vc4_p_reg_0_6_16_24;
		par->reg_width = width;
		par->reg_code = ch;

	} else if (match_c(par->txt, "(r%%i{%c})", &ch)) {

		assert(ch >= 'a' && ch <= 'z');
		width = op->vals_lc[ch - 'a'].length;
		assert(width == 4 || width == 5);
		par->type = (width == 4) ? vc4_p_addr_reg_0_15 : vc4_p_addr_reg_0_31;
		par->reg_width = width;
		par->reg_code = ch;

	} else if (match_c(par->txt, "(r%%i{%c}", &ch)) {

		assert(ch >= 'a' && ch <= 'z');
		width = op->vals_lc[ch - 'a'].length;
		assert(width == 5);
		par->type = vc4_p_addr_2reg_begin_0_31;
		par->reg_width = width;
		par->reg_code = ch;

	} else if (match_c(par->txt, "r%%i{%c})", &ch)) {

		assert(ch >= 'a' && ch <= 'z');
		width = op->vals_lc[ch - 'a'].length;
		assert(width == 5);
		par->type = vc4_p_addr_2reg_end_0_31;
		par->reg_width = width;
		par->reg_code = ch;

	} else if (match_c(par->txt, "(r%%i{%c})++", &ch)) {

		assert(ch >= 'a' && ch <= 'z');
		width = op->vals_lc[ch - 'a'].length;
		assert(width == 4 || width == 5);
		par->type = vc4_p_addr_reg_post_inc;
		par->reg_width = width;
		par->reg_code = ch;

	} else if (match_c(par->txt, "--(r%%i{%c})", &ch)) {

		assert(ch >= 'a' && ch <= 'z');
		width = op->vals_lc[ch - 'a'].length;
		assert(width == 4 || width == 5);
		par->type = vc4_p_addr_reg_pre_dec;
		par->reg_width = width;
		par->reg_code = ch;

	} else if (match_c(par->txt, "#%%i{%c}", &ch) ||
		   match_c(par->txt, "#%%d{%c}", &ch) ||
		   match_sc(par->txt, "#0x%%%[0-9]x{%c}", extra, &ch) ||
		   match_sc(par->txt, "0x%%%[0-9]x{%c}", extra, &ch)  ||
		   match_c(par->txt, "0x%%x{%c}", &ch) ||
		   match_c(par->txt, "%%x{%c}", &ch) ||
		   match_c(par->txt, "%%d{%c}", &ch)) {

		assert(ch >= 'a' && ch <= 'z');
		width = op->vals_lc[ch - 'a'].length;
		assert(width >= 1);
		if (ch == 'i' || ch == 'o') {
			par->type = vc4_p_num_s;
		} else {
			par->type = vc4_p_num_u;
		}
		par->num_width = width;
		par->num_code = ch;

	} else if (match_sc(par->txt, "#0x%%%[0-9]x{%c*4}", extra, &ch) ||
		   match_sc(par->txt, "0x%%%[0-9]x{%c*4}", extra, &ch)  ||
		   match_c(par->txt, "#0x%%x{%c*4}", &ch) ||
		   match_c(par->txt, "0x%%x{%c*4}", &ch) ||
		   match_c(par->txt, "%%x{%c*4}", &ch)) {

		assert(ch >= 'a' && ch <= 'z');
		width = op->vals_lc[ch - 'a'].length;
		assert(width >= 1);
		if (ch == 'i' || ch == 'o') {
			par->type = vc4_p_num_s4;
		} else {
			par->type = vc4_p_num_u4;
		}
		par->num_width = width;
		par->num_code = ch;

	} else if (match_scc(par->txt, "0x%%%[0-9]x{%c}(r%%i{%c})", extra, &ch, &ch2) ||
		   match_cc(par->txt, "0x%%x{%c}(r%%i{%c})", &ch, &ch2)) {

		assert(ch >= 'a' && ch <= 'z');
		assert(ch2 >= 'a' && ch2 <= 'z');
		width = op->vals_lc[ch - 'a'].length;
		assert(width >= 1);
		if (ch == 'i' || ch == 'o') {
			par->type = vc4_p_addr_reg_num_s;
		} else {
			par->type = vc4_p_addr_reg_num_u;
		}
		par->num_width = width;
		par->num_code = ch;

		width = op->vals_lc[ch2 - 'a'].length;
		assert(width == 4 || width == 5);
		par->reg_width = width;
		par->reg_code = ch2;

	} else if (match_scc(par->txt, "#0x%%%[0-9]x{%c*4}(r%%i{%c})", extra, &ch, &ch2) ||
		   match_scc(par->txt, "0x%%%[0-9]x{%c*4}(r%%i{%c})", extra, &ch, &ch2)  ||
		   match_cc(par->txt, "#0x%%x{%c*4}(r%%i{%c})", &ch, &ch2) ||
		   match_cc(par->txt, "0x%%x{%c*4}(r%%i{%c})", &ch, &ch2) ||
		   match_cc(par->txt, "%%x{%c*4}(r%%i{%c})", &ch, &ch2)) {

		assert(ch >= 'a' && ch <= 'z');
		width = op->vals_lc[ch - 'a'].length;
		assert(width >= 1);
		if (ch == 'i' || ch == 'o') {
			par->type = vc4_p_addr_reg_0_15_num_s4;
		} else {
			par->type = vc4_p_addr_reg_0_15_num_u4;
		}
		par->num_width = width;
		par->num_code = ch;

		width = op->vals_lc[ch2 - 'a'].length;
		assert(width == 4);
		par->reg_width = width;
		par->reg_code = ch2;

	} else if (match_sc(par->txt, "0x%%%[0-9]x{$+%c}", extra, &ch)) {

		assert(ch >= 'a' && ch <= 'z');
		width = op->vals_lc[ch - 'a'].length;
		assert(width >= 1);
		assert(ch == 'i' || ch == 'o');
		par->type = vc4_p_pc_rel_s;
		par->num_width = width;
		par->num_code = ch;

	} else if (match_sc(par->txt, "0x%%%[0-9]x{$+%c*2}", extra, &ch)) {

		assert(ch >= 'a' && ch <= 'z');
		width = op->vals_lc[ch - 'a'].length;
		assert(width >= 1);
		assert(ch == 'i' || ch == 'o');
		par->type = vc4_p_pc_rel_s2;
		par->num_width = width;
		par->num_code = ch;

	} else if (match_sc(par->txt, "0x%%%[0-9]x{$+%c*4}", extra, &ch)) {

		assert(ch >= 'a' && ch <= 'z');
		width = op->vals_lc[ch - 'a'].length;
		assert(width >= 1);
		assert(ch == 'i' || ch == 'o');
		par->type = vc4_p_pc_rel_s4;
		par->num_width = width;
		par->num_code = ch;

	} else if (match_sc(par->txt, "0x%%%[0-9]x{%c}(sp)", extra, &ch) ||
		   match_c(par->txt, "0x%%x{%c}(sp)", &ch)) {

		assert(ch >= 'a' && ch <= 'z');
		width = op->vals_lc[ch - 'a'].length;
		assert(width >= 1);
		assert(ch == 'i' || ch == 'o');
		par->type = vc4_p_sp_rel_s;
		par->num_width = width;
		par->num_code = ch;

	} else if (match_sc(par->txt, "0x%%%[0-9]x{%c*4}(sp)", extra, &ch) ||
		   match_c(par->txt, "0x%%x{%c*4}(sp)", &ch)) {

		assert(ch >= 'a' && ch <= 'z');
		width = op->vals_lc[ch - 'a'].length;
		assert(width >= 1);
		assert(ch == 'i' || ch == 'o');
		par->type = vc4_p_sp_rel_s4;
		par->num_width = width;
		par->num_code = ch;

	} else if (match_sc(par->txt, "0x%%%[0-9]x{%c}(r24)", extra, &ch) ||
		   match_c(par->txt, "0x%%x{%c}(r24)", &ch)) {

		assert(ch >= 'a' && ch <= 'z');
		width = op->vals_lc[ch - 'a'].length;
		assert(width >= 1);
		assert(ch == 'i' || ch == 'o');
		par->type = vc4_p_r24_rel_s;
		par->num_width = width;
		par->num_code = ch;

	} else if (match_sc(par->txt, "0x%%%[0-9]x{%c*4}(r24)", extra, &ch) ||
		   match_c(par->txt, "0x%%x{%c*4}(r24)", &ch)) {

		assert(ch >= 'a' && ch <= 'z');
		width = op->vals_lc[ch - 'a'].length;
		assert(width >= 1);
		assert(ch == 'i' || ch == 'o');
		par->type = vc4_p_r24_rel_s4;
		par->num_width = width;
		par->num_code = ch;

	} else if (match_sc(par->txt, "0x%%%[0-9]x{%c}(pc)", extra, &ch) ||
		   match_c(par->txt, "0x%%x{%c}(pc)", &ch)) {

		assert(ch >= 'a' && ch <= 'z');
		width = op->vals_lc[ch - 'a'].length;
		assert(width >= 1);
		assert(ch == 'i' || ch == 'o');
		par->type = vc4_p_pc_rel_s;
		par->num_width = width;
		par->num_code = ch;

	} else if (match_sc(par->txt, "0x%%%[0-9]x{%c*4}(pc)", extra, &ch) ||
		   match_c(par->txt, "0x%%x{%c*4}(pc)", &ch)) {

		assert(ch >= 'a' && ch <= 'z');
		width = op->vals_lc[ch - 'a'].length;
		assert(width >= 1);
		assert(ch == 'i' || ch == 'o');
		par->type = vc4_p_pc_rel_s4;
		par->num_width = width;
		par->num_code = ch;

	} else if (match_sc(par->txt, "0x%%%[0-9]x{%c}(r0)", extra, &ch) ||
		   match_c(par->txt, "0x%%x{%c}(r0)", &ch)) {

		assert(ch >= 'a' && ch <= 'z');
		width = op->vals_lc[ch - 'a'].length;
		assert(width >= 1);
		assert(ch == 'i' || ch == 'o');
		par->type = vc4_p_r0_rel_s;
		par->num_width = width;
		par->num_code = ch;

	} else if (match_sc(par->txt, "0x%%%[0-9]x{%c*4}(r0)", extra, &ch) ||
		   match_c(par->txt, "0x%%x{%c*4}(r0)", &ch)) {

		assert(ch >= 'a' && ch <= 'z');
		width = op->vals_lc[ch - 'a'].length;
		assert(width >= 1);
		assert(ch == 'i' || ch == 'o');
		par->type = vc4_p_r0_rel_s4;
		par->num_width = width;
		par->num_code = ch;

	} else if (strcmp(par->txt, "r6") == 0) {

		par->type = vc4_p_reg_r6;

	} else if (strcmp(par->txt, "r6-r%d{6+n}") == 0 ||
		   strcmp(par->txt, "r6-r%d{(6+n)&31}") == 0) {

		par->type = vc4_p_reg_range_r6;
		par->reg_width = 2;
		par->reg_code = 'b';
		par->num_width = 5;
		par->num_code = 'n';

	} else if (strcmp(par->txt, "r%d{b*8}-r%d{(n+b*8)&31}") == 0) {

		par->type = vc4_p_reg_range;
		par->reg_width = 2;
		par->reg_code = 'b';
		par->num_width = 5;
		par->num_code = 'n';

	} else if (strcmp(par->txt, "pc") == 0) {

		par->type = vc4_p_reg_pc;

	} else if (strcmp(par->txt, "sp") == 0) {

		par->type = vc4_p_reg_sp;

	} else if (strcmp(par->txt, "lr") == 0) {

		par->type = vc4_p_reg_lr;

	} else if (strcmp(par->txt, "cpuid") == 0) {

		par->type = vc4_p_reg_cpuid;

	} else {

		fprintf(stderr, "Bad operand? <%s> <%s>\n", par->txt, op->format);
	} 
}

static void vc4_build_params(struct vc4_opcode *op)
{
	size_t i;
	char *fmt;
	char *c;
	char *p0;
	struct vc4_val vals[256];

	if (op->format[0] == '!')
		return;

	fmt = strdup(op->format);

	vc4_build_values(vals, op, NULL, 0);
	memcpy(op->vals_lc, &vals['a'], sizeof(op->vals_lc));
	memcpy(op->vals_uc, &vals['A'], sizeof(op->vals_uc));

	if ((c = strchr(fmt, ';')) != NULL) {
		*c = 0;
	}

	/* Remove any ? characters */
	while ((c = strchr(fmt, '?')) != NULL) {
		*c = ' ';
	}

	vc4_trim_space(fmt);

	op->num_params = 0;

	p0 = strchr(fmt, ' ');
	if (p0 != NULL) {

		for (;;) {
			while (isblank(*p0))
				p0++;

			char *p1 = strchr(p0, ',');
			if (p1 != NULL)
				*p1++ = 0;

			op->params[op->num_params++].txt = strdup(p0);
			assert(op->num_params <= VC4_MAX_PARAMS);

			if (p1 == NULL)
				break;

			p0 = p1;
			while (isblank(*p0))
				p0++;
		}
	}

	free(fmt);

	for (i=0; i<op->num_params; i++) {
		vc4_trim_space(op->params[i].txt);

		vc4_classify_param(op, &op->params[i]);
	}
}

static void vc4_parse_string16(const char *p, uint16_t *bitsp, uint16_t *maskp)
{
	uint16_t mask, val, fval;

	assert(strlen(p) >= 16);

	mask = 0x8000;
	val = fval = 0;
	while (mask) {
		if (*p == '0') {
			fval |= mask;
		} else if (*p == '1') {
			val |= mask;
			fval |= mask;
		} else {
		}
		mask >>= 1;
		p++;
	}

	*bitsp = val;
	*maskp = fval;
}

static void vc4_add_opcode(struct vc4_info *info, struct vc4_opcode *op)
{
	uint32_t i;

	assert(op->length >= 1 && op->length <= 5);

	vc4_parse_string16(op->string, &op->ins[0], &op->ins_mask[0]);

	op->mode = vc4_get_instruction_mode(op->ins[0]);

	vc4_build_params(op);

#if 0
	printf("> %-30s %s  %04x %d %d\n",
	       op->format, op->string, op->ins[0],
	       op->length, vc4_get_instruction_length(op->ins[0]));
	
	for (i = 0; i< op->num_params; i++) {
		printf("  p%d = %-15s %d %d %d %c\n", i + 1,
		       op->params[i].txt,
		       op->params[i].type,
		       op->params[i].reg_width,
		       op->params[i].num_width,
		       op->params[i].reg_code);
	}
#endif

	assert(op->length == vc4_get_instruction_length(op->ins[0]));

	for (i = 0; i <= (op->ins_mask[0] ^ 0xFFFFu); i++) {
		uint16_t x = op->ins[0] | (i & (op->ins_mask[0] ^ 0xFFFF));
		vc4_add_opcode_tab(&info->opcodes[x], op);
	}

	if (op->length == 1)
		return;

	vc4_parse_string16(op->string + 16, &op->ins[1], &op->ins_mask[1]);
}


static int scan_format(char *d, const char **pp)
{
	int bits = 0;
	const char *p = *pp;
	char *dd = d;

	for (;;) {
		if (isspace(*p)) {
			p++;
			continue;
		}
		if (*p == '"')
			break;
		if (*p == ':') {
			long count;
			char *end;
			assert(bits > 0);
			count = strtol(p+1, &end, 10);
			assert(count > 0 && count <= 32);
			while (count-- > 1) {
				if (d != NULL)
					*d++ = 	p[-1];
				bits++;
			}
			p = end;
		} else if (vc4_isopcode(p[0])) {
			if (d != NULL)
				*d++ = *p;
			p++;
			bits++;
		} else {
			return -1;
		}
	}
	if (d != NULL)
		*d = 0;
	*pp = p;
	assert(d == NULL || (d - dd) == bits);
	return bits;
}

static struct vc4_opcode *vc4_scan_opcode(const char *line)
{
	const char *p;
	char *format;
	int bits;
	struct vc4_opcode *op;

	p = line;
	bits = scan_format(NULL, &p);
	if  (bits < 0)
		return NULL;

	if ((bits % 16) != 0) {
		fprintf(stderr, "Wrong number of nybles 2!\n");
		abort();
	}

	while (*p && isspace(*p))
		p++;
	if (!*p)
		return NULL;

	if (*p != '"') {
		fprintf(stderr, "No opening \"");
		abort();
	}
	assert(p[1] == ';');
	assert(p[2] == ' ');
	format = strdup(p+3);
	if (!strchr(format, '\"')) {
		fprintf(stderr, "No closing \"! [%s] \n", format);
		abort();
	}
	*strchr(format, '"') = 0;

	op = (struct vc4_opcode *)calloc(1, sizeof(struct vc4_opcode));
	op->format = format;
	op->length = bits / 16;

	p = line;
	scan_format(op->string, &p);

	return op;
}

static void vc4_read_opcode(struct vc4_info *info, const char *line)
{
	struct vc4_opcode *op = vc4_scan_opcode(line);

	if (op != NULL) {
		vc4_add_opcode(info, op);

		op->next = info->all_opcodes;
		info->all_opcodes = op;
	}
}

struct vc4_info *vc4_read_arch_file(const char *path)
{
	FILE *fp;
	char *line = NULL;
	size_t len = 0;
	int n1, n2, n3;
	char ch;
	ssize_t r;
	struct vc4_info *inf;
	char buf2[2];

	fp = fopen(path, "r");
	if (fp == NULL) {
		perror("file open");
		exit(1);
	}

	inf = calloc(sizeof(struct vc4_info), 1);

	for (;;) {
		if ((r = getline(&line, &len, fp)) < 0)
			break;

		/* Remove any comment */
		if (vc4_remove_comment(line))
			continue;

		n1 = n2 = n3 = -1;
		if (sscanf(line, " ( define-signed %c ) ", &ch) == 1) {
			buf2[0] = ch;
			buf2[1] = 0;
			strcat(inf->signed_ops, buf2);
		} else if (sscanf(line, " ( define-table %c [ %n %*[^]] %n ] ) %n", &ch, &n1, &n2, &n3) >= 1 && n1 > 0 && n2 > 0 && n3 > 0) {
			line[n2] = 0;
			struct vc4_decode_table *t = vc4_read_table(ch, line + n1);
			/*fprintf(stderr, "Table %c (%d)\n", ch, t->count);*/
			t->next = inf->tables;
			inf->tables = t;
		} else {
			vc4_read_opcode(inf, line);
		}
	}

	free(line);

	fclose(fp);

	return inf;
}

void vc4_free_info(struct vc4_info *info)
{
	size_t i, j;

	while (info->all_opcodes != NULL) {
		struct vc4_opcode *op = info->all_opcodes;
		info->all_opcodes = op->next;

		for (j = 0; j < op->num_params; j++) {
			free(op->params[j].txt);
		}
		free(op->format);
		free(op);
	}

	while (info->tables != NULL) {
		struct vc4_decode_table *tab = info->tables;
		info->tables = tab->next;

		free(tab);
	}

	while (info->all_asms != NULL) {
		struct vc4_asm *as = info->all_asms;
		info->all_asms = as->next_all;

		free(as);
	}

	for (i=0; i<0x10000; i++) {
		free(info->opcodes[i]);
	}

	free(info->lookup_tab);

	free(info);
}

static int vc4_lookup_compare(const void *va, const void *vb)
{
	const struct vc4_lookup *a = (const struct vc4_lookup *)va;
	const struct vc4_lookup *b = (const struct vc4_lookup *)vb;
	return strcmp(a->str, b->str);
}

struct vc4_lookup *vc4_lookup_find(const struct vc4_info *inf, const char *name)
{
	struct vc4_lookup key;
	struct vc4_lookup *ret;

	if (inf->lookup_count == 0)
		return NULL;

	key.str = name;
	key.chain = NULL;

	ret = bsearch(&key, inf->lookup_tab, inf->lookup_count,
		      sizeof(struct vc4_lookup), vc4_lookup_compare);
	return ret;
}

static struct vc4_lookup *vc4_lookup_add(struct vc4_info *inf, const char *name)
{
	struct vc4_lookup key;
	struct vc4_lookup *ret;

	ret = vc4_lookup_find(inf, name);
	if (ret != NULL)
		return ret;

	if (inf->lookup_count == 0) {
		inf->lookup_tab = malloc(sizeof(struct vc4_lookup));
	} else {
		inf->lookup_tab = realloc(
			inf->lookup_tab,
			(inf->lookup_count + 1) * sizeof(struct vc4_lookup));
	}

	assert(inf->lookup_tab != NULL);

	inf->lookup_tab[inf->lookup_count].str = name;
	inf->lookup_tab[inf->lookup_count].chain = NULL;
	inf->lookup_count++;

	qsort(inf->lookup_tab, inf->lookup_count,
	      sizeof(struct vc4_lookup), vc4_lookup_compare);

	key.str = name;
	key.chain = NULL;

	ret = bsearch(&key, inf->lookup_tab, inf->lookup_count,
		      sizeof(struct vc4_lookup), vc4_lookup_compare);
	assert(ret != NULL);
	return ret;
}

static void vc4_go_got_one(struct vc4_info *info,
			   struct vc4_opcode *op,
			   const char *str,
			   const struct vc4_op_pat *pat)
{
	struct vc4_asm *a = calloc(sizeof(struct vc4_asm), 1);
	uint16_t ins[5];
	uint16_t ins_mask[5];
	size_t i;
	struct vc4_lookup *lup;

	assert(a != NULL);

	ins[0] = op->ins[0];
	ins[1] = op->ins[1];
	ins[2] = ins[3] = ins[4] = 0;

	ins_mask[0] = op->ins_mask[0];
	ins_mask[1] = op->ins_mask[1];
	ins_mask[2] = ins_mask[3] = ins_mask[4] = 0;

	for (i=0; i<pat->count; i++) {
		vc4_fill_value(ins, ins_mask, op, pat->pat[i].code, pat->pat[i].val);
	}

	a->next = NULL;
	a->next_all = NULL;

	strcpy(a->str, str);
	a->pat = *pat;
	a->op = op;

	a->ins[0] = ins[0];
	a->ins[1] = ins[1];
	a->ins_mask[0] = ins_mask[0];
	a->ins_mask[1] = ins_mask[1];

	/* We need to keep this list in the original order. */
	if (info->all_asms == NULL) {
		assert(info->all_asms_tail == NULL);
		info->all_asms = a;
	} else {
		assert(info->all_asms_tail != NULL);
		info->all_asms_tail->next_all = a;
	}
	info->all_asms_tail = a;

	/* Add to lookup table of opcodes. */
	lup = vc4_lookup_add(info, a->str);
	a->next = lup->chain;
	lup->chain = a;
}

static void vc4_go_got_one_slash(struct vc4_info *info,
				 struct vc4_opcode *op,
				 const char *str,
				 const struct vc4_op_pat *base_pat)
{
	const char *c;
	char *p;
	char *q;

	vc4_go_got_one(info, op, str, base_pat);

	if ((c = strchr(str, '/')) == NULL) {
		return;
	}

	p = strdup(str);
	q = strchr(p, '/');
	*q = 0;
	vc4_go_got_one(info, op, p, base_pat);

	strcpy(p, str);
	q = strchr(p, '/');
	q[-2] = q[1];
	q[-1] = q[2];
	q[0] = 0;
	vc4_go_got_one(info, op, p, base_pat);

	free(p);
}

static void vc4_go_expand(struct vc4_info *info,
			  struct vc4_opcode *op,
			  const char *str,
			  const struct vc4_op_pat *base_pat)
{
	struct vc4_decode_table *t;
	char fmt[128];
	char exp[16];
	int l0, r;
	size_t i;
	const char *c;
	char *new_str;
	struct vc4_op_pat new_pat;
	uint32_t lim;

	if ((c = strchr(str, '%')) == NULL) {
		vc4_go_got_one_slash(info, op, str, base_pat);
		return;
	}

	l0 = -1;
	r = sscanf(c, "%127[^{]{%15[^}]}%n", fmt, exp, &l0);

	if (r < 2 || l0 < 1 || fmt[0] == 0 || exp[0] == 0) {
		fprintf(stderr, "bad line '%s'\n", str);
		//fprintf(stderr, "bad line  %s/%s/%s %d %d\n", fmt, exp, c+l0, l0, r);
		abort();
	}

	assert(strcmp(fmt, "%s") == 0);
	assert(strlen(exp) == 1);
	assert(exp[0] >= 'a' && exp[0] <= 'z');

	t = info->tables;
	while (t != NULL && t->code != exp[0]) {
		t = t->next;
	}
	assert(t != NULL);

	memcpy(&new_pat, base_pat, sizeof(struct vc4_op_pat));
	new_pat.count++;
	new_pat.pat[new_pat.count - 1].code = exp[0];

	lim = 1u << vc4_op_get_val_width(op, exp[0]);

	for (i = 0; i < lim; i++) {
		new_pat.pat[new_pat.count - 1].val = i;

		new_str = strndup(str, c - str);
		vc4_strcat(&new_str, t->tab[i]);
		vc4_strcat(&new_str, c + l0);

		vc4_go_expand(info, op, new_str, &new_pat);
		free(new_str);
	}
}

void vc4_get_opcodes(struct vc4_info *info)
{
	struct vc4_opcode *op;
	char str[32];
	struct vc4_op_pat pat;

	pat.count = 0;

	assert(info->all_asms == NULL);
	
	for (op = info->all_opcodes; op != NULL; op = op->next) {

		sscanf(op->format, "%31s ", str);
		if (str[0] != '!')
			vc4_go_expand(info, op, str, &pat);
	}
}
