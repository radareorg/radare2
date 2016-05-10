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

uint16_t vc4_get_le16(const uint8_t *b)
{
	return (uint16_t)b[0] | ((uint16_t)b[1] << 8);
}

enum vc4_ins_mode vc4_get_instruction_mode(uint16_t b0)
{
	if ((b0 & 0x8000) == 0)
		return VC4_INS_SCALAR16;
	else if ((b0 & 0x4000) == 0)
		return VC4_INS_SCALAR32_1;
	else if ((b0 & 0x2000) == 0)
		return VC4_INS_SCALAR32_2;
	else if ((b0 & 0x1000) == 0)
		return VC4_INS_SCALAR48;
	else if ((b0 & 0x0800) == 0)
		return VC4_INS_VECTOR48;
	else
		return VC4_INS_VECTOR80;
}

uint16_t vc4_get_instruction_length(uint16_t b0)
{
	if ((b0 & 0x8000) == 0)
		return 1;
	else if ((b0 & 0x4000) == 0)
		return 2;
	else if ((b0 & 0x2000) == 0)
		return 2;
	else if ((b0 & 0x1000) == 0)
		return 3;
	else if ((b0 & 0x0800) == 0)
		return 3;
	else
		return 5;
}

void vc4_trim_space(char *p)
{
	if (p == NULL)
		return;
	while (isblank(*p)) {
		memmove(p, p+1, strlen(p));
	}
	char *q;
	q = p + strlen(p);
	while (q > p  && isblank(q[-1])) {
		q[-1] = 0;
		q--;
	}
}

void vc4_strncat(char **dest, const char *src, int len)
{
	char *new_dest;
	int r;

	r = asprintf(&new_dest, "%s%.*s", *dest, len, src);

	assert(new_dest != NULL);
	assert(r >= 0);

	free(*dest);

	*dest = new_dest;
}

void vc4_strcat(char **dest, const char *src)
{
	vc4_strncat(dest, src, strlen(src));
}

void vc4_add_opcode_tab(struct vc4_opcode_tab **tabp, struct vc4_opcode *op)
{
	uint16_t j;
	struct vc4_opcode_tab *tab;

	if ((tab = *tabp) == NULL) {
		tab = (struct vc4_opcode_tab *)calloc(1, opcode_tab_size(1));
		tab->count = 1;
		tab->tab[0] = op;
	} else {
		for (j=0; j<tab->count; j++)
			if (tab->tab[j] == op)
				return;

		tab = (struct vc4_opcode_tab *)realloc(tab, opcode_tab_size(tab->count + 1));
		tab->tab[tab->count] = op;
		tab->count++;
	}

	*tabp = tab;
}

/*
static void fill_value_u32(uint32_t *ins, uint32_t *ins_mask,
			   const char *f,
			   char code, uint32_t val)
{
	uint32_t mask;

	*ins = 0;
	if (ins_mask != NULL)
		*ins_mask = 0;

	for (mask = 1; mask != 0; mask <<= 1) {
		if (*--f == code) {
			*ins &= ~mask;
			if (val & 1)
				*ins |= mask;
			if (ins_mask != NULL)
				*ins_mask |= mask;
			val >>= 1;
		}
	}
}
*/

/*
static uint32_t get_u32_2u16(const uint16_t *v)
{
	return v[0] | (v[1] << 16);
}

static void put_u32_2u16(uint16_t *v, uint32_t d)
{
	v[0] = d & 0xffff;
	v[1] = (d >> 16) & 0xffff;
}
*/

void vc4_swap_ins(uint16_t *ins, const struct vc4_opcode *op)
{
	uint16_t t;

	if (op->mode == VC4_INS_SCALAR48) {
		t = ins[1];
		ins[1] = ins[2];
		ins[2] = t;
	}
}

void vc4_fill_value(uint16_t *pins, uint16_t *pins_mask, const struct vc4_opcode *op,
		    char code, uint32_t val)
{
	uint16_t mask;
	const char *f;
	size_t pi;
	uint16_t ins[5];
	uint16_t ins_mask[5];

	assert(op->length >= 1 && op->length <= 5);
	assert(strlen(op->string) == 16 * op->length);
	assert(code >= 'a' && code <= 'z');

	if (strchr(op->string, code) == NULL) {
		return;
	}

	for (pi = 0; pi < op->length; pi++) {
		ins[pi] = pins[pi];
		ins_mask[pi] = pins_mask ? pins_mask[pi] : 0;
	}

	vc4_swap_ins(ins, op);
	vc4_swap_ins(ins_mask, op);

	mask = 0x0000;
	pi = op->length;
	f = op->string + 16 * op->length;

	assert(*f == 0);

	for (;;) {
		if (mask == 0) {
			if (pi == 0)
				break;
			mask = 0x0001;
			pi--;
		}

		if (*--f == code) {
			ins[pi] &= ~mask;
			if (val & 1)
				ins[pi] |= mask;
			ins_mask[pi] |= mask;
			val >>= 1;
		}
		mask <<= 1;
	}

	vc4_swap_ins(ins, op);
	vc4_swap_ins(ins_mask, op);

	for (pi = 0; pi < op->length; pi++) {
		pins[pi] = ins[pi];
		if (pins_mask != NULL)
			pins_mask[pi] = ins_mask[pi];
	}
}

struct vc4_param_info
{
	const char *name;
	int has_reg;
	int has_num;
	int pc_rel;
	int divide;
};

#define VC4_PX_INFO(name, has_reg, has_num, pc_rel, divide) { # name, has_reg, has_num, pc_rel, divide },
static const struct vc4_param_info vc4_param_info[] =
{
	{ "unknown", 0, 0, 0, 0 },
	VC4_PX_LIST(INFO)
};

const char *vc4_param_name(enum vc4_param_type type)
{
	if (type >= vc4_p_MAX)
		return vc4_param_info[vc4_p_unknown].name;
	return vc4_param_info[type].name;
}

char *vc4_param_print(const struct vc4_param *par, char *buf)
{
	switch (par->type) {

	case vc4_p_reg_0_15:
	case vc4_p_reg_0_31:
	case vc4_p_reg_0_6_16_24:
	case vc4_p_addr_reg_post_inc:
	case vc4_p_addr_reg_pre_dec:
	case vc4_p_reg_shl_8:
	case vc4_p_addr_reg_0_15:
	case vc4_p_addr_reg_0_31:
	case vc4_p_addr_2reg_begin_0_31:
	case vc4_p_addr_2reg_end_0_31:
		assert(par->reg_code >= 'a' && par->reg_code <= 'z');
		assert(par->num_code == 0);
		sprintf(buf, "%s[%c:%zu]", vc4_param_name(par->type),
			par->reg_code, par->reg_width);
		break;

	case vc4_p_reg_r6:
	case vc4_p_reg_sp:
	case vc4_p_reg_lr:
	case vc4_p_reg_sr:
	case vc4_p_reg_pc:
	case vc4_p_reg_cpuid:
		assert(par->reg_code == 0);
		assert(par->num_code == 0);
		sprintf(buf, "%s", vc4_param_name(par->type));
		break;

	case vc4_p_reg_range:
	case vc4_p_reg_range_r6:
	case vc4_p_num_u_shl_p1:
	case vc4_p_num_s_shl_p1:
	case vc4_p_num_u_lsr_p1:
	case vc4_p_num_s_lsr_p1:
	case vc4_p_reg_shl:
	case vc4_p_reg_shl_p1:
	case vc4_p_reg_lsr:
	case vc4_p_reg_lsr_p1:
	case vc4_p_addr_reg_num_u:
	case vc4_p_addr_reg_num_s:
	case vc4_p_addr_reg_0_15_num_u4:
	case vc4_p_addr_reg_0_15_num_s4:
		assert(par->reg_code >= 'a' && par->reg_code <= 'z');
		assert(par->num_code >= 'a' && par->num_code <= 'z');
		sprintf(buf, "%s[%c:%zu %c:%zu]", vc4_param_name(par->type),
			par->reg_code, par->reg_width,
			par->num_code, par->num_width);
		break;

	case vc4_p_r0_rel_s:
	case vc4_p_r0_rel_s2:
	case vc4_p_r0_rel_s4:
	case vc4_p_r24_rel_s:
	case vc4_p_r24_rel_s2:
	case vc4_p_r24_rel_s4:
	case vc4_p_sp_rel_s:
	case vc4_p_sp_rel_s2:
	case vc4_p_sp_rel_s4:
	case vc4_p_num_u:
	case vc4_p_num_s:
	case vc4_p_num_u4:
	case vc4_p_num_s4:
	case vc4_p_pc_rel_s:
	case vc4_p_pc_rel_s2:
	case vc4_p_pc_rel_s4:
		assert(par->reg_code == 0);
		assert(par->num_code >= 'a' && par->num_code <= 'z');
		sprintf(buf, "%s[%c:%zu]", vc4_param_name(par->type),
			par->num_code, par->num_width);
		break;

	default:
		assert(0);
		break;
	}
	return buf;
}

int vc4_param_has_reg(enum vc4_param_type type)
{
	if (type >= vc4_p_MAX)
		return vc4_param_info[vc4_p_unknown].has_reg;
	return vc4_param_info[type].has_reg;
}

int vc4_param_has_num(enum vc4_param_type type)
{
	if (type >= vc4_p_MAX)
		return vc4_param_info[vc4_p_unknown].has_num;
	return vc4_param_info[type].has_num;
}

int vc4_param_pc_rel(enum vc4_param_type type)
{
	if (type >= vc4_p_MAX)
		return vc4_param_info[vc4_p_unknown].pc_rel;
	return vc4_param_info[type].pc_rel;
}

int vc4_param_divide(enum vc4_param_type type)
{
	if (type >= vc4_p_MAX)
		return vc4_param_info[vc4_p_unknown].divide;
	return vc4_param_info[type].divide;
}
