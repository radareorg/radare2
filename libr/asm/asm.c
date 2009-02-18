/* radare - LGPL - Copyright 2009 nibble<.ds@gmail.com> */

#include <stdio.h>

#include <r_types.h>
#include <r_util.h>
#include <r_asm.h>
#include <list.h>

struct r_asm_t *r_asm_new()
{
	struct r_asm_t *a = MALLOC_STRUCT(struct r_asm_t);
	r_asm_init(a);
	return a;
}

void r_asm_free(struct r_asm_t *a)
{
	free(a);
}

int r_asm_init(struct r_asm_t *a)
{
	a->user = NULL;
	INIT_LIST_HEAD(&a->asms);
	r_asm_set_bits(a, 32);
	r_asm_set_big_endian(a, 0);
	r_asm_set_syntax(a, R_ASM_SYN_INTEL);
	r_asm_set_pc(a, 0);
	return R_TRUE;
}

void r_asm_set_user_ptr(struct r_asm_t *a, void *user)
{
	a->user = user;
}

int r_asm_add(struct r_asm_t *a, struct r_asm_handle_t *foo)
{
	if (foo->init)
		foo->init(a->user);
	list_add_tail(&(foo->list), &(a->asms));
	return R_TRUE;
}

int r_asm_list(struct r_asm_t *a)
{
	struct list_head *pos;
	list_for_each_prev(pos, &a->asms) {
		struct r_asm_handle_t *h = list_entry(pos, struct r_asm_handle_t, list);
		printf(" %s: %s\n", h->name, h->desc);
	}
	return R_FALSE;
}

int r_asm_set(struct r_asm_t *a, const char *name)
{
	struct list_head *pos;
	list_for_each_prev(pos, &a->asms) {
		struct r_asm_handle_t *h = list_entry(pos, struct r_asm_handle_t, list);
		if (!memcmp(h->name, name, strlen(h->name))) {
			a->cur = h;
			return R_TRUE;
		}
	}
	return R_FALSE;
}

int r_asm_set_bits(struct r_asm_t *a, int bits)
{
	switch (bits) {
	case 16:
	case 32:
	case 64:
		a->bits = bits;
		return R_TRUE;
	default:
		return R_FALSE;
	}
}

int r_asm_set_big_endian(struct r_asm_t *a, int boolean)
{
	a->big_endian = boolean;
	return R_TRUE;
}

int r_asm_set_syntax(struct r_asm_t *a, int syntax)
{
	switch (syntax) {
	case R_ASM_SYN_INTEL:
	case R_ASM_SYN_ATT:
	case R_ASM_SYN_OLLY:
		a->syntax = syntax;
		return R_TRUE;
	default:
		return R_FALSE;
	}
}

int r_asm_set_pc(struct r_asm_t *a, u64 pc)
{
	a->pc = pc;
	return R_TRUE;
}

int r_asm_disassemble(struct r_asm_t *a, struct r_asm_aop_t *aop, u8 *buf, u64 len)
{
	if (a->cur && a->cur->disassemble)
		return a->cur->disassemble(a, aop, buf, len);
	
	return R_FALSE;
}

int r_asm_assemble(struct r_asm_t *a, struct r_asm_aop_t *aop, char *buf)
{
	if (a->cur && a->cur->assemble)
		return a->cur->assemble(a, aop, buf);
	
	return R_FALSE;
}
