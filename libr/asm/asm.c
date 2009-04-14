/* radare - LGPL - Copyright 2009 nibble<.ds@gmail.com> */

#include <stdio.h>

#include <r_types.h>
#include <r_util.h>
#include <r_cmd.h>
#include <r_asm.h>
#include <list.h>
#include "../config.h"

static struct r_asm_handle_t *asm_static_plugins[] = 
	{ R_ASM_STATIC_PLUGINS };

static int r_asm_byte(void *data, const char *input)
{
	int ret;
	struct r_asm_aop_t **aop = (struct r_asm_aop_t**)data;
	char *arg = strchr(input, ' ');
	ret = r_hex_str2bin(arg, (*aop)->buf);
	strncpy((*aop)->buf_hex, r_str_trim(arg), 1024);
	return ret;
}

R_API struct r_asm_t *r_asm_new()
{
	struct r_asm_t *a = MALLOC_STRUCT(struct r_asm_t);
	r_asm_init(a);
	return a;
}

R_API void r_asm_free(struct r_asm_t *a)
{
	free(a);
}

R_API int r_asm_init(struct r_asm_t *a)
{
	int i;
	a->user = NULL;
	a->cur = NULL;
	INIT_LIST_HEAD(&a->asms);
	a->bits = 32;
	a->big_endian = 0;
	a->syntax = R_ASM_SYN_INTEL;
	a->pc = 0;
	for(i=0;asm_static_plugins[i];i++)
		r_asm_add(a, asm_static_plugins[i]);
	r_cmd_init(&a->cmd);
	r_cmd_add(&a->cmd, "b", ".byte", &r_asm_byte);
	r_cmd_add_long(&a->cmd, "byte", "b", ".byte");
	return R_TRUE;
}

R_API void r_asm_set_user_ptr(struct r_asm_t *a, void *user)
{
	a->user = user;
}

R_API int r_asm_add(struct r_asm_t *a, struct r_asm_handle_t *foo)
{
	struct list_head *pos;
	if (foo->init)
		foo->init(a->user);
	/* avoid dupped plugins */
	list_for_each_prev(pos, &a->asms) {
		struct r_asm_handle_t *h = list_entry(pos, struct r_asm_handle_t, list);
		if (!strcmp(h->name, foo->name))
			return R_FALSE;
	}
	
	list_add_tail(&(foo->list), &(a->asms));
	return R_TRUE;
}

R_API int r_asm_del(struct r_asm_t *a, const char *name)
{
#warning TODO: Implement r_asm_del
	return R_FALSE;
}

R_API int r_asm_list(struct r_asm_t *a)
{
	struct list_head *pos;
	list_for_each_prev(pos, &a->asms) {
		struct r_asm_handle_t *h = list_entry(pos, struct r_asm_handle_t, list);
		printf(" %s: %s\n", h->name, h->desc);
	}
	return R_FALSE;
}

R_API int r_asm_set(struct r_asm_t *a, const char *name)
{
	struct list_head *pos;
	list_for_each_prev(pos, &a->asms) {
		struct r_asm_handle_t *h = list_entry(pos, struct r_asm_handle_t, list);
		if (!strcmp(h->name, name)) {
			a->cur = h;
			return R_TRUE;
		}
	}
	return R_FALSE;
}

static int has_bits(struct r_asm_handle_t *h, int bits)
{
	int i;
	if (h && h->bits) {
		for(i=0; h->bits[i]; i++) {
			if (bits == h->bits[i])
				return R_TRUE;
		}
	}
	return R_FALSE;
}


R_API int r_asm_set_bits(struct r_asm_t *a, int bits)
{
	if (has_bits(a->cur, bits)) {
		a->bits = bits;
		return R_TRUE;
	}
	return R_FALSE;
}

R_API int r_asm_set_big_endian(struct r_asm_t *a, int boolean)
{
	a->big_endian = boolean;
	return R_TRUE;
}

R_API int r_asm_set_syntax(struct r_asm_t *a, int syntax)
{
	switch (syntax) {
	case R_ASM_SYN_INTEL:
	case R_ASM_SYN_ATT:
		a->syntax = syntax;
		return R_TRUE;
	default:
		return R_FALSE;
	}
}

R_API int r_asm_set_pc(struct r_asm_t *a, u64 pc)
{
	a->pc = pc;
	return R_TRUE;
}

R_API int r_asm_disassemble(struct r_asm_t *a, struct r_asm_aop_t *aop, u8 *buf, u64 len)
{
	int ret = 0;
	if (a->cur && a->cur->disassemble)
		ret = a->cur->disassemble(a, aop, buf, len);
	if (ret > 0) {
		memcpy(aop->buf, buf, ret);
		r_hex_bin2str(buf, ret, aop->buf_hex);
	}
	return ret;
}

R_API int r_asm_assemble(struct r_asm_t *a, struct r_asm_aop_t *aop, const char *buf)
{
	int ret = 0;
	struct list_head *pos;
	if (a->cur) {
		if (a->cur->assemble)
			ret = a->cur->assemble(a, aop, buf);
		else /* find callback if no assembler support in current plugin */
			list_for_each_prev(pos, &a->asms) {
				struct r_asm_handle_t *h = list_entry(pos, struct r_asm_handle_t, list);
				if (h->arch && h->assemble && has_bits(h, a->bits) && !strcmp(a->cur->arch, h->arch)) {
					printf("NAME %s\n", h->name);
					ret = h->assemble(a, aop, buf);
					break;
				}
			}
	}
	if (aop && ret > 0)
		r_hex_bin2str(aop->buf, ret, aop->buf_hex);
	return ret;
}

R_API int r_asm_massemble(struct r_asm_t *a, struct r_asm_aop_t *aop, char *buf)
{
	char *lbuf=NULL, *ptr = NULL, *tokens[1024], buf_hex[1024];
	u8 buf_bin[1024];
	int ret, idx, ctr, i, j;

	if (buf == NULL)
		return 0;
	lbuf = strdup(buf);

	for (tokens[0] = lbuf, ctr = 0;
		(ptr = strchr(tokens[ctr], ';'));
		tokens[++ctr] = ptr+1)
			*ptr = '\0';

	r_cmd_set_data(&a->cmd, &aop);
	for (ret = idx = i = 0, *buf_hex='\0'; i <= ctr; i++, idx+=ret) {
		r_asm_set_pc(a, a->pc + ret);
		if ((ptr = strchr(tokens[i], '.'))) /* Pseudo */
			ret = r_cmd_call(&a->cmd, ptr+1);
		else /* Instruction */
			ret = r_asm_assemble(a, aop, tokens[i]);
		if (ret) {
			for (j = 0; j < ret; j++)
				buf_bin[idx+j] = aop->buf[j];
			strcat(buf_hex, aop->buf_hex);
		} else {
			fprintf(stderr, "invalid\n");
			return 0;
		}
	}
	
	memcpy(aop->buf, buf_bin, 1024);
	memcpy(aop->buf_hex, buf_hex, 1024);

	return idx;
}
