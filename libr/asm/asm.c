/* radare - LGPL - Copyright 2009 nibble<.ds@gmail.com> */

#include <stdio.h>

#include <r_types.h>
#include <r_util.h>
#include <r_asm.h>
#include <list.h>
#include "../config.h"

static struct r_asm_handle_t *asm_static_plugins[] = 
	{ R_ASM_STATIC_PLUGINS };

static int r_asm_string(struct r_asm_aop_t *aop, const char *input)
{
	int len = 0;
	char *arg = strchr(input, ' ');
	if (arg && (len = strlen(arg+1))) {
		arg += 1; len += 1;
		r_hex_bin2str((u8*)arg, len, aop->buf_hex);
		strncpy((char*)aop->buf, arg, R_ASM_BUFSIZE);
	}
	return len;
}

static int r_asm_arch(struct r_asm_t *a, const char *input)
{
	char *arg = strchr(input, ' '), str[R_ASM_BUFSIZE];
	if (arg) {
		arg += 1;
		sprintf(str, "asm_%s", arg);
		if (!r_asm_set(a, str)) {
			fprintf(stderr, "Error: Unknown plugin\n");
			return -1;
		}
	}
	return 0;
}

static int r_asm_org(struct r_asm_t *a, const char *input)
{
	char *arg = strchr(input, ' ');
	if (arg) {
		arg += 1;
		r_asm_set_pc(a, r_num_math(NULL, arg));
	}
	return 0;
}

static int r_asm_byte(struct r_asm_aop_t *aop, const char *input)
{
	int len = 0;
	char *arg = strchr(input, ' ');
	if (arg) {
		arg += 1;
		len = r_hex_str2bin(arg, aop->buf);
		strncpy(aop->buf_hex, r_str_trim(arg), R_ASM_BUFSIZE);
	}
	return len;
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
	/* TODO: Implement r_asm_del */
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
					ret = h->assemble(a, aop, buf);
					break;
				}
			}
	}
	if (aop && ret > 0) {
		r_hex_bin2str(aop->buf, ret, aop->buf_hex);
		strncpy(aop->buf_asm, buf, R_ASM_BUFSIZE);
	}
	return ret;
}

R_API int r_asm_massemble(struct r_asm_t *a, struct r_asm_aop_t *aop, char *buf)
{
	struct {
		char name[256];
		u64 offset;
	} flags[1024];
	char *lbuf = NULL, *ptr = NULL, *ptr_start = NULL, *label_name = NULL,
		 *tokens[R_ASM_BUFSIZE], buf_hex[R_ASM_BUFSIZE],
		 buf_token[R_ASM_BUFSIZE], buf_token2[R_ASM_BUFSIZE];
	u8 buf_bin[R_ASM_BUFSIZE];
	int labels = 0, stage, ret, idx, ctr, i, j;
	u64 label_offset;

	if (buf == NULL)
		return 0;
	lbuf = strdup(buf);

	if (strchr(lbuf, '_'))
		labels = 1;

	for (tokens[0] = lbuf, ctr = 0;
		(ptr = strchr(tokens[ctr], ';')) || 
		(ptr = strchr(tokens[ctr], '\n')) || (ptr = strchr(tokens[ctr], '\r'));
		tokens[++ctr] = ptr+1)
			*ptr = '\0';

	/* Stage 1: Parse labels*/
	/* Stage 2: Assemble */
	for (stage = 0; stage < 2; stage++) {
		if (stage == 0 && !labels)
			continue;
		for (idx = ret = i = j = 0, label_offset = a->pc, buf_hex[0] = '\0';
			i <= ctr; i++, idx += ret, label_offset += ret) {
			strncpy(buf_token, tokens[i], R_ASM_BUFSIZE);
			if (stage == 1)
				r_asm_set_pc(a, a->pc + ret);
			for (ptr_start = buf_token;*ptr_start&&isseparator(*ptr_start);ptr_start++);
			if (labels) { /* Labels */
				while (ptr_start[0] != '.' && (ptr = strchr(ptr_start, '_'))) {
					if ((label_name = r_str_word_get_first(ptr))) {
						if ((ptr == ptr_start)) {
							if (stage == 0 && j < 1024) {
								strncpy(flags[j].name, label_name, 256);
								flags[j].offset = label_offset;
								j++;
							}
							ptr_start += strlen(label_name)+1;
						} else {
							*ptr = '\0';
							if (stage == 1) {
								for (j = 0; j < 1024; j++)
									if (!strcmp(label_name, flags[j].name)) {
										label_offset = flags[j].offset;
										break;
									}
								if (j == 1024)
									return 0;
							}
							snprintf(buf_token2, R_ASM_BUFSIZE, "%s0x%llx%s",
									ptr_start, label_offset, ptr+strlen(label_name));
							strncpy(buf_token, buf_token2, R_ASM_BUFSIZE);
							ptr_start = buf_token;
						}
						free(label_name);
					}
				}
			}
			if ((ptr = strchr(ptr_start, '.'))) { /* Pseudo */
				if (!memcmp(ptr, ".string", 7))
					ret = r_asm_string(aop, ptr);
				else if (!memcmp(ptr, ".arch", 5))
					ret = r_asm_arch(a, ptr);
				else if (!memcmp(ptr, ".byte", 5))
					ret = r_asm_byte(aop, ptr);
				else if (!memcmp(ptr, ".org", 4))
					ret = r_asm_org(a, ptr);
				else return 0;
				if (!ret)
					continue;
				else if (ret < 0)
					return 0;
			} else { /* Instruction */
				ret = r_asm_assemble(a, aop, ptr_start);
				if (!ret)
					return 0;
			}
			if (stage == 1) {
				for (j = 0; j < ret && idx+j < R_ASM_BUFSIZE; j++)
					buf_bin[idx+j] = aop->buf[j];
				strcat(buf_hex, aop->buf_hex);
			}
		}
	}
	
	memcpy(aop->buf, buf_bin, R_ASM_BUFSIZE);
	memcpy(aop->buf_hex, buf_hex, R_ASM_BUFSIZE);

	return idx;
}
