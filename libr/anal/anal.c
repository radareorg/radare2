/* radare - LGPL - Copyright 2009 */
/*   nibble<.ds@gmail.com> */
/*   pancake<nopcode.org> */

#include <r_anal.h>
#include <r_util.h>

struct r_anal_t *r_anal_new()
{
	struct r_anal_t *r = MALLOC_STRUCT(struct r_anal_t);
	r_anal_init(r);
	return r;
}

struct r_anal_t *r_anal_free(struct r_anal_t *r)
{
	free(r);
	return NULL;
}

int r_anal_init(struct r_anal_t *anal)
{
	anal->user = NULL;
	r_anal_set_bits(anal, 32);
	r_anal_set_big_endian(anal, R_FALSE);
	INIT_LIST_HEAD(&anal->anals);
	return R_TRUE;
}

void r_anal_set_user_ptr(struct r_anal_t *anal, void *user)
{
	anal->user = user;
}

int r_anal_add(struct r_anal_t *anal, struct r_anal_handle_t *foo)
{
	if (foo->init)
		foo->init(anal->user);
	list_add_tail(&(foo->list), &(anal->anals));
	return R_TRUE;
}

int r_anal_list(struct r_anal_t *anal)
{
	struct list_head *pos;
	list_for_each_prev(pos, &anal->anals) {
		struct r_anal_handle_t *h = list_entry(pos, struct r_anal_handle_t, list);
		printf(" %s: %s\n", h->name, h->desc);
	}
	return R_FALSE;
}

int r_anal_set(struct r_anal_t *anal, const char *name)
{
	struct list_head *pos;
	list_for_each_prev(pos, &anal->anals) {
		struct r_anal_handle_t *h = list_entry(pos, struct r_anal_handle_t, list);
		if (!strcmp(h->name, name)) {
			anal->cur = h;
			return R_TRUE;
		}
	}
	return R_FALSE;
}

int r_anal_set_bits(struct r_anal_t *anal, int bits)
{
	switch (bits) {
	case 16:
	case 32:
	case 64:
		anal->bits = bits;
		return R_TRUE;
	default:
		return R_FALSE;
	}
}

int r_anal_set_big_endian(struct r_anal_t *anal, int boolean)
{
	anal->big_endian = boolean;
	return R_TRUE;
}

int r_anal_set_pc(struct r_anal_t *a, u64 pc)
{
	a->pc = pc;
	return R_TRUE;
}

int r_anal_aop(struct r_anal_t *anal, struct r_anal_aop_t *aop, void *data)
{ 
	if (anal->cur && anal->cur->aop)
		return anal->cur->aop(anal, aop, data);
	return R_FALSE;
}

struct r_anal_refline_t *r_anal_reflines_get(struct r_anal_t *anal, u8 *buf, u64 len, int nlines, int linesout)
{
	struct r_anal_refline_t *list = MALLOC_STRUCT(struct r_anal_refline_t);
	struct r_anal_refline_t *list2;
	struct r_anal_aop_t aop;
	u8 *ptr = buf;
	u8 *end = buf + len;
	u64 opc = anal->pc, sz = 0, index = 0;

	INIT_LIST_HEAD(&(list->list));

	/* analyze code block */
	while( ptr < end ) {
		if (nlines != -1 && --nlines == 0)
			break;
#if 0
		if (config.interrupted)
			break;
		int dt = data_type(config.seek+bsz);
		if (dt != DATA_FUN && dt != DATA_CODE) {
			u64 sz = data_size(config.seek+bsz);
			if (sz > 0) {
				ptr= ptr +sz;
				bsz=bsz+sz;
				continue;
			}
		}
#endif
		anal->pc += sz;
		sz = r_anal_aop(anal, &aop, ptr);
		if (sz < 1) {
			sz = 1;
		} else {
			/* store data */
			switch(aop.type) {
			case R_ANAL_AOP_TYPE_CALL:
			case R_ANAL_AOP_TYPE_CJMP:
			case R_ANAL_AOP_TYPE_JMP:
				if (!linesout && (aop.jump > opc+len || aop.jump < opc))
					goto __next;
				if (aop.jump == 0)
					goto __next;

				list2 = MALLOC_STRUCT(struct r_anal_refline_t);
				list2->from = anal->pc;
				list2->to = aop.jump;
				list2->index = index++;
				list_add_tail(&(list2->list), &(list->list));
				break;
			}
		}
	__next:
		ptr = ptr + sz;
	}

	anal->pc = opc;

	return list;
}

int r_anal_reflines_str(struct r_anal_t *anal, struct r_anal_refline_t *list, char *str, int opts)
{
	struct list_head *pos;
	int dir = 0;
	char ch = ' ';

	int linestyle = opts & R_ANAL_REFLINE_STYLE;
	int wide = opts & R_ANAL_REFLINE_WIDE;

	if (!list)
		return R_FALSE;

	str[0] = '\0';
	strcat(str, " ");

	for (pos = linestyle?(&(list->list))->next:(&(list->list))->prev; pos != (&(list->list)); pos = linestyle?pos->next:pos->prev) {
		struct r_anal_refline_t *ref = list_entry(pos, struct r_anal_refline_t, list);

		if (anal->pc == ref->to)
			dir = 1;
		if (anal->pc == ref->from)
			dir = 2;

		if (anal->pc == ref->to) {
			if (ref->from > ref->to)
				strcat(str, ".");
			else
				strcat(str, "`");
			ch = '-';
		} else
			if (anal->pc == ref->from) {
				if (ref->from > ref->to)
					strcat(str, "`");
				else
					strcat(str, ".");
				ch = '=';
			} else {
				if (ref->from < ref->to) {
					/* down */
					//C strcat(str, C_YELLOW);
					if (anal->pc > ref->from && anal->pc < ref->to) {
						if (ch=='-'||ch=='=')
							r_str_concatch(str, ch);
						else
							strcat(str, "|");
					} else
#if 0 
						C {
							if (ch=='-')
								cons_printf(C_WHITE"-");
							else if (ch=='=')
								cons_printf(C_YELLOW"=");
							else {
								r_str_concatch(str, ch);
							}
						} else 
#endif 
							r_str_concatch(str, ch);
				} else {
					//C strcat(str, C_WHITE);
					/* up */
					if (anal->pc < ref->from && anal->pc > ref->to) {
						if (ch=='-'||ch=='=')
							r_str_concatch(str, ch);
						else // ^
							strcat(str, "|");
					} else
						r_str_concatch(str, ch);
				}
			}
		if (wide) {
			switch(ch) {
			case '=':
			case '-':
				r_str_concatch(str, ch);
				break;
			default:
				strcat(str, " ");
				break;
			}
		}
	}

	if (dir==1) { 
#if 0 
		C strcat(str, C_RED"-> "C_RESET);
		else 
#endif 
			strcat(str, "-> ");
	} else
		if (dir==2) {
#if 0 
			C strcat(str, C_GREEN"=< "C_RESET);
			else 
#endif 
				strcat(str, "=< ");
		}
		else strcat(str, "   ");

	return R_TRUE;
}
