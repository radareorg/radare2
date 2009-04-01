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
	int seek = anal->pc, sz, bsz = 0, index = 0;

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
		seek += bsz;
		sz = r_anal_aop(anal, &aop, ptr);
		if (sz < 1) {
			sz = 1;
		} else {
			/* store data */
			switch(aop.type) {
			case R_ANAL_AOP_TYPE_CALL:
			case R_ANAL_AOP_TYPE_CJMP:
			case R_ANAL_AOP_TYPE_JMP:
				if (!linesout) {
					/* skip outside lines */
					if (aop.jump > anal->pc+len)
						goto __next;
				} else {
					if (aop.jump == 0)
						goto __next;
				}

				list2 = MALLOC_STRUCT(struct r_anal_refline_t);
				list2->from = seek;
				list2->to = aop.jump;
				list2->index = index++;
				list_add_tail(&(list2->list), &(list->list));
				break;
			}
		}
	__next:
		ptr = ptr + sz;
		bsz += sz;
	}

	return list;
}

int r_anal_reflines_str(struct r_anal_t *anal, struct r_anal_refline_t *list, u64 addr, char *str, int opts)
{
	struct list_head *pos;
	char ch = ' ';
	int dir = 0;  /* dir 1=in ; 2=out */

	int linestyle = opts & R_ANAL_REFLINE_LINESTYLE;
	int nlines = opts & R_ANAL_REFLINE_NLINES;
	int lineswide = opts & R_ANAL_REFLINE_LINESWIDE;
	int expand = opts & R_ANAL_REFLINE_EXPAND;

	if (!list)
		return R_FALSE;

	str[0] = '\0';
	strcat(str, " ");

#define _h34d_ &(list->list)
	
	if (nlines) {
		int count = 0;

		for (pos = linestyle?(_h34d_)->next:(_h34d_)->prev; pos != (_h34d_); pos = linestyle?pos->next:pos->prev)
			count++;
		for (;count<nlines;count++)
			strcat(str, " ");
	}

	for (pos = linestyle?(_h34d_)->next:(_h34d_)->prev; pos != (_h34d_); pos = linestyle?pos->next:pos->prev) {
		struct r_anal_refline_t *ref = list_entry(pos, struct r_anal_refline_t, list);
		
		if (addr == ref->to)
			dir = 1;
		if (addr == ref->from)
			dir = 2;

		if (addr == ref->to) {
			if (!expand) {
				if (ref->from > ref->to)
					strcat(str, ".");
				else
					strcat(str, "`");
				ch = '-';
			} else
				ch = '.';
		} else
		if (addr == ref->from) {
			if (!expand) {
				if (ref->from > ref->to)
					strcat(str, "`");
				else
					strcat(str, ".");
				ch = '=';
			}
		} else {
			if (ref->from < ref->to) {
				/* down */
				if (addr > ref->from && addr < ref->to) {
					if (ch=='-'||ch=='=')
						sprintf(str, "%s%c", str, ch);
					else
						strcat(str, "|");
				} else
				if (!expand)
					sprintf(str, "%s%c", str, ch);
			} else {
				/* up */
				if (addr < ref->from && addr > ref->to) {
					if (ch=='-'||ch=='=')
						sprintf(str, "%s%c", str, ch);
					else // ^
						strcat(str, "|");
				} else {
					sprintf(str, "%s%c", str, ch);
				}
			}
		}

		if (lineswide) {
			switch(ch) {
			case '=':
			case '-':
				sprintf(str, "%s%c", str, ch);
				break;
			default:
				strcat(str, " ");
				break;
			}
		}

	}

	if (expand) {
		strcat(str, "   ");
	} else
	if (dir==1) { 
		strcat(str, "-> ");
	} else
	if (dir==2) {
		strcat(str, "=< ");
	}
	else strcat(str, "   ");

	return R_TRUE;
}
