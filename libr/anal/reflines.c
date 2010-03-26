/* radare - LGPL - Copyright 2009-2010 */
/*   nibble<.ds@gmail.com> */
/*   pancake<nopcode.org> */

#include <r_anal.h>
#include <r_util.h>

R_API struct r_anal_refline_t *r_anal_reflines_get(struct r_anal_t *anal,
	ut64 addr, ut8 *buf, ut64 len, int nlines, int linesout)
{
	struct r_anal_refline_t *list = R_NEW (struct r_anal_refline_t);
	struct r_anal_refline_t *list2;
	struct r_anal_aop_t aop;
	ut8 *ptr = buf;
	ut8 *end = buf + len;
	ut64 opc = addr;
	int sz = 0, index = 0;

	INIT_LIST_HEAD(&(list->list));

	/* analyze code block */
	while (ptr<end) {
		if (nlines != -1 && --nlines == 0)
			break;
#if 0
		if (config.interrupted)
			break;
		int dt = data_type(config.seek+bsz);
		if (dt != DATA_FUN && dt != DATA_CODE) {
			ut64 sz = data_size(config.seek+bsz);
			if (sz > 0) {
				ptr= ptr +sz;
				bsz=bsz+sz;
				continue;
			}
		}
#endif

		addr += sz;
		sz = r_anal_aop (anal, &aop, addr, ptr, (int)(end-ptr));
		if (sz > 0) {
			/* store data */
			switch(aop.type) {
			case R_ANAL_OP_TYPE_CALL:
			case R_ANAL_OP_TYPE_CJMP:
			case R_ANAL_OP_TYPE_JMP:
				if (!linesout && (aop.jump > opc+len || aop.jump < opc))
					goto __next;
				if (aop.jump == 0)
					goto __next;
				list2 = R_NEW (struct r_anal_refline_t);
				list2->from = addr;
				list2->to = aop.jump;
				list2->index = index++;
				list_add_tail (&(list2->list), &(list->list));
				break;
			}
		} else sz = 1;
	__next:
		ptr = ptr + sz;
	}

	return list;
}

/* umf..this should probably be outside this file */
R_API int r_anal_reflines_str(struct r_anal_t *anal, struct r_anal_refline_t *list,
	ut64 addr, char *str, int opts)
{
	struct r_anal_refline_t *ref;
	struct list_head *pos;
	int dir = 0;
	char ch = ' ';
	int linestyle = opts & R_ANAL_REFLINE_STYLE;
	int wide = opts & R_ANAL_REFLINE_WIDE;

	if (!list)
		return R_FALSE;
	strcpy (str, " ");
	for (pos = linestyle?(&(list->list))->next:(&(list->list))->prev;
		pos != (&(list->list)); pos = linestyle?pos->next:pos->prev) {
		ref = list_entry (pos, struct r_anal_refline_t, list);

		if (addr == ref->to) dir = 1;
		// TODO: use else here
		if (addr == ref->from) dir = 2;

		// TODO: if dir==1
		if (addr == ref->to) {
			if (ref->from > ref->to)
				strcat (str, ".");
			else strcat (str, "`");
			ch = '-';
		} else if (addr == ref->from) {
			if (ref->from > ref->to)
				strcat (str, "`");
			else strcat (str, ".");
			ch = '=';
		} else if (ref->from < ref->to) { /* down */
			if (addr > ref->from && addr < ref->to) {
				if (ch=='-'||ch=='=')
					r_str_concatch(str, ch);
				else strcat(str, "|");
			} else r_str_concatch (str, ch);
		} else { /* up */
			if (addr < ref->from && addr > ref->to) {
				if (ch=='-'||ch=='=')
					r_str_concatch (str, ch);
				else strcat (str, "|");
			} else r_str_concatch (str, ch);
		}
		if (wide) {
			if (ch == '=' || ch == '-')
				r_str_concatch (str, ch);
			else strcat (str, " ");
		}
	}
	strcat (str, (dir==1)?"-> ":(dir==2)?"=< ":"   ");
	return R_TRUE;
}

R_API int r_anal_reflines_middle(RAnal *anal, RAnalRefline *list, ut64 addr, int len) {
	struct list_head *pos;
	for (pos = (&(list->list))->next; pos != (&(list->list)); pos = pos->next) {
		RAnalRefline *ref = list_entry (pos, RAnalRefline, list);
		if ((ref->to> addr) && (ref->to < addr+len))
			return R_TRUE;
	}
	return R_FALSE;
}
