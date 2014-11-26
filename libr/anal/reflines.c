/* radare - LGPL - Copyright 2009-2014 - pancake, nibble */

#include <r_core.h>
#include <r_util.h>
#include <r_cons.h>

R_API struct r_anal_refline_t *r_anal_reflines_get(RAnal *anal,
	ut64 addr, const ut8 *buf, ut64 len, int nlines, int linesout, int linescall)
{
	RAnalRefline *list2, *list = R_NEW (RAnalRefline);
	RAnalOp op = {0};
	const ut8 *ptr = buf;
	const ut8 *end = buf + len;
	ut64 opc = addr;
	int sz = 0, index = 0;
	int count = 0;

	INIT_LIST_HEAD (&(list->list));

	//end -= 8; // XXX Fix some segfaults when r_anal backends are buggy
	if (ptr != (end - 8)) end -= 8;
	/* analyze code block */
	while (ptr<end) {
		if (nlines != -1 && --nlines == 0)
			break;
		if (anal->maxreflines && count> anal->maxreflines)
			break;
#if 0
		if (config.interrupted)
			break;
		int dt = data_type(config.seek+bsz);
		if (dt != DATA_FUN && dt != DATA_CODE) {
			ut64 sz = data_size (config.seek+bsz);
			if (sz > 0) {
				ptr += sz;
				bsz += sz;
				continue;
			}
		}
#endif
		addr += sz;
		// This can segflauta if opcode length and buffer check fails
		r_anal_op_fini (&op);
		sz = r_anal_op (anal, &op, addr, ptr, (int)(end-ptr));
		if (sz > 0) {
			/* store data */
			switch (op.type) {
			case R_ANAL_OP_TYPE_CALL:
				if (!linescall)
					break;
			case R_ANAL_OP_TYPE_CJMP:
			case R_ANAL_OP_TYPE_JMP:
				if (!linesout && (op.jump > opc+len || op.jump < opc))
					goto __next;
				if (op.jump == 0LL)
					goto __next;
				list2 = R_NEW (RAnalRefline);
				list2->from = addr;
				list2->to = op.jump;
				list2->index = index++;
				list_add_tail (&(list2->list), &(list->list));
				count++;
				break;
			case R_ANAL_OP_TYPE_SWITCH:
				//if (!linesout && (op.jump > opc+len || op.jump < opc))
				//	goto __next;
				//if (op.jump == 0LL)
				//	goto __next;
				// add caseops
				if (op.switch_op) {
					RAnalCaseOp *caseop;
					RListIter *iter;
					r_list_foreach (op.switch_op->cases, iter, caseop) {
						if (caseop) {
							if (!linesout && (op.jump > opc+len || op.jump < opc))
								continue;
							list2 = R_NEW (RAnalRefline);
							list2->from = op.switch_op->addr;
							list2->to = caseop->jump;
							list2->index = index++;
							list_add_tail (&(list2->list), &(list->list));
							count++;
						}
					}
				}
				break;
			}
		} else sz = 1;
	__next:
		ptr += sz;
	}
	r_anal_op_fini (&op);
	return list;
}

R_API struct r_anal_refline_t *r_anal_reflines_fcn_get( struct r_anal_t *anal, RAnalFunction *fcn,
    int nlines, int linesout, int linescall)
{
	RAnalRefline *list2, *list = R_NEW0 (RAnalRefline);
	RAnalBlock *bb;
	RListIter *bb_iter;

	int index = 0;
	ut32 len;

	INIT_LIST_HEAD (&(list->list));

	/* analyze code block */
	r_list_foreach (fcn->bbs, bb_iter, bb) {
		if (!bb || bb->size == 0) continue;
		if (nlines != -1 && --nlines == 0) break;
		len = bb->size;

		/* store data */
		ut64 control_type = bb->type;
		control_type &= R_ANAL_BB_TYPE_SWITCH | R_ANAL_BB_TYPE_JMP | R_ANAL_BB_TYPE_COND | R_ANAL_BB_TYPE_CALL;

		// handle call
		if ( (control_type & R_ANAL_BB_TYPE_CALL) == R_ANAL_BB_TYPE_CALL &&  !linescall) {
			continue;
		}

		// Handles conditonal + unconditional jump
		if ( (control_type & R_ANAL_BB_TYPE_CJMP) == R_ANAL_BB_TYPE_CJMP) {
			// dont need to continue here is opc+len exceed function scope
			if (linesout && bb->fail > 0LL && bb->fail != bb->addr + len) {
				list2 = R_NEW0 (RAnalRefline);
				list2->from = bb->addr;
				list2->to = bb->fail;
				list2->index = index++;
				list_add_tail (&(list2->list), &(list->list));
			}
		}
		if ( (control_type & R_ANAL_BB_TYPE_JMP) == R_ANAL_BB_TYPE_JMP) {
			if (!linesout || bb->jump == 0LL || bb->jump == bb->addr + len)
				continue;

			list2 = R_NEW0 (RAnalRefline);
			list2->from = bb->addr;
			list2->to = bb->jump;
			list2->index = index++;
			list_add_tail (&(list2->list), &(list->list));
			continue;
		}

		// XXX - Todo test handle swith op
		if ( control_type & R_ANAL_BB_TYPE_SWITCH) {
			if (bb->switch_op) {
				RAnalCaseOp *caseop;
				RListIter *iter;
				r_list_foreach (bb->switch_op->cases, iter, caseop) {
					if (caseop) {
						if (!linesout)// && (op.jump > opc+len || op.jump < pc))
							continue;
						list2 = R_NEW (RAnalRefline);
						list2->from = bb->switch_op->addr;
						list2->to = caseop->jump;
						list2->index = index++;
						list_add_tail (&(list2->list), &(list->list));
					}
				}
			}
		}
	}
	return list;
}

R_API int r_anal_reflines_middle(RAnal *a, RAnalRefline *list, ut64 addr, int len) {
	struct list_head *pos;
	if (list)
	for (pos = (&(list->list))->next; pos != (&(list->list)); pos = pos->next) {
		RAnalRefline *ref = list_entry (pos, RAnalRefline, list);
		if ((ref->to> addr) && (ref->to < addr+len))
			return R_TRUE;
	}
	return R_FALSE;
}

// TODO: move into another file
// TODO: this is TOO SLOW. do not iterate over all reflines or gtfo
R_API char* r_anal_reflines_str(void *core, ut64 addr, int opts) {
	RBuffer *b;
	int l, linestyle = opts & R_ANAL_REFLINE_TYPE_STYLE;
	int dir = 0, wide = opts & R_ANAL_REFLINE_TYPE_WIDE;
	char ch = ' ', *str = NULL;
	struct list_head *pos;
	RAnalRefline *ref, *list = ((RCore*)core)->reflines;

	if (!list) return NULL;

	b = r_buf_new ();
	r_buf_append_string (b, " ");
	for (pos = linestyle?(&(list->list))->next:(&(list->list))->prev;
		pos != (&(list->list)); pos = linestyle?pos->next:pos->prev) {
		ref = list_entry (pos, RAnalRefline, list);
		dir = (addr == ref->to)? 1: (addr == ref->from)? 2: dir;
		if (addr == ref->to) {
			r_buf_append_string (b, (ref->from>ref->to)? "." : "`");
			ch = '-';
		} else if (addr == ref->from) {
			r_buf_append_string (b, (ref->from>ref->to)? "`" : ",");
			ch = '=';
		} else if (ref->from < ref->to) {
			if (addr > ref->from && addr < ref->to) {
				if (ch=='-' || ch=='=')
					r_buf_append_bytes (b, (const ut8*)&ch, 1);
				else r_buf_append_string (b, "|");
			} else r_buf_append_bytes (b, (const ut8*)&ch, 1);
		} else {
			if (addr < ref->from && addr > ref->to) {
				if (ch=='-' || ch=='=')
					r_buf_append_bytes (b, (const ut8*)&ch, 1);
				else r_buf_append_string (b, "|"); // line going up
			} else r_buf_append_bytes (b, (const ut8*)&ch, 1);
		}
		if (wide) {
			char w = (ch=='=' || ch=='-')? ch : ' ';
			r_buf_append_bytes (b, (const ut8*)&w, 1);
		}
	}
	str = r_buf_free_to_string (b);
	if (((RCore*)core)->anal->lineswidth>0) {
		int lw = ((RCore*)core)->anal->lineswidth;
		l = strlen (str);
		if (l > lw) {
			r_str_cpy (str, str + l - lw);
		} else {
			char pfx[128];
			lw-=l;
			memset (pfx, ' ', sizeof (pfx));
			if (lw>=sizeof (pfx)) lw = sizeof (pfx);
			if (lw > 0) {
				pfx[lw - 1] = 0;
				str = r_str_prefix (str, pfx);
			}
		}
	}
	str = r_str_concat (str, (dir==1)? "-> "
		: (dir==2)? "=< " : "   ");

	/* HACK */
	if (((RCore*)core)->utf8 && ((RCore*)core)->cons->vline) {
		RCons *c = ((RCore*)core)->cons;
		//str = r_str_replace (str, "=", "-", 1);
		str = r_str_replace (str, "<", c->vline[ARROW_LEFT], 1);
		str = r_str_replace (str, ">", c->vline[ARROW_RIGHT], 1);
		str = r_str_replace (str, "!", c->vline[LINE_UP], 1);
		str = r_str_replace (str, "|", c->vline[LINE_VERT], 1);
		str = r_str_replace (str, "=", c->vline[LINE_HORIZ], 1);
		str = r_str_replace (str, "-", c->vline[LINE_HORIZ], 1);
		//str = r_str_replace (str, ".", "\xe2\x94\x8c", 1);
		str = r_str_replace (str, ",", c->vline[LUP_CORNER], 1);
		str = r_str_replace (str, ".", c->vline[LUP_CORNER], 1);
		str = r_str_replace (str, "`", c->vline[LDWN_CORNER], 1);
	}
	return str;
}
