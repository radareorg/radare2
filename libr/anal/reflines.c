/* radare - LGPL - Copyright 2009-2015 - pancake, nibble */

#include <r_core.h>
#include <r_util.h>
#include <r_cons.h>

R_API void r_anal_reflines_free (RAnalRefline *rl) {
	if (rl) {
		//free_refline_list (&rl->list);
		free (rl);
	}
}

/* returns a list of RAnalRefline for the code present in the buffer buf, of
 * length len. A RAnalRefline exists from address A to address B if a jmp,
 * conditional jmp or call instruction exists at address A and it targets
 * address B.
 *
 * nlines - max number of lines of code to consider
 * linesout - true if you want to display lines that go outside of the scope [addr;addr+len)
 * linescall - true if you want to display call lines */
R_API RList *r_anal_reflines_get(RAnal *anal, ut64 addr, const ut8 *buf, ut64 len, int nlines, int linesout, int linescall) {
	RList *list;
	RAnalRefline *item;
	RAnalOp op = {0};
	const ut8 *ptr = buf;
	const ut8 *end = buf + len;
	int sz = 0, count = 0;
	ut64 opc = addr;

	list = r_list_new ();
	if (!list) return NULL;

	/* analyze code block */
	while (ptr < end) {
		if (nlines != -1) {
			nlines--;
			if (nlines == 0) break;
		}
		if (anal->maxreflines && count > anal->maxreflines) {
			break;
		}

		addr += sz;
		// This can segfault if opcode length and buffer check fails
		r_anal_op_fini (&op);
		sz = r_anal_op (anal, &op, addr, ptr, (int)(end - ptr));
		if (sz <= 0) {
			sz = 1;
			goto __next;
		}

		/* store data */
		switch (op.type) {
		case R_ANAL_OP_TYPE_CALL:
			if (!linescall) break;
		case R_ANAL_OP_TYPE_CJMP:
		case R_ANAL_OP_TYPE_JMP:
			if ((!linesout && (op.jump > opc + len || op.jump < opc)) ||
				op.jump == 0LL) {
				break;
			}
			item = R_NEW0 (RAnalRefline);
			if (!item) goto list_err;

			item->from = addr;
			item->to = op.jump;
			item->index = count++;
			r_list_append (list, item);
			break;
		case R_ANAL_OP_TYPE_SWITCH:
		{
			RAnalCaseOp *caseop;
			RListIter *iter;

			// add caseops
			if (!op.switch_op) break;

			r_list_foreach (op.switch_op->cases, iter, caseop) {
				if (!linesout && (op.jump > opc + len || op.jump < opc)) {
					continue;
				}
				item = R_NEW0 (RAnalRefline);
				if (!item) goto list_err;

				item->from = op.switch_op->addr;
				item->to = caseop->jump;
				item->index = count++;
				r_list_append (list, item);
			}
			break;
		}
		}
	__next:
		ptr += sz;
	}
	r_anal_op_fini (&op);
	return list;
list_err:
	r_list_free (list);
	return NULL;
}

R_API RList*r_anal_reflines_fcn_get(RAnal *anal, RAnalFunction *fcn, int nlines, int linesout, int linescall) {
	RList *list;
	RAnalRefline *item;
	RAnalBlock *bb;
	RListIter *bb_iter;

	int index = 0;
	ut32 len;

	list = r_list_new ();
	if (!list) return NULL;

	/* analyze code block */
	r_list_foreach (fcn->bbs, bb_iter, bb) {
		if (!bb || bb->size == 0) continue;
		if (nlines != -1 && --nlines == 0) break;
		len = bb->size;

		/* store data */
		ut64 control_type = bb->type;
		control_type &= R_ANAL_BB_TYPE_SWITCH | R_ANAL_BB_TYPE_JMP | R_ANAL_BB_TYPE_COND | R_ANAL_BB_TYPE_CALL;

		// handle call
		if ( (control_type & R_ANAL_BB_TYPE_CALL) == R_ANAL_BB_TYPE_CALL && !linescall) {
			continue;
		}

		// Handles conditonal + unconditional jump
		if ( (control_type & R_ANAL_BB_TYPE_CJMP) == R_ANAL_BB_TYPE_CJMP) {
			// dont need to continue here is opc+len exceed function scope
			if (linesout && bb->fail > 0LL && bb->fail != bb->addr + len) {
				item = R_NEW0 (RAnalRefline);
				if (!item) {
					r_list_free (list);
					return NULL;
				}
				item->from = bb->addr;
				item->to = bb->fail;
				item->index = index++;
				r_list_append (list, item);
			}
		}
		if ( (control_type & R_ANAL_BB_TYPE_JMP) == R_ANAL_BB_TYPE_JMP) {
			if (!linesout || bb->jump == 0LL || bb->jump == bb->addr + len)
				continue;
			item = R_NEW0 (RAnalRefline);
			if (!item) {
				r_list_free (list);
				return NULL;
			}
			item->from = bb->addr;
			item->to = bb->jump;
			item->index = index++;
			r_list_append (list, item);
			continue;
		}

		// XXX - Todo test handle swith op
		if (control_type & R_ANAL_BB_TYPE_SWITCH) {
			if (bb->switch_op) {
				RAnalCaseOp *caseop;
				RListIter *iter;
				r_list_foreach (bb->switch_op->cases, iter, caseop) {
					if (caseop) {
						if (!linesout)// && (op.jump > opc+len || op.jump < pc))
							continue;
						item = R_NEW0 (RAnalRefline);
						if (!item){
							r_list_free (list);
							return NULL;
						}
						item->from = bb->switch_op->addr;
						item->to = caseop->jump;
						item->index = index++;
						r_list_append (list, item);
					}
				}
			}
		}
	}
	return list;
}

R_API int r_anal_reflines_middle(RAnal *a, RList* /*<RAnalRefline>*/ list, ut64 addr, int len) {
	if (a && list) {
		RAnalRefline *ref;
		RListIter *iter;
		r_list_foreach (list, iter, ref) {
			if ((ref->to > addr) && (ref->to < addr+len))
				return R_TRUE;
		}
	}
	return R_FALSE;
}

// TODO: move into another file
// TODO: this is TOO SLOW. do not iterate over all reflines or gtfo
R_API char* r_anal_reflines_str(void *_core, ut64 addr, int opts) {
	RCore *core = _core;
	RAnal *anal = core->anal;
	RBuffer *b;
	RListIter *iter;
	int l;
	int dir = 0, wide = opts & R_ANAL_REFLINE_TYPE_WIDE;
	char ch = ' ', *str = NULL;
	RAnalRefline *ref;

	if (!anal || !anal->reflines) return NULL;

	b = r_buf_new ();
	r_buf_append_string (b, " ");
	r_list_foreach_prev (anal->reflines, iter, ref) {
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
	if (core->anal->lineswidth>0) {
		int lw = core->anal->lineswidth;
		l = strlen (str);
		if (l > lw) {
			r_str_cpy (str, str + l - lw);
		} else {
			char pfx[128];
			lw -= l;
			memset (pfx, ' ', sizeof (pfx));
			if (lw >= sizeof (pfx)) {
				lw = sizeof (pfx)-1;
			}
			if (lw > 0) {
				pfx[lw] = 0;
				str = r_str_prefix (str, pfx);
			}
		}
	}
	str = r_str_concat (str, (dir==1)? "-> "
		: (dir==2)? "=< " : "   ");

	if (core->utf8 || opts & R_ANAL_REFLINE_TYPE_UTF8) {
		RCons *c = core->cons;
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
