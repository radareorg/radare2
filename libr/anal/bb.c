/* radare - LGPL - Copyright 2010-2019 - pancake, nibble */

#include <r_anal.h>
#include <r_util.h>
#include <r_list.h>
#include <limits.h>

#define DFLT_NINSTR 3

R_API RAnalBlock *r_anal_bb_new() {
	RAnalBlock *bb = R_NEW0 (RAnalBlock);
	if (bb) {
		bb->addr = UT64_MAX;
		bb->jump = UT64_MAX;
		bb->fail = UT64_MAX;
		bb->type = R_ANAL_BB_TYPE_NULL;
		bb->op_pos = R_NEWS0 (ut16, DFLT_NINSTR);
		bb->op_pos_size = DFLT_NINSTR;
		bb->stackptr = 0;
		bb->parent_stackptr = INT_MAX;
		bb->cmpval = UT64_MAX;
	}
	return bb;
}

R_API void r_anal_bb_free(RAnalBlock *bb) {
	if (bb) {
		r_anal_cond_free (bb->cond);
		free (bb->fingerprint);
		r_anal_diff_free (bb->diff);
		free (bb->op_bytes);
		r_anal_switch_op_free (bb->switch_op);
		free (bb->label);
		free (bb->op_pos);
		free (bb->parent_reg_arena);
		free (bb);
	}
}

R_API RList *r_anal_bb_list_new() {
	return r_list_newf ((RListFree)r_anal_bb_free);
}

R_API inline int r_anal_bb_is_in_offset (RAnalBlock *bb, ut64 off) {
	return (off >= bb->addr && off < bb->addr + bb->size);
}

R_API RAnalBlock *r_anal_bb_from_offset(RAnal *anal, ut64 off) {
	RListIter *iter, *iter2;
	RAnalFunction *fcn;
	RAnalBlock *bb;
	const bool x86 = anal->cur->arch && !strcmp (anal->cur->arch, "x86");
	if (anal->opt.jmpmid && x86) {
		RAnalBlock *nearest_bb = NULL;
		r_list_foreach (anal->fcns, iter, fcn) {
			r_list_foreach (fcn->bbs, iter2, bb) {
				if (r_anal_bb_op_starts_at (bb, off)) {
					return bb;
				} else if (r_anal_bb_is_in_offset (bb, off)
				           && (!nearest_bb || nearest_bb->addr < bb->addr)) {
					nearest_bb = bb;
				}
			}
		}
		return nearest_bb;
	}
	r_list_foreach (anal->fcns, iter, fcn) {
		r_list_foreach (fcn->bbs, iter2, bb) {
			if (r_anal_bb_is_in_offset (bb, off)) {
				return bb;
			}
		}
	}
	return NULL;
}

R_API RAnalBlock *r_anal_bb_get_jumpbb(RAnalFunction *fcn, RAnalBlock *bb) {
	if (bb->jump == UT64_MAX) {
		return NULL;
	}
	if (bb->jumpbb) {
		return bb->jumpbb;
	}
	RListIter *iter;
	RAnalBlock *b;
	r_list_foreach (fcn->bbs, iter, b) {
		if (b->addr == bb->jump) {
			bb->jumpbb = b;
			b->prev = bb;
			return b;
		}
	}
	return NULL;
}

R_API RAnalBlock *r_anal_bb_get_failbb(RAnalFunction *fcn, RAnalBlock *bb) {
	RListIter *iter;
	RAnalBlock *b;
	if (bb->fail == UT64_MAX) {
		return NULL;
	}
	if (bb->failbb) {
		return bb->failbb;
	}
	r_list_foreach (fcn->bbs, iter, b) {
		if (b->addr == bb->fail) {
			bb->failbb = b;
			b->prev = bb;
			return b;
		}
	}
	return NULL;
}

/* return the offset of the i-th instruction in the basicblock bb.
 * If the index of the instruction is not valid, it returns UT16_MAX */
R_API ut16 r_anal_bb_offset_inst(RAnalBlock *bb, int i) {
	if (i < 0 || i >= bb->ninstr) {
		return UT16_MAX;
	}
	return (i > 0 && (i - 1) < bb->op_pos_size)? bb->op_pos[i - 1]: 0;
}

/* return the address of the i-th instruction in the basicblock bb.
 * If the index of the instruction is not valid, it returns UT64_MAX */
R_API ut64 r_anal_bb_opaddr_i(RAnalBlock *bb, int i) {
	ut16 offset = r_anal_bb_offset_inst (bb, i);
	if (offset == UT16_MAX) {
		return UT64_MAX;
	}
	return bb->addr + offset;
}

/* set the offset of the i-th instruction in the basicblock bb */
R_API bool r_anal_bb_set_offset(RAnalBlock *bb, int i, ut16 v) {
	// the offset 0 of the instruction 0 is not stored because always 0
	if (i > 0 && v > 0) {
		if (i >= bb->op_pos_size) {
			int new_pos_size = i * 2;
			ut16 *tmp_op_pos = realloc (bb->op_pos, new_pos_size * sizeof (*bb->op_pos));
			if (!tmp_op_pos) {
				return false;
			}
			bb->op_pos_size = new_pos_size;
			bb->op_pos = tmp_op_pos;
		}
		bb->op_pos[i - 1] = v;
		return true;
	}
	return true;
}

/* return the address of the instruction that occupy a given offset.
 * If the offset is not part of the given basicblock, UT64_MAX is returned. */
R_API ut64 r_anal_bb_opaddr_at(RAnalBlock *bb, ut64 off) {
	ut16 delta, delta_off, last_delta;
	int i;

	if (!r_anal_bb_is_in_offset (bb, off)) {
		return UT64_MAX;
	}
	last_delta = 0;
	delta_off = off - bb->addr;
	for (i = 0; i < bb->ninstr; i++) {
		delta = r_anal_bb_offset_inst (bb, i);
		if (delta > delta_off) {
			return bb->addr + last_delta;
		}
		last_delta = delta;
	}
	return bb->addr + last_delta;
}

/* return true if an instruction starts at a given address of the given
 * basic block. */
R_API bool r_anal_bb_op_starts_at(RAnalBlock *bb, ut64 addr) {
	int i;

	if (!r_anal_bb_is_in_offset (bb, addr)) {
		return false;
	}
	ut16 off = addr - bb->addr;
	for (i = 0; i < bb->ninstr; i++) {
		ut16 inst_off = r_anal_bb_offset_inst (bb, i);
		if (off == inst_off) {
			return true;
		}
	}
	return false;
}

/* returns the address of the basic block that contains addr or UT64_MAX if
 * there is no such basic block */
R_API ut64 r_anal_get_bbaddr(RAnal *anal, ut64 addr) {
	RAnalBlock *bb;
	RListIter *iter;
	RAnalFunction *fcni = r_anal_get_fcn_in_bounds (anal, addr, 0);
	if (fcni) {
		r_list_foreach (fcni->bbs, iter, bb) {
			if (addr >= bb->addr && addr < bb->addr + bb->size) {
				return bb->addr;
			}
		}
	}
	return UT64_MAX;
}
