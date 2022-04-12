/* radare - LGPL - Copyright 2010-2022 - nibble, alvaro, pancake, th3str4ng3r */

#include <r_anal.h>
#include <r_parse.h>
#include <r_util.h>
#include <r_list.h>

#define aprintf(format, ...) if (anal->verbose) eprintf (format, __VA_ARGS__)

#define JMPTBL_MAXSZ 512

static void apply_case(RAnal *anal, RAnalBlock *block, ut64 switch_addr, ut64 offset_sz, ut64 case_addr, ut64 id, ut64 case_addr_loc) {
	// eprintf ("** apply_case: 0x%"PFMT64x " from 0x%"PFMT64x "\n", case_addr, case_addr_loc);
	r_meta_set_data_at (anal, case_addr_loc, offset_sz);
	r_anal_hint_set_immbase (anal, case_addr_loc, 10);
	r_anal_xrefs_set (anal, switch_addr, case_addr, R_ANAL_REF_TYPE_CODE | R_ANAL_REF_TYPE_EXEC);
	if (block) {
		r_anal_block_add_switch_case (block, switch_addr, id, case_addr);
	}
	if (anal->flb.set) {
		char flagname[0x30];
		int iid = R_ABS((int)id);
		snprintf (flagname, sizeof (flagname), "case.0x%"PFMT64x ".%d", (ut64)switch_addr, iid);
		anal->flb.set (anal->flb.f, flagname, case_addr, 1);
	}
}

static void apply_switch(RAnal *anal, ut64 switch_addr, ut64 jmptbl_addr, ut64 cases_count, ut64 default_case_addr) {
	char tmp[0x30];
	snprintf (tmp, sizeof (tmp), "switch table (%"PFMT64u" cases) at 0x%"PFMT64x, cases_count, jmptbl_addr);
	r_meta_set_string (anal, R_META_TYPE_COMMENT, switch_addr, tmp);
	if (anal->flb.set) {
		snprintf (tmp, sizeof (tmp), "switch.0x%08"PFMT64x, switch_addr);
		anal->flb.set (anal->flb.f, tmp, switch_addr, 1);
		if (default_case_addr != UT64_MAX) {
			r_anal_xrefs_set (anal, switch_addr, default_case_addr, R_ANAL_REF_TYPE_CODE | R_ANAL_REF_TYPE_EXEC);
			snprintf (tmp, sizeof (tmp), "case.default.0x%"PFMT64x, switch_addr);
			anal->flb.set (anal->flb.f, tmp, default_case_addr, 1);
		}
	}
}

// analyze a jmptablle inside a function // maybe rename to r_anal_function_jmptbl() ?
R_API bool r_anal_jmptbl(RAnal *anal, RAnalFunction *fcn, RAnalBlock *block, ut64 jmpaddr, ut64 table, ut64 tablesize, ut64 default_addr) {
	const int depth = 50;
	return try_walkthrough_jmptbl (anal, fcn, block, depth, jmpaddr, 0, table, table, tablesize, tablesize, default_addr, false);
}

static inline void analyze_new_case(RAnal *anal, RAnalFunction *fcn, RAnalBlock *block, ut64 ip, ut64 jmpptr, int depth) {
	const ut64 block_size = block->size;
	(void)r_anal_function_bb (anal, fcn, jmpptr, depth - 1);
	if (block->size != block_size) {
		// block was be split during anal and does not contain the
		// jmp instruction anymore, so we need to search for it and get it again
		RAnalSwitchOp *sop = block->switch_op;
		block = r_anal_get_block_at (anal, ip);
		if (!block) {
			block = r_anal_bb_from_offset (anal, ip);
			if (block) {
				if (block->addr != ip) {
					st64 d = block->addr - ip;
					eprintf ("Cannot find basic block for switch case at 0x%08"PFMT64x" bbdelta = %d\n", ip, (int)R_ABS (d));
					block = NULL;
					return;
				} else {
					eprintf ("Inconsistent basicblock storage issue at 0x%08"PFMT64x"\n", ip);
				}
			} else {
				eprintf ("Major disaster at 0x%08"PFMT64x"\n", ip);
				return;
			}
			// analyze at given address
			// block = r_anal_create_block(RAnal *anal, ut64 addr, ut64 size) {
		}
		block->switch_op = sop;
	}
}

R_API bool try_walkthrough_casetbl(RAnal *anal, RAnalFunction *fcn, RAnalBlock *block, int depth, ut64 ip, st64 start_casenum_shift, ut64 jmptbl_loc, ut64 casetbl_loc, ut64 jmptbl_off, ut64 sz, ut64 jmptbl_size, ut64 default_case, bool ret0) {
	bool ret = ret0;
	if (jmptbl_size == 0) {
		jmptbl_size = JMPTBL_MAXSZ;
	}
	if (jmptbl_loc == UT64_MAX) {
		aprintf ("Warning: Invalid JumpTable location 0x%08" PFMT64x "\n", jmptbl_loc);
		return false;
	}
	if (casetbl_loc == UT64_MAX) {
		aprintf ("Warning: Invalid CaseTable location 0x%08" PFMT64x "\n", jmptbl_loc);
		return false;
	}
	if (jmptbl_size < 1 || jmptbl_size > ST32_MAX) {
		aprintf ("Warning: Invalid JumpTable size at 0x%08" PFMT64x "\n", ip);
		return false;
	}
	ut64 jmpptr, case_idx, jmpptr_idx;
	ut8 *jmptbl = calloc (jmptbl_size, sz);
	if (!jmptbl || !anal->iob.read_at (anal->iob.io, jmptbl_loc, jmptbl, jmptbl_size * sz)) {
		free (jmptbl);
		return false;
	}
	ut8 *casetbl = calloc (jmptbl_size, sizeof (ut8));
	if (!casetbl || !anal->iob.read_at (anal->iob.io, casetbl_loc, casetbl, jmptbl_size)) {
		free (jmptbl);
		free (casetbl);
		return false;
	}
	for (case_idx = 0; case_idx < jmptbl_size; case_idx++) {
		jmpptr_idx = casetbl[case_idx];

		if (jmpptr_idx >= jmptbl_size) {
			ret = false;
			break;
		}

		switch (sz) {
		case 1:
			jmpptr = r_read_le8 (jmptbl + jmpptr_idx);
			break;
		case 2:
			jmpptr = r_read_le16 (jmptbl + jmpptr_idx * 2);
			break;
		case 4:
			jmpptr = r_read_le32 (jmptbl + jmpptr_idx * 4);
			break;
		default:
			jmpptr = r_read_le64 (jmptbl + jmpptr_idx * 8);
			break;
		}
		if (jmpptr == 0 || jmpptr == UT32_MAX || jmpptr == UT64_MAX) {
			break;
		}
		if (!anal->iob.is_valid_offset (anal->iob.io, jmpptr, 0)) {
			st32 jmpdelta = (st32)jmpptr;
			// jump tables where sign extended movs are used
			jmpptr = jmptbl_off + jmpdelta;
			if (!anal->iob.is_valid_offset (anal->iob.io, jmpptr, 0)) {
				break;
			}
		}
		if (anal->limit) {
			if (jmpptr < anal->limit->from || jmpptr > anal->limit->to) {
				break;
			}
		}

		const ut64 jmpptr_idx_off = casetbl_loc + case_idx;
		r_meta_set_data_at (anal, jmpptr_idx_off, 1);
		r_anal_hint_set_immbase (anal, jmpptr_idx_off, 10);

		int casenum = case_idx + start_casenum_shift;
		apply_case (anal, block, ip, sz, jmpptr, casenum, jmptbl_loc + jmpptr_idx * sz);
		analyze_new_case (anal, fcn, block, ip, jmpptr, depth);
	}

	if (case_idx > 0) {
		if (default_case == 0) {
			default_case = UT64_MAX;
		}
		apply_switch (anal, ip, jmptbl_loc, case_idx, default_case);
	}

	free (jmptbl);
	free (casetbl);
	return ret;
}

R_API bool try_walkthrough_jmptbl(RAnal *anal, RAnalFunction *fcn, RAnalBlock *block, int depth, ut64 ip, st64 start_casenum_shift, ut64 jmptbl_loc, ut64 jmptbl_off, ut64 sz, ut64 jmptbl_size, ut64 default_case, bool ret0) {
	bool ret = ret0;
	// jmptbl_size can not always be determined
	if (jmptbl_size == 0) {
		jmptbl_size = JMPTBL_MAXSZ;
	}
	if (jmptbl_loc == UT64_MAX) {
		aprintf ("Warning: Invalid JumpTable location 0x%08"PFMT64x"\n", jmptbl_loc);
		return false;
	}
	if (jmptbl_size < 1 || jmptbl_size > ST32_MAX) {
		aprintf ("Warning: Invalid JumpTable size at 0x%08"PFMT64x"\n", ip);
		return false;
	}
	ut64 jmpptr, offs;
	int jmptblsz = jmptbl_size * sz;
	if (jmptblsz < 1) {
		if (anal->verbose) {
			eprintf ("Invalid jump table size\n");
		}
		return false;
	}
	ut8 *jmptbl = calloc (jmptbl_size, sz);
	if (!jmptbl) {
		return false;
	}
	bool is_arm = anal->cur->arch && !strncmp (anal->cur->arch, "arm", 3);
	bool is_x86 = !is_arm && anal->cur->arch && !strncmp (anal->cur->arch, "x86", 3);
	const bool is_v850 = !is_arm && !is_x86 && ((anal->cur->arch && !strncmp (anal->cur->arch, "v850", 4)) || !strncmp (anal->coreb.cfgGet (anal->coreb.core, "asm.cpu"), "v850", 4));
	// eprintf ("JMPTBL AT 0x%"PFMT64x"\n", jmptbl_loc);
	anal->iob.read_at (anal->iob.io, jmptbl_loc, jmptbl, jmptblsz);
	for (offs = 0; offs + sz - 1 < jmptbl_size * sz; offs += sz) {
		switch (sz) {
		case 1:
			jmpptr = (ut64)(ut8)r_read_le8 (jmptbl + offs);
			break;
		case 2:
			jmpptr = (ut64)r_read_le16 (jmptbl + offs);
			break;
		case 4:
			jmpptr = r_read_le32 (jmptbl + offs);
			break;
		case 8:
			jmpptr = r_read_le64 (jmptbl + offs);
			break; // XXX
		default:
			jmpptr = r_read_le64 (jmptbl + offs);
			break;
		}
		// eprintf ("WALKING %llx\n", jmpptr);
		// if we don't check for 0 here, the next check with ptr+jmpptr
		// will obviously be a good offset since it will be the start
		// of the table, which is not what we want
		if (jmpptr == 0 || jmpptr == UT32_MAX || jmpptr == UT64_MAX) {
			break;
		}
		if (sz == 2 && (is_arm || is_v850)) {
			jmpptr = ip +  4 + (jmpptr * 2); // tbh [pc, r2, lsl 1]  // assume lsl 1
		} else if (sz == 1 && is_arm) {
			jmpptr = ip +  4 + (jmpptr * 2); // lbb [pc, r2]  // assume lsl 1
		} else if (!anal->iob.is_valid_offset (anal->iob.io, jmpptr, 0)) {
			st32 jmpdelta = (st32)jmpptr;
			// jump tables where sign extended movs are used
			jmpptr = jmptbl_off + jmpdelta;
			if (!anal->iob.is_valid_offset (anal->iob.io, jmpptr, 0)) {
				break;
			}
		} else if (sz == 2 && is_x86) {
			st32 jmpdelta = (st32)jmpptr;
			// jump tables where sign extended movs are used
			jmpptr = jmptbl_off + jmpdelta;
		}
		if (anal->limit) {
			if (jmpptr < anal->limit->from || jmpptr > anal->limit->to) {
				break;
			}
		}
		//apply_case (anal, block, ip, sz, jmpptr, offs / sz, jmptbl_loc + offs);
		//(void)r_anal_function_bb (anal, fcn, jmpptr, depth - 1);
		int case_idx = offs / sz;
		int casenum = case_idx + start_casenum_shift;
		apply_case (anal, block, ip, sz, jmpptr, casenum, jmptbl_loc + offs);
		analyze_new_case (anal, fcn, block, ip, jmpptr, depth);
	}

	if (offs > 0) {
		if (default_case == 0) {
			default_case = UT64_MAX;
		}
		apply_switch (anal, ip, jmptbl_loc, offs / sz, default_case);
	}

	free (jmptbl);
	return ret;
}

static bool detect_casenum_shift(RAnalOp *op, RRegItem **cmp_reg, st64 *start_casenum_shift) {
	if (!*cmp_reg) {
		return true;
	}
	if (op->dst && op->dst->reg && op->dst->reg->offset == (*cmp_reg)->offset) {
		if (op->type == R_ANAL_OP_TYPE_LEA && op->ptr == UT64_MAX) {
			*start_casenum_shift = -(st64)op->disp;
		} else if (op->val != UT64_MAX) {
			if (op->type == R_ANAL_OP_TYPE_ADD) {
				*start_casenum_shift = -(st64)op->val;
			} else if (op->type == R_ANAL_OP_TYPE_SUB) {
				*start_casenum_shift = op->val;
			}
		} else if (op->type == R_ANAL_OP_TYPE_MOV) {
			*cmp_reg = op->src[0]->reg;
			return false;
		}
		return true;
	}
	return false;
}

R_API bool try_get_delta_jmptbl_info(RAnal *anal, RAnalFunction *fcn, ut64 jmp_addr, ut64 lea_addr, ut64 *table_size, ut64 *default_case, st64 *start_casenum_shift) {
	bool isValid = false;
	bool foundCmp = false;
	ut64 i;

	RAnalOp tmp_aop = {0};
	if (lea_addr > jmp_addr) {
		return false;
	}
	int search_sz = jmp_addr - lea_addr;
	ut8 *buf = malloc (search_sz);
	if (!buf) {
		return false;
	}
	// search for a cmp register with a reasonable size
	anal->iob.read_at (anal->iob.io, lea_addr, (ut8 *)buf, search_sz);

	RVector v;
	r_vector_init (&v, sizeof (ut64), NULL, NULL);
	int len = 0;
	RRegItem *cmp_reg = NULL;
	for (i = 0; i + 8 < search_sz; i += len) {
		len = r_anal_op (anal, &tmp_aop, lea_addr + i, buf + i, search_sz - i, R_ANAL_OP_MASK_BASIC);
		if (len < 1) {
			len = 1;
		}

		if (foundCmp) {
			if (tmp_aop.type != R_ANAL_OP_TYPE_CJMP) {
				continue;
			}

			*default_case = tmp_aop.jump == tmp_aop.jump + len ? tmp_aop.fail : tmp_aop.jump;
			break;
		}

		ut32 type = tmp_aop.type & R_ANAL_OP_TYPE_MASK;
		if (type != R_ANAL_OP_TYPE_CMP) {
			continue;
		}
		// get the value of the cmp
		// for operands in op, check if type is immediate and val is sane
		// TODO: How? opex?

		// for the time being, this seems to work
		// might not actually have a value, let the next step figure out the size then
		if (tmp_aop.val == UT64_MAX && tmp_aop.refptr == 0) {
			isValid = true;
			*table_size = 0;
		} else if (tmp_aop.refptr == 0) {
			isValid = tmp_aop.val < 0x200;
			*table_size = tmp_aop.val + 1;
		} else {
			isValid = tmp_aop.refptr < 0x200;
			*table_size = tmp_aop.refptr + 1;
		}
		r_vector_push (&v, &i);
		r_anal_op (anal, &tmp_aop, lea_addr + i, buf + i, search_sz - i, R_ANAL_OP_MASK_VAL);
		if (tmp_aop.dst && tmp_aop.dst->reg) {
			cmp_reg = tmp_aop.dst->reg;
		} else if (tmp_aop.reg) {
			cmp_reg = r_reg_get (anal->reg, tmp_aop.reg, R_REG_TYPE_ALL);
		} else if (tmp_aop.src[0] && tmp_aop.src[0]->reg) {
			cmp_reg = tmp_aop.src[0]->reg;
		}
		r_anal_op_fini (&tmp_aop);
		// TODO: check the jmp for whether val is included in valid range or not (ja vs jae)
		foundCmp = true;
	}
	if (isValid) {
		*start_casenum_shift = 0;
		void **it;
		r_vector_foreach_prev (&v, it) {
			const ut64 op_off = *(ut64 *)it;
			ut64 op_addr = lea_addr + op_off;
			r_anal_op (anal, &tmp_aop, op_addr,
					buf + op_off, search_sz - op_off,
					R_ANAL_OP_MASK_VAL);
			if (detect_casenum_shift (&tmp_aop, &cmp_reg, start_casenum_shift)) {
				r_anal_op_fini (&tmp_aop);
				break;
			}
			r_anal_op_fini (&tmp_aop);
		}
	}
	r_vector_fini (&v);
	free (buf);
	return isValid;
}

// TODO: find a better function name
R_API int walkthrough_arm_jmptbl_style(RAnal *anal, RAnalFunction *fcn, RAnalBlock *block, int depth, ut64 ip, ut64 jmptbl_loc, ut64 sz, ut64 jmptbl_size, ut64 default_case, int ret0) {
	/*
	 * Example about arm jump table
	 *
	 * 0x000105b4      060050e3       cmp r0, 3
	 * 0x000105b8      00f18f90       addls pc, pc, r0, lsl 2
	 * 0x000105bc      0d0000ea       b loc.000105f8
	 * 0x000105c0      050000ea       b 0x105dc
	 * 0x000105c4      050000ea       b 0x105e0
	 * 0x000105c8      060000ea       b 0x105e8
	 * ; CODE XREF from loc._a_7 (+0x10)
	 * 0x000105dc      b6ffffea       b sym.input_1
	 * ; CODE XREF from loc._a_7 (+0x14)
	 * 0x000105e0      b9ffffea       b sym.input_2
	 * ; CODE XREF from loc._a_7 (+0x28)
	 * 0x000105e4      ccffffea       b sym.input_7
	 * ; CODE XREF from loc._a_7 (+0x18)
	 * 0x000105e8      bbffffea       b sym.input_3
	 */

	ut64 offs, jmpptr;
	int ret = ret0;

	if (jmptbl_size == 0) {
		jmptbl_size = JMPTBL_MAXSZ;
	}

	for (offs = 0; offs + sz - 1 < jmptbl_size * sz; offs += sz) {
		jmpptr = jmptbl_loc + offs;
		apply_case (anal, block, ip, sz, jmpptr, offs / sz, jmptbl_loc + offs);
		analyze_new_case (anal, fcn, block, ip, jmpptr, depth);
	}

	if (offs > 0) {
		if (default_case == 0 || default_case == UT32_MAX) {
			default_case = UT64_MAX;
		}
		apply_switch (anal, ip, jmptbl_loc, offs / sz, default_case);
	}
	return ret;
}

R_API bool try_get_jmptbl_info(RAnal *anal, RAnalFunction *fcn, ut64 addr, RAnalBlock *my_bb, ut64 *table_size, ut64 *default_case, st64 *start_casenum_shift) {
	bool isValid = false;
	int i;
	RListIter *iter;
	RAnalBlock *tmp_bb, *prev_bb;
	prev_bb = 0;
	if (!fcn->bbs) {
		return false;
	}

	/* if UJMP is in .plt section just skip it */
	RBinSection *s = anal->binb.get_vsect_at (anal->binb.bin, addr);
	if (s && s->name[0]) {
		bool in_plt = strstr (s->name, ".plt");
		if (!in_plt && strstr (s->name, "_stubs")) {
			/* for mach0 */
			in_plt = true;
		}
		if (in_plt) {
			return false;
		}
	}

	// search for the predecessor bb
	r_list_foreach (fcn->bbs, iter, tmp_bb) {
		if (tmp_bb->jump == my_bb->addr || tmp_bb->fail == my_bb->addr) {
			prev_bb = tmp_bb;
			break;
		}
	}
	// predecessor must be a conditional jump
	if (!prev_bb || !prev_bb->jump || !prev_bb->fail) {
		aprintf ("Warning: [anal.jmp.tbl] Missing predecesessor cjmp bb at 0x%08"PFMT64x"\n", addr);
		return false;
	}

	// default case is the jump target of the unconditional jump
	*default_case = prev_bb->jump == my_bb->addr ? prev_bb->fail : prev_bb->jump;

	RAnalHint *hint = r_anal_hint_get (anal, addr);
	if (hint) {
		ut64 val = hint->val;
		r_anal_hint_free (hint);
		if (val != UT64_MAX) {
			*table_size = val;
			return true;
		}
	}

	RAnalOp tmp_aop = {0};
	ut8 *bb_buf = calloc (1, prev_bb->size);
	if (!bb_buf) {
		return false;
	}
	// search for a cmp register with a reasonable size
	anal->iob.read_at (anal->iob.io, prev_bb->addr, (ut8 *) bb_buf, prev_bb->size);
	isValid = false;

	RRegItem *cmp_reg = NULL;
	for (i = prev_bb->ninstr - 1; i >= 0; i--) {
		const ut64 prev_pos = r_anal_bb_offset_inst (prev_bb, i);
		const ut64 op_addr = r_anal_bb_opaddr_i (prev_bb, i);
		if (prev_pos >= prev_bb->size) {
			continue;
		}
		int buflen = prev_bb->size - prev_pos;
		int len = r_anal_op (anal, &tmp_aop, op_addr,
			bb_buf + prev_pos, buflen,
			R_ANAL_OP_MASK_BASIC | R_ANAL_OP_MASK_HINT);
		ut32 type = tmp_aop.type & R_ANAL_OP_TYPE_MASK;
		if (len < 1 || type != R_ANAL_OP_TYPE_CMP) {
			r_anal_op_fini (&tmp_aop);
			continue;
		}
		// get the value of the cmp
		// for operands in op, check if type is immediate and val is sane
		// TODO: How? opex?

		// for the time being, this seems to work
		// might not actually have a value, let the next step figure out the size then
		if (tmp_aop.val == UT64_MAX && tmp_aop.refptr == 0) {
			isValid = true;
			*table_size = 0;
		} else if (tmp_aop.refptr == 0 || tmp_aop.val != UT64_MAX) {
			isValid = tmp_aop.val < 0x200;
			*table_size = tmp_aop.val + 1;
		} else {
			isValid = tmp_aop.refptr < 0x200;
			*table_size = tmp_aop.refptr + 1;
		}
		if (isValid) {
			r_anal_op_fini (&tmp_aop);
			r_anal_op (anal, &tmp_aop, op_addr,
					bb_buf + prev_pos, buflen,
					R_ANAL_OP_MASK_VAL);
			if (tmp_aop.dst && tmp_aop.dst->reg) {
				cmp_reg = tmp_aop.dst->reg;
			} else if (tmp_aop.reg) {
				cmp_reg = r_reg_get (anal->reg, tmp_aop.reg, R_REG_TYPE_ALL);
			} else if (tmp_aop.src[0] && tmp_aop.src[0]->reg) {
				cmp_reg = tmp_aop.src[0]->reg;
			}
		}
		r_anal_op_fini (&tmp_aop);
		// TODO: check the jmp for whether val is included in valid range or not (ja vs jae)
		break;
	}
	if (isValid) {
		*start_casenum_shift = 0;
		for (i--; i >= 0; i--) {
			const ut64 prev_pos = r_anal_bb_offset_inst (prev_bb, i);
			const ut64 op_addr = r_anal_bb_opaddr_i (prev_bb, i);
			if (prev_pos >= prev_bb->size) {
				continue;
			}
			int buflen = prev_bb->size - prev_pos;
			r_anal_op (anal, &tmp_aop, op_addr,
					bb_buf + prev_pos, buflen,
					R_ANAL_OP_MASK_VAL);
			if (detect_casenum_shift (&tmp_aop, &cmp_reg, start_casenum_shift)) {
				r_anal_op_fini (&tmp_aop);
				break;
			}

			r_anal_op_fini (&tmp_aop);
		}
	}
	free (bb_buf);
	// eprintf ("switch at 0x%" PFMT64x "\n\tdefault case 0x%" PFMT64x "\n\t#cases: %d\n",
	// 		addr,
	// 		*default_case,
	// 		*table_size);
	return isValid;
}
