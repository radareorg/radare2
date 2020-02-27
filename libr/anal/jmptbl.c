/* radare - LGPL - Copyright 2010-2019 - nibble, alvaro, pancake */

#include <r_anal.h>
#include <r_parse.h>
#include <r_util.h>
#include <r_list.h>

#define JMPTBL_MAXSZ 512

static void queue_case(RAnal *anal, ut64 switch_addr, int offset_sz, ut64 case_addr, ut64 id, ut64 case_addr_loc) {
	// eprintf ("** queue_case: 0x%"PFMT64x " from 0x%"PFMT64x "\n", case_addr, case_addr_loc);
	r_strbuf_appendf (anal->cmdtail,
		"Cd %d @ 0x%08"PFMT64x"\n", offset_sz, case_addr_loc);
	r_strbuf_appendf (anal->cmdtail,
		"ahi 10 @ 0x%08"PFMT64x"\n", case_addr_loc);
	r_strbuf_appendf (anal->cmdtail,
		"axc 0x%"PFMT64x " 0x%"PFMT64x "\n",
		(ut64)case_addr, (ut64)switch_addr);
	r_strbuf_appendf (anal->cmdtail,
		"afbe 0x%"PFMT64x " 0x%"PFMT64x "\n",
		(ut64)switch_addr, (ut64)case_addr);
	// r_strbuf_appendf (anal->cmdtail,
	// 	"aho case %d: from 0x%"PFMT64x " @ 0x%"PFMT64x "\n",
	// 	id, switch_addr, case_addr_loc);
	// r_strbuf_appendf (anal->cmdtail,
	// 	"CCu case %d: @ 0x%"PFMT64x "\n",
	// 	id, case_addr);
	r_strbuf_appendf (anal->cmdtail,
		"f case.0x%"PFMT64x ".%d 1 @ 0x%08"PFMT64x "\n",
		(ut64)switch_addr, (int)id, (ut64)case_addr);
}

// analyze a jmptablle inside a function // maybe rename to r_anal_fcn_jmptbl() ?
R_API bool r_anal_jmptbl(RAnal *anal, RAnalFunction *fcn, ut64 jmpaddr, ut64 table, ut64 tablesize, ut64 default_addr) {
	const int depth = 50;
	return try_walkthrough_jmptbl (anal, fcn, depth, jmpaddr, table, table, tablesize, tablesize, default_addr, false);
}

R_API bool try_walkthrough_jmptbl(RAnal *anal, RAnalFunction *fcn, int depth, ut64 ip, ut64 jmptbl_loc, ut64 jmptbl_off, ut64 sz, int jmptbl_size, ut64 default_case, bool ret0) {
	bool ret = ret0;
	// jmptbl_size can not always be determined
	if (jmptbl_size == 0) {
		jmptbl_size = JMPTBL_MAXSZ;
	}
	if (jmptbl_loc == UT64_MAX) {
		if (anal->verbose) {
			eprintf ("Warning: Invalid JumpTable location 0x%08"PFMT64x"\n", jmptbl_loc);
		}
		return false;
	}
	if (jmptbl_size < 1 || jmptbl_size > ST32_MAX) {
		if (anal->verbose) {
			eprintf ("Warning: Invalid JumpTable size at 0x%08"PFMT64x"\n", ip);
		}
		return false;
	}
	ut64 jmpptr, offs;
	ut8 *jmptbl = calloc (jmptbl_size, sz);
	if (!jmptbl) {
		return false;
	}
	bool is_arm = anal->cur->arch && !strncmp (anal->cur->arch, "arm", 3);
	// eprintf ("JMPTBL AT 0x%"PFMT64x"\n", jmptbl_loc);
	anal->iob.read_at (anal->iob.io, jmptbl_loc, jmptbl, jmptbl_size * sz);
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
		if (sz == 2 && is_arm) {
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
		}
		if (anal->limit) {
			if (jmpptr < anal->limit->from || jmpptr > anal->limit->to) {
				break;
			}
		}
		queue_case (anal, ip, sz, jmpptr, offs / sz, jmptbl_loc + offs);
		(void)r_anal_fcn_bb (anal, fcn, jmpptr, depth - 1);
	}

	if (offs > 0) {
		// eprintf("\n\nSwitch statement at 0x%llx:\n", ip);
		r_strbuf_appendf (anal->cmdtail,
			"CCu switch table (%d cases) at 0x%"PFMT64x " @ 0x%"PFMT64x "\n",
			(int)(offs/sz), jmptbl_loc, ip);
		r_strbuf_appendf (anal->cmdtail,
			"f switch.0x%08"PFMT64x" 1 @ 0x%08"PFMT64x"\n", ip, ip);
		if (default_case != 0 && default_case != UT64_MAX) {
			r_strbuf_appendf (anal->cmdtail,
				"f case.default.0x%"PFMT64x " 1 @ 0x%08"PFMT64x "\n",
				ip, default_case);
		}
	}

	free (jmptbl);
	return ret;
}

// TODO: RENAME
R_API bool try_get_delta_jmptbl_info(RAnal *anal, RAnalFunction *fcn, ut64 jmp_addr, ut64 lea_addr, ut64 *table_size, ut64 *default_case) {
	bool isValid = false;
	bool foundCmp = false;
	int i;

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

	for (i = 0; i + 8 < search_sz; i++) {
		int len = r_anal_op (anal, &tmp_aop, lea_addr + i, buf + i, search_sz - i, R_ANAL_OP_MASK_BASIC);
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
		// TODO: check the jmp for whether val is included in valid range or not (ja vs jae)
		foundCmp = true;
	}
	free (buf);
	return isValid;
}

// TODO: find a better function name
R_API int walkthrough_arm_jmptbl_style(RAnal *anal, RAnalFunction *fcn, int depth, ut64 ip, ut64 jmptbl_loc, ut64 sz, ut64 jmptbl_size, ut64 default_case, int ret0) {
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
		queue_case (anal, ip, sz, jmpptr, offs / sz, jmptbl_loc + offs);
		(void)r_anal_fcn_bb (anal, fcn, jmpptr, depth - 1);
	}

	if (offs > 0) {
		// eprintf("\n\nSwitch statement at 0x%llx:\n", ip);
		r_strbuf_appendf (anal->cmdtail,
			"CCu switch table (%d cases) at 0x%"PFMT64x " @ 0x%"PFMT64x "\n",
			offs / sz, jmptbl_loc, ip);
		r_strbuf_appendf (anal->cmdtail,
			"f switch.0x%08"PFMT64x" 1 @ 0x%08"PFMT64x"\n",
			ip, ip);
		if (default_case != 0 && default_case != UT64_MAX && default_case != UT32_MAX) {
			r_strbuf_appendf (anal->cmdtail,
				"f case.default.0x%"PFMT64x " 1 @ 0x%08"PFMT64x "\n",
				default_case, default_case);
		}

	}
	return ret;
}

R_API bool try_get_jmptbl_info(RAnal *anal, RAnalFunction *fcn, ut64 addr, RAnalBlock *my_bb, ut64 *table_size, ut64 *default_case) {
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
		bool in_plt = strstr (s->name, ".plt") != NULL;
		if (!in_plt && strstr (s->name, "_stubs") != NULL) {
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
		if (anal->verbose) {
			eprintf ("Warning: [anal.jmp.tbl] Missing predecesessor cjmp bb at 0x%08"PFMT64x"\n", addr);
		}
		return false;
	}

	// default case is the jump target of the unconditional jump
	*default_case = prev_bb->jump == my_bb->addr ? prev_bb->fail : prev_bb->jump;

	RAnalOp tmp_aop = {0};
	ut8 *bb_buf = calloc (1, prev_bb->size);
	if (!bb_buf) {
		return false;
	}
	// search for a cmp register with a reasonable size
	anal->iob.read_at (anal->iob.io, prev_bb->addr, (ut8 *) bb_buf, prev_bb->size);
	isValid = false;

	RAnalHint *hint = r_anal_hint_get (anal, addr);
	if (hint) {
		ut64 val = hint->val;
		r_anal_hint_free (hint);
		if (val != UT64_MAX) {
			*table_size = val;
			return true;
		}
	}

	for (i = 0; i < prev_bb->op_pos_size; i++) {
		ut64 prev_pos = prev_bb->op_pos[i];
		ut64 op_addr = prev_bb->addr + prev_pos;
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
		r_anal_op_fini (&tmp_aop);
		// TODO: check the jmp for whether val is included in valid range or not (ja vs jae)
		break;
	}
	free (bb_buf);
	// eprintf ("switch at 0x%" PFMT64x "\n\tdefault case 0x%" PFMT64x "\n\t#cases: %d\n",
	// 		addr,
	// 		*default_case,
	// 		*table_size);
	return isValid;
}
