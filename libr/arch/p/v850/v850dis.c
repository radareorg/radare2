/* V850 disassembler inspired by the GNU binutils one -- 2021-2024 - pancake */

#include "v850dis.h"
#include "opc.inc.c"

enum {
	V850_ARG_TYPE_UNKNOWN,
	V850_ARG_TYPE_STRING,
	V850_ARG_TYPE_NUMBER
};

static const ut8 v850_cacheop_codes[] = {
	0x00, 0x20, 0x40, 0x60, 0x61, 0x04, 0x06,
	0x07, 0x24, 0x26, 0x27, 0x44, 0x64, 0x65
};

static const ut8 v850_prefop_codes[] = { 0x00, 0x04 };

static void print_value(RStrBuf *sb, int flags, ut64 memaddr, long value) {
	const char *format = (flags & V850_OPERAND_SIGNED)? "%ld": "%lu";
	if (flags & V850_PCREL) {
		ut64 addr = value + memaddr;
		if (flags & V850_INVERSE_PCREL) {
			addr = memaddr - value;
		}
		r_strbuf_appendf (sb, "0x%"PFMT64x, (ut64)addr); // memaddr);
	} else if (flags & V850_OPERAND_DISP) {
		r_strbuf_appendf (sb, format, value);
	} else if ((flags & V850E_IMMEDIATE32) || (flags & V850E_IMMEDIATE16HI)) {
		r_strbuf_appendf (sb, "0x%"PFMT64x, (ut64)value);
	} else {
		r_strbuf_appendf (sb, format, value);
	}
}

static long get_operand_value(const struct v850_operand *operand, unsigned long insn, const ut8* buffer, size_t len, bool *invalid) {
	if ((operand->flags & V850E_IMMEDIATE16) || (operand->flags & V850E_IMMEDIATE16HI)) {
		if (len < 2) {
			// truncated
			return 0;
		}
		ut32 value = r_read_le16 (buffer);
		if (operand->flags & V850E_IMMEDIATE16HI) {
			value <<= 16;
		} else if (value & 0x8000) {
			value |= (UT64_MAX << 16);
		}
		return value;
	}

	if (operand->flags & V850E_IMMEDIATE23) {
		if (len < 2) {
			// truncated
			return 0;
		}
		ut32 value = r_read_le16 (buffer);
		return operand->extract (value, invalid);
	}
	if (operand->flags & V850E_IMMEDIATE32) {
		if (len < 4) {
			// truncated
			return 0;
		}
		// len += 4;
		return r_read_le32 (buffer);
	}
	if (operand->extract) {
		return operand->extract (insn, invalid);
	}
	ut64 value = (operand->bits == -1)
		? (insn & operand->shift)
		: (insn >> operand->shift) & ((1UL << operand->bits) - 1);
	if (operand->flags & V850_OPERAND_SIGNED) {
		unsigned long sign = 1UL << (operand->bits - 1);
		value = (value ^ sign) - sign;
	}
	return value;
}

static const char *get_v850_sreg_name(size_t reg) {
#if 0
	static const char *const v850_sreg_names[] = {
		"eipc/vip/mpm", "eipsw/mpc", "fepc/tid", "fepsw/ppa", "ecr/vmecr", "psw/vmtid",
		"sr6/fpsr/vmadr/dcc", "sr7/fpepc/dc0",
		"sr8/fpst/vpecr/dcv1", "sr9/fpcc/vptid", "sr10/fpcfg/vpadr/spal", "sr11/spau",
		"sr12/vdecr/ipa0l", "eiic/vdtid/ipa0u", "feic/ipa1l", "dbic/ipa1u",
		"ctpc/ipa2l", "ctpsw/ipa2u", "dbpc/ipa3l", "dbpsw/ipa3u", "ctbp/dpa0l",
		"dir/dpa0u", "bpc/dpa0u", "asid/dpa1l",
		"bpav/dpa1u", "bpam/dpa2l", "bpdv/dpa2u", "bpdm/dpa3l", "eiwr/dpa3u",
		"fewr", "dbwr", "bsel"
	};
#else
	static const char *const v850_sreg_names[] = {
		"eipc", "eipsw", "fepc", "fepsw", "ecr", "psw",
		"sr6", "sr7", "sr8", "sr9", "sr10", "sr11",
		"sr12", "eiic", "feic", "dbic",
		"ctpc", "ctpsw", "dbpc", "dbpsw", "ctbp",
		"dir", "bpc", "asid",
		"bpav", "bpam", "bpdv", "bpdm", "eiwr",
		"fewr", "dbwr", "bsel"
	};
#endif
	if (reg < R_ARRAY_SIZE (v850_sreg_names)) {
		return v850_sreg_names[reg];
	}
	return "<invalid s-reg number>";
}

static const char *get_v850_reg_name(size_t reg) {
	static const char *const v850_reg_names[] = {
		"r0", "r1", "r2", "sp", "gp", "tp", "r6", "r7",
		"r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
		"r16", "r17", "r18", "r19", "r20", "r21", "r22", "r23",
		"r24", "r25", "r26", "r27", "r28", "r29", "ep", "lp"
	};
	R_RETURN_VAL_IF_FAIL (reg < R_ARRAY_SIZE (v850_reg_names), NULL);
	return v850_reg_names[reg];
}

static const char *get_v850_vreg_name(unsigned int reg) {
	static const char *const v850_vreg_names[] = {
		"vr0", "vr1", "vr2", "vr3", "vr4", "vr5", "vr6", "vr7", "vr8", "vr9",
		"vr10", "vr11", "vr12", "vr13", "vr14", "vr15", "vr16", "vr17", "vr18",
		"vr19", "vr20", "vr21", "vr22", "vr23", "vr24", "vr25", "vr26", "vr27",
		"vr28", "vr29", "vr30", "vr31"
	};
	R_RETURN_VAL_IF_FAIL (reg < R_ARRAY_SIZE (v850_vreg_names), NULL);
	return v850_vreg_names[reg];
}

static const char *get_v850_cc_name(unsigned int reg) {
	static const char *const v850_cc_names[] = {
		"v", "c/l", "z", "nh", "s/n", "t", "lt", "le",
		"nv", "nc/nl", "nz", "h", "ns/p", "sa", "ge", "gt"
	};
	R_RETURN_VAL_IF_FAIL (reg < R_ARRAY_SIZE (v850_cc_names), NULL);
	return v850_cc_names[reg];
}

static const char *get_v850_float_cc_name(unsigned int reg) {
	static const char *const v850_float_cc_names[] = {
		"f/t", "un/or", "eq/neq", "ueq/ogl", "olt/uge", "ult/oge", "ole/ugt", "ule/ogt",
		"sf/st", "ngle/gle", "seq/sne", "ngl/gl", "lt/nlt", "nge/ge", "le/nle", "ngt/gt"
	};
	R_RETURN_VAL_IF_FAIL (reg < R_ARRAY_SIZE (v850_float_cc_names), NULL);
	return v850_float_cc_names[reg];
}

static const char *get_v850_cacheop_name(size_t reg) {
	static const char *const v850_cacheop_names[] = {
		"chbii", "cibii", "cfali", "cisti", "cildi", "chbid", "chbiwbd",
		"chbwbd", "cibid", "cibiwbd", "cibwbd", "cfald", "cistd", "cildd"
	};
	R_RETURN_VAL_IF_FAIL (reg < R_ARRAY_SIZE (v850_cacheop_names), NULL);
	return v850_cacheop_names[reg];
}

static const char *get_v850_prefop_name(size_t reg) {
	static const char *const v850_prefop_names[] = { "prefi", "prefd" };
	R_RETURN_VAL_IF_FAIL (reg < R_ARRAY_SIZE (v850_prefop_names), NULL);
	return v850_prefop_names[reg];
}

static int print_prefop(RStrBuf *sb, int value) {
	int idx;
	for (idx = 0; idx < R_ARRAY_SIZE (v850_prefop_codes); idx++) {
		if (value == v850_prefop_codes[idx]) {
			r_strbuf_append (sb, get_v850_prefop_name (idx));
			return V850_ARG_TYPE_STRING;
		}
	}
	r_strbuf_appendf (sb, "%d", (int)value);
	return V850_ARG_TYPE_NUMBER;
}

static int print_cacheop(RStrBuf *sb, int value) {
	int idx;
	for (idx = 0; idx < R_ARRAY_SIZE (v850_cacheop_codes); idx++) {
		if (value == v850_cacheop_codes[idx]) {
			r_strbuf_append (sb, get_v850_cacheop_name (idx));
			return V850_ARG_TYPE_STRING;
		}
	}
	r_strbuf_appendf (sb, "%d", (int)value);
	return V850_ARG_TYPE_NUMBER;
}

static bool print_reglist(RStrBuf *sb, v850np_inst *inst, const struct v850_operand *operand, long value) {
	static const int list12_regs[32]  = {
		30, 0, 0, 0, 0, 0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
		0,  0, 0, 0, 0, 31, 29, 28, 23, 22, 21, 20, 27, 26, 25, 24
	};
	const int *regs;
	int i, pc = 0;
	ut32 mask = 0;

	switch (operand->shift) {
	case 0xffe00001:
		regs = list12_regs;
		break;
	default:
		// eprintf ("unknown operand shift: 0x%x\n", operand->shift);
		return false;
	}

	for (i = 0; i < 32; i++) {
		if (value & (1u << i)) {
			switch (regs[i]) {
			case 0:
				/* xgettext:c-format */
				// eprintf ("unknown reg: %d at 0x%x\n", i);
				// inst->text = r_strbuf_drain (sb);
				return false;
			case -1:
				pc = 1;
				break;
			default:
				mask |= (1u << regs[i]);
				break;
			}
		}
	}

	r_strbuf_append (sb, "{");
	if (mask) {
		ut32 bit;
		const char *comma = "";
		for (bit = 0; bit < 32; bit++) {
			if (mask & (1u << bit)) {
				ut32 first = bit;
				r_strbuf_appendf (sb, "%s%s", comma, get_v850_reg_name (first));
				comma = ", ";

				// for (bit++; bit < 32 && (mask & (1u << bit)); bit++) {}
				for (bit++; bit < 32; bit++) {
					if ((mask & (1u << bit)) == 0) {
						break;
					}
				}
				ut32 last = bit;

				if (last > first + 1) {
					for (i = first + 1; i < last ; i++) {
						const char *rn = get_v850_reg_name (i);
						if (rn) {
							r_strbuf_appendf (sb, ", %s", rn);
						}
					}
					//r_strbuf_appendf (sb, " - %s", get_v850_reg_name (last - 1));
				}
			}
		}
	}
	if (pc) {
		r_strbuf_appendf (sb, "%sPC", mask ? ", " : "");
	}
	r_strbuf_append (sb, "}");
	return true;
}

static char *distillate(v850np_inst *inst, const char *esilfmt) {
	RStrBuf *sb = r_strbuf_new ("");
	RList *args = NULL;
	char *arg = strchr (inst->text, ' ');
	char *p = inst->text;
	bool in_list = false;
	while (*p) {
		if (*p == '{') {
			in_list = true;
		} else if (*p == '}') {
			in_list = false;
		} else if (in_list) {
			if (*p == ',') {
				*p = ';';
			}
		}
		p++;
	}
	if (arg) {
		arg = strdup (arg + 1);
		arg = r_str_replace (arg, "{", "", true);
		arg = r_str_replace (arg, "}", "", true);
		arg = r_str_replace (arg, "[", ",", true);
		arg = r_str_replace (arg, "]", "", true);
		args = r_str_split_list (arg, ",", 0);
		RListIter *iter;
		r_list_foreach (args, iter, arg) {
			r_str_replace_ch (arg, ';', ',', true);
			r_str_replace_ch (arg, ' ', 0, true);
		}
	}
	p = inst->text;
	while (*p) {
		if (*p == ';') {
			*p = ',';
		}
		p++;
	}
	if (args) {
		while (*esilfmt) {
			char ch = *esilfmt;
			if (ch == '#') {
				const int n = esilfmt[1] - '0';
				if (n >= 0 && n < 10) {
					const char *argn = (const char *)r_list_get_n (args, n);
					r_strbuf_appendf (sb, "%s", argn);
					esilfmt += 2;
					continue;
				}
			}
			r_strbuf_append_n (sb, &ch, 1);
			esilfmt++;
		}
		r_list_free (args);
	}
	char *res = r_strbuf_drain (sb);
	if (r_str_startswith (res, "DISPOSE,")) {
		RList *regs = r_str_split_list (res + 8, ",", 0);
		RListIter *iter;
		char *reg;
		RStrBuf *sb2 = r_strbuf_new ("");
		int count = 0;
		r_list_foreach (regs, iter, reg) {
			r_strbuf_appendf (sb2, "%ssp,[4],%s,:=,4,sp,+=", count?",":"", reg);
			count ++;
		}
		free (res);
		res = r_strbuf_drain (sb2);
		r_list_free (regs);
	} else if (r_str_startswith (res, "PREPARE,")) {
		RList *regs = r_str_split_list (res + 8, ",", 0);
		RListIter *iter;
		char *reg;
		RStrBuf *sb2 = r_strbuf_new ("");
		int count = 0;
		r_list_foreach (regs, iter, reg) {
			r_strbuf_appendf (sb2, "%s4,sp,-=,%s,sp,=[4]", count?",":"", reg);
			count ++;
		}
		free (res);
		res = r_strbuf_drain (sb2);
		r_list_free (regs);
	}
	return res;
}

// do absolute addressing on references relative to r0
#define ABS_R0REF 1

static bool v850np_disassemble(v850np_inst *inst, int cpumodel, ut64 memaddr, const ut8* buffer, int buffer_size, unsigned long insn) {
	const v850_opcode *op = (v850_opcode *) v850_opcodes;
	const struct v850_operand *operand = NULL;
	bool match = false;
	RStrBuf *sb = r_strbuf_new ("");

	/* If this is a two byte insn, then mask off the high bits.  */
	if (buffer_size == 2) {
		insn &= 0xffff;
	}
	inst->text = NULL;
	/* Find the opcode.  */
	for (inst->text = NULL; op->name; op++) {
		if (op->processors & V850_CPU_OPTION_ALIAS) {
			continue;
		}
		if ((op->mask & insn) != op->opcode || !(op->processors & cpumodel)) {
			continue;
		}
		/* Code check start.  */
		const ut8 *opindex_ptr;
		unsigned int opnum;
		unsigned int memop;

		bool operand_fail = false;
		for (opindex_ptr = op->operands, opnum = 1; !operand_fail && *opindex_ptr != 0; opindex_ptr++, opnum++) {
			bool invalid = false;

			operand = &v850_operands[*opindex_ptr];

			long value = get_operand_value (operand, insn, buffer, buffer_size, &invalid);
			if (value) {
				inst->value = value;
			}

			operand_fail = true;
			if (invalid) {
			} else if ((operand->flags & V850_NOT_R0) && value == 0 && op->memop <= 2) {
			} else if ((operand->flags & V850_NOT_SA) && value == 0xd) {
			} else if ((operand->flags & V850_NOT_IMM0) && value == 0) {
			} else {
				operand_fail = false;
			}
		}
		if (operand_fail) {
			continue;
		}

		/* Code check end.  */

		match = true;
		r_strbuf_append (sb, op->name);
		r_strbuf_append (sb, " ");
		inst->op = op;
		memop = op->memop;
		/* Now print the operands.

		   MEMOP is the operand number at which a memory
		   address specification starts, or zero if this
		   instruction has no memory addresses.

		   A memory address is always two arguments.

		   This information allows us to determine when to
		   insert commas into the output stream as well as
		   when to insert disp[reg] expressions onto the
		   output stream.  */

		int atype = 0;
		inst->value = 0;
		opindex_ptr = op->operands;
		opnum = 1;
		long prevalue = 0;
		long value = 0;
		for (; *opindex_ptr; opindex_ptr++, opnum++) {
			bool square = false;

			bool done = false;
			operand = &v850_operands[*opindex_ptr];
			prevalue = value;

			bool invalid = false;
			value = get_operand_value (operand, insn, buffer + 2, buffer_size - 2, &invalid);
			if (invalid) {
				// R_LOG_WARN ("Cannot get operand value");
				break;
			}

			// first argument have no special processing
			const char *prefix = (operand->flags & V850_OPERAND_BANG)? "|" :(operand->flags & V850_OPERAND_PERCENT)? "%":"";
#define IS_PUSHPOP(x) (!strcmp ((x), "pushsp") || !strcmp ((x), "popsp") || !strcmp ((x), "dbpush" ))
			if (opnum == 1 && opnum == memop) {
				r_strbuf_append (sb, "[");
				square = true;
			} else if ((!strcmp ("stc.w", op->name) || !strcmp ("cache", op->name) || !strcmp ("pref",  op->name))
					&& opnum == 2 && opnum == memop) {
				r_strbuf_append (sb, ", [");
				square = true;
			} else if (IS_PUSHPOP (op->name) && opnum == 2) {
				r_strbuf_append (sb, "-");
			} else if (opnum > 1
					&& (v850_operands[*(opindex_ptr - 1)].flags & V850_OPERAND_DISP)
					&& opnum == memop) {
#if ABS_R0REF
				if (opnum == 2 && value == 0) { // "-X[r0]"
					ut32 addr = UT32_MAX + 1 + prevalue;
					// uncommenting this breaks `rasm2 -a v850 -d 01fb`
					// trim last char and append this
					char *s = r_strbuf_drain (sb);
					if (*s) {
						s[strlen (s) - 1] = 0;
						r_str_trim (s);
					}
					if (addr < 256) {
						sb = r_strbuf_newf ("%s %"PFMT32d, s, addr);
					} else {
						sb = r_strbuf_newf ("%s 0x%08"PFMT32x, s, addr);
					}
					free (s);
					// r_strbuf_appendf (sb, "0x%08"PFMT32x, addr);
					inst->value = addr;
					done = true;
				} else {
					r_strbuf_appendf (sb, "%s[", prefix);
					done = false;
					square = true;
				}
#else
				r_strbuf_appendf (sb, "%s[", prefix);
				square = true;
#endif
			} else if (opnum == 2 && (op->opcode == 0x00e407e0 /* clr1 */
						|| op->opcode == 0x00e207e0 /* not1 */
						|| op->opcode == 0x00e007e0 /* set1 */
						|| op->opcode == 0x00e607e0 /* tst1 */
					   )) {
				r_strbuf_appendf (sb, ", %s[", prefix);
				square = true;
			} else if (opnum > 1) {
				r_strbuf_appendf (sb, ", %s", prefix);
			}

			/* Extract the flags, ignoring ones which do not
			   effect disassembly output.  */
			ut32 flag = operand->flags & (V850_OPERAND_REG
					| V850_REG_EVEN
					| V850_OPERAND_EP
					| V850_OPERAND_SRG
					| V850E_OPERAND_REG_LIST
					| V850_OPERAND_CC
					| V850_OPERAND_VREG
					| V850_OPERAND_CACHEOP
					| V850_OPERAND_PREFOP
					| V850_OPERAND_FLOAT_CC);

			if (!done)
			switch (flag) {
			case V850_OPERAND_REG:
				r_strbuf_append (sb, get_v850_reg_name (value));
				break;
			case (V850_OPERAND_REG|V850_REG_EVEN):
				r_strbuf_append (sb, get_v850_reg_name (value * 2));
				break;
			case V850_OPERAND_EP:
				r_strbuf_append (sb, "ep");
				break;
			case V850_OPERAND_SRG:
				r_strbuf_append (sb, get_v850_sreg_name (value));
				break;
			case V850E_OPERAND_REG_LIST:
				if (!print_reglist (sb, inst, operand, value)) {
					goto fail;
				}
				break;
			case V850_OPERAND_CC:
				r_strbuf_append (sb, get_v850_cc_name (value));
				break;
			case V850_OPERAND_FLOAT_CC:
				r_strbuf_append (sb, get_v850_float_cc_name (value));
				break;
			case V850_OPERAND_CACHEOP:
				atype = print_cacheop (sb, value);
				break;
			case V850_OPERAND_PREFOP:
				atype = print_prefop (sb, value);
				break;
			case V850_OPERAND_VREG:
				r_strbuf_append (sb, get_v850_vreg_name (value));
				break;
			default:
				{
#if ABS_R0REF
					const struct v850_operand *nextop = &v850_operands[opindex_ptr[1]];
					long nextvalue = get_operand_value (nextop, insn, buffer + 2, buffer_size - 2, &invalid);
					if (opnum > 0 && (v850_operands[*(opindex_ptr)].flags & V850_OPERAND_DISP)
							&& opnum + 1 == memop && nextvalue == 0 && value < 1) {
						// dont print coz we replace later
						//r_strbuf_append (sb, "?");
					} else {
						print_value (sb, operand->flags, memaddr, value);
						inst->value = value;
					}
#else
					print_value (sb, operand->flags, memaddr, value);
					inst->value = value;
#endif
				}
				break;
			}
			inst->args[opnum - 1].atype = atype;
			inst->args[opnum - 1].value = value;
			// eprintf ("atype=%d\n", atype);
			if (square) {
				r_strbuf_append (sb, "]");
			}
		}
		if (!*opindex_ptr) {
			break;
		}
	}

	if (match) {
		inst->text = r_strbuf_drain (sb);
		if (op->esil) {
			// take advantage of the arguments parsed and honor the formats tring below
			inst->esil = distillate (inst, op->esil);
		}
	} else {
		r_strbuf_free (sb);
	}
	return true;
fail:
	r_strbuf_free (sb);
	return false;
}

int v850np_disasm(v850np_inst *inst, int cpumodel, ut64 addr, const ut8* buffer, size_t len) {
	int length = 0, code_length = 0;
	if (len < 2) {
		return -1;
	}
	ut32 insn = r_read_le16 (buffer);
	ut32 insn2 = (len < 4)? 0: r_read_le16 (buffer + 2);

	/* Special case.  */
	if (length == 0 && ((cpumodel & V850_CPU_E2_UP) != 0)) {
		if ((insn & 0xffff) == 0x02e0 && (insn2 & 0x1) == 0) {
			/* jr 32bit */
			length = 2;
			code_length = 6;
		} else if ((insn & 0xffe0) == 0x02e0 && (insn2 & 0x1) == 0) {
			/* jarl 32bit */
			length = 2;
			code_length = 6;
		} else if ((insn & 0xffe0) == 0x06e0 && (insn2 & 0x1) == 0) {
			/* jmp 32bit */
			length = 2;
			code_length = 6;
		}
	}

	if (length == 0 && (cpumodel & V850_CPU_E3V5_UP)) {
		if (/* ld.dw 23bit (v850e3v5) */
				((insn & 0xffe0) == 0x07a0 && (insn2 & 0x000f) == 0x0009)
				|| /* st.dw 23bit (v850e3v5) */
				((insn & 0xffe0) == 0x07a0 && (insn2 & 0x000f) == 0x000f)) {
			length = 4;
			code_length = 6;
		}
	}

	if (length == 0 && (cpumodel & V850_CPU_E2V3_UP)) {
		/* ld.b 23bit */
		if (((insn & 0xffe0) == 0x0780 && (insn2 & 0x000f) == 0x0005)
				|| ((insn & 0xffe0) == 0x07a0 && (insn2 & 0x000f) == 0x0005)/* ld.bu 23bit */
				|| ((insn & 0xffe0) == 0x0780 && (insn2 & 0x000f) == 0x0007)/* ld.h 23bit */
				|| ((insn & 0xffe0) == 0x07a0 && (insn2 & 0x000f) == 0x0007)/* ld.hu 23bit */
				|| ((insn & 0xffe0) == 0x0780 && (insn2 & 0x000f) == 0x0009)) { /* ld.w 23bit */
			length = 4;
			code_length = 6;
		} else if (((insn & 0xffe0) == 0x0780 && (insn2 & 0x000f) == 0x000d)	/* st.b 23bit */
				|| ((insn & 0xffe0) == 0x07a0 && (insn2 & 0x000f) == 0x000d)	/* st.h 23bit */
				|| ((insn & 0xffe0) == 0x0780 && (insn2 & 0x000f) == 0x000f)) { /* st.w 23bit */
			length = 4;
			code_length = 6;
		}
	}

	if (length == 0 && cpumodel != V850_CPU_0) {
		if ((insn & 0xffe0) == 0x0620) {
			/* 32 bit MOV */
			length = 2;
			code_length = 6;
		} else if ((insn & 0xffc0) == 0x0780 && (insn2 & 0x001f) == 0x0013) {
			/* prepare {list}, imm5, imm16<<16 */
			length = 4;
			code_length = 6;
		} else if ((insn & 0xffc0) == 0x0780 && (insn2 & 0x001f) == 0x000b) {
			/* prepare {list}, imm5, imm16 */
			length = 4;
			code_length = 6;
		} else if ((insn & 0xffc0) == 0x0780 && (insn2 & 0x001f) == 0x001b) {
			/* prepare {list}, imm5, imm32 */
			length = 4;
			code_length = 8;
		}
	}

	if (length == 4 || (length == 0 && (insn & 0x0600) == 0x0600)) {
		if (len < 4) {
			inst->text = r_str_newf ("truncated from %d to %d", code_length, length);
			return -1;
		}
		/* This is a 4 byte insn.  */
		insn = r_read_le32 (buffer);
		length = code_length = 4;
	}

	if (code_length > len) {
		// truncated instruction
		inst->text = r_str_newf ("truncated from %d to %d", code_length, length);
		return -1;
	}

	if (length == 0) {
		length = code_length = 2;
		insn &= 0xffff;
	} else if (length == 2) {
		insn &= 0xffff;
	}

	// length is unused
	if (!v850np_disassemble (inst, cpumodel, addr, buffer, len, insn)) {
		return -1;
	}
	inst->size = code_length;
	return code_length;
}
