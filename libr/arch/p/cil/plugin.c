/* radare2 - LGPL - Copyright 2025 - pancake */

#include <r_anal.h>
#include <r_arch.h>
#include <r_lib.h>
#include <r_util.h>

#include "cil.inc.c"

static char table_to_type(int table) {
	switch (table) {
	case 0x70: return 's'; // string
	case 0x02: return 't'; // typedef
	case 0x01: return 'r'; // typeref
	case 0x1b: return 'T'; // typespec
	case 0x04: return 'f'; // field
	case 0x06: return 'm'; // methoddef
	case 0x0a: return 'M'; // memberref
	case 0x11: return 'S'; // standalone signature
	case 0x2b: return 'g'; // methodspec
	default: return 0;
	}
}

static void cil_stack_delta(RAnalOp *op, int delta) {
	op->stackop = R_ANAL_STACK_INC;
	op->stackptr = delta;
}

static void cil_esil_push(RAnalOp *op, const char *value) {
	r_strbuf_setf (&op->esil, "8,sp,-=,%s,sp,=[8]", value);
	cil_stack_delta (op, -8);
}

static void cil_esil_pop_to(RAnalOp *op, const char *dst) {
	r_strbuf_setf (&op->esil, "sp,[8],%s,=,8,sp,+=", dst);
	cil_stack_delta (op, 8);
}

static void cil_esil_binary(RAnalOp *op, const char *operation) {
	r_strbuf_setf (&op->esil,
		"sp,[8],8,sp,+,[8],%s,8,sp,+,=[8],8,sp,+=", operation);
	cil_stack_delta (op, 8);
}

static void cil_esil_compare_branch(RAnalOp *op, const char *operation) {
	r_strbuf_setf (&op->esil,
		"sp,[8],8,sp,+,[8],%s,?{,0x%" PFMT64x ",pc,=,},16,sp,+=",
		operation, op->jump);
	cil_stack_delta (op, 16);
}

static void cil_esil_unsigned_condition(RStrBuf *esil, const char *condition) {
	r_strbuf_append (esil, "8,sp,+,[8],tmp,=,sp,[8],tmp,-=,64,$b");
	if (!strcmp (condition, "ge")) {
		r_strbuf_append (esil, ",!");
	} else if (!strcmp (condition, "gt")) {
		r_strbuf_append (esil, ",!,$z,!,&");
	} else if (!strcmp (condition, "le")) {
		r_strbuf_append (esil, ",$z,|");
	}
}

static void cil_esil_unsigned_compare(RAnalOp *op, const char *condition) {
	r_strbuf_set (&op->esil, "");
	cil_esil_unsigned_condition (&op->esil, condition);
	r_strbuf_append (&op->esil, ",8,sp,+,=[8],8,sp,+=");
	cil_stack_delta (op, 8);
}

static void cil_esil_unsigned_branch(RAnalOp *op, const char *condition) {
	r_strbuf_set (&op->esil, "");
	cil_esil_unsigned_condition (&op->esil, condition);
	r_strbuf_appendf (&op->esil, ",?{,0x%" PFMT64x ",pc,=,},16,sp,+=", op->jump);
	cil_stack_delta (op, 16);
}

static const char *cil_resolve_token(RArchSession *as, ut32 token) {
	char type = table_to_type (token >> 24);
	return type && as->arch->binb.bin && as->arch->binb.get_name
		? as->arch->binb.get_name (as->arch->binb.bin, type, token & 0xffffff, false)
		: NULL;
}

static ut64 cil_resolve_offset(RArchSession *as, ut32 token) {
	char type = table_to_type (token >> 24);
	return type && as->arch->binb.bin && as->arch->binb.get_offset
		? as->arch->binb.get_offset (as->arch->binb.bin, type, token & 0xffffff)
		: UT64_MAX;
}

static bool cil_call_signature(const char *signature, int *argument_count, bool *has_return) {
	if (!signature || !argument_count || !has_return) {
		return false;
	}
	const char *open = strchr (signature, '(');
	const char *close = strrchr (signature, ')');
	if (!open || !close || close < open || close[1] != ':') {
		return false;
	}
	int count = 0;
	const char *p = open + 1;
	if (close - p >= 5 && !memcmp (p, "this;", 5)) {
		count++;
		p += 5;
	}
	if (p < close) {
		count++;
		int depth = 0;
		for (; p < close; p++) {
			switch (*p) {
			case '<':
			case '[':
				depth++;
				break;
			case '>':
			case ']':
				depth = R_MAX (0, depth - 1);
				break;
			case ',':
				if (!depth) {
					count++;
				}
				break;
			default:
				break;
			}
		}
	}
	*argument_count = count;
	*has_return = strcmp (close + 2, "void");
	return true;
}

static void cil_esil_call(RAnalOp *op, const char *signature, bool new_object, bool indirect) {
	int arguments;
	bool has_return;
	if (!cil_call_signature (signature, &arguments, &has_return)) {
		return;
	}
	if (new_object && arguments > 0) {
		arguments--; // newobj does not consume the implicit `this` slot.
	}
	if (indirect) {
		arguments++; // calli also consumes the function pointer.
	}
	bool pushes_result = new_object || has_return;
	RStrBuf *sb = &op->esil;
	if (arguments > 0) {
		r_strbuf_setf (sb, "%d,sp,+=", arguments * 8);
	}
	if (pushes_result) {
		r_strbuf_append (sb, arguments > 0? ",8,sp,-=,r0,sp,=[8]": "8,sp,-=,r0,sp,=[8]");
	}
	cil_stack_delta (op, (arguments - (pushes_result? 1: 0)) * 8);
}

static void cil_esil_unknown_result(RAnalOp *op, int consumed) {
	RStrBuf *sb = &op->esil;
	if (consumed > 0) {
		r_strbuf_setf (sb, "%d,sp,+=", consumed * 8);
	}
	r_strbuf_append (sb, consumed > 0? ",8,sp,-=,r0,sp,=[8]": "8,sp,-=,r0,sp,=[8]");
	cil_stack_delta (op, (consumed - 1) * 8);
}

static void cil_esil_load_indirect(RAnalOp *op, int size) {
	r_strbuf_setf (&op->esil, "sp,[8],[%d],sp,=[8]", size);
}

static void cil_esil_load_indirect_signed(RAnalOp *op, int size) {
	r_strbuf_setf (&op->esil, "%d,sp,[8],[%d],~,sp,=[8]", size * 8, size);
}

static void cil_esil_store_indirect(RAnalOp *op, int size) {
	r_strbuf_setf (&op->esil, "sp,[8],8,sp,+,[8],=[%d],16,sp,+=", size);
	cil_stack_delta (op, 16);
}

static void cil_esil_convert_signed(RAnalOp *op, int bits) {
	r_strbuf_setf (&op->esil, "%d,sp,[8],~,sp,=[8]", bits);
}

static void cil_esil_convert_unsigned(RAnalOp *op, ut64 mask) {
	r_strbuf_setf (&op->esil, "0x%" PFMT64x ",sp,[8],&,sp,=[8]", mask);
}

static int cil_short_index(ut8 opcode, const ut8 *buf, bool extended) {
	if (extended) {
		return r_read_le16 (buf + 2);
	}
	if (opcode >= 0x02 && opcode <= 0x05) {
		return opcode - 0x02;
	}
	if (opcode >= 0x06 && opcode <= 0x09) {
		return opcode - 0x06;
	}
	if (opcode >= 0x0a && opcode <= 0x0d) {
		return opcode - 0x0a;
	}
	return buf[1];
}

static void cil_build_esil(RAnalOp *op, ut8 opcode, ut8 opcode2, const ut8 *buf,
		bool extended, const char *token_name, ut64 token_offset) {
	char value[64];
	if (extended) {
		switch (opcode2) {
		case 0x00: cil_esil_unknown_result (op, 0); return;
		case 0x01: cil_esil_binary (op, "=="); return;
		case 0x02: cil_esil_binary (op, ">"); return;
		case 0x03: cil_esil_unsigned_compare (op, "gt"); return;
		case 0x04: cil_esil_binary (op, "<"); return;
		case 0x05: cil_esil_unsigned_compare (op, "lt"); return;
		case 0x09:
			snprintf (value, sizeof (value), "a%d", cil_short_index (opcode, buf, true));
			cil_esil_push (op, value);
			return;
		case 0x0a: cil_esil_unknown_result (op, 0); return;
		case 0x0b:
			snprintf (value, sizeof (value), "a%d", cil_short_index (opcode, buf, true));
			cil_esil_pop_to (op, value);
			return;
		case 0x0c:
			snprintf (value, sizeof (value), "l%d", cil_short_index (opcode, buf, true));
			cil_esil_push (op, value);
			return;
		case 0x0d: cil_esil_unknown_result (op, 0); return;
		case 0x0e:
			snprintf (value, sizeof (value), "l%d", cil_short_index (opcode, buf, true));
			cil_esil_pop_to (op, value);
			return;
		case 0x06: cil_esil_unknown_result (op, 0); return;
		case 0x07: cil_esil_unknown_result (op, 1); return;
		case 0x0f: cil_esil_unknown_result (op, 1); return;
		case 0x11:
			r_strbuf_set (&op->esil, "8,sp,+=");
			cil_stack_delta (op, 8);
			return;
		case 0x15:
			r_strbuf_set (&op->esil, "8,sp,+=");
			cil_stack_delta (op, 8);
			return;
		case 0x17:
		case 0x18:
			r_strbuf_set (&op->esil, "24,sp,+=");
			cil_stack_delta (op, 24);
			return;
		case 0x1c: cil_esil_unknown_result (op, 0); return;
		case 0x1d: cil_esil_unknown_result (op, 1); return;
		default:
			return;
		}
	}
	if (opcode >= 0x02 && opcode <= 0x05) {
		snprintf (value, sizeof (value), "a%d", opcode - 0x02);
		cil_esil_push (op, value);
		return;
	}
	if (opcode >= 0x06 && opcode <= 0x09) {
		snprintf (value, sizeof (value), "l%d", opcode - 0x06);
		cil_esil_push (op, value);
		return;
	}
	if (opcode >= 0x0a && opcode <= 0x0d) {
		snprintf (value, sizeof (value), "l%d", opcode - 0x0a);
		cil_esil_pop_to (op, value);
		return;
	}
	switch (opcode) {
	case 0x0e:
		snprintf (value, sizeof (value), "a%u", buf[1]);
		cil_esil_push (op, value);
		break;
	case 0x0f: cil_esil_unknown_result (op, 0); break;
	case 0x10:
		snprintf (value, sizeof (value), "a%u", buf[1]);
		cil_esil_pop_to (op, value);
		break;
	case 0x11:
		snprintf (value, sizeof (value), "l%u", buf[1]);
		cil_esil_push (op, value);
		break;
	case 0x12: cil_esil_unknown_result (op, 0); break;
	case 0x13:
		snprintf (value, sizeof (value), "l%u", buf[1]);
		cil_esil_pop_to (op, value);
		break;
	case 0x14: cil_esil_push (op, "0"); break;
	case 0x15: cil_esil_push (op, "-1"); break;
	case 0x16: case 0x17: case 0x18: case 0x19: case 0x1a:
	case 0x1b: case 0x1c: case 0x1d: case 0x1e:
		snprintf (value, sizeof (value), "%u", opcode - 0x16);
		cil_esil_push (op, value);
		break;
	case 0x1f:
		snprintf (value, sizeof (value), "%d", (st8)buf[1]);
		cil_esil_push (op, value);
		break;
	case 0x20:
		snprintf (value, sizeof (value), "%d", (st32)r_read_le32 (buf + 1));
		cil_esil_push (op, value);
		break;
	case 0x21:
		snprintf (value, sizeof (value), "0x%" PFMT64x, r_read_le64 (buf + 1));
		cil_esil_push (op, value);
		break;
	case 0x25:
		r_strbuf_set (&op->esil, "8,sp,-=,8,sp,+,[8],sp,=[8]");
		cil_stack_delta (op, -8);
		break;
	case 0x26:
		r_strbuf_set (&op->esil, "8,sp,+=");
		cil_stack_delta (op, 8);
		break;
	case 0x28: cil_esil_call (op, token_name, false, false); break;
	case 0x29: cil_esil_call (op, token_name, false, true); break;
	case 0x2a: break; // Return stack shape depends on the enclosing method signature.
	case 0x2b:
	case 0x38:
		r_strbuf_setf (&op->esil, "0x%" PFMT64x ",pc,=", op->jump);
		break;
	case 0x2c:
	case 0x39:
		r_strbuf_setf (&op->esil, "sp,[8],!,?{,0x%" PFMT64x ",pc,=,},8,sp,+=", op->jump);
		cil_stack_delta (op, 8);
		break;
	case 0x2d:
	case 0x3a:
		r_strbuf_setf (&op->esil, "sp,[8],?{,0x%" PFMT64x ",pc,=,},8,sp,+=", op->jump);
		cil_stack_delta (op, 8);
		break;
	case 0x2e: case 0x3b: cil_esil_compare_branch (op, "=="); break;
	case 0x2f: case 0x3c: cil_esil_compare_branch (op, ">="); break;
	case 0x30: case 0x3d: cil_esil_compare_branch (op, ">"); break;
	case 0x31: case 0x3e: cil_esil_compare_branch (op, "<="); break;
	case 0x32: case 0x3f: cil_esil_compare_branch (op, "<"); break;
	case 0x33: case 0x40: cil_esil_compare_branch (op, "==,!"); break;
	case 0x34: case 0x41: cil_esil_unsigned_branch (op, "ge"); break;
	case 0x35: case 0x42: cil_esil_unsigned_branch (op, "gt"); break;
	case 0x36: case 0x43: cil_esil_unsigned_branch (op, "le"); break;
	case 0x37: case 0x44: cil_esil_unsigned_branch (op, "lt"); break;
	case 0x45:
		r_strbuf_set (&op->esil, "8,sp,+=");
		cil_stack_delta (op, 8);
		break;
	case 0x46: cil_esil_load_indirect_signed (op, 1); break;
	case 0x47: cil_esil_load_indirect (op, 1); break;
	case 0x48: cil_esil_load_indirect_signed (op, 2); break;
	case 0x49: cil_esil_load_indirect (op, 2); break;
	case 0x4a: cil_esil_load_indirect_signed (op, 4); break;
	case 0x4b: case 0x4e: cil_esil_load_indirect (op, 4); break;
	case 0x4c: case 0x4d: case 0x4f: case 0x50: cil_esil_load_indirect (op, 8); break;
	case 0x51: cil_esil_store_indirect (op, 8); break;
	case 0x52: cil_esil_store_indirect (op, 1); break;
	case 0x53: cil_esil_store_indirect (op, 2); break;
	case 0x54: case 0x56: cil_esil_store_indirect (op, 4); break;
	case 0x55: case 0x57: cil_esil_store_indirect (op, 8); break;
	case 0x58: cil_esil_binary (op, "+"); break;
	case 0x59: cil_esil_binary (op, "-"); break;
	case 0x5a: cil_esil_binary (op, "*"); break;
	case 0x5b: cil_esil_binary (op, "~/"); break;
	case 0x5c: cil_esil_binary (op, "/"); break;
	case 0x5d: cil_esil_binary (op, "~%"); break;
	case 0x5e: cil_esil_binary (op, "%"); break;
	case 0x5f: cil_esil_binary (op, "&"); break;
	case 0x60: cil_esil_binary (op, "|"); break;
	case 0x61: cil_esil_binary (op, "^"); break;
	case 0x62: cil_esil_binary (op, "<<"); break;
	case 0x63: cil_esil_binary (op, "ASR"); break;
	case 0x64: cil_esil_binary (op, ">>"); break;
	case 0x65: r_strbuf_set (&op->esil, "sp,[8],0,-,sp,=[8]"); break;
	case 0x66: r_strbuf_set (&op->esil, "sp,[8],~,sp,=[8]"); break;
	case 0x67: case 0x82: case 0xb3: cil_esil_convert_signed (op, 8); break;
	case 0x68: case 0x83: case 0xb5: cil_esil_convert_signed (op, 16); break;
	case 0x69: case 0x84: case 0xb7: cil_esil_convert_signed (op, 32); break;
	case 0x86: case 0xb4: case 0xd2: cil_esil_convert_unsigned (op, 0xff); break;
	case 0x87: case 0xb6: case 0xd1: cil_esil_convert_unsigned (op, 0xffff); break;
	case 0x6d: case 0x88: case 0xb8: cil_esil_convert_unsigned (op, 0xffffffff); break;
	case 0x6f: cil_esil_call (op, token_name, false, false); break;
	case 0x70:
		r_strbuf_set (&op->esil, "16,sp,+=");
		cil_stack_delta (op, 16);
		break;
	case 0x71: cil_esil_unknown_result (op, 1); break;
	case 0x72:
		snprintf (value, sizeof (value), "0x%" PFMT64x, token_offset == UT64_MAX? (ut64)r_read_le32 (buf + 1): token_offset);
		cil_esil_push (op, value);
		break;
	case 0xd0:
		snprintf (value, sizeof (value), "0x%x", r_read_le32 (buf + 1));
		cil_esil_push (op, value);
		break;
	case 0x73: cil_esil_call (op, token_name, true, false); break;
	case 0x79: cil_esil_unknown_result (op, 1); break;
	case 0x7a:
		r_strbuf_set (&op->esil, "8,sp,+=");
		cil_stack_delta (op, 8);
		break;
	case 0x7b: case 0x7c: cil_esil_unknown_result (op, 1); break;
	case 0x7d:
		r_strbuf_set (&op->esil, "16,sp,+=");
		cil_stack_delta (op, 16);
		break;
	case 0x7e: case 0x7f: cil_esil_unknown_result (op, 0); break;
	case 0x80:
		r_strbuf_set (&op->esil, "8,sp,+=");
		cil_stack_delta (op, 8);
		break;
	case 0x81:
		r_strbuf_set (&op->esil, "16,sp,+=");
		cil_stack_delta (op, 16);
		break;
	case 0x8c: cil_esil_unknown_result (op, 1); break;
	case 0x8d: case 0x8e: cil_esil_unknown_result (op, 1); break;
	case 0x8f: cil_esil_unknown_result (op, 2); break;
	case 0x90: case 0x91: case 0x92: case 0x93:
	case 0x94: case 0x95: case 0x96: case 0x97:
	case 0x98: case 0x99: case 0x9a:
		cil_esil_unknown_result (op, 2);
		break;
	case 0xa3: cil_esil_unknown_result (op, 2); break;
	case 0x9b: case 0x9c: case 0x9d: case 0x9e:
	case 0x9f: case 0xa0: case 0xa1: case 0xa2:
		r_strbuf_set (&op->esil, "24,sp,+=");
		cil_stack_delta (op, 24);
		break;
	case 0xa4:
		r_strbuf_set (&op->esil, "24,sp,+=");
		cil_stack_delta (op, 24);
		break;
	case 0xa5: cil_esil_unknown_result (op, 1); break;
	case 0xc2: cil_esil_unknown_result (op, 1); break;
	case 0xc6: cil_esil_unknown_result (op, 1); break;
	case 0xd6: case 0xd7: cil_esil_binary (op, "+"); break;
	case 0xd8: case 0xd9: cil_esil_binary (op, "*"); break;
	case 0xda: case 0xdb: cil_esil_binary (op, "-"); break;
	case 0xdd:
	case 0xde:
		r_strbuf_setf (&op->esil, "0x%" PFMT64x ",pc,=", op->jump);
		break;
	case 0xdf: cil_esil_store_indirect (op, 8); break;
	default:
		break;
	}
}

static bool decode(RArchSession *as, RAnalOp *op, RArchDecodeMask mask) {
	const ut8 *buf = op->bytes;
	int len = op->size;
	ut64 addr = op->addr;

	if (len < 1) {
		return false;
	}

	op->size = 1;
	op->type = R_ANAL_OP_TYPE_UNK;
	op->family = R_ANAL_OP_FAMILY_CPU;

	ut8 opcode = buf[0];
	ut8 opcode2 = 0;
	bool extended = opcode == 0xfe;
	const CilInstruction *ci = NULL;
	if (extended) {
		if (len < 2) {
			return false;
		}
		opcode2 = buf[1];
		ci = &cil_fe_instructions[opcode2];
		if (!ci->mnemonic) {
			op->type = R_ANAL_OP_TYPE_ILL;
			if (mask & R_ARCH_OP_MASK_DISASM) {
				op->mnemonic = r_str_newf ("ill 0xfe%02x", opcode2);
			}
			op->size = 2;
			return true;
		}
		op->size = ci->size;
		if (len < op->size) {
			return false;
		}
	} else {
		ci = &cil_instructions[opcode];
		if (!ci->mnemonic) {
			op->type = R_ANAL_OP_TYPE_ILL;
			if (mask & R_ARCH_OP_MASK_DISASM) {
				op->mnemonic = r_str_newf ("ill 0x%02x", opcode);
			}
			return true;
		}
		op->size = ci->size;
		if (opcode == 0x45) { // switch
			if (len < 5) {
				return false;
			}
			ut32 count = r_read_le32 (buf + 1);
			if (count > (ut32)(len - 5) / 4) {
				return false;
			}
			op->size = 5 + 4 * count;
		}
		if (len < op->size) {
			return false;
		}
	}

	op->type = ci->type;
	ut32 token = 0;
	if (ci->operand == CIL_OP_TOKEN) {
		token = r_read_le32 (buf + (extended? 2: 1));
	}
	const char *token_name = token? cil_resolve_token (as, token): NULL;
	ut64 token_offset = token? cil_resolve_offset (as, token): UT64_MAX;
	if (token_offset != UT64_MAX) {
		if (!extended && (opcode == 0x27 || opcode == 0x28 || opcode == 0x6f || opcode == 0x73)) {
			op->jump = token_offset;
			op->eob = opcode == 0x27;
		} else if ((!extended && opcode == 0x72) || (extended && (opcode2 == 0x06 || opcode2 == 0x07))) {
			op->ptr = token_offset;
		}
	}
	if (mask & R_ARCH_OP_MASK_DISASM) {
		char *mnemonic = r_str_new (ci->mnemonic);
		// Decode operand
		switch (ci->operand) {
		case CIL_OP_I1:
			mnemonic = r_str_appendf (mnemonic, " %d", (st8)buf[op->size - 1]);
			break;
		case CIL_OP_I4:
			mnemonic = r_str_appendf (mnemonic, " 0x%08x", r_read_le32 (buf + 1));
			break;
		case CIL_OP_I8:
			mnemonic = r_str_appendf (mnemonic, " 0x%016" PFMT64x, r_read_le64 (buf + 1));
			break;
		case CIL_OP_R4:
			{
				ut32 raw = r_read_le32 (buf + 1);
				float f;
				memcpy (&f, &raw, sizeof (f));
				mnemonic = r_str_appendf (mnemonic, " %f", f);
			}
			break;
		case CIL_OP_R8:
			{
				ut64 raw = r_read_le64 (buf + 1);
				double d;
				memcpy (&d, &raw, sizeof (d));
				mnemonic = r_str_appendf (mnemonic, " %f", d);
			}
			break;
		case CIL_OP_BR_S:
			{
				st8 offset = buf[op->size - 1];
				ut64 target = addr + op->size + offset;
				mnemonic = r_str_appendf (mnemonic, " 0x%08" PFMT64x, target);
			}
			break;
		case CIL_OP_BR_L:
			{
				st32 offset = r_read_le32 (buf + 1);
				ut64 target = addr + op->size + offset;
				mnemonic = r_str_appendf (mnemonic, " 0x%08" PFMT64x, target);
			}
			break;
		case CIL_OP_TOKEN:
			{
				ut32 token = r_read_le32 (buf + (extended? 2: 1));
				if (token_name) {
					mnemonic = r_str_appendf (mnemonic, " %s", token_name);
				} else {
					mnemonic = r_str_appendf (mnemonic, " 0x%08x", token);
 				}
 			}
 			break;
		case CIL_OP_VAR_S:
			mnemonic = r_str_appendf (mnemonic, " %u", buf[op->size - 1]);
			break;
		case CIL_OP_VAR_L:
			mnemonic = r_str_appendf (mnemonic, " %u", r_read_le16 (buf + 2));
			break;
		case CIL_OP_NONE:
		default:
			break;
		}
		ut32 i;
		if (opcode == 0x45) { // switch
			ut32 count = r_read_le32 (buf + 1);
			for (i = 0; i < count; i++) {
				st32 offset = r_read_le32 (buf + 5 + i * 4);
				ut64 target = addr + op->size + offset;
				mnemonic = r_str_appendf (mnemonic, i? ", 0x%08" PFMT64x: " 0x%08" PFMT64x, target);
			}
		}
		op->mnemonic = mnemonic;
	}

	// Set jump addresses for branches
	if (opcode >= 0x2b && opcode <= 0x44) {
		if (opcode >= 0x38) {
			// 32-bit offset
			st32 offset = r_read_le32 (buf + 1);
			op->jump = addr + 5 + offset;
			if (opcode == 0x38) {
				op->eob = true;
			} else {
				op->fail = addr + 5;
			}
		} else {
			// 8-bit offset
			st8 offset = buf[1];
			op->jump = addr + 2 + offset;
			if (opcode == 0x2b) {
				op->eob = true;
			} else {
				op->fail = addr + 2;
			}
		}
	} else if (opcode == 0x45) {
		ut32 count = r_read_le32 (buf + 1);
		op->fail = addr + op->size;
		op->switch_op = r_anal_switch_op_new (addr, 0, count? count - 1: 0, op->fail);
		ut32 i;
		for (i = 0; op->switch_op && i < count; i++) {
			st32 offset = r_read_le32 (buf + 5 + i * 4);
			ut64 target = addr + op->size + offset;
			r_anal_switch_op_add_case (op->switch_op, addr, i, target);
		}
	} else if (opcode == 0xdd) {
		st32 offset = r_read_le32 (buf + 1);
		op->jump = addr + 5 + offset;
		op->eob = true;
	} else if (opcode == 0xde) {
		st8 offset = buf[1];
		op->jump = addr + 2 + offset;
		op->eob = true;
	}

	if (op->type == R_ANAL_OP_TYPE_RET || op->type == R_ANAL_OP_TYPE_TRAP) {
		op->eob = true;
	}
	if (mask & R_ARCH_OP_MASK_ESIL) {
		cil_build_esil (op, opcode, opcode2, buf, extended, token_name, token_offset);
	}

	return true;
}

static bool encode(RArchSession *as, RAnalOp *op, RArchEncodeMask mask) {
	if (!op->mnemonic) {
		return false;
	}
	// Simple assembler for basic instructions
	int i;
	for (i = 0; i < 256; i++) {
		if (cil_instructions[i].mnemonic && !strcmp (cil_instructions[i].mnemonic, op->mnemonic)) {
			op->size = cil_instructions[i].size;
			free (op->bytes);
			op->bytes = malloc (op->size);
			if (!op->bytes) {
				return false;
			}
			op->bytes[0] = i;
			return true;
		}
	}
	for (i = 0; i < 256; i++) {
		if (cil_fe_instructions[i].mnemonic && !strcmp (cil_fe_instructions[i].mnemonic, op->mnemonic)) {
			op->size = cil_fe_instructions[i].size;
			free (op->bytes);
			op->bytes = malloc (op->size);
			if (!op->bytes) {
				return false;
			}
			op->bytes[0] = 0xfe;
			op->bytes[1] = i;
			return true;
		}
	}
	return false;
}

// static int info (RArchSession *as, ut32 q) {
// 	return -1;
// }

// CIL methods address arguments by slot (ldarg.N) and locals by slot (ldloc.N).
// Expose a0..a31 and l0..l31 as synthetic regs so per-method arg recovery,
// driven by bin-symbol metadata, can name argument variables uniformly.
static char *regs(RArchSession *as) {
	RStrBuf *sb = r_strbuf_new (
		"=PC	pc\n"
		"=SP	sp\n"
		"=A0	a0\n"
		"=A1	a1\n"
		"=A2	a2\n"
		"=A3	a3\n"
		"=R0	r0\n"
		"gpr	pc	.64	0	0\n"
		"gpr	sp	.64	8	0\n"
		"gpr	r0	.64	16	0\n"
		"gpr	tmp	.64	24	0\n"
	);
	int i, off = 32;
	for (i = 0; i < 32; i++, off += 8) {
		r_strbuf_appendf (sb, "gpr\ta%d\t.64\t%d\t0\n", i, off);
	}
	for (i = 0; i < 32; i++, off += 8) {
		r_strbuf_appendf (sb, "gpr\tl%d\t.64\t%d\t0\n", i, off);
	}
	return r_strbuf_drain (sb);
}

static int cil_info(RArchSession *as, ut32 q) {
	if (q == R_ARCH_INFO_ISVM) {
		return R_ARCH_INFO_ISVM;
	}
	return -1;
}

const RArchPlugin r_arch_plugin_cil = {
	.meta = {
		.name = "cil",
		.author = "pancake",
		.desc = "Common Intermediate Language disassembler",
		.license = "LGPL-3.0-only",
	},
	.arch = "cil",
	.bits = R_SYS_BITS_PACK (32),
	.decode = &decode,
	.encode = &encode,
	.regs = regs,
	.info = cil_info,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ARCH,
	.data = &r_arch_plugin_cil,
	.version = R2_VERSION
};
#endif
