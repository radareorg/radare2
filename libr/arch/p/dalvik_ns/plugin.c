/* radare2 - MIT - Copyright 2024 - NowSecure, Inc. */

#define R_LOG_ORIGIN "arch.dalvik"

#include <r_asm.h>
#include <r_lib.h>

#include "dalvik.h"
#include "dalvik.c"

#if 0
static inline ut64 get_offset(RArch *arch, int type, int idx) {
	R_RETURN_VAL_IF_FAIL (arch && arch->binb.bin && arch->binb.get_offset, UT64_MAX);
	return arch->binb.get_offset (arch->binb.bin, type, idx);
}

static inline void append_offset(RStrBuf *sb, RArch *arch, int type, int idx) {
	ut64 off = get_offset (arch, type, idx);
	switch (type) {
	case 's':
		if (off == UT64_MAX) {
			r_strbuf_appendf (sb, "string+%i", idx);
		} else {
			r_strbuf_appendf (sb, "0x%"PFMT64x, off);
		}
		break;
	case 'o':
		if (off == UT64_MAX) {
			r_strbuf_appendf (sb, "[obj+%04x]", idx);
		} else {
			r_strbuf_appendf (sb, "[0x%"PFMT64x"]", off);
		}
		break;
	case 't':
		if (off == UT64_MAX) {
			r_strbuf_appendf (sb, "thing+%i", idx);
		} else {
			r_strbuf_appendf (sb, "0x%"PFMT64x, off);
		}
		break;
	default:
		// unreachable
		break;
	}
}
#endif

static inline char *get_name(RArch *arch, int type, int idx) {
	R_RETURN_VAL_IF_FAIL (arch && arch->binb.bin && arch->binb.get_name, NULL);
	return (char *)arch->binb.get_name (arch->binb.bin, type, idx, false);
}

static inline void append_name(RStrBuf *sb, RArch *arch, int type, int idx) {
	char *flag = get_name (arch, 'c', idx);
	switch (idx) {
	case 's':
		if (flag == NULL) {
			r_strbuf_appendf (sb, "class+%i", idx);
		} else {
			r_strbuf_appendf (sb, "%s", flag);
		}
		break;
	case 'f':
		if (flag == NULL) {
			r_strbuf_appendf (sb, "field+%i", idx);
		} else {
			r_strbuf_appendf (sb, "%s", flag);
		}
		break;
	case 'c':
		if (flag == NULL) {
			r_strbuf_appendf (sb, "class+%i", idx);
		} else {
			r_strbuf_appendf (sb, "%s", flag);
		}
		break;
	case 'm':
		if (flag == NULL) {
			r_strbuf_appendf (sb, "method+%i", idx);
		} else {
			r_strbuf_appendf (sb, "%s", flag);
		}
		break;
	case 'p':
		if (flag == NULL) {
			r_strbuf_appendf (sb, "proto+%i", idx);
		} else {
			r_strbuf_appendf (sb, "%s", flag);
		}
		break;
	default:
		// unreachable
		break;
	}
}

static char *mnemonic(RArch *arch, ut64 addr, struct dalvik_instr *instr) {
	const struct dalvik_op_detail *d = &dalvik_opcodes[instr->op];
	RStrBuf *sb = r_strbuf_new (d->name);

	switch (d->fmt) {
	case DALVIK_FMT_12X:
		r_strbuf_appendf (sb, " v%u, v%u", instr->f12x.a, instr->f12x.b);
		break;
	case DALVIK_FMT_11N:
		r_strbuf_appendf (sb, " v%u, %#x", instr->f12x.a, instr->f12x.b);
		break;
	case DALVIK_FMT_11X:
		r_strbuf_appendf (sb, " v%u", instr->f11x.a);
		break;
	case DALVIK_FMT_10T:
		r_strbuf_appendf (sb, " 0x%"PFMT64x, addr + (ut64)instr->f11x.a * 2);
		break;
	case DALVIK_FMT_20T:
		r_strbuf_appendf (sb, " 0x%"PFMT64x, addr + (ut64)instr->f20t.a * 2);
		break;
	case DALVIK_FMT_22X:
		r_strbuf_appendf (sb, " v%u, v%u", instr->f22x.a, instr->f22x.b);
		break;
	case DALVIK_FMT_21T:
	case DALVIK_FMT_21S:
		r_strbuf_appendf (sb, " v%u, %#x", instr->f22x.a, instr->f22x.b);
		break;
	case DALVIK_FMT_21H:
		switch (instr->op) {
		case DALVIK_OP_CONST_HIGH16:
			r_strbuf_appendf (sb, " v%u, 0x%"PFMT64x, instr->f22x.a, (ut64)instr->f22x.b << 16);
			break;
		case DALVIK_OP_CONST_WIDE_HIGH16:
			r_strbuf_appendf (sb, " v%u, 0x%"PFMT64x, instr->f22x.a, (ut64)instr->f22x.b << 48);
			break;
		default:
			// unreachable
			break;
		}
		break;
	case DALVIK_FMT_21C:
		// TODO
		switch (instr->op) {
		case DALVIK_OP_CONST_STRING:
			break;
		case DALVIK_OP_CONST_CLASS:
			break;
		case DALVIK_OP_CHECK_CAST:
			break;
		case DALVIK_OP_NEW_INSTANCE:
			break;
		case DALVIK_OP_SGET:
		case DALVIK_OP_SGET_WIDE:
		case DALVIK_OP_SGET_OBJECT:
		case DALVIK_OP_SGET_BOOLEAN:
		case DALVIK_OP_SGET_BYTE:
		case DALVIK_OP_SGET_CHAR:
		case DALVIK_OP_SGET_SHORT:
			break;
		case DALVIK_OP_CONST_METHOD_HANDLE:
			break;
		case DALVIK_OP_CONST_METHOD_TYPE:
			break;
		default:
			// unreachable
			break;
		}
		break;
	case DALVIK_FMT_23X:
		r_strbuf_appendf (sb, " v%u, v%u, v%u", instr->f23x.a, instr->f23x.b, instr->f23x.c);
		break;
	case DALVIK_FMT_22B:
		r_strbuf_appendf (sb, " v%u, v%u, %#x", instr->f23x.a, instr->f23x.b, instr->f23x.c);
		break;
	case DALVIK_FMT_22T:
		r_strbuf_appendf (sb, " v%u, v%u, 0x%"PFMT64x, instr->f22t.a, instr->f22t.b, addr + (ut64)instr->f22t.c * 2);
		break;
	case DALVIK_FMT_22S:
		r_strbuf_appendf (sb, " v%u, v%u, %#x", instr->f22t.a, instr->f22t.b, instr->f22t.c);
		break;
	case DALVIK_FMT_22C:
		// TODO
		break;
	case DALVIK_FMT_32X:
		r_strbuf_appendf (sb, " v%u, v%u", instr->f32x.a, instr->f32x.b);
		break;
	case DALVIK_FMT_30T:
		r_strbuf_appendf (sb, " 0x%"PFMT64x, addr + (ut64)instr->f30t.a * 2);
		break;
	case DALVIK_FMT_31T:
		// TODO: packed-switch/sparse-switch/fill-array-data
		break;
	case DALVIK_FMT_31I:
		r_strbuf_appendf (sb, " v%u, %#x", instr->f31i.a, instr->f31i.b);
		break;
	case DALVIK_FMT_31C:
		r_strbuf_appendf (sb, " v%u, ", instr->f31i.a);
		append_name (sb, arch, 's', instr->f31i.b);
		break;
	case DALVIK_FMT_35C:
		// TODO:
		// filled-new-array {vC, vD, vE, vF, vG}, type@BBBB
		// invoke-kind {vC, vD, vE, vF, vG}, meth@BBBB
		// invoke-custom {vC, vD, vE, vF, vG}, call_site@BBBB
		break;
	case DALVIK_FMT_3RC:
		// TODO:
		// filled-new-array/range {vCCCC .. vNNNN}, type@BBBB
		// invoke-kind/range {vCCCC .. vNNNN}, meth@BBBB
		// invoke-custom/range {vCCCC .. vNNNN}, call_site@BBBB
		break;
	case DALVIK_FMT_45CC:
		// TODO: invoke-polymorphic {vC, vD, vE, vF, vG}, meth@BBBB, proto@HHHH
		break;
	case DALVIK_FMT_4RCC:
		// TODO: invoke-polymorphic/range {vCCCC .. vNNNN}, meth@BBBB, proto@HHHH
		break;
	case DALVIK_FMT_51L:
		r_strbuf_appendf (sb, " v%u, 0x%08"PFMT64x, instr->f51l.a, instr->f51l.b);
		break;
	case DALVIK_FMT_10X:
	case DALVIK_FMT_MAX:
		// unreachable
		break;
	}

	return r_strbuf_drain (sb);
}

static bool decode(RArchSession *s, RAnalOp *op, RArchDecodeMask mask) {
	R_RETURN_VAL_IF_FAIL (s && op && op->size > 0, false);

	RArch *arch = s->arch;

	op->type = R_ANAL_OP_TYPE_UNK;
	op->nopcode = 1;

	RBuffer *buf = r_buf_new_with_pointers (op->bytes, op->size, false);
	if (!buf) {
		return false;
	}

	struct dalvik_instr instr = {0};
	if (!dalvik_read_instr (buf, &instr)) {
		if (mask & R_ARCH_OP_MASK_DISASM) {
			op->mnemonic = strdup ("invalid");
		}
		op->size = 0;
		return true;
	}
	op->id = instr.op;

	if (mask & R_ARCH_OP_MASK_DISASM) {
		op->mnemonic = mnemonic (arch, op->addr, &instr);
	}
	op->size = r_buf_tell (buf);
	// skip over pseudo-ops if needed
	struct dalvik_payload payload;
	int size;
	if (dalvik_read_payload (buf, &instr, &payload)) {
		switch (payload.op) {
		case DALVIK_PSEUDO_OP_PACKED_SWITCH_PAYLOAD:
			op->payload = 4 + (payload.packed_switch.len * 4);
			size = 4;
			break;
		case DALVIK_PSEUDO_OP_SPARSE_SWITCH_PAYLOAD:
			op->payload = payload.sparse_switch.len * 8;
			size = 4;
			break;
		case DALVIK_PSEUDO_OP_FILL_ARRAY_DATA_PAYLOAD:
			op->payload = payload.fill_array_data.len * payload.fill_array_data.element_width;
			size = 8;
			break;
		}
		op->nopcode = 2;
		op->size = size + op->payload;
		dalvik_payload_fini (&payload);
	}
	r_buf_free (buf);
	// TODO:
	// for each op, add analysis info (e.g. jump destination)
	// add ESIL info
	switch (instr.op) {
	case DALVIK_OP_PACKED_SWITCH:
	case DALVIK_OP_SPARSE_SWITCH:
		op->type = R_ANAL_OP_TYPE_SWITCH;
		break;
	case DALVIK_OP_NOP:
		op->type = R_ANAL_OP_TYPE_NOP;
		break;
	case DALVIK_OP_MOVE:
	case DALVIK_OP_MOVE_FROM16:
	case DALVIK_OP_MOVE_16:
	case DALVIK_OP_MOVE_WIDE:
	case DALVIK_OP_MOVE_WIDE_FROM16:
	case DALVIK_OP_MOVE_WIDE_16:
	case DALVIK_OP_MOVE_OBJECT:
	case DALVIK_OP_MOVE_OBJECT_FROM16:
	case DALVIK_OP_MOVE_OBJECT_16:
	case DALVIK_OP_MOVE_RESULT:
	case DALVIK_OP_MOVE_RESULT_WIDE:
	case DALVIK_OP_MOVE_RESULT_OBJECT:
	case DALVIK_OP_MOVE_EXCEPTION:
		op->type = R_ANAL_OP_TYPE_MOV;
		break;
	case DALVIK_OP_RETURN_VOID:
	case DALVIK_OP_RETURN:
	case DALVIK_OP_RETURN_WIDE:
	case DALVIK_OP_RETURN_OBJECT:
		op->type = R_ANAL_OP_TYPE_RET;
		op->eob = true;
		break;
	case DALVIK_OP_CONST_STRING:
		op->datatype = R_ANAL_DATATYPE_STRING;
		op->type = R_ANAL_OP_TYPE_MOV;
		break;
	case DALVIK_OP_CONST_STRING_JUMBO:
		op->datatype = R_ANAL_DATATYPE_STRING;
		op->type = R_ANAL_OP_TYPE_MOV;
		break;
	case DALVIK_OP_CONST_CLASS:
		op->type = R_ANAL_OP_TYPE_MOV;
		op->datatype = R_ANAL_DATATYPE_CLASS;
		break;
	case DALVIK_OP_CONST_4:
	case DALVIK_OP_CONST_16:
	case DALVIK_OP_CONST:
	case DALVIK_OP_CONST_HIGH16:
	case DALVIK_OP_CONST_WIDE_16:
	case DALVIK_OP_CONST_WIDE_32:
	case DALVIK_OP_CONST_WIDE:
	case DALVIK_OP_CONST_WIDE_HIGH16:
		// fallthrough
	case DALVIK_OP_CONST_METHOD_HANDLE:
	case DALVIK_OP_CONST_METHOD_TYPE:
		op->type = R_ANAL_OP_TYPE_MOV;
		break;
	case DALVIK_OP_GOTO:
	case DALVIK_OP_GOTO_16:
	case DALVIK_OP_GOTO_32:
		op->type = R_ANAL_OP_TYPE_JMP;
		op->eob = true;
		break;
	case DALVIK_OP_IF_EQ:
	case DALVIK_OP_IF_NE:
	case DALVIK_OP_IF_LT:
	case DALVIK_OP_IF_GE:
	case DALVIK_OP_IF_GT:
	case DALVIK_OP_IF_LE:
	case DALVIK_OP_IF_EQZ:
	case DALVIK_OP_IF_NEZ:
	case DALVIK_OP_IF_LTZ:
	case DALVIK_OP_IF_GEZ:
	case DALVIK_OP_IF_GTZ:
	case DALVIK_OP_IF_LEZ:
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->eob = true;
		break;
	case DALVIK_OP_APUT:
	case DALVIK_OP_APUT_WIDE:
	case DALVIK_OP_APUT_OBJECT:
	case DALVIK_OP_APUT_BOOLEAN:
	case DALVIK_OP_APUT_BYTE:
	case DALVIK_OP_APUT_CHAR:
	case DALVIK_OP_APUT_SHORT:
	case DALVIK_OP_IPUT:
	case DALVIK_OP_IPUT_WIDE:
	case DALVIK_OP_IPUT_OBJECT:
	case DALVIK_OP_IPUT_BOOLEAN:
	case DALVIK_OP_IPUT_BYTE:
	case DALVIK_OP_IPUT_CHAR:
	case DALVIK_OP_IPUT_SHORT:
	case DALVIK_OP_SPUT:
	case DALVIK_OP_SPUT_WIDE:
	case DALVIK_OP_SPUT_OBJECT:
	case DALVIK_OP_SPUT_BOOLEAN:
	case DALVIK_OP_SPUT_BYTE:
	case DALVIK_OP_SPUT_CHAR:
	case DALVIK_OP_SPUT_SHORT:
		op->type = R_ANAL_OP_TYPE_STORE;
		break;
	case DALVIK_OP_AGET:
	case DALVIK_OP_AGET_WIDE:
	case DALVIK_OP_AGET_OBJECT:
	case DALVIK_OP_AGET_BOOLEAN:
	case DALVIK_OP_AGET_BYTE:
	case DALVIK_OP_AGET_CHAR:
	case DALVIK_OP_AGET_SHORT:
	case DALVIK_OP_IGET:
	case DALVIK_OP_IGET_WIDE:
	case DALVIK_OP_IGET_OBJECT:
	case DALVIK_OP_IGET_BOOLEAN:
	case DALVIK_OP_IGET_BYTE:
	case DALVIK_OP_IGET_CHAR:
	case DALVIK_OP_IGET_SHORT:
	case DALVIK_OP_SGET:
	case DALVIK_OP_SGET_WIDE:
	case DALVIK_OP_SGET_OBJECT:
	case DALVIK_OP_SGET_BOOLEAN:
	case DALVIK_OP_SGET_BYTE:
	case DALVIK_OP_SGET_CHAR:
	case DALVIK_OP_SGET_SHORT:
		op->type = R_ANAL_OP_TYPE_LOAD;
		break;
	case DALVIK_OP_INVOKE_VIRTUAL:
	case DALVIK_OP_INVOKE_SUPER:
	case DALVIK_OP_INVOKE_DIRECT:
	case DALVIK_OP_INVOKE_STATIC:
	case DALVIK_OP_INVOKE_INTERFACE:
	case DALVIK_OP_INVOKE_VIRTUAL_RANGE:
	case DALVIK_OP_INVOKE_SUPER_RANGE:
	case DALVIK_OP_INVOKE_DIRECT_RANGE:
	case DALVIK_OP_INVOKE_STATIC_RANGE:
	case DALVIK_OP_INVOKE_INTERFACE_RANGE:
	case DALVIK_OP_INVOKE_POLYMORPHIC:
	case DALVIK_OP_INVOKE_POLYMORPHIC_RANGE:
	case DALVIK_OP_INVOKE_CUSTOM:
	case DALVIK_OP_INVOKE_CUSTOM_RANGE:
		op->type = R_ANAL_OP_TYPE_CALL;
		break;
	case DALVIK_OP_NEG_FLOAT:
	case DALVIK_OP_NEG_DOUBLE:
		op->family = R_ANAL_OP_FAMILY_FPU;
		// fallthrough
	case DALVIK_OP_NEG_INT:
	case DALVIK_OP_NOT_INT:
	case DALVIK_OP_NEG_LONG:
	case DALVIK_OP_NOT_LONG:
		op->type = R_ANAL_OP_TYPE_NOT;
		break;
	case DALVIK_OP_INT_TO_FLOAT:
	case DALVIK_OP_INT_TO_DOUBLE:
	case DALVIK_OP_LONG_TO_FLOAT:
	case DALVIK_OP_LONG_TO_DOUBLE:
	case DALVIK_OP_FLOAT_TO_INT:
	case DALVIK_OP_FLOAT_TO_LONG:
	case DALVIK_OP_FLOAT_TO_DOUBLE:
	case DALVIK_OP_DOUBLE_TO_INT:
	case DALVIK_OP_DOUBLE_TO_LONG:
	case DALVIK_OP_DOUBLE_TO_FLOAT:
		op->family = R_ANAL_OP_FAMILY_FPU;
		// fallthrough
	case DALVIK_OP_INT_TO_LONG:
	case DALVIK_OP_LONG_TO_INT:
	case DALVIK_OP_INT_TO_BYTE:
	case DALVIK_OP_INT_TO_CHAR:
	case DALVIK_OP_INT_TO_SHORT:
		op->type = R_ANAL_OP_TYPE_CAST;
		break;
	case DALVIK_OP_ADD_FLOAT:
	case DALVIK_OP_ADD_DOUBLE:
	case DALVIK_OP_ADD_FLOAT_2ADDR:
	case DALVIK_OP_ADD_DOUBLE_2ADDR:
		op->family = R_ANAL_OP_FAMILY_FPU;
		// fallthrough
	case DALVIK_OP_ADD_INT:
	case DALVIK_OP_ADD_LONG:
	case DALVIK_OP_ADD_INT_2ADDR:
	case DALVIK_OP_ADD_LONG_2ADDR:
	case DALVIK_OP_ADD_INT_LIT16:
	case DALVIK_OP_ADD_INT_LIT8:
		op->type = R_ANAL_OP_TYPE_ADD;
		break;
	case DALVIK_OP_SUB_FLOAT:
	case DALVIK_OP_SUB_DOUBLE:
	case DALVIK_OP_SUB_FLOAT_2ADDR:
	case DALVIK_OP_SUB_DOUBLE_2ADDR:
		op->family = R_ANAL_OP_FAMILY_FPU;
		// fallthrough
	case DALVIK_OP_SUB_INT:
	case DALVIK_OP_SUB_LONG:
	case DALVIK_OP_SUB_INT_2ADDR:
	case DALVIK_OP_SUB_LONG_2ADDR:
	case DALVIK_OP_RSUB_INT:
	case DALVIK_OP_RSUB_INT_LIT8:
		op->type = R_ANAL_OP_TYPE_SUB;
		break;
	case DALVIK_OP_MUL_FLOAT:
	case DALVIK_OP_MUL_DOUBLE:
	case DALVIK_OP_MUL_FLOAT_2ADDR:
	case DALVIK_OP_MUL_DOUBLE_2ADDR:
		op->family = R_ANAL_OP_FAMILY_FPU;
		// fallthrough
	case DALVIK_OP_MUL_INT:
	case DALVIK_OP_MUL_LONG:
	case DALVIK_OP_MUL_INT_2ADDR:
	case DALVIK_OP_MUL_LONG_2ADDR:
	case DALVIK_OP_MUL_INT_LIT16:
	case DALVIK_OP_MUL_INT_LIT8:
		op->type = R_ANAL_OP_TYPE_MUL;
		break;
	case DALVIK_OP_DIV_FLOAT:
	case DALVIK_OP_DIV_DOUBLE:
	case DALVIK_OP_DIV_FLOAT_2ADDR:
	case DALVIK_OP_DIV_DOUBLE_2ADDR:
		op->family = R_ANAL_OP_FAMILY_FPU;
		// fallthrough
	case DALVIK_OP_DIV_INT:
	case DALVIK_OP_DIV_LONG:
	case DALVIK_OP_DIV_INT_2ADDR:
	case DALVIK_OP_DIV_LONG_2ADDR:
	case DALVIK_OP_DIV_INT_LIT16:
	case DALVIK_OP_DIV_INT_LIT8:
		op->type = R_ANAL_OP_TYPE_DIV;
		break;
	case DALVIK_OP_REM_FLOAT:
	case DALVIK_OP_REM_DOUBLE:
	case DALVIK_OP_REM_FLOAT_2ADDR:
	case DALVIK_OP_REM_DOUBLE_2ADDR:
		op->family = R_ANAL_OP_FAMILY_FPU;
		// fallthrough
	case DALVIK_OP_REM_INT:
	case DALVIK_OP_REM_LONG:
	case DALVIK_OP_REM_INT_2ADDR:
	case DALVIK_OP_REM_LONG_2ADDR:
	case DALVIK_OP_REM_INT_LIT16:
	case DALVIK_OP_REM_INT_LIT8:
		op->type = R_ANAL_OP_TYPE_MOD;
		break;
	case DALVIK_OP_AND_INT:
	case DALVIK_OP_AND_LONG:
	case DALVIK_OP_AND_INT_2ADDR:
	case DALVIK_OP_AND_LONG_2ADDR:
	case DALVIK_OP_AND_INT_LIT16:
	case DALVIK_OP_AND_INT_LIT8:
		op->type = R_ANAL_OP_TYPE_AND;
		break;
	case DALVIK_OP_OR_INT:
	case DALVIK_OP_OR_LONG:
	case DALVIK_OP_OR_INT_2ADDR:
	case DALVIK_OP_OR_LONG_2ADDR:
	case DALVIK_OP_OR_INT_LIT16:
	case DALVIK_OP_OR_INT_LIT8:
		op->type = R_ANAL_OP_TYPE_OR;
		break;
	case DALVIK_OP_XOR_INT:
	case DALVIK_OP_XOR_LONG:
	case DALVIK_OP_XOR_INT_2ADDR:
	case DALVIK_OP_XOR_LONG_2ADDR:
	case DALVIK_OP_XOR_INT_LIT16:
	case DALVIK_OP_XOR_INT_LIT8:
		op->type = R_ANAL_OP_TYPE_XOR;
		break;
	case DALVIK_OP_SHL_INT:
	case DALVIK_OP_SHL_LONG:
	case DALVIK_OP_SHL_INT_2ADDR:
	case DALVIK_OP_SHL_LONG_2ADDR:
	case DALVIK_OP_SHL_INT_LIT8:
		op->type = R_ANAL_OP_TYPE_SHL;
		break;
	case DALVIK_OP_SHR_INT:
	case DALVIK_OP_SHR_LONG:
	case DALVIK_OP_SHR_INT_2ADDR:
	case DALVIK_OP_SHR_LONG_2ADDR:
	case DALVIK_OP_SHR_INT_LIT8:
	case DALVIK_OP_USHR_INT:
	case DALVIK_OP_USHR_LONG:
	case DALVIK_OP_USHR_INT_2ADDR:
	case DALVIK_OP_USHR_LONG_2ADDR:
	case DALVIK_OP_USHR_INT_LIT8:
		op->type = R_ANAL_OP_TYPE_SHR;
		break;
	case DALVIK_OP_CHECK_CAST:
	case DALVIK_OP_INSTANCE_OF:
		op->type = R_ANAL_OP_TYPE_CMP;
		break;
	case DALVIK_OP_ARRAY_LENGTH:
		op->type = R_ANAL_OP_TYPE_LENGTH;
		op->datatype = R_ANAL_DATATYPE_ARRAY;
		break;
	case DALVIK_OP_NEW_INSTANCE:
		op->type = R_ANAL_OP_TYPE_NEW;
		break;
	case DALVIK_OP_NEW_ARRAY:
	case DALVIK_OP_FILLED_NEW_ARRAY:
	case DALVIK_OP_FILLED_NEW_ARRAY_RANGE:
	case DALVIK_OP_FILL_ARRAY_DATA:
		op->type = R_ANAL_OP_TYPE_NEW;
		break;
	case DALVIK_OP_THROW:
		op->type = R_ANAL_OP_TYPE_TRAP;
		break;
	case DALVIK_OP_CMPL_FLOAT:
	case DALVIK_OP_CMPG_FLOAT:
	case DALVIK_OP_CMPL_DOUBLE:
	case DALVIK_OP_CMPG_DOUBLE:
		op->type = R_ANAL_OP_TYPE_CMP;
		op->family = R_ANAL_OP_FAMILY_FPU;
		break;
	case DALVIK_OP_CMP_LONG:
		op->type = R_ANAL_OP_TYPE_CMP;
		break;
	case DALVIK_OP_MONITOR_ENTER:
	case DALVIK_OP_MONITOR_EXIT:
	default:
		break;
	}

	return true;
}

static char *regs (RArchSession *as) {
	int i;
	RStrBuf *sb = r_strbuf_new (
		"=PC	ip\n"
		"=SP	sp\n"
		"=BP	bp\n"
		"=A0	v0\n"
		"=A1	v1\n"
		"=A2	v2\n"
		"=A3	v3\n"
		"=SN	v0\n"
		"gpr	ip	.32	0	0\n"
		"gpr	sp	.32	4	0\n"
		"gpr	bp	.32	8	0\n"
	);
	// TODO:
	// handle the full v0-v65535 range of registers
	// specific handling for adjacent register pairs (64-bit values)
	for (i = 0; i < 32; i++) {
		r_strbuf_appendf (sb, "gpr	v%u	.32	%d	0\n", i, 12 + i * 4);
	}
	return r_strbuf_drain (sb);
}

const RArchPlugin r_arch_plugin_dalvik_ns = {
	.meta = {
		.name = "dalvik.ns",
		.author = "NowSecure",
		.desc = "Android Dalvik Virtual bytecode machine",
		.license = "MIT",
	},
	.arch = "dalvik",
	.bits = R_SYS_BITS_PACK (32),
	.regs = regs,
	.decode = decode,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ARCH,
	.data = &r_arch_plugin_dalvik_ns,
	.version = R2_VERSION
};
#endif
