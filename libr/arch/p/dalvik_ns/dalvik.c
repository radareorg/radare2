/* radare2 - MIT - Copyright 2024 - NowSecure, Inc. */

#include "dalvik.h"

static inline ut64 fmt_size(enum dalvik_fmt fmt) {
	R_RETURN_VAL_IF_FAIL (fmt < DALVIK_FMT_MAX, 0);
	if (fmt >= DALVIK_FMT_10X && fmt <= DALVIK_FMT_10T) {
		return 1;
	}
	if (fmt >= DALVIK_FMT_20T && fmt <= DALVIK_FMT_22C) {
		return 3;
	}
	if (fmt >= DALVIK_FMT_32X && fmt <= DALVIK_FMT_3RC) {
		return 5;
	}
	if (fmt >= DALVIK_FMT_45CC && fmt <= DALVIK_FMT_4RCC) {
		return 7;
	}
	if (fmt == DALVIK_FMT_51L) {
		return 9;
	}
	// unreachable
	return 0;
}

static inline ut8 nibble(ut8 const *buf, ut32 i) {
	ut8 const *b = buf + i / 2;
	return (i & 1)? (*b & 0xf0) >> 4: *b & 0xf;
}

static bool dalvik_read_instr(RBuffer *buf, struct dalvik_instr *instr) {
	ut8 opcode;
	if (r_buf_read (buf, &opcode, sizeof (opcode)) != sizeof (opcode)) {
		return false;
	}
	const struct dalvik_op_detail *d = &dalvik_opcodes[opcode];
	// if opcode is invalid
	if (d->name == NULL)
		return false;
	instr->op = opcode;
	// maximum possible opcode size
	ut8 v[9];
	ut64 size = fmt_size (d->fmt);
	if (r_buf_read (buf, (ut8 *)&v, size) != size) {
		return false;
	}
	switch (d->fmt) {
		case DALVIK_FMT_10X:
			// could be a pseudo-opcode
			instr->f10x.a = v[0];
			break;
		case DALVIK_FMT_12X:
		case DALVIK_FMT_11N:
			instr->f12x.a = nibble (&v[0], 0);
			instr->f12x.b = nibble (&v[0], 1);
			break;
		case DALVIK_FMT_11X:
		case DALVIK_FMT_10T:
			instr->f11x.a = v[0];
			break;
		case DALVIK_FMT_20T:
			instr->f20t.a = r_read_le16 (&v[1]);
			break;
		case DALVIK_FMT_22X:
		case DALVIK_FMT_21T:
		case DALVIK_FMT_21S:
		case DALVIK_FMT_21H:
		case DALVIK_FMT_21C:
			instr->f22x.a = v[0];
			instr->f22x.b = r_read_le16 (&v[1]);
			break;
		case DALVIK_FMT_23X:
		case DALVIK_FMT_22B:
			instr->f23x.a = v[0];
			instr->f23x.b = v[1];
			instr->f23x.c = v[2];
			break;
		case DALVIK_FMT_22T:
		case DALVIK_FMT_22S:
		case DALVIK_FMT_22C:
			instr->f22t.a = nibble (&v[0], 0);
			instr->f22t.b = nibble (&v[0], 1);
			instr->f22t.c = r_read_le16 (&v[1]);
			break;
		case DALVIK_FMT_32X:
			instr->f32x.a = r_read_le16 (&v[1]);
			instr->f32x.b = r_read_le16 (&v[3]);
			break;
		case DALVIK_FMT_30T:
			instr->f30t.a = r_read_le32 (&v[1]);
			break;
		case DALVIK_FMT_31T:
		case DALVIK_FMT_31I:
		case DALVIK_FMT_31C:
			instr->f31i.a = v[0];
			instr->f31i.b = r_read_le32 (&v[1]);
			break;
		case DALVIK_FMT_35C:
			instr->f35c.a = nibble (&v[0], 1);
			instr->f35c.g = nibble (&v[0], 0);
			instr->f35c.b = r_read_le16 (&v[1]);
			instr->f35c.f = nibble (&v[3], 3);
			instr->f35c.e = nibble (&v[3], 2);
			instr->f35c.d = nibble (&v[3], 1);
			instr->f35c.c = nibble (&v[3], 0);
			break;
		case DALVIK_FMT_3RC:
			instr->f3rc.a = v[0];
			instr->f3rc.b = r_read_le16 (&v[1]);
			instr->f3rc.c = r_read_le16 (&v[3]);
			break;
		case DALVIK_FMT_45CC:
			instr->f45cc.a = nibble (&v[0], 1);
			instr->f45cc.g = nibble (&v[0], 0);
			instr->f45cc.b = r_read_le16 (&v[1]);
			instr->f45cc.f = nibble (&v[3], 3);
			instr->f45cc.e = nibble (&v[3], 2);
			instr->f45cc.d = nibble (&v[3], 1);
			instr->f45cc.c = nibble (&v[3], 0);
			instr->f45cc.h = r_read_le16 (&v[5]);
			break;
		case DALVIK_FMT_4RCC:
			instr->f4rcc.a = v[0];
			instr->f4rcc.b = r_read_le16 (&v[1]);
			instr->f4rcc.c = r_read_le16 (&v[3]);
			instr->f4rcc.h = r_read_le16 (&v[5]);
			break;
		case DALVIK_FMT_51L:
			instr->f51l.a = v[0];
			instr->f51l.b = r_read_le64 (&v[1]);
			break;
		case DALVIK_FMT_MAX:
			return false;
	}
	return true;
}

static bool dalvik_read_payload(RBuffer *buf, const struct dalvik_instr *instr, struct dalvik_payload *payload) {
	if (instr->op != DALVIK_OP_NOP) {
		return false;
	}
	payload->op = 0;
	switch (instr->f10x.a) {
	case DALVIK_PSEUDO_OP_PACKED_SWITCH_PAYLOAD: {
		ut8 v[6];
		if (r_buf_read (buf, (ut8 *)&v, sizeof (v)) != sizeof (v)) {
			return false;
		}

		ut16 len = r_read_le16 (&v);
		if (len == 0) {
			return false;
		}
		st32 first_key = r_read_le32 (&v[2]);

		if (SZT_MUL_OVFCHK (len, sizeof (st32))) {
			return false;
		}
		size_t targets_size = (size_t)len * sizeof (st32);
		st32 *targets = malloc (targets_size);
		if (targets == NULL) {
			return false;
		}
		if (r_buf_read (buf, (ut8 *)targets, targets_size) != targets_size) {
			free (targets);
			return false;
		}
		size_t i;
		for (i = 0; i < len; i++) {
			targets[i] = r_read_le32 (&targets[i]);
		}
		payload->packed_switch.len = len;
		payload->packed_switch.first_key = first_key;
		payload->packed_switch.targets = targets;
		break;
	}
	case DALVIK_PSEUDO_OP_SPARSE_SWITCH_PAYLOAD: {
		ut8 v[2];
		if (r_buf_read (buf, (ut8 *)&v, sizeof (v)) != sizeof (v)) {
			return false;
		}

		ut16 len = r_read_le16 (&v);
		if (len == 0) {
			return false;
		}

		if (SZT_MUL_OVFCHK (len, sizeof (st32))) {
			return false;
		}
		size_t size = (size_t)len * sizeof (st32);
		st32 *keys = malloc (size);
		st32 *targets = malloc (size);
		if (keys == NULL || targets == NULL) {
			free (keys);
			free (targets);
			return false;
		}
		if (r_buf_read (buf, (ut8 *)keys, size) != size
			|| r_buf_read (buf, (ut8 *)targets, size) != size) {
			free (keys);
			free (targets);
			return false;
		}
		size_t i;
		for (i = 0; i < len; i++) {
			keys[i] = r_read_le32 (&keys[i]);
			targets[i] = r_read_le32 (&targets[i]);
		}
		payload->sparse_switch.len = len;
		payload->sparse_switch.keys = keys;
		payload->sparse_switch.targets = targets;
		break;
	}
	case DALVIK_PSEUDO_OP_FILL_ARRAY_DATA_PAYLOAD: {
		ut8 v[6];
		ut16 element_width;
		ut32 len;
		if (r_buf_read (buf, (ut8 *)&v, sizeof (v)) != sizeof (v)) {
			return false;
		}

		element_width = r_read_le16 (&v);
		if (element_width == 0) {
			return false;
		}
		len = r_read_le32 (&v[2]);
		if (len == 0) {
			return false;
		}

		if (SZT_MUL_OVFCHK (len, element_width)) {
			return false;
		}
		size_t size = (size_t)len * (size_t)element_width;
		R_RETURN_VAL_IF_FAIL (size < 0x10000000, false);
		ut8 *data = malloc (size);
		if (data == NULL) {
			return false;
		}
		if (r_buf_read (buf, (ut8 *)data, size) != size) {
			free (data);
			return false;
		}
		payload->fill_array_data.element_width = element_width;
		payload->fill_array_data.len = len;
		payload->fill_array_data.data = data;
		break;
	}
	default:
		return false;
	}
	payload->op = instr->f10x.a;
	return true;
}

static void dalvik_payload_fini(struct dalvik_payload *payload) {
	switch (payload->op) {
	case DALVIK_PSEUDO_OP_PACKED_SWITCH_PAYLOAD:
		free (payload->packed_switch.targets);
		break;
	case DALVIK_PSEUDO_OP_SPARSE_SWITCH_PAYLOAD:
		free (payload->sparse_switch.keys);
		free (payload->sparse_switch.targets);
		break;
	case DALVIK_PSEUDO_OP_FILL_ARRAY_DATA_PAYLOAD:
		free (payload->fill_array_data.data);
		break;
	}
}

// Generated from: see URL in enum dalvik_op
//
// const fs = require("fs");
// const buf = fs.readFileSync(process.argv[2]).toString();
// for (let line of buf.split("\n")) {
//     line = line.replace(/\\/g, "").trim();
//     if (line === "") continue;
//     const es = line.split(",");
//     const opcode = es[1].trim();
//     const name = es[2].trim();
//     const fmt = es[3].trim().toUpperCase().slice(1);
//     console.log(`[DALVIK_OP_${opcode}] = {${name}, DALVIK_FMT_${fmt}},`)
// }
static const struct dalvik_op_detail dalvik_opcodes[DALVIK_OP_MAX] = {
	[DALVIK_OP_NOP] = {"nop", DALVIK_FMT_10X},
	[DALVIK_OP_MOVE] = {"move", DALVIK_FMT_12X},
	[DALVIK_OP_MOVE_FROM16] = {"move/from16", DALVIK_FMT_22X},
	[DALVIK_OP_MOVE_16] = {"move/16", DALVIK_FMT_32X},
	[DALVIK_OP_MOVE_WIDE] = {"move-wide", DALVIK_FMT_12X},
	[DALVIK_OP_MOVE_WIDE_FROM16] = {"move-wide/from16", DALVIK_FMT_22X},
	[DALVIK_OP_MOVE_WIDE_16] = {"move-wide/16", DALVIK_FMT_32X},
	[DALVIK_OP_MOVE_OBJECT] = {"move-object", DALVIK_FMT_12X},
	[DALVIK_OP_MOVE_OBJECT_FROM16] = {"move-object/from16", DALVIK_FMT_22X},
	[DALVIK_OP_MOVE_OBJECT_16] = {"move-object/16", DALVIK_FMT_32X},
	[DALVIK_OP_MOVE_RESULT] = {"move-result", DALVIK_FMT_11X},
	[DALVIK_OP_MOVE_RESULT_WIDE] = {"move-result-wide", DALVIK_FMT_11X},
	[DALVIK_OP_MOVE_RESULT_OBJECT] = {"move-result-object", DALVIK_FMT_11X},
	[DALVIK_OP_MOVE_EXCEPTION] = {"move-exception", DALVIK_FMT_11X},
	[DALVIK_OP_RETURN_VOID] = {"return-void", DALVIK_FMT_10X},
	[DALVIK_OP_RETURN] = {"return", DALVIK_FMT_11X},
	[DALVIK_OP_RETURN_WIDE] = {"return-wide", DALVIK_FMT_11X},
	[DALVIK_OP_RETURN_OBJECT] = {"return-object", DALVIK_FMT_11X},
	[DALVIK_OP_CONST_4] = {"const/4", DALVIK_FMT_11N},
	[DALVIK_OP_CONST_16] = {"const/16", DALVIK_FMT_21S},
	[DALVIK_OP_CONST] = {"const", DALVIK_FMT_31I},
	[DALVIK_OP_CONST_HIGH16] = {"const/high16", DALVIK_FMT_21H},
	[DALVIK_OP_CONST_WIDE_16] = {"const-wide/16", DALVIK_FMT_21S},
	[DALVIK_OP_CONST_WIDE_32] = {"const-wide/32", DALVIK_FMT_31I},
	[DALVIK_OP_CONST_WIDE] = {"const-wide", DALVIK_FMT_51L},
	[DALVIK_OP_CONST_WIDE_HIGH16] = {"const-wide/high16", DALVIK_FMT_21H},
	[DALVIK_OP_CONST_STRING] = {"const-string", DALVIK_FMT_21C},
	[DALVIK_OP_CONST_STRING_JUMBO] = {"const-string/jumbo", DALVIK_FMT_31C},
	[DALVIK_OP_CONST_CLASS] = {"const-class", DALVIK_FMT_21C},
	[DALVIK_OP_MONITOR_ENTER] = {"monitor-enter", DALVIK_FMT_11X},
	[DALVIK_OP_MONITOR_EXIT] = {"monitor-exit", DALVIK_FMT_11X},
	[DALVIK_OP_CHECK_CAST] = {"check-cast", DALVIK_FMT_21C},
	[DALVIK_OP_INSTANCE_OF] = {"instance-of", DALVIK_FMT_22C},
	[DALVIK_OP_ARRAY_LENGTH] = {"array-length", DALVIK_FMT_12X},
	[DALVIK_OP_NEW_INSTANCE] = {"new-instance", DALVIK_FMT_21C},
	[DALVIK_OP_NEW_ARRAY] = {"new-array", DALVIK_FMT_22C},
	[DALVIK_OP_FILLED_NEW_ARRAY] = {"filled-new-array", DALVIK_FMT_35C},
	[DALVIK_OP_FILLED_NEW_ARRAY_RANGE] = {"filled-new-array/range", DALVIK_FMT_3RC},
	[DALVIK_OP_FILL_ARRAY_DATA] = {"fill-array-data", DALVIK_FMT_31T},
	[DALVIK_OP_THROW] = {"throw", DALVIK_FMT_11X},
	[DALVIK_OP_GOTO] = {"goto", DALVIK_FMT_10T},
	[DALVIK_OP_GOTO_16] = {"goto/16", DALVIK_FMT_20T},
	[DALVIK_OP_GOTO_32] = {"goto/32", DALVIK_FMT_30T},
	[DALVIK_OP_PACKED_SWITCH] = {"packed-switch", DALVIK_FMT_31T},
	[DALVIK_OP_SPARSE_SWITCH] = {"sparse-switch", DALVIK_FMT_31T},
	[DALVIK_OP_CMPL_FLOAT] = {"cmpl-float", DALVIK_FMT_23X},
	[DALVIK_OP_CMPG_FLOAT] = {"cmpg-float", DALVIK_FMT_23X},
	[DALVIK_OP_CMPL_DOUBLE] = {"cmpl-double", DALVIK_FMT_23X},
	[DALVIK_OP_CMPG_DOUBLE] = {"cmpg-double", DALVIK_FMT_23X},
	[DALVIK_OP_CMP_LONG] = {"cmp-long", DALVIK_FMT_23X},
	[DALVIK_OP_IF_EQ] = {"if-eq", DALVIK_FMT_22T},
	[DALVIK_OP_IF_NE] = {"if-ne", DALVIK_FMT_22T},
	[DALVIK_OP_IF_LT] = {"if-lt", DALVIK_FMT_22T},
	[DALVIK_OP_IF_GE] = {"if-ge", DALVIK_FMT_22T},
	[DALVIK_OP_IF_GT] = {"if-gt", DALVIK_FMT_22T},
	[DALVIK_OP_IF_LE] = {"if-le", DALVIK_FMT_22T},
	[DALVIK_OP_IF_EQZ] = {"if-eqz", DALVIK_FMT_21T},
	[DALVIK_OP_IF_NEZ] = {"if-nez", DALVIK_FMT_21T},
	[DALVIK_OP_IF_LTZ] = {"if-ltz", DALVIK_FMT_21T},
	[DALVIK_OP_IF_GEZ] = {"if-gez", DALVIK_FMT_21T},
	[DALVIK_OP_IF_GTZ] = {"if-gtz", DALVIK_FMT_21T},
	[DALVIK_OP_IF_LEZ] = {"if-lez", DALVIK_FMT_21T},
	[DALVIK_OP_AGET] = {"aget", DALVIK_FMT_23X},
	[DALVIK_OP_AGET_WIDE] = {"aget-wide", DALVIK_FMT_23X},
	[DALVIK_OP_AGET_OBJECT] = {"aget-object", DALVIK_FMT_23X},
	[DALVIK_OP_AGET_BOOLEAN] = {"aget-boolean", DALVIK_FMT_23X},
	[DALVIK_OP_AGET_BYTE] = {"aget-byte", DALVIK_FMT_23X},
	[DALVIK_OP_AGET_CHAR] = {"aget-char", DALVIK_FMT_23X},
	[DALVIK_OP_AGET_SHORT] = {"aget-short", DALVIK_FMT_23X},
	[DALVIK_OP_APUT] = {"aput", DALVIK_FMT_23X},
	[DALVIK_OP_APUT_WIDE] = {"aput-wide", DALVIK_FMT_23X},
	[DALVIK_OP_APUT_OBJECT] = {"aput-object", DALVIK_FMT_23X},
	[DALVIK_OP_APUT_BOOLEAN] = {"aput-boolean", DALVIK_FMT_23X},
	[DALVIK_OP_APUT_BYTE] = {"aput-byte", DALVIK_FMT_23X},
	[DALVIK_OP_APUT_CHAR] = {"aput-char", DALVIK_FMT_23X},
	[DALVIK_OP_APUT_SHORT] = {"aput-short", DALVIK_FMT_23X},
	[DALVIK_OP_IGET] = {"iget", DALVIK_FMT_22C},
	[DALVIK_OP_IGET_WIDE] = {"iget-wide", DALVIK_FMT_22C},
	[DALVIK_OP_IGET_OBJECT] = {"iget-object", DALVIK_FMT_22C},
	[DALVIK_OP_IGET_BOOLEAN] = {"iget-boolean", DALVIK_FMT_22C},
	[DALVIK_OP_IGET_BYTE] = {"iget-byte", DALVIK_FMT_22C},
	[DALVIK_OP_IGET_CHAR] = {"iget-char", DALVIK_FMT_22C},
	[DALVIK_OP_IGET_SHORT] = {"iget-short", DALVIK_FMT_22C},
	[DALVIK_OP_IPUT] = {"iput", DALVIK_FMT_22C},
	[DALVIK_OP_IPUT_WIDE] = {"iput-wide", DALVIK_FMT_22C},
	[DALVIK_OP_IPUT_OBJECT] = {"iput-object", DALVIK_FMT_22C},
	[DALVIK_OP_IPUT_BOOLEAN] = {"iput-boolean", DALVIK_FMT_22C},
	[DALVIK_OP_IPUT_BYTE] = {"iput-byte", DALVIK_FMT_22C},
	[DALVIK_OP_IPUT_CHAR] = {"iput-char", DALVIK_FMT_22C},
	[DALVIK_OP_IPUT_SHORT] = {"iput-short", DALVIK_FMT_22C},
	[DALVIK_OP_SGET] = {"sget", DALVIK_FMT_21C},
	[DALVIK_OP_SGET_WIDE] = {"sget-wide", DALVIK_FMT_21C},
	[DALVIK_OP_SGET_OBJECT] = {"sget-object", DALVIK_FMT_21C},
	[DALVIK_OP_SGET_BOOLEAN] = {"sget-boolean", DALVIK_FMT_21C},
	[DALVIK_OP_SGET_BYTE] = {"sget-byte", DALVIK_FMT_21C},
	[DALVIK_OP_SGET_CHAR] = {"sget-char", DALVIK_FMT_21C},
	[DALVIK_OP_SGET_SHORT] = {"sget-short", DALVIK_FMT_21C},
	[DALVIK_OP_SPUT] = {"sput", DALVIK_FMT_21C},
	[DALVIK_OP_SPUT_WIDE] = {"sput-wide", DALVIK_FMT_21C},
	[DALVIK_OP_SPUT_OBJECT] = {"sput-object", DALVIK_FMT_21C},
	[DALVIK_OP_SPUT_BOOLEAN] = {"sput-boolean", DALVIK_FMT_21C},
	[DALVIK_OP_SPUT_BYTE] = {"sput-byte", DALVIK_FMT_21C},
	[DALVIK_OP_SPUT_CHAR] = {"sput-char", DALVIK_FMT_21C},
	[DALVIK_OP_SPUT_SHORT] = {"sput-short", DALVIK_FMT_21C},
	[DALVIK_OP_INVOKE_VIRTUAL] = {"invoke-virtual", DALVIK_FMT_35C},
	[DALVIK_OP_INVOKE_SUPER] = {"invoke-super", DALVIK_FMT_35C},
	[DALVIK_OP_INVOKE_DIRECT] = {"invoke-direct", DALVIK_FMT_35C},
	[DALVIK_OP_INVOKE_STATIC] = {"invoke-static", DALVIK_FMT_35C},
	[DALVIK_OP_INVOKE_INTERFACE] = {"invoke-interface", DALVIK_FMT_35C},
	[DALVIK_OP_INVOKE_VIRTUAL_RANGE] = {"invoke-virtual/range", DALVIK_FMT_3RC},
	[DALVIK_OP_INVOKE_SUPER_RANGE] = {"invoke-super/range", DALVIK_FMT_3RC},
	[DALVIK_OP_INVOKE_DIRECT_RANGE] = {"invoke-direct/range", DALVIK_FMT_3RC},
	[DALVIK_OP_INVOKE_STATIC_RANGE] = {"invoke-static/range", DALVIK_FMT_3RC},
	[DALVIK_OP_INVOKE_INTERFACE_RANGE] = {"invoke-interface/range", DALVIK_FMT_3RC},
	[DALVIK_OP_NEG_INT] = {"neg-int", DALVIK_FMT_12X},
	[DALVIK_OP_NOT_INT] = {"not-int", DALVIK_FMT_12X},
	[DALVIK_OP_NEG_LONG] = {"neg-long", DALVIK_FMT_12X},
	[DALVIK_OP_NOT_LONG] = {"not-long", DALVIK_FMT_12X},
	[DALVIK_OP_NEG_FLOAT] = {"neg-float", DALVIK_FMT_12X},
	[DALVIK_OP_NEG_DOUBLE] = {"neg-double", DALVIK_FMT_12X},
	[DALVIK_OP_INT_TO_LONG] = {"int-to-long", DALVIK_FMT_12X},
	[DALVIK_OP_INT_TO_FLOAT] = {"int-to-float", DALVIK_FMT_12X},
	[DALVIK_OP_INT_TO_DOUBLE] = {"int-to-double", DALVIK_FMT_12X},
	[DALVIK_OP_LONG_TO_INT] = {"long-to-int", DALVIK_FMT_12X},
	[DALVIK_OP_LONG_TO_FLOAT] = {"long-to-float", DALVIK_FMT_12X},
	[DALVIK_OP_LONG_TO_DOUBLE] = {"long-to-double", DALVIK_FMT_12X},
	[DALVIK_OP_FLOAT_TO_INT] = {"float-to-int", DALVIK_FMT_12X},
	[DALVIK_OP_FLOAT_TO_LONG] = {"float-to-long", DALVIK_FMT_12X},
	[DALVIK_OP_FLOAT_TO_DOUBLE] = {"float-to-double", DALVIK_FMT_12X},
	[DALVIK_OP_DOUBLE_TO_INT] = {"double-to-int", DALVIK_FMT_12X},
	[DALVIK_OP_DOUBLE_TO_LONG] = {"double-to-long", DALVIK_FMT_12X},
	[DALVIK_OP_DOUBLE_TO_FLOAT] = {"double-to-float", DALVIK_FMT_12X},
	[DALVIK_OP_INT_TO_BYTE] = {"int-to-byte", DALVIK_FMT_12X},
	[DALVIK_OP_INT_TO_CHAR] = {"int-to-char", DALVIK_FMT_12X},
	[DALVIK_OP_INT_TO_SHORT] = {"int-to-short", DALVIK_FMT_12X},
	[DALVIK_OP_ADD_INT] = {"add-int", DALVIK_FMT_23X},
	[DALVIK_OP_SUB_INT] = {"sub-int", DALVIK_FMT_23X},
	[DALVIK_OP_MUL_INT] = {"mul-int", DALVIK_FMT_23X},
	[DALVIK_OP_DIV_INT] = {"div-int", DALVIK_FMT_23X},
	[DALVIK_OP_REM_INT] = {"rem-int", DALVIK_FMT_23X},
	[DALVIK_OP_AND_INT] = {"and-int", DALVIK_FMT_23X},
	[DALVIK_OP_OR_INT] = {"or-int", DALVIK_FMT_23X},
	[DALVIK_OP_XOR_INT] = {"xor-int", DALVIK_FMT_23X},
	[DALVIK_OP_SHL_INT] = {"shl-int", DALVIK_FMT_23X},
	[DALVIK_OP_SHR_INT] = {"shr-int", DALVIK_FMT_23X},
	[DALVIK_OP_USHR_INT] = {"ushr-int", DALVIK_FMT_23X},
	[DALVIK_OP_ADD_LONG] = {"add-long", DALVIK_FMT_23X},
	[DALVIK_OP_SUB_LONG] = {"sub-long", DALVIK_FMT_23X},
	[DALVIK_OP_MUL_LONG] = {"mul-long", DALVIK_FMT_23X},
	[DALVIK_OP_DIV_LONG] = {"div-long", DALVIK_FMT_23X},
	[DALVIK_OP_REM_LONG] = {"rem-long", DALVIK_FMT_23X},
	[DALVIK_OP_AND_LONG] = {"and-long", DALVIK_FMT_23X},
	[DALVIK_OP_OR_LONG] = {"or-long", DALVIK_FMT_23X},
	[DALVIK_OP_XOR_LONG] = {"xor-long", DALVIK_FMT_23X},
	[DALVIK_OP_SHL_LONG] = {"shl-long", DALVIK_FMT_23X},
	[DALVIK_OP_SHR_LONG] = {"shr-long", DALVIK_FMT_23X},
	[DALVIK_OP_USHR_LONG] = {"ushr-long", DALVIK_FMT_23X},
	[DALVIK_OP_ADD_FLOAT] = {"add-float", DALVIK_FMT_23X},
	[DALVIK_OP_SUB_FLOAT] = {"sub-float", DALVIK_FMT_23X},
	[DALVIK_OP_MUL_FLOAT] = {"mul-float", DALVIK_FMT_23X},
	[DALVIK_OP_DIV_FLOAT] = {"div-float", DALVIK_FMT_23X},
	[DALVIK_OP_REM_FLOAT] = {"rem-float", DALVIK_FMT_23X},
	[DALVIK_OP_ADD_DOUBLE] = {"add-double", DALVIK_FMT_23X},
	[DALVIK_OP_SUB_DOUBLE] = {"sub-double", DALVIK_FMT_23X},
	[DALVIK_OP_MUL_DOUBLE] = {"mul-double", DALVIK_FMT_23X},
	[DALVIK_OP_DIV_DOUBLE] = {"div-double", DALVIK_FMT_23X},
	[DALVIK_OP_REM_DOUBLE] = {"rem-double", DALVIK_FMT_23X},
	[DALVIK_OP_ADD_INT_2ADDR] = {"add-int/2addr", DALVIK_FMT_12X},
	[DALVIK_OP_SUB_INT_2ADDR] = {"sub-int/2addr", DALVIK_FMT_12X},
	[DALVIK_OP_MUL_INT_2ADDR] = {"mul-int/2addr", DALVIK_FMT_12X},
	[DALVIK_OP_DIV_INT_2ADDR] = {"div-int/2addr", DALVIK_FMT_12X},
	[DALVIK_OP_REM_INT_2ADDR] = {"rem-int/2addr", DALVIK_FMT_12X},
	[DALVIK_OP_AND_INT_2ADDR] = {"and-int/2addr", DALVIK_FMT_12X},
	[DALVIK_OP_OR_INT_2ADDR] = {"or-int/2addr", DALVIK_FMT_12X},
	[DALVIK_OP_XOR_INT_2ADDR] = {"xor-int/2addr", DALVIK_FMT_12X},
	[DALVIK_OP_SHL_INT_2ADDR] = {"shl-int/2addr", DALVIK_FMT_12X},
	[DALVIK_OP_SHR_INT_2ADDR] = {"shr-int/2addr", DALVIK_FMT_12X},
	[DALVIK_OP_USHR_INT_2ADDR] = {"ushr-int/2addr", DALVIK_FMT_12X},
	[DALVIK_OP_ADD_LONG_2ADDR] = {"add-long/2addr", DALVIK_FMT_12X},
	[DALVIK_OP_SUB_LONG_2ADDR] = {"sub-long/2addr", DALVIK_FMT_12X},
	[DALVIK_OP_MUL_LONG_2ADDR] = {"mul-long/2addr", DALVIK_FMT_12X},
	[DALVIK_OP_DIV_LONG_2ADDR] = {"div-long/2addr", DALVIK_FMT_12X},
	[DALVIK_OP_REM_LONG_2ADDR] = {"rem-long/2addr", DALVIK_FMT_12X},
	[DALVIK_OP_AND_LONG_2ADDR] = {"and-long/2addr", DALVIK_FMT_12X},
	[DALVIK_OP_OR_LONG_2ADDR] = {"or-long/2addr", DALVIK_FMT_12X},
	[DALVIK_OP_XOR_LONG_2ADDR] = {"xor-long/2addr", DALVIK_FMT_12X},
	[DALVIK_OP_SHL_LONG_2ADDR] = {"shl-long/2addr", DALVIK_FMT_12X},
	[DALVIK_OP_SHR_LONG_2ADDR] = {"shr-long/2addr", DALVIK_FMT_12X},
	[DALVIK_OP_USHR_LONG_2ADDR] = {"ushr-long/2addr", DALVIK_FMT_12X},
	[DALVIK_OP_ADD_FLOAT_2ADDR] = {"add-float/2addr", DALVIK_FMT_12X},
	[DALVIK_OP_SUB_FLOAT_2ADDR] = {"sub-float/2addr", DALVIK_FMT_12X},
	[DALVIK_OP_MUL_FLOAT_2ADDR] = {"mul-float/2addr", DALVIK_FMT_12X},
	[DALVIK_OP_DIV_FLOAT_2ADDR] = {"div-float/2addr", DALVIK_FMT_12X},
	[DALVIK_OP_REM_FLOAT_2ADDR] = {"rem-float/2addr", DALVIK_FMT_12X},
	[DALVIK_OP_ADD_DOUBLE_2ADDR] = {"add-double/2addr", DALVIK_FMT_12X},
	[DALVIK_OP_SUB_DOUBLE_2ADDR] = {"sub-double/2addr", DALVIK_FMT_12X},
	[DALVIK_OP_MUL_DOUBLE_2ADDR] = {"mul-double/2addr", DALVIK_FMT_12X},
	[DALVIK_OP_DIV_DOUBLE_2ADDR] = {"div-double/2addr", DALVIK_FMT_12X},
	[DALVIK_OP_REM_DOUBLE_2ADDR] = {"rem-double/2addr", DALVIK_FMT_12X},
	[DALVIK_OP_ADD_INT_LIT16] = {"add-int/lit16", DALVIK_FMT_22S},
	[DALVIK_OP_RSUB_INT] = {"rsub-int", DALVIK_FMT_22S},
	[DALVIK_OP_MUL_INT_LIT16] = {"mul-int/lit16", DALVIK_FMT_22S},
	[DALVIK_OP_DIV_INT_LIT16] = {"div-int/lit16", DALVIK_FMT_22S},
	[DALVIK_OP_REM_INT_LIT16] = {"rem-int/lit16", DALVIK_FMT_22S},
	[DALVIK_OP_AND_INT_LIT16] = {"and-int/lit16", DALVIK_FMT_22S},
	[DALVIK_OP_OR_INT_LIT16] = {"or-int/lit16", DALVIK_FMT_22S},
	[DALVIK_OP_XOR_INT_LIT16] = {"xor-int/lit16", DALVIK_FMT_22S},
	[DALVIK_OP_ADD_INT_LIT8] = {"add-int/lit8", DALVIK_FMT_22B},
	[DALVIK_OP_RSUB_INT_LIT8] = {"rsub-int/lit8", DALVIK_FMT_22B},
	[DALVIK_OP_MUL_INT_LIT8] = {"mul-int/lit8", DALVIK_FMT_22B},
	[DALVIK_OP_DIV_INT_LIT8] = {"div-int/lit8", DALVIK_FMT_22B},
	[DALVIK_OP_REM_INT_LIT8] = {"rem-int/lit8", DALVIK_FMT_22B},
	[DALVIK_OP_AND_INT_LIT8] = {"and-int/lit8", DALVIK_FMT_22B},
	[DALVIK_OP_OR_INT_LIT8] = {"or-int/lit8", DALVIK_FMT_22B},
	[DALVIK_OP_XOR_INT_LIT8] = {"xor-int/lit8", DALVIK_FMT_22B},
	[DALVIK_OP_SHL_INT_LIT8] = {"shl-int/lit8", DALVIK_FMT_22B},
	[DALVIK_OP_SHR_INT_LIT8] = {"shr-int/lit8", DALVIK_FMT_22B},
	[DALVIK_OP_USHR_INT_LIT8] = {"ushr-int/lit8", DALVIK_FMT_22B},
	[DALVIK_OP_INVOKE_POLYMORPHIC] = {"invoke-polymorphic", DALVIK_FMT_45CC},
	[DALVIK_OP_INVOKE_POLYMORPHIC_RANGE] = {"invoke-polymorphic/range", DALVIK_FMT_4RCC},
	[DALVIK_OP_INVOKE_CUSTOM] = {"invoke-custom", DALVIK_FMT_35C},
	[DALVIK_OP_INVOKE_CUSTOM_RANGE] = {"invoke-custom/range", DALVIK_FMT_3RC},
	[DALVIK_OP_CONST_METHOD_HANDLE] = {"const-method-handle", DALVIK_FMT_21C},
	[DALVIK_OP_CONST_METHOD_TYPE] = {"const-method-type", DALVIK_FMT_21C},
};
