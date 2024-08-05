/* radare - LGPL - Copyright 2018-2021 - pancake */

#include <r_asm.h>

// XXX R2_590 - this file should be just r_arch_op so should be removed soon
R_API RAnalOp *r_asm_op_new(void) {
	return R_NEW0 (RAnalOp);
}

R_API void r_asm_op_free(RAnalOp *op) {
	if (op) {
		r_asm_op_fini (op);
		free (op);
	}
}

R_API void r_asm_op_init(RAnalOp *op) {
	if (op) {
		memset (op, 0, sizeof (*op));
	}
}

R_DEPRECATE R_API void r_asm_op_fini(RAnalOp *op) {
	R_RETURN_IF_FAIL (op);
	r_anal_op_fini (op);
}

// R2_600 - must use RArchOp.getHex()
R_DEPRECATE R_API char *r_asm_op_get_hex(RAnalOp *op) {
	R_RETURN_VAL_IF_FAIL (op && op->bytes, NULL);
	const int size = op->size;
	if (size < 1) {
		return NULL;
	}
	char* str = calloc (size + 1, 2);
	if (str) {
		int res = r_hex_bin2str (op->bytes, size, str);
		if (res < 1) {
			R_FREE (str);
		}
	}
	return str;
}

// XXX R2_600
R_DEPRECATE R_API char *r_asm_op_get_asm(RAnalOp *op) {
	R_RETURN_VAL_IF_FAIL (op, NULL);
	return op->mnemonic;
}

#if 0
UNUSED
R_API ut8 *r_asm_op_get_buf(RAnalOp *op) {
	R_RETURN_VAL_IF_FAIL (op, NULL);
	return op->bytes;
}
#endif

R_API int r_asm_op_get_size(RAnalOp *op) {
	R_RETURN_VAL_IF_FAIL (op, 1);
	const int len = op->size - op->payload;
	return R_MAX (1, len);
}

R_API void r_asm_op_set_asm(RAnalOp *op, const char *str) {
	R_RETURN_IF_FAIL (op && str);
	r_anal_op_set_mnemonic (op, op->addr, str);
}

R_API int r_asm_op_set_hex(RAnalOp *op, const char *str) {
	R_RETURN_VAL_IF_FAIL (op && str, 0);
	ut8 *bin = (ut8*)strdup (str);
	if (bin) {
		int len = r_hex_str2bin (str, bin);
		if (len > 0) {
			if (!op->weakbytes) {
				free (op->bytes);
			}
			op->bytes = bin;
			op->size = len;
		} else {
			free (bin);
		}
		return len;
	}
	return 0;
}

R_API int r_asm_op_set_hexbuf(RAnalOp *op, const ut8 *buf, int len) {
	R_RETURN_VAL_IF_FAIL (op && buf && len >= 0, 0);
	char *hex = malloc (len * 4 + 1);
	if (hex) {
		(void)r_hex_bin2str (buf, len, hex);
		int olen = r_asm_op_set_hex (op, hex);
		free (hex);
		return olen;
	}
	return 0;
}

R_DEPRECATE R_API void r_asm_op_set_buf(RAnalOp *op, const ut8 *buf, int len) {
	R_RETURN_IF_FAIL (op && buf && len >= 0);
	r_anal_op_set_bytes (op, op->addr, buf, len);
}
