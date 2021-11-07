/* radare - <TODO> - Copyright 2021 - <TODO> */

#include <r_types.h>
#include <r_util.h>
#include <r_asm.h>

static int jdh8Disass(RAsmOp *op, const ut8 *buf, int len) {
	if (len < 1) {
		return 0;
	}
	r_strbuf_setf (&op->buf_asm, "unknown(0x%02x)", buf[0]);
	return 1;
}
