/* radare - LGPL - Copyright 2014-2018 condret */

#include <string.h>
#include <r_types.h>
#include <r_asm.h>
#include <r_anal.h>
#include <r_lib.h>
#include <r_io.h>
#define WS_API static
#include "../../asm/arch/whitespace/wsdis.c"

static ut64 ws_find_label(int l, RIOBind iob) {
	RIO *io = iob.io;
	ut64 cur = 0, size = iob.desc_size (io->desc);
	ut8 buf[128];
	RAsmOp aop;
	iob.read_at (iob.io, cur, buf, 128);
	while (cur <= size && wsdis (&aop, buf, 128)) {
		const char *buf_asm = r_strbuf_get (&aop.buf_asm); // r_asm_op_get_asm (&aop);
		if (buf_asm && (strlen (buf_asm) > 4) && buf_asm[0] == 'm' && buf_asm[1] == 'a' && l == atoi (buf_asm + 5)) {
			return cur;
		}
		cur = cur + aop.size;
		iob.read_at (iob.io, cur, buf, 128);
	}
	return 0;
}

static int ws_anal(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *data, int len, RAnalOpMask mask) {
	memset (op, '\0', sizeof (RAnalOp));
	op->addr = addr;
	op->type = R_ANAL_OP_TYPE_UNK;
	RAsmOp *aop = R_NEW0 (RAsmOp);
	op->size = wsdis (aop, data, len);
	if (op->size) {
		const char *buf_asm = r_strbuf_get (&aop->buf_asm); // r_asm_op_get_asm (aop);
		switch (*buf_asm) {
		case 'n':
			op->type = R_ANAL_OP_TYPE_NOP;
			break;
		case 'e':
			op->type = R_ANAL_OP_TYPE_TRAP;
			break;
		case 'd':
			op->type = (buf_asm[1] == 'u')? R_ANAL_OP_TYPE_UPUSH: R_ANAL_OP_TYPE_DIV;
			break;
		case 'i':
			op->type = R_ANAL_OP_TYPE_ILL;
			break;
		case 'a':
			op->type = R_ANAL_OP_TYPE_ADD;
			break;
		case 'm':
			op->type = (buf_asm[1] == 'o') ? R_ANAL_OP_TYPE_MOD : R_ANAL_OP_TYPE_MUL;
			break;
		case 'r':
			op->type = R_ANAL_OP_TYPE_RET;
			break;
		case 'l':
			op->type = R_ANAL_OP_TYPE_LOAD;
			break;
		case 'c':
			if (buf_asm[1] == 'a') {
				op->type = R_ANAL_OP_TYPE_CALL;
				op->fail = addr + aop->size;
				op->jump = ws_find_label (atoi (buf_asm + 5), anal->iob);
			} else {
				op->type = R_ANAL_OP_TYPE_UPUSH;
			}
			break;
		case 'j':
			if (buf_asm[1] == 'm') {
				op->type = R_ANAL_OP_TYPE_JMP;
				op->jump = ws_find_label(atoi (buf_asm + 4), anal->iob);
			} else {
				op->type = R_ANAL_OP_TYPE_CJMP;
				op->jump = ws_find_label(atoi(buf_asm + 3), anal->iob);
			}
			op->fail = addr + aop->size;
			break;
		case 'g':
			op->type = R_ANAL_OP_TYPE_IO;
			break;
		case 'p':
			if (buf_asm[1] == 'o') {
				op->type = R_ANAL_OP_TYPE_POP;
			} else {
				if (buf_asm[2] == 's') {
					op->type = R_ANAL_OP_TYPE_PUSH;
					if (127 > atoi (buf_asm + 5) && atoi (buf_asm + 5) >= 33) {
						char c[4];
						c[3] = '\0';
						c[0] = c[2] = '\'';
						c[1] = (char) atoi (buf_asm + 5);
						r_meta_set_string (anal, R_META_TYPE_COMMENT, addr, c);
					}
				} else {
					op->type = R_ANAL_OP_TYPE_IO;
				}
			}
			break;
		case 's':
			switch (buf_asm[1]) {
			case 'u':
				op->type = R_ANAL_OP_TYPE_SUB;
				break;
			case 't':
				op->type = R_ANAL_OP_TYPE_STORE;
				break;
			case 'l':
				op->type = R_ANAL_OP_TYPE_LOAD;	// XXX
				break;
			case 'w':
				op->type = R_ANAL_OP_TYPE_ROR;
			}
			break;
		}
	}
	free (aop);
	return op->size;
}

RAnalPlugin r_anal_plugin_ws = {
	.name = "ws",
	.desc = "Space, tab and linefeed analysis plugin",
	.license = "LGPL3",
	.arch = "ws",
	.bits = 32,
	.op = &ws_anal,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_ws,
	.version = R2_VERSION
};
#endif
