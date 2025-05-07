/* radare - LGPL - Copyright 2014-2023 condret */

#include <r_arch.h>
#include "wsdis.c"

#if 0
// R2_590 - Reimplement this logic as an anal plugin and put the hints
static ut64 ws_find_label(int l, const RIOBind *iob) {
	RIO *io = iob->io;
	ut64 cur = 0ULL;
	ut8 buf[128];
	ut32 opsize = 0;
	RStrBuf *mn = r_strbuf_new (NULL);
	iob->read_at (iob->io, cur, buf, 128);
	while (iob->is_valid_offset (io, cur, R_PERM_R) && (opsize = wsdis (mn, buf, 128))) {
	// TODO: also check for R_PERM_X, but would probably break with io.va = false, because text files are usually not opened as exec
//	while (iob.is_valid_offset (iob->io, cur, R_PERM_R | R_PERM_X) && (opsize = wsdis (mn, buf, 128))) {
		const char *buf_asm = r_strbuf_tostring (mn);
		if (buf_asm && r_str_startswith (buf_asm, "mark ") && l == atoi (buf_asm + 5)) {
			r_strbuf_free (mn);
			return cur;
		}
		cur = cur + opsize;
		iob->read_at (iob->io, cur, buf, 128);
	}
	r_strbuf_free (mn);
	return 0;
}
#endif

static bool decode(RArchSession *session, RAnalOp *op, RArchDecodeMask mask) {
	RStrBuf *mn = r_strbuf_new (NULL);
	op->type = R_ANAL_OP_TYPE_UNK;
	op->size = wsdis (mn, op->bytes, op->size);
	if (op->size) {
		char *buf_asm = r_strbuf_drain (mn);
		if (!buf_asm) {
			return false;
		}
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
				op->fail = op->addr + op->size;
				op->jump = UT64_MAX; // ws_find_label (atoi (buf_asm + 5), &anal->iob);
			} else {
				op->type = R_ANAL_OP_TYPE_UPUSH;
			}
			break;
		case 'j':
			if (buf_asm[1] == 'm') {
				op->type = R_ANAL_OP_TYPE_JMP;
				op->jump = UT64_MAX; // ws_find_label (atoi (buf_asm + 4), &anal->iob);
			} else {
				op->type = R_ANAL_OP_TYPE_CJMP;
				op->jump = UT64_MAX; // ws_find_label (atoi(buf_asm + 3), &anal->iob);
			}
			op->fail = op->addr + op->size;
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
						// XXX R2_590 - anal plugin for this
						// r_meta_set_string (anal, R_META_TYPE_COMMENT, addr, c);
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
		if (mask & R_ARCH_OP_MASK_DISASM) {
			op->mnemonic = buf_asm;
		} else {
			free (buf_asm);
		}
	} else {
		r_strbuf_free (mn);
	}
	return op->size;
}

static int archinfo(RArchSession *as, ut32 q) {
	switch (q) {
	case R_ARCH_INFO_ISVM:
		return R_ARCH_INFO_ISVM;
	case R_ARCH_INFO_MAXOP_SIZE:
		return 0xff;
		// return 32;
	}
	return 1;
}

const RArchPlugin r_arch_plugin_ws = {
	.meta = {
		.name = "ws",
		.desc = "Kind of brainfuck but based on non-printable characters",
		.license = "LGPL-3.0-only",
		.author = "pancake"
	},
	.endian = R_SYS_ENDIAN_LITTLE | R_SYS_ENDIAN_BIG,
	.arch = "ws",
	.bits = 32,
	.info = archinfo,
	.decode = &decode,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ARCH,
	.data = &r_anal_plugin_ws,
	.version = R2_VERSION
};
#endif
