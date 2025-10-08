/* radare - LGPL - Copyright 2016-2024 - pancake, condret */

#include <r_arch.h>
#include "./gperfdb.c"

static char *i4004_regs(RArchSession *a) {
	const char *p =
#include "./regs.h"
		;
	return strdup (p);
}

/* That 3 is a hack */
static const int i4004_ins_len[16] = {
	1, 2, 3, 1, 2, 2, 1, 2, 1, 1, 1, 1, 1, 1, 1, 1
};


static bool is_valid_input_num_value(RNum * R_NULLABLE num, const char *input_value) {
	if (!input_value) {
		return false;
	}
	ut64 value = r_num_math (num, input_value);
	return !(value == 0 && *input_value != '0');
}

static const char *i4004_e[16] = {
	"wrm",
	"wmp",
	"wrr",
	"wpm",
	"wr0",
	"wr1",
	"wr2",
	"wr3",
	"sbm",
	"rdm",
	"rdr",
	"adm",
	"rd0",
	"rd1",
	"rd2",
	"rd3"
};

static const char *i4004_f[16] = {
	"clb",
	"clc",
	"iac",
	"cmc",
	"cma",
	"ral",
	"rar",
	"tcc",
	"dac", // decrement
	"tcs",
	"stc",
	"daa",
	"kbp",
	"dcl",
	"invalid",
	"invalid"
};

static int i4004_get_ins_len(ut8 hex) {
	ut8 high = (hex & 0xf0) >> 4;
	int ret = i4004_ins_len[high];
	if (ret == 3) {
		ret = (hex & 1) ? 1 : 2;
	}
	return ret;
}

static bool i4004_decode(RArchSession *s, RAnalOp *op, RArchDecodeMask mask) {
	ut64 addr = op->addr;
	const ut8 *buf = op->bytes;
	int len = op->size;
	char basm[64];
	const size_t basz = sizeof (basm);
	int rlen = i4004_get_ins_len (*buf);
	if (!op) {
		return 2;
	}
	ut8 high = (*buf & 0xf0) >> 4;
	ut8 low = (*buf & 0xf);
	basm[0] = 0;

	if (rlen > len) {
		op->size = 0;
		op->type = R_ANAL_OP_TYPE_ILL;
		return false;
	}
	switch (high) {
	case 0:
		if (low) {
			op->type = R_ANAL_OP_TYPE_ILL;
			if (mask & R_ARCH_OP_MASK_DISASM) {
				strcpy (basm, "invalid");
			}
		} else {
			op->type = R_ANAL_OP_TYPE_NOP;
			if (mask & R_ARCH_OP_MASK_DISASM) {
				strcpy (basm, "nop");
			}
		}
		break;
	case 1:
		op->type = R_ANAL_OP_TYPE_CJMP;
		if (mask & R_ARCH_OP_MASK_DISASM) {
			snprintf (basm, basz, "jcn 0x%x 0x%x", low, buf[1]);
		}
		op->jump = (addr & (~0xFF)) + buf[1];
		op->fail = addr + rlen;
		break;
	case 2:
		if (rlen == 1) {
			if (mask & R_ARCH_OP_MASK_DISASM) {
				snprintf (basm, basz, "src r%d", (low & 0xe) >> 1);
			}
		} else {
			op->type = R_ANAL_OP_TYPE_MOV;
			op->val = buf[1];
			if (mask & R_ARCH_OP_MASK_DISASM) {
				snprintf (basm, basz, "fim r%dr%d, 0x%x", low & 0xe,
					(low & 0xe) + 1, buf[1]);
			}
		}
		break;
	case 3:
		if (low & 1) {
			op->type = R_ANAL_OP_TYPE_RJMP;
			if (mask & R_ARCH_OP_MASK_DISASM) {
				snprintf (basm, basz, "jin r%dr%d", low & 0xe, (low & 0xe) + 1);
			}
		} else {
			op->type = R_ANAL_OP_TYPE_MOV;
			if (mask & R_ARCH_OP_MASK_DISASM) {
				snprintf (basm, basz, "fin r%dr%d", low & 0xe, (low & 0xe) + 1);
			}
		}
		break;
	case 4:
		op->type = R_ANAL_OP_TYPE_JMP;
		op->jump = (ut16) (low << 8) | buf[1];
		if (mask & R_ARCH_OP_MASK_DISASM) {
			snprintf (basm, basz, "jun 0x%x", (ut16)op->jump);
		}
		break;
	case 5:
		op->type = R_ANAL_OP_TYPE_CALL;
		op->jump = (ut16) (low << 8) | buf[1];
		op->fail = addr + rlen;
		if (mask & R_ARCH_OP_MASK_DISASM) {
			snprintf (basm, basz, "jms 0x%x", (ut16)op->jump);
		}
		break;
	case 6:
		op->type = R_ANAL_OP_TYPE_ADD;
		if (mask & R_ARCH_OP_MASK_DISASM) {
			snprintf (basm, basz, "inc r%d", low);
		}
		break;
	case 7:
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->fail = (addr & (~0xFF)) + buf[1];
		op->jump = addr + rlen;
		if (mask & R_ARCH_OP_MASK_DISASM) {
			snprintf (basm, basz, "isz r%d, 0x%x", low, buf[1]);
		}
		break;
	case 8:
		op->type = R_ANAL_OP_TYPE_ADD;
		if (mask & R_ARCH_OP_MASK_DISASM) {
			snprintf (basm, basz, "add r%d", low);
		}
		break;
	case 9:
		op->type = R_ANAL_OP_TYPE_SUB;
		if (mask & R_ARCH_OP_MASK_DISASM) {
			snprintf (basm, basz, "sub r%d", low);
		}
		break;
	case 10:
		op->type = R_ANAL_OP_TYPE_MOV;
		if (mask & R_ARCH_OP_MASK_DISASM) {
			snprintf (basm, basz, "ld r%d", low);
		}
		break;
	case 11:
		op->type = R_ANAL_OP_TYPE_XCHG;
		if (mask & R_ARCH_OP_MASK_DISASM) {
			snprintf (basm, basz, "xch r%d", low);
		}
		break;
	case 12:
		op->type = R_ANAL_OP_TYPE_RET;
		if (mask & R_ARCH_OP_MASK_DISASM) {
			snprintf (basm, basz, "bbl 0x%x", low);
		}
		break;
	case 13:
		op->type = R_ANAL_OP_TYPE_LOAD;
		if (mask & R_ARCH_OP_MASK_DISASM) {
			snprintf (basm, basz, "ldm 0x%x", low);
		}
		break;
	case 14:
		r_str_ncpy (basm, i4004_e[low], basz);
		break;
	case 15:
		r_str_ncpy (basm, i4004_f[low], basz);
		if (!strcmp (basm, "dac")) {
			op->type = R_ANAL_OP_TYPE_SUB;
		}
		break;
	}
	if (!strcmp (basm, "invalid")) {
		op->type = R_ANAL_OP_TYPE_ILL;
	} else if (!strcmp (basm, "ral")) {
		op->type = R_ANAL_OP_TYPE_SHL;
	} else if (!strcmp (basm, "rar")) {
		op->type = R_ANAL_OP_TYPE_SHR;
	}
	if (mask & R_ARCH_OP_MASK_DISASM) {
		op->mnemonic = strdup (basm);
	}
	op->size = rlen;
	return true;
}

static bool i4004_encode(RArchSession *se, RAnalOp *op, RArchEncodeMask mask) {
	ut8 outbuf[32];
	// r_anal_op_set_bytes (op, addr, outbuf, outsize);
	char *s = strdup (op->mnemonic);
	r_str_case (s, false);
	s = r_str_replace (s, "_", "?", false);	// mitigate a bug in sdb -C
	s = r_str_replace (s, ",", " _ ", false);
	int i, nelems;
	char **elems = r_str_argv (s, &nelems);
	RStrBuf *sbuf = r_strbuf_new (elems[0]);
	for (i = 1; i < nelems; i++) {
		if (is_valid_input_num_value (NULL, elems[i])) {
			r_strbuf_appendf (sbuf, " 0x%"PFMT64x, r_num_get (NULL, elems[i]));
		} else {
			r_strbuf_appendf (sbuf, " %s", elems[i]);
		}
	}
	// this db should be instantiated once on plugin session
#if 1
	Sdb *asm_db = sdb_new0 ();
	sdb_open_gperf (asm_db, (SdbGperf *)&gperf_i4004);
	char *hex_output = sdb_get (asm_db, r_strbuf_get (sbuf), NULL);
	sdb_free (asm_db);
	r_strbuf_free (sbuf);
	if (hex_output) {
		r_str_argv_free (elems);
		free (s);
		int hexlen = r_hex_str2bin (hex_output, outbuf);
		op->size = hexlen;
		free (op->bytes);
		op->bytes = r_mem_dup (outbuf, hexlen);
		free (hex_output);
		return true;
	}
#endif
	if (strlen (elems[0]) != 3) {
		r_str_argv_free (elems);
		return 0;
	}
	int ret = 0;
	switch (elems[0][0] << 16 | elems[0][1] << 8 | elems[0][2]) {
	case 0x6a636e: // jcn
		if (nelems > 2 && is_valid_input_num_value (NULL, elems[1])
			&& is_valid_input_num_value (NULL, elems[2])) {
			ut64 v = r_num_get (NULL, elems[1]);
			if (v < 0x10) {
				outbuf[0] = 0x10 | (ut8)v;
				v = r_num_get (NULL, elems[2]);
				if (v < 0x100) {
					outbuf[1] = (ut8)v;
					ret = 2;
				}
			}
		}
		break;
	case 0x66696d: // fim
		if (nelems > 3 && !strcmp (elems[2], "_") && is_valid_input_num_value (NULL, elems[3])) {
			const ut64 v = r_num_get (NULL, elems[3]);
			if (v < 0x100) {
				ret = 2;
				if (!strcmp (elems[1], "r0r1")) {
					outbuf[0] = 0x20;
					outbuf[1] = (ut8)v;
				} else if (!strcmp (elems[1], "r2r3")) {
					outbuf[0] = 0x22;
					outbuf[1] = (ut8)v;
				} else if (!strcmp (elems[1], "r4r5")) {
					outbuf[0] = 0x24;
					outbuf[1] = (ut8)v;
				} else if (!strcmp (elems[1], "r6r7")) {
					outbuf[0] = 0x26;
					outbuf[1] = (ut8)v;
				} else if (!strcmp (elems[1], "r8r9")) {
					outbuf[0] = 0x28;
					outbuf[1] = (ut8)v;
				} else if (!strcmp (elems[1], "r10r11")) {
					outbuf[0] = 0x2a;
					outbuf[1] = (ut8)v;
				} else if (!strcmp (elems[1], "r12r14")) {
					outbuf[0] = 0x2c;
					outbuf[1] = (ut8)v;
				} else if (!strcmp (elems[1], "r14r15")) {
					outbuf[0] = 0x2e;
					outbuf[1] = (ut8)v;
				} else {
					ret = 0;
				}
			}
		}
		break;
	case 0x6a756e: // jun
		if (nelems > 1 && is_valid_input_num_value (NULL, elems[1])) {
			const ut64 v = r_num_get (NULL, elems[1]);
			if (v < 0x1000) {
				outbuf[0] = 0x40 | (v & 0xf00) >> 8;
				outbuf[1] = v & 0xff;
				ret = 2;
			}
		}
		break;
	case 0x6a6d73: // jms
		if (nelems > 1 && is_valid_input_num_value (NULL, elems[1])) {
			const ut64 v = r_num_get (NULL, elems[1]);
			if (v < 0x1000) {
				outbuf[0] = 0x50 | (v & 0xf00) >> 8;
				outbuf[1] = v & 0xff;
				ret = 2;
			}
		}
		break;
	case 0x69737a: // isz
		if (nelems > 3 && elems[1][0] == 'r' && is_valid_input_num_value (NULL, &elems[1][1])
			&& !strcmp (elems[2], "_") && is_valid_input_num_value (NULL, elems[3])) {
			ut64 v = r_num_get (NULL, &elems[1][1]);
			if (v < 0x10) {
				outbuf[0] = 0x70 | (ut8)v;
				v = r_num_get (NULL, elems[3]);
				if (v < 0x100) {
					outbuf[1] = (ut8)v;
					ret = 2;
				}
			}
		}
		break;
	default:
		break;
	}
	free (op->bytes);
	op->bytes = r_mem_dup (outbuf, ret);
	op->size = ret;
	r_str_argv_free (elems);
	return true;
}

const RArchPlugin r_arch_plugin_i4004 = {
	.meta = {
		.name = "i4004",
		.author = "pancake,condret",
		.desc = "The classic Intel 4004",
		.license = "LGPL-3.0-only",
	},
	.arch = "i4004",
	.endian = R_SYS_ENDIAN_BIG,
	.bits = R_SYS_BITS_PACK1 (4),
	.addr_bits = R_SYS_BITS_PACK1 (12),
	.decode = &i4004_decode,
	.encode = &i4004_encode,
	.regs = &i4004_regs,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ARCH,
	.data = &r_arch_plugin_i4004,
	.version = R2_VERSION
};
#endif
