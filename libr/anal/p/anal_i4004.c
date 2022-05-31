/* radare - LGPL - Copyright 2016-2022 - pancake, condret */

#include <string.h>
#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>
#include "../arch/i4004/i4004_0.c"
#include "../arch/i4004/i4004_1.c"

static bool set_reg_profile(RAnal *anal) {
	const char *p =
		"=PC	PC\n"
		/* syntax not yet supported */
		// "=SP	&PC1\n"
		"=A0	r0\n"
		"=A1	r1\n"
		"=A2	r2\n"
		"=A3	r3\n"
		"=R0	r0\n"
		"gpr	r0	.4	0	0\n"
		"gpr	r1	.4	.4	0\n"
		"gpr	r0r1	1	0	0\n"
		"gpr	r2	.4	.8	0\n"
		"gpr	r3	.4	.12	0\n"
		"gpr	r2r3	1	1	0\n"
		"gpr	r4	.4	.16	0\n"
		"gpr	r5	.4	.20	0\n"
		"gpr	r4r5	1	2	0\n"
		"gpr	r6	.4	.24	0\n"
		"gpr	r7	.4	.28	0\n"
		"gpr	r6r7	1	3	0\n"
		"gpr	r8	.4	.32	0\n"
		"gpr	r9	.4	.36	0\n"
		"gpr	r8r9	1	4	0\n"
		"gpr	r10	.4	.40	0\n"
		"gpr	r11	.4	.44	0\n"
		"gpr	r10r11	1	5	0\n"
		"gpr	r12	.4	.52	0\n"
		"gpr	r13	.4	.56	0\n"
		"gpr	r12r13	1	6	0\n"
		"gpr	r14	.4	.60	0\n"
		"gpr	r15	.4	.64	0\n"
		"gpr	r14r15	1	7	0\n"
		"gpr	PC	.12	.72	0\n"
		/* stack */
		"gpr	PC1	.12	.88	0\n"
		"gpr	PC2	.12	.104	0\n"
		"gpr	PC3	.12	.120	0\n"
		;

	return r_reg_set_profile_string (anal->reg, p);
}

/* That 3 is a hack */
static const int i4004_ins_len[16] = {
	1, 2, 3, 1, 2, 2, 1, 2, 1, 1, 1, 1, 1, 1, 1, 1
};

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
	ut8 high = (hex & 0xf0)>>4;
	int ret = i4004_ins_len[high];
	if (ret == 3) {
		ret = (hex & 1) ? 1 : 2;
	}
	return ret;
}

static int i4004_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf, int len, RAnalOpMask mask) {
	char basm[64];
	const size_t basz = sizeof (basm);
	int rlen = i4004_get_ins_len (*buf);
	if (!op) {
		return 2;
	}
	ut8 high = (*buf & 0xf0)>>4;
	ut8 low = (*buf & 0xf);
	basm[0] = 0;

	if (rlen > len) {
		return op->size = 0;
	}
	switch (high) {
	case 0:
		if (low) {
			op->type = R_ANAL_OP_TYPE_ILL;
			if (mask & R_ANAL_OP_MASK_DISASM) {
				strcpy (basm, "invalid");
			}
		} else {
			op->type = R_ANAL_OP_TYPE_NOP;
			if (mask & R_ANAL_OP_MASK_DISASM) {
				strcpy (basm, "nop");
			}
		}
		break;
	case 1: 
		op->type = R_ANAL_OP_TYPE_CJMP;
		if (mask & R_ANAL_OP_MASK_DISASM) {
			snprintf (basm, basz, "jcn 0x%x 0x%x", low, buf[1]);
		}
		op->jump = (addr & (~0xFF)) + buf[1];
		op->fail = addr + rlen;
		break;
	case 2:
		if (rlen == 1) {
			if (mask & R_ANAL_OP_MASK_DISASM) {
				snprintf (basm, basz, "src r%d", (low & 0xe) >> 1);
			}
		} else {
			op->type = R_ANAL_OP_TYPE_MOV;
			op->val = buf[1];
			if (mask & R_ANAL_OP_MASK_DISASM) {
				snprintf (basm, basz, "fim r%dr%d, 0x%x", low & 0xe,
					(low & 0xe) + 1, buf[1]);
			}
		}
		break;
	case 3:
		if (low & 1) {
			op->type = R_ANAL_OP_TYPE_RJMP;
			if (mask & R_ANAL_OP_MASK_DISASM) {
				snprintf (basm, basz, "jin r%dr%d", low & 0xe, (low & 0xe) + 1);
			}
		} else {
			op->type = R_ANAL_OP_TYPE_MOV;
			if (mask & R_ANAL_OP_MASK_DISASM) {
				snprintf (basm, basz, "fin r%dr%d", low & 0xe, (low & 0xe) + 1);
			}
		}
		break;
	case 4:
		op->type = R_ANAL_OP_TYPE_JMP;
		op->jump = (ut16) (low<<8) | buf[1];
		if (mask & R_ANAL_OP_MASK_DISASM) {
			snprintf (basm, basz, "jun 0x%x", (ut16)op->jump);
		}
		break;
	case 5:
		op->type = R_ANAL_OP_TYPE_CALL;
		op->jump = (ut16) (low<<8) | buf[1];
		op->fail = addr + rlen;
		if (mask & R_ANAL_OP_MASK_DISASM) {
			snprintf (basm, basz, "jms 0x%x", (ut16)op->jump);
		}
		break;
	case 6:
		op->type = R_ANAL_OP_TYPE_ADD;
		if (mask & R_ANAL_OP_MASK_DISASM) {
			snprintf (basm, basz, "inc r%d", low);
		}
		break;
	case 7:
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->fail = (addr & (~0xFF)) + buf[1];
		op->jump = addr + rlen;
		if (mask & R_ANAL_OP_MASK_DISASM) {
			snprintf (basm, basz, "isz r%d, 0x%x", low, buf[1]);
		}
		break;
	case 8:
		op->type = R_ANAL_OP_TYPE_ADD;
		if (mask & R_ANAL_OP_MASK_DISASM) {
			snprintf (basm, basz, "add r%d", low);
		}
		break;
	case 9:
		op->type = R_ANAL_OP_TYPE_SUB;
		if (mask & R_ANAL_OP_MASK_DISASM) {
			snprintf (basm, basz, "sub r%d", low);
		}
		break;
	case 10:
		op->type = R_ANAL_OP_TYPE_MOV;
		if (mask & R_ANAL_OP_MASK_DISASM) {
			snprintf (basm, basz, "ld r%d", low);
		}
		break;
	case 11:
		op->type = R_ANAL_OP_TYPE_XCHG;
		if (mask & R_ANAL_OP_MASK_DISASM) {
			snprintf (basm, basz, "xch r%d", low);
		}
		break;
	case 12:
		op->type = R_ANAL_OP_TYPE_RET;
		if (mask & R_ANAL_OP_MASK_DISASM) {
			snprintf (basm, basz, "bbl %d", low);
		}
		break;
	case 13:
		op->type = R_ANAL_OP_TYPE_LOAD;
		if (mask & R_ANAL_OP_MASK_DISASM) {
			snprintf (basm, basz, "ldm %d", low);
		}
		break;
	case 14:
		strncpy (basm, i4004_e[low], basz);
		basm[basz - 1] = '\0';
		break;
	case 15:
		strncpy (basm, i4004_f[low], basz);
		basm[basz - 1] = '\0';
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
	if (mask & R_ANAL_OP_MASK_DISASM) {
		op->mnemonic = strdup (basm);
	}
	return op->size = rlen;
}

static int i4004_anal_opasm(RAnal *a, ut64 addr, const char *str, ut8 *outbuf, int outsize) {
	char *s = strdup (str);
	r_str_case (s, false);
	s = r_str_replace (s, "_", "?", false);	// mitigate a bug in sdb -C
	s = r_str_replace (s, ",", " _ ", false);
	int i, nelems;
	char **elems = r_str_argv (s, &nelems);
	RStrBuf *sbuf = r_strbuf_new (elems[0]);
	for (i = 1; i < nelems; i++) {
		if (r_is_valid_input_num_value (NULL, elems[i])) {
			r_strbuf_appendf (sbuf, " 0x%"PFMT64x"", r_num_get (NULL, elems[i]));
		} else {
			r_strbuf_appendf (sbuf, " %s", elems[i]);
		}
	}
	r_str_argv_free (elems);
	free (s);
	s = r_strbuf_drain (sbuf);
	Sdb *asm_db = sdb_new0 ();
	sdb_open_gperf (asm_db, (SdbGperf *)&gperf_i4004_0);
	char *hex_output = sdb_get (asm_db, s, NULL);
	if (!hex_output) {
		sdb_open_gperf (asm_db, (SdbGperf *)&gperf_i4004_1);
		hex_output = sdb_get (asm_db, s, NULL);
	}
	sdb_free (asm_db);
	free (s);
	if (!hex_output) {
		return 0;
	}
	// sanity check here?
	const int ret = r_hex_str2bin (hex_output, outbuf);
	free (hex_output);
	return ret;
}

RAnalPlugin r_anal_plugin_i4004 = {
	.name = "i4004",
	.desc = "i4004 code analysis plugin",
	.license = "LGPL3",
	.arch = "i4004",
	.esil = false,
	.bits = 4,
	.author = "pancake, condret",
	.op = &i4004_op,
	.opasm = &i4004_anal_opasm,
	.set_reg_profile = &set_reg_profile
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_i4004,
	.version = R2_VERSION
};
#endif
