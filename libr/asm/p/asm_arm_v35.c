/* radare2 - LGPL - Copyright 2020 - pancake */

#include <r_asm.h>
#include <r_lib.h>

#include "../arch/arm/asm-arm.h"
#include "../arch/arm/v35arm64/disassembler/operations.h"
#include "../arch/arm/v35arm64/disassembler/encodings.h"
#include "../arch/arm/v35arm64/disassembler/arm64dis.h"
bool arm64ass(const char *str, ut64 addr, ut32 *op);

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	Instruction inst = {0};
	char output[256];
	op->size = 4;
	if (len < 4) {
		return -1;
	}
	ut32 n = r_read_le32 (buf);
	FailureCodes fc = aarch64_decompose (n, &inst, a->pc);
	if (fc != DISASM_SUCCESS) {
		return -1;
	}
	output[0] = 0;
	fc = aarch64_disassemble (&inst, output, sizeof (output));
	if (fc == DISASM_SUCCESS) {
		if (*output) {
			// XXX trim tailing newline on UNDEFINED string
			/// output[strlen (output) - 2] = 0;
		}
		r_str_trim_tail (output);
		r_str_replace_char (output, '\t', ' ');
		r_str_replace_char (output, '#', ' ');
		if (r_str_startswith (output, "UNDEF")) {
			r_strbuf_set (&op->buf_asm, "undefined");
			return 4 - (a->pc % 4);
		}
		r_strbuf_set (&op->buf_asm, output);
		return op->size;
	}
	r_strbuf_set (&op->buf_asm, "invalid");
	return 4 - (a->pc % 4);
}

static const char* v35_insn_name(int id) {
	Instruction insn = { .operation = id };
	return get_operation (&insn);
}

static char *mnemonics(RAsm *a, int id, bool json) {
	int i;
	if (id != -1) {
		const char *name = v35_insn_name (id);
		if (json) {
			return name? r_str_newf ("[\"%s\"]\n", name): NULL;
		}
		return name? strdup (name): NULL;
	}
	RStrBuf *buf = r_strbuf_new ("");
	if (json) {
		r_strbuf_append (buf, "[");
	}
	for (i = 1; ; i++) {
		const char *op = v35_insn_name (i);
		if (!op) {
			break;
		}
		if (json) {
			r_strbuf_append (buf, "\"");
		}
		r_strbuf_append (buf, op);
		if (json) {
			if (v35_insn_name (i + 1)) {
				r_strbuf_append (buf, "\",");
			} else {
				r_strbuf_append (buf, "\"]\n");
			}
		} else {
			r_strbuf_append (buf, "\n");
		}
	}
	return r_strbuf_drain (buf);
}

static int assemble(RAsm *a, RAsmOp *op, const char *buf) {
	const bool is_thumb = (a->bits == 16);
	int opsize;
	ut32 opcode;
	if (a->bits == 64) {
		if (!arm64ass (buf, a->pc, &opcode)) {
			return -1;
		}
	} else {
		opcode = armass_assemble (buf, a->pc, is_thumb);
		if (a->bits != 32 && a->bits != 16) {
			eprintf ("Error: ARM assembler only supports 16 or 32 bits\n");
			return -1;
		}
	}
	if (opcode == UT32_MAX) {
		return -1;
	}
	ut8 opbuf[4];
	if (is_thumb) {
		const int o = opcode >> 16;
		opsize = o > 0? 4: 2;
		if (opsize == 4) {
			if (a->big_endian) {
				r_write_le16 (opbuf, opcode >> 16);
				r_write_le16 (opbuf + 2, opcode & UT16_MAX);
			} else {
				r_write_be32 (opbuf, opcode);
			}
		} else if (opsize == 2) {
			if (a->big_endian) {
				r_write_le16 (opbuf, opcode & UT16_MAX);
			} else {
				r_write_be16 (opbuf, opcode & UT16_MAX);
			}
		}
	} else {
		opsize = 4;
		if (a->big_endian) {
			r_write_le32 (opbuf, opcode);
		} else {
			r_write_be32 (opbuf, opcode);
		}
	}
	r_strbuf_setbin (&op->buf, opbuf, opsize);
// XXX. thumb endian assembler needs no swap
	return opsize;
}

RAsmPlugin r_asm_plugin_arm_v35 = {
	.name = "arm.v35",
	.desc = "Vector35 ARM64 disassembler",
	.license = "Apache",
	.arch = "arm",
	.bits = 64,
	.endian = R_SYS_ENDIAN_LITTLE,
	.mnemonics = mnemonics,
	.disassemble = &disassemble,
	.assemble = &assemble,
};


#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_arm_v35,
	.version = R2_VERSION
};
#endif
