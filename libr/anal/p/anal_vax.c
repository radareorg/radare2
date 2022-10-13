/* radare - GPL - Copyright 2015-2022 - pancake, condret */

#include <r_lib.h>
#include <r_anal.h>
#include "../../asm/arch/include/disas-asm.h"
#include "../arch/vax/vax.h"

// XXX: this is just a PoC
// XXX: do not hardcode size/type here, use proper decoding table
// http://hotkosc.ru:8080/method-vax.doc

static int vax_buffer_read_memory(bfd_vma memaddr, bfd_byte *myaddr, ut32 length, struct disassemble_info *info) {
	const size_t bytes_size = 8;
	int delta = (memaddr - info->buffer_vma);
	if (delta < 0) {
		return -1; // disable backward reads
	}
	if (delta >= bytes_size) {
		return -1;
	}
	const int left = bytes_size - delta;
	ut8 *bytes = info->buffer;
	memcpy (myaddr, bytes + delta, R_MIN (length, left));
	return 0;
}

static int symbol_at_address(bfd_vma addr, struct disassemble_info *info) {
	return 0;
}

static void memory_error_func(int status, bfd_vma memaddr, struct disassemble_info *info) {
	//--
}

DECLARE_GENERIC_PRINT_ADDRESS_FUNC_NOGLOBALS()
DECLARE_GENERIC_FPRINTF_FUNC_NOGLOBALS()

static int vax_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf, int len, RAnalOpMask mask) {
	ut8 bytes[8] = {0};
	struct disassemble_info disasm_obj;
	RStrBuf *sb = r_strbuf_new (NULL);
	memcpy (bytes, buf, R_MIN (len, sizeof (bytes)));

	/* prepare disassembler */
	memset (&disasm_obj, '\0', sizeof (struct disassemble_info));
	disasm_obj.buffer = (ut8*)bytes;
	disasm_obj.buffer_vma = addr;
	disasm_obj.read_memory_func = &vax_buffer_read_memory;
	disasm_obj.symbol_at_address_func = &symbol_at_address;
	disasm_obj.memory_error_func = &memory_error_func;
	disasm_obj.print_address_func = &generic_print_address_func;
	disasm_obj.endian = BFD_ENDIAN_LITTLE;
	disasm_obj.fprintf_func = &generic_fprintf_func;
	disasm_obj.stream = sb;
	op->size = print_insn_vax ((bfd_vma)addr, &disasm_obj);

	op->addr = addr;
	op->type = R_ANAL_OP_TYPE_UNK;
	if (mask & R_ANAL_OP_MASK_DISASM) {
		op->mnemonic = r_strbuf_drain (sb);
	} else {
		r_strbuf_free (sb);
	}
	if (op->size == -1) {
		return op->size;
	}
	switch (buf[0]) {
	case 0x04:
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	case 0x2e:
		op->type = R_ANAL_OP_TYPE_MOV;
		break;
	case 0x78:
		op->type = R_ANAL_OP_TYPE_SHL;
		break;
	case 0xc0:
	case 0xc1:
	case 0xd8:
		op->type = R_ANAL_OP_TYPE_ADD;
		break;
	case 0xd7:
		op->type = R_ANAL_OP_TYPE_SUB; // dec
		break;
	case 0x00:
	case 0x01:
		// op->type = R_ANAL_OP_TYPE_TRAP; // HALT
		op->type = R_ANAL_OP_TYPE_NOP;
		break;
	case 0xac:
		op->type = R_ANAL_OP_TYPE_XOR;
		break;
	case 0x11:
	case 0x12:
	case 0x13:
	case 0x14:
	case 0x15:
	case 0x16:
	case 0x17:
	case 0x18:
	case 0x19:
	case 0x1e:
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + op->size + ((len > 1)? ((char)buf[1]): 0);
		op->fail = op->addr + op->size;
		break;
	case 0xd0: // mcoml
		op->type = R_ANAL_OP_TYPE_MOV;
		break;
	case 0xd4: //
		op->type = R_ANAL_OP_TYPE_NOP;
		break;
	case 0xc2: // subl2 r0, r7
		op->type = R_ANAL_OP_TYPE_SUB;
		break;
	case 0xca: // bicl
		op->type = R_ANAL_OP_TYPE_SUB;
		break;
	case 0x31:
	case 0xe9:
		op->type = R_ANAL_OP_TYPE_CJMP;
		if (len > 2) {
			op->jump = op->addr + op->size + ((buf[1] << 8) + buf[2]);
			op->fail = op->addr + op->size;
		}
		break;
	case 0xc6:
	case 0xc7:
		op->type = R_ANAL_OP_TYPE_DIV;
		break;
	case 0x94: // movb
	case 0x7d: // movb
		op->type = R_ANAL_OP_TYPE_MOV;
		break;
	case 0x90:
	case 0x9e:
	case 0xde:
		op->type = R_ANAL_OP_TYPE_MOV;
		break;
	case 0xdd:
	case 0x9f:
	case 0xdf:
		op->type = R_ANAL_OP_TYPE_PUSH;
		break;
	case 0xd1:
	case 0xd5:
	case 0x91:
	case 0x51:
	case 0x73:
		op->type = R_ANAL_OP_TYPE_CMP;
		break;
	case 0x95: // tstb
		op->type = R_ANAL_OP_TYPE_CMP;
		break;
	case 0xd6:
	case 0x61:
		op->type = R_ANAL_OP_TYPE_ADD;
		break;
	case 0x40:
		op->type = R_ANAL_OP_TYPE_ADD;
		break;
	case 0x9a:
		op->type = R_ANAL_OP_TYPE_MOV;
		break;
	case 0x83:
		op->type = R_ANAL_OP_TYPE_SUB;
		break;
	case 0x62:
		op->type = R_ANAL_OP_TYPE_SUB;
		break;
	case 0xfb: // calls
		op->type = R_ANAL_OP_TYPE_CALL;
		if (len > 6 && op->size <= len) {
			const int oa = 3;
			ut32 delta = buf[oa];
			delta |= (ut32)(buf[oa + 1]) << 8;
			delta |= (ut32)(buf[oa + 2]) << 16;
			delta |= (ut32)(buf[oa + 3]) << 24;
			delta += op->size;
			op->jump = op->addr + delta;
		}
		op->fail = op->addr + op->size;
		break;
	case 0xff:
		break;
	}
	if (op->size > len) {
		return -1;
	}
	return op->size;
}

// TODO: add the V vector instructions
static char *get_reg_profile(RAnal *anal) {
	const char *p =
		"=PC	r15\n"
		"=SP	r14\n"
		"=BP	r13\n"
		"=R0	r0\n"
		"=SN	r0\n" // XXX
		// stack
		"=A0	r1\n"
		"=A1	r2\n"
		"=A2	r3\n"
		"=A3	r4\n"

		"gpr	r0	.32	0	0\n"
		"gpr	r1	.32	4	0\n"
		"gpr	r2	.32	8	0\n"
		"gpr	r3	.32	12	0\n"
		"gpr	r4	.32	16	0\n"
		"gpr	r5	.32	24	0\n"
		"gpr	r6	.32	28	0\n"
		"gpr	r7	.32	32	0\n"
		"gpr	r8	.32	36	0\n"
		"gpr	r9	.32	40	0\n"
		"gpr	r10	.32	44	0\n"
		"gpr	r11	.32	48	0\n"
		"gpr	r12	.32	52	0\n"
		"gpr	ap	.32	52	0\n"
		"gpr	r13	.32	56	0\n"
		"gpr	fp	.32	56	0\n"
		"gpr	r14	.32	60	0\n"
		"gpr	sp	.32	60	0\n"
		"gpr	r15	.32	64	0\n"
		"gpr	pc	.32	64	0\n"
		"gpr	ps	.32	68	0\n"
	;
	return strdup (p);
	// return r_reg_set_profile_string (anal->reg, p);
}

static int archinfo(RAnal *anal, int q) {
	if (q == R_ANAL_ARCHINFO_DATA_ALIGN) {
		return 1;
	}
	if (q == R_ANAL_ARCHINFO_ALIGN) {
		return 1;
	}
	if (q == R_ANAL_ARCHINFO_MAX_OP_SIZE) {
		return 56;
	}
	if (q == R_ANAL_ARCHINFO_MIN_OP_SIZE) {
		return 1;
	}
	return 1;
}

RAnalPlugin r_anal_plugin_vax = {
	.name = "vax",
	.desc = "VAX code analysis plugin",
	.license = "GPL",
	.arch = "vax",
	.esil = false,
	.bits = 32,
	.endian = R_SYS_ENDIAN_LITTLE,
	.op = &vax_op,
	.get_reg_profile = &get_reg_profile,
	.archinfo = archinfo,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_vax,
	.version = R2_VERSION
};
#endif
