/* radare2 - MIT - Copyright 2023 - keegan */

#define R_LOG_ORIGIN "arch.dis"

#include <r_asm.h>
#include <r_lib.h>

#include "dis.h"
#include "dis.c"

#define MAX_OPERAND_SIZE 0x100

static void operand(char *buffer, enum dis_operand op, st32 imm1, st32 imm2) {
	switch (op) {
	case DIS_OPERAND_IMM:
		snprintf (buffer, MAX_OPERAND_SIZE, "$0x%x", imm1);
		break;
	case DIS_OPERAND_IND_FP:
		snprintf (buffer, MAX_OPERAND_SIZE, "%d(fp)", imm1);
		break;
	case DIS_OPERAND_IND_MP:
		snprintf (buffer, MAX_OPERAND_SIZE, "%d(mp)", imm1);
		break;
	case DIS_OPERAND_DIND_FP:
		snprintf (buffer, MAX_OPERAND_SIZE, "%d(%d(fp))", imm2, imm1);
		break;
	case DIS_OPERAND_DIND_MP:
		snprintf (buffer, MAX_OPERAND_SIZE, "%d(%d(mp))", imm2, imm1);
		break;
	case DIS_OPERAND_NONE:
		break;
	}
}

static char *mnemonic(struct dis_instr *instr) {
	char buffer[MAX_OPERAND_SIZE];
	const char *opcode = dis_opcodes[instr->opcode];
	RStrBuf *sb = r_strbuf_newf ("%s", opcode);

	if (instr->sop) {
		operand (buffer, instr->sop, instr->sop_imm1, instr->sop_imm2);
		r_strbuf_appendf (sb, " %s", buffer);
		if (instr->mop || instr->dop) {
			r_strbuf_append (sb, ",");
		}
	}

	if (instr->mop) {
		// no imm2 for middle operands
		operand (buffer, instr->mop, instr->mop_imm, 0);
		r_strbuf_appendf (sb, " %s", buffer);
		if (instr->dop) {
			r_strbuf_append (sb, ",");
		}
	}

	if (instr->dop) {
		operand (buffer, instr->dop, instr->dop_imm1, instr->dop_imm2);
		r_strbuf_appendf (sb, " %s", buffer);
	}

	return r_strbuf_drain (sb);
}

static bool decode(RArchSession *s, RAnalOp *op, RArchDecodeMask mask) {
	R_RETURN_VAL_IF_FAIL (s && op, false);

	if (op->size < 1) {
		return false;
	}

	// require dis bin plugin for resolving pcs into addresses
	RBinDisObj *o = NULL;
	RBin *bin = s->arch->binb.bin;
	RBinPlugin *plugin = R_UNWRAP4 (bin, cur, bo, plugin);
	if (plugin) {
		if (!strcmp (plugin->meta.name, "dis")) {
			o = bin->cur->bo->bin_obj;
		} else {
			return false;
		}
	}

	op->type = R_ANAL_OP_TYPE_UNK;

	struct dis_instr instr = {0};
	RBuffer *buf = r_buf_new_with_pointers (op->bytes, op->size, false);
	if (!buf) {
		return false;
	}

	if (!dis_read_instr (buf, &instr)) {
		if (mask & R_ARCH_OP_MASK_DISASM) {
			op->mnemonic = strdup ("invalid");
		}
		op->size = 0;
		return true;
	}
	if (mask & R_ARCH_OP_MASK_DISASM) {
		op->mnemonic = mnemonic (&instr);
	}
	op->size = r_buf_tell (buf);
	r_buf_free (buf);

	bool found;
	ut64 addr;
	switch (instr.opcode) {
	case DIS_OP_NOP:
		op->type = R_ANAL_OP_TYPE_NOP;
		break;
	case DIS_OP_GOTO:
	case DIS_OP_MOVPC:
		// TODO
		op->type = R_ANAL_OP_TYPE_UNK;
		break;
	case DIS_OP_JMP:
		op->type = R_ANAL_OP_TYPE_JMP;
		addr = ht_uu_find (o->pcs, instr.dop_imm1, &found);
		if (!found) {
			addr = UT64_MAX;
		}
		op->jump = addr;
		break;
	case DIS_OP_CALL:
		op->type = R_ANAL_OP_TYPE_CALL;
		op->fail = op->addr + op->size;
		addr = ht_uu_find (o->pcs, instr.dop_imm1, &found);
		if (!found) {
			addr = UT64_MAX;
		}
		op->jump = addr;
		break;
	case DIS_OP_RET:
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	case DIS_OP_CASE:
	case DIS_OP_CASEC:
	case DIS_OP_CASEL:
		op->type = R_ANAL_OP_TYPE_SWITCH;
		break;
	case DIS_OP_EXIT:
		op->type = R_ANAL_OP_TYPE_TRAP;
		break;
	case DIS_OP_NEW:
	case DIS_OP_NEWA:
	case DIS_OP_NEWCB:
	case DIS_OP_NEWCW:
	case DIS_OP_NEWCF:
	case DIS_OP_NEWCP:
	case DIS_OP_NEWCM:
	case DIS_OP_NEWCMP:
	case DIS_OP_NEWCL:
	case DIS_OP_NEWZ:
	case DIS_OP_NEWAZ:
	case DIS_OP_MNEWZ:
		op->type = R_ANAL_OP_TYPE_NEW;
		break;
	case DIS_OP_SEND:
		op->type = R_ANAL_OP_TYPE_STORE;
		break;
	case DIS_OP_RECV:
		op->type = R_ANAL_OP_TYPE_LOAD;
		break;
	case DIS_OP_CONSB:
	case DIS_OP_CONSW:
	case DIS_OP_CONSP:
	case DIS_OP_CONSF:
	case DIS_OP_CONSM:
	case DIS_OP_CONSMP:
	case DIS_OP_CONSL:
		op->type = R_ANAL_OP_TYPE_STORE;
		break;
	case DIS_OP_HEADB:
	case DIS_OP_HEADW:
	case DIS_OP_HEADP:
	case DIS_OP_HEADF:
	case DIS_OP_HEADM:
	case DIS_OP_HEADMP:
	case DIS_OP_HEADL:
		op->type = R_ANAL_OP_TYPE_LOAD;
		break;
	case DIS_OP_TAIL:
		op->type = R_ANAL_OP_TYPE_NEW;
		break;
	case DIS_OP_LEA:
	case DIS_OP_INDX:
		op->type = R_ANAL_OP_TYPE_LEA;
		break;
	case DIS_OP_MOVP:
	case DIS_OP_MOVM:
	case DIS_OP_MOVMP:
	case DIS_OP_MOVB:
	case DIS_OP_MOVW:
	case DIS_OP_MOVF:
		op->type = R_ANAL_OP_TYPE_MOV;
		break;
	case DIS_OP_ADDB:
	case DIS_OP_ADDW:
	case DIS_OP_ADDF:
	case DIS_OP_ADDL:
		op->type = R_ANAL_OP_TYPE_ADD;
		break;
	case DIS_OP_SUBB:
	case DIS_OP_SUBW:
	case DIS_OP_SUBF:
	case DIS_OP_SUBL:
		op->type = R_ANAL_OP_TYPE_SUB;
		break;
	case DIS_OP_MULB:
	case DIS_OP_MULW:
	case DIS_OP_MULF:
	case DIS_OP_MULL:
	case DIS_OP_MULX:
	case DIS_OP_MULX0:
	case DIS_OP_MULX1:
		op->type = R_ANAL_OP_TYPE_MUL;
		break;
	case DIS_OP_DIVB:
	case DIS_OP_DIVW:
	case DIS_OP_DIVF:
	case DIS_OP_DIVL:
	case DIS_OP_DIVX:
	case DIS_OP_DIVX0:
	case DIS_OP_DIVX1:
		op->type = R_ANAL_OP_TYPE_DIV;
		break;
	case DIS_OP_MODW:
	case DIS_OP_MODB:
	case DIS_OP_MODL:
		op->type = R_ANAL_OP_TYPE_MOD;
		break;
	case DIS_OP_ANDB:
	case DIS_OP_ANDW:
	case DIS_OP_ANDL:
		op->type = R_ANAL_OP_TYPE_AND;
		break;
	case DIS_OP_ORB:
	case DIS_OP_ORW:
	case DIS_OP_ORL:
		op->type = R_ANAL_OP_TYPE_OR;
		break;
	case DIS_OP_XORB:
	case DIS_OP_XORW:
	case DIS_OP_XORL:
		op->type = R_ANAL_OP_TYPE_XOR;
		break;
	case DIS_OP_SHLB:
	case DIS_OP_SHLW:
	case DIS_OP_SHLL:
	case DIS_OP_LSRW:
	case DIS_OP_LSRL:
		op->type = R_ANAL_OP_TYPE_SHL;
		break;
	case DIS_OP_SHRB:
	case DIS_OP_SHRW:
	case DIS_OP_SHRL:
		op->type = R_ANAL_OP_TYPE_SHR;
		break;
	case DIS_OP_INSC:
		op->type = R_ANAL_OP_TYPE_STORE;
		break;
	case DIS_OP_INDC:
		op->type = R_ANAL_OP_TYPE_LEA;
		break;
	case DIS_OP_ADDC:
		op->type = R_ANAL_OP_TYPE_NEW;
		break;
	case DIS_OP_LENC:
	case DIS_OP_LENA:
	case DIS_OP_LENL:
		op->type = R_ANAL_OP_TYPE_LENGTH;
		break;
	case DIS_OP_BEQB:
	case DIS_OP_BNEB:
	case DIS_OP_BLTB:
	case DIS_OP_BLEB:
	case DIS_OP_BGTB:
	case DIS_OP_BGEB:
	case DIS_OP_BEQW:
	case DIS_OP_BNEW:
	case DIS_OP_BLTW:
	case DIS_OP_BLEW:
	case DIS_OP_BGTW:
	case DIS_OP_BGEW:
	case DIS_OP_BEQF:
	case DIS_OP_BNEF:
	case DIS_OP_BLTF:
	case DIS_OP_BLEF:
	case DIS_OP_BGTF:
	case DIS_OP_BGEF:
	case DIS_OP_BEQC:
	case DIS_OP_BNEC:
	case DIS_OP_BLTC:
	case DIS_OP_BLEC:
	case DIS_OP_BGTC:
	case DIS_OP_BGEC:
	case DIS_OP_BNEL:
	case DIS_OP_BLTL:
	case DIS_OP_BLEL:
	case DIS_OP_BGTL:
	case DIS_OP_BGEL:
	case DIS_OP_BEQL:
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->fail = op->addr + op->size;
		addr = ht_uu_find (o->pcs, instr.dop_imm1, &found);
		if (!found) {
			addr = UT64_MAX;
		}
		op->jump = addr;
		break;
	case DIS_OP_SLICEA:
	case DIS_OP_SLICELA:
	case DIS_OP_SLICEC:
		op->type = R_ANAL_OP_TYPE_NEW;
		break;
	case DIS_OP_INDW:
	case DIS_OP_INDF:
	case DIS_OP_INDB:
	case DIS_OP_INDL:
		op->type = R_ANAL_OP_TYPE_LEA;
		break;
	case DIS_OP_NEGF:
		op->type = R_ANAL_OP_TYPE_CPL;
		break;
	case DIS_OP_MOVL:
		op->type = R_ANAL_OP_TYPE_MOV;
		break;
	case DIS_OP_TCMP:
		op->type = R_ANAL_OP_TYPE_CMP;
		break;
	case DIS_OP_FRAME:
	case DIS_OP_SPAWN:
	case DIS_OP_NBALT:
	case DIS_OP_ALT:
	case DIS_OP_RUNT:
	case DIS_OP_LOAD:
	case DIS_OP_MFRAME:
	case DIS_OP_MSPAWN:
	case DIS_OP_MCALL:
	case DIS_OP_RAISE:
	case DIS_OP_ECLR:
	case DIS_OP_SELF:
	case DIS_OP_EXPW:
	case DIS_OP_EXPL:
	case DIS_OP_EXPF:
	case DIS_OP_CVTBW:
	case DIS_OP_CVTWB:
	case DIS_OP_CVTFW:
	case DIS_OP_CVTWF:
	case DIS_OP_CVTCA:
	case DIS_OP_CVTAC:
	case DIS_OP_CVTWC:
	case DIS_OP_CVTCW:
	case DIS_OP_CVTFC:
	case DIS_OP_CVTCF:
	case DIS_OP_CVTLF:
	case DIS_OP_CVTFL:
	case DIS_OP_CVTLW:
	case DIS_OP_CVTWL:
	case DIS_OP_CVTLC:
	case DIS_OP_CVTCL:
	case DIS_OP_CVTRF:
	case DIS_OP_CVTFR:
	case DIS_OP_CVTWS:
	case DIS_OP_CVTSW:
	case DIS_OP_CVTXX:
	case DIS_OP_CVTXX0:
	case DIS_OP_CVTXX1:
	case DIS_OP_CVTFX:
	case DIS_OP_CVTXF:
	case DIS_OP_INVALID:
		break;
	}

	return true;
}

static char *regs(RArchSession *as) {
	return strdup (
		"=PC    pc\n"
		"=SP    sp\n"
		"=BP    fp\n"
		"=A0    r0\n"
		"=SN    r0\n"
		"gpr    pc      .32     0       0\n"
		"gpr    sp      .32     4       0\n"
		"gpr    fp      .32     8       0\n"
		"gpr    mp      .32     12      0\n"
		"gpr    r0      .32     16      0\n"
	);
}

const RArchPlugin r_arch_plugin_dis = {
	.meta = {
		.name = "dis",
		.author = "keegan",
		.desc = "Inferno Dis VM disassembler",
		.license = "MIT",
	},
	.arch = "dis",
	.bits = R_SYS_BITS_PACK (32),
	.addr_bits = R_SYS_BITS_PACK (32),
	.endian = R_SYS_ENDIAN_BIG,
	.regs = regs,
	.decode = decode,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ARCH,
	.data = &r_arch_plugin_dis,
	.version = R2_VERSION
};
#endif
