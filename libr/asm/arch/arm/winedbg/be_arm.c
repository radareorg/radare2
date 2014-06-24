#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "r_types.h"
#include "r_util.h"
#include "be_arm.h"

#define ARM_INSN_SIZE    4
#define THUMB_INSN_SIZE  2
#define THUMB2_INSN_SIZE 4

#define ROR32(n, r) (((n) >> (r)) | ((n) << (32 - (r))))

#define get_cond(ins)           tbl_cond[(ins >> 28) & 0x0f]
#define get_nibble(ins, num)    ((ins >> (num * 4)) & 0x0f)

static char const tbl_regs[][4] = {
	"r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10",
	"fp", "ip", "sp", "lr", "pc", "cpsr"
};

static char const tbl_addrmode[][3] = {
	"da", "ia", "db", "ib"
};

static char const tbl_cond[][3] = {
	"eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc", "hi", "ls", "ge",
	"lt", "gt", "le", "", ""
};

static char const tbl_dataops[][4] = {
	"and", "eor", "sub", "rsb", "add", "adc", "sbc", "rsc", "tst", "teq",
	"cmp", "cmn", "orr", "mov", "bic", "mvn"
};

static char const tbl_shifts[][4] = {
	"lsl", "lsr", "asr", "ror"
};

static char const tbl_hiops_t[][4] = {
	"add", "cmp", "mov", "bx"
};

static char const tbl_aluops_t[][4] = {
	"and", "eor", "lsl", "lsr", "asr", "adc", "sbc", "ror", "tst", "neg",
	"cmp", "cmn", "orr", "mul", "bic", "mvn"
};

static char const tbl_immops_t[][4] = {
	"mov", "cmp", "add", "sub"
};

static char const tbl_sregops_t[][5] = {
	"strh", "ldsb", "ldrh", "ldsh"
};

static ut32 db_get_inst(const ut8* buf, int size) {
	 ut32 result = 0;

	switch (size) {
	case 4:
		result = *(ut32*)buf;
		break;
	case 2:
		result = *(ut16*)buf;
		break;
	}
	return result;
}

static ut32 arm_disasm_branch(struct winedbg_arm_insn *arminsn, ut32 inst) {
	short link = (inst >> 24) & 0x01;
	int offset = (inst << 2) & 0x03ffffff;

	if (offset & 0x02000000) offset |= 0xfc000000;
	offset += 8;
	arminsn->str_asm = r_str_concatf(arminsn->str_asm, "b%s%s 0x%"PFMT64x, link ? "l" : "", get_cond(inst), arminsn->pc+offset);

	arminsn->jmp = arminsn->pc+offset;
	arminsn->fail = arminsn->pc+4;
	return 0;
}

static ut32 arm_disasm_mul(struct winedbg_arm_insn *arminsn, ut32 inst) {
	short accu = (inst >> 21) & 0x01;
	short condcodes = (inst >> 20) & 0x01;

	if (accu)
		arminsn->str_asm = r_str_concatf(arminsn->str_asm, "mla%s%s %s, %s, %s, %s", get_cond(inst), condcodes ? "s" : "",
				tbl_regs[get_nibble(inst, 4)], tbl_regs[get_nibble(inst, 0)],
				tbl_regs[get_nibble(inst, 2)], tbl_regs[get_nibble(inst, 3)]);
	else
		arminsn->str_asm = r_str_concatf(arminsn->str_asm, "mul%s%s %s, %s, %s", get_cond(inst), condcodes ? "s" : "",
				tbl_regs[get_nibble(inst, 4)], tbl_regs[get_nibble(inst, 0)],
				tbl_regs[get_nibble(inst, 2)]);
	return 0;
}

static ut32 arm_disasm_longmul(struct winedbg_arm_insn *arminsn, ut32 inst) {
	short sign = (inst >> 22) & 0x01;
	short accu = (inst >> 21) & 0x01;
	short condcodes = (inst >> 20) & 0x01;

	arminsn->str_asm = r_str_concatf(arminsn->str_asm, "%s%s%s%s %s, %s, %s, %s", sign ? "s" : "u", accu ? "mlal" : "mull",
			get_cond(inst), condcodes ? "s" : "",
			tbl_regs[get_nibble(inst, 3)], tbl_regs[get_nibble(inst, 4)],
			tbl_regs[get_nibble(inst, 0)], tbl_regs[get_nibble(inst, 2)]);
    return 0;
}

static ut32 arm_disasm_swp(struct winedbg_arm_insn *arminsn, ut32 inst) {
	short byte = (inst >> 22) & 0x01;

	arminsn->str_asm = r_str_concatf(arminsn->str_asm, "swp%s%s %s, %s, [%s]", get_cond(inst), byte ? "b" : "",
			tbl_regs[get_nibble(inst, 3)], tbl_regs[get_nibble(inst, 0)],
			tbl_regs[get_nibble(inst, 4)]);
	return 0;
}

static ut32 arm_disasm_branchreg(struct winedbg_arm_insn *arminsn, ut32 inst) {
	arminsn->str_asm = r_str_concatf(arminsn->str_asm, "b%s %s", get_cond(inst), tbl_regs[get_nibble(inst, 0)]);
	return 0;
}

static ut32 arm_disasm_branchxchg(struct winedbg_arm_insn *arminsn, ut32 inst) {
	arminsn->str_asm = r_str_concatf(arminsn->str_asm, "bx%s %s", get_cond(inst), tbl_regs[get_nibble(inst, 0)]);
	return 0;
}

static ut32 arm_disasm_mrstrans(struct winedbg_arm_insn *arminsn, ut32 inst) {
	short src = (inst >> 22) & 0x01;

	arminsn->str_asm = r_str_concatf(arminsn->str_asm, "mrs%s %s, %s", get_cond(inst), tbl_regs[get_nibble(inst, 3)],
			src ? "spsr" : "cpsr");
	return 0;
}

static ut32 arm_disasm_msrtrans(struct winedbg_arm_insn *arminsn, ut32 inst) {
	short immediate = (inst >> 25) & 0x01;
	short dst = (inst >> 22) & 0x01;
	short simple = (inst >> 16) & 0x01;

	if (simple || !immediate) {
		arminsn->str_asm = r_str_concatf(arminsn->str_asm, "msr%s %s, %s", get_cond(inst), dst ? "spsr" : "cpsr",
				tbl_regs[get_nibble(inst, 0)]);
		return 0;
	}
	arminsn->str_asm = r_str_concatf(arminsn->str_asm, "msr%s %s, #%u", get_cond(inst), dst ? "spsr" : "cpsr",
			ROR32(inst & 0xff, 2 * get_nibble(inst, 2)));
	return 0;
}

static ut32 arm_disasm_wordmov(struct winedbg_arm_insn *arminsn, ut32 inst) {
	short top = (inst >> 22) & 0x01;

	arminsn->str_asm = r_str_concatf(arminsn->str_asm, "mov%s%s %s, #%u", top ? "t" : "w", get_cond(inst),
			tbl_regs[get_nibble(inst, 3)],
			(get_nibble(inst, 4) << 12) | (inst & 0x0fff));
	return 0;
}

static ut32 arm_disasm_nop(struct winedbg_arm_insn *arminsn, ut32 inst) {
	arminsn->str_asm = r_str_concatf(arminsn->str_asm, "nop%s", get_cond(inst));
	return 0;
}

static ut32 arm_disasm_dataprocessing(struct winedbg_arm_insn *arminsn, ut32 inst) {
	short condcodes = (inst >> 20) & 0x01;
	short opcode    = (inst >> 21) & 0x0f;
	short immediate = (inst >> 25) & 0x01;
	short no_op1    = (opcode & 0x0d) == 0x0d;
	short no_dst    = (opcode & 0x0c) == 0x08;

	arminsn->str_asm = r_str_concatf(arminsn->str_asm, "%s%s%s", tbl_dataops[opcode], condcodes ? "s" : "", get_cond(inst));
	if (!no_dst) arminsn->str_asm = r_str_concatf(arminsn->str_asm, " %s, ", tbl_regs[get_nibble(inst, 3)]);
	else arminsn->str_asm = r_str_concatf(arminsn->str_asm, " ");
	if (no_op1) {
		if (immediate)
			arminsn->str_asm = r_str_concatf(arminsn->str_asm, "#%u", ROR32(inst & 0xff, 2 * get_nibble(inst, 2)));
		else
			arminsn->str_asm = r_str_concatf(arminsn->str_asm, "%s", tbl_regs[get_nibble(inst, 0)]);
	} else {
		if (immediate)
			arminsn->str_asm = r_str_concatf(arminsn->str_asm, "%s, #%u", tbl_regs[get_nibble(inst, 4)],
					ROR32(inst & 0xff, 2 * get_nibble(inst, 2)));
		else if (((inst >> 4) & 0xff) == 0x00) /* no shift */
			arminsn->str_asm = r_str_concatf(arminsn->str_asm, "%s, %s", tbl_regs[get_nibble(inst, 4)],
					tbl_regs[get_nibble(inst, 0)]);
		else if (((inst >> 4) & 0x09) == 0x01) /* register shift */
			arminsn->str_asm = r_str_concatf(arminsn->str_asm, "%s, %s, %s %s", tbl_regs[get_nibble(inst, 4)],
					tbl_regs[get_nibble(inst, 0)],
					tbl_shifts[(inst >> 5) & 0x03], tbl_regs[(inst >> 8) & 0x0f]);
		else if (((inst >> 4) & 0x01) == 0x00) /* immediate shift */
			arminsn->str_asm = r_str_concatf(arminsn->str_asm, "%s, %s, %s #%d", tbl_regs[get_nibble(inst, 4)],
					tbl_regs[get_nibble(inst, 0)], tbl_shifts[(inst >> 5) & 0x03],
					(inst >> 7) & 0x1f);
		else
			return inst;
	}
	return 0;
}

static ut32 arm_disasm_singletrans(struct winedbg_arm_insn *arminsn, ut32 inst) {
	short load      = (inst >> 20) & 0x01;
	short writeback = (inst >> 21) & 0x01;
	short byte      = (inst >> 22) & 0x01;
	short direction = (inst >> 23) & 0x01;
	short indexing  = (inst >> 24) & 0x01;
	short immediate = !((inst >> 25) & 0x01);
	short offset    = inst & 0x0fff;

	if (!direction) offset *= -1;

	arminsn->str_asm = r_str_concatf(arminsn->str_asm, "%s%s%s%s", load ? "ldr" : "str", byte ? "b" : "", writeback ? "t" : "",
			get_cond(inst));
	arminsn->str_asm = r_str_concatf(arminsn->str_asm, " %s, ", tbl_regs[get_nibble(inst, 3)]);
	if (indexing) {
		if (immediate)
			arminsn->str_asm = r_str_concatf(arminsn->str_asm, "[%s, #%d]", tbl_regs[get_nibble(inst, 4)], offset);
		else if (((inst >> 4) & 0xff) == 0x00) /* no shift */
			arminsn->str_asm = r_str_concatf(arminsn->str_asm, "[%s, %s]", tbl_regs[get_nibble(inst, 4)],
					tbl_regs[get_nibble(inst, 0)]);
		else if (((inst >> 4) & 0x01) == 0x00) /* immediate shift (there's no register shift) */
			arminsn->str_asm = r_str_concatf(arminsn->str_asm, "[%s, %s, %s #%d]", tbl_regs[get_nibble(inst, 4)],
					tbl_regs[get_nibble(inst, 0)], tbl_shifts[(inst >> 5) & 0x03],
					(inst >> 7) & 0x1f);
		else
			return inst;
	} else {
		if (immediate)
			arminsn->str_asm = r_str_concatf(arminsn->str_asm, "[%s], #%d", tbl_regs[get_nibble(inst, 4)], offset);
		else if (((inst >> 4) & 0xff) == 0x00) /* no shift */
			arminsn->str_asm = r_str_concatf(arminsn->str_asm, "[%s], %s", tbl_regs[get_nibble(inst, 4)],
					tbl_regs[get_nibble(inst, 0)]);
		else if (((inst >> 4) & 0x01) == 0x00) /* immediate shift (there's no register shift) */
			arminsn->str_asm = r_str_concatf(arminsn->str_asm, "[%s], %s, %s #%d", tbl_regs[get_nibble(inst, 4)],
					tbl_regs[get_nibble(inst, 0)], tbl_shifts[(inst >> 5) & 0x03],
					(inst >> 7) & 0x1f);
		else
			return inst;
	}
	return 0;
}

static ut32 arm_disasm_halfwordtrans(struct winedbg_arm_insn *arminsn, ut32 inst) {
	short halfword  = (inst >> 5)  & 0x01;
	short sign      = (inst >> 6)  & 0x01;
	short load      = (inst >> 20) & 0x01;
	short writeback = (inst >> 21) & 0x01;
	short immediate = (inst >> 22) & 0x01;
	short direction = (inst >> 23) & 0x01;
	short indexing  = (inst >> 24) & 0x01;
	short offset    = ((inst >> 4) & 0xf0) + (inst & 0x0f);

	if (!direction) offset *= -1;

	arminsn->str_asm = r_str_concatf(arminsn->str_asm, "%s%s%s%s%s", load ? "ldr" : "str", sign ? "s" : "",
			halfword ? "h" : (sign ? "b" : ""), writeback ? "t" : "", get_cond(inst));
	arminsn->str_asm = r_str_concatf(arminsn->str_asm, " %s, ", tbl_regs[get_nibble(inst, 3)]);
	if (indexing) {
		if (immediate)
			arminsn->str_asm = r_str_concatf(arminsn->str_asm, "[%s, #%d]", tbl_regs[get_nibble(inst, 4)], offset);
		else
			arminsn->str_asm = r_str_concatf(arminsn->str_asm, "[%s, %s]", tbl_regs[get_nibble(inst, 4)],
					tbl_regs[get_nibble(inst, 0)]);
	} else {
		if (immediate)
			arminsn->str_asm = r_str_concatf(arminsn->str_asm, "[%s], #%d", tbl_regs[get_nibble(inst, 4)], offset);
		else
			arminsn->str_asm = r_str_concatf(arminsn->str_asm, "[%s], %s", tbl_regs[get_nibble(inst, 4)],
					tbl_regs[get_nibble(inst, 0)]);
	}
	return 0;
}

static ut32 arm_disasm_blocktrans(struct winedbg_arm_insn *arminsn, ut32 inst) {
	short load      = (inst >> 20) & 0x01;
	short writeback = (inst >> 21) & 0x01;
	short psr       = (inst >> 22) & 0x01;
	short addrmode  = (inst >> 23) & 0x03;
	short i;
	short last=15;

	for (i=15;i>=0;i--)
		if ((inst>>i) & 1) {
			last = i;
			break;
		}

	arminsn->str_asm = r_str_concatf(arminsn->str_asm, "%s%s%s %s%s, {", load ? "ldm" : "stm", tbl_addrmode[addrmode],
			get_cond(inst), tbl_regs[get_nibble(inst, 4)], writeback ? "!" : "");
	for (i=0;i<=15;i++)
		if ((inst>>i) & 1) {
			if (i == last) arminsn->str_asm = r_str_concatf(arminsn->str_asm, "%s", tbl_regs[i]);
			else arminsn->str_asm = r_str_concatf(arminsn->str_asm, "%s, ", tbl_regs[i]);
		}
	arminsn->str_asm = r_str_concatf(arminsn->str_asm, "}%s", psr ? "^" : "");
	return 0;
}

static ut32 arm_disasm_swi(struct winedbg_arm_insn *arminsn, ut32 inst) {
	ut32 comment = inst & 0x00ffffff;
	arminsn->str_asm = r_str_concatf(arminsn->str_asm, "swi%s #%d", get_cond(inst), comment);
	return 0;
}

static ut32 arm_disasm_coproctrans(struct winedbg_arm_insn *arminsn, ut32 inst) {
	ut16 CRm    = inst & 0x0f;
	ut16 CP     = (inst >> 5)  & 0x07;
	ut16 CPnum  = (inst >> 8)  & 0x0f;
	ut16 CRn    = (inst >> 16) & 0x0f;
	ut16 load   = (inst >> 20) & 0x01;
	ut16 CP_Opc = (inst >> 21) & 0x07;

	arminsn->str_asm = r_str_concatf(arminsn->str_asm, "%s%s %u, %u, %s, cr%u, cr%u, {%u}", load ? "mrc" : "mcr",
			get_cond(inst), CPnum, CP, tbl_regs[get_nibble(inst, 3)], CRn, CRm, CP_Opc);
	return 0;
}

static ut32 arm_disasm_coprocdataop(struct winedbg_arm_insn *arminsn, ut32 inst) {
	ut16 CRm    = inst & 0x0f;
	ut16 CP     = (inst >> 5)  & 0x07;
	ut16 CPnum  = (inst >> 8)  & 0x0f;
	ut16 CRd    = (inst >> 12) & 0x0f;
	ut16 CRn    = (inst >> 16) & 0x0f;
	ut16 CP_Opc = (inst >> 20) & 0x0f;

	arminsn->str_asm = r_str_concatf(arminsn->str_asm, "cdp%s %u, %u, cr%u, cr%u, cr%u, {%u}", get_cond(inst),
			CPnum, CP, CRd, CRn, CRm, CP_Opc);
	return 0;
}

static ut32 arm_disasm_coprocdatatrans(struct winedbg_arm_insn *arminsn, ut32 inst) {
	ut16 CPnum  = (inst >> 8)  & 0x0f;
	ut16 CRd    = (inst >> 12) & 0x0f;
	ut16 load      = (inst >> 20) & 0x01;
	ut16 writeback = (inst >> 21) & 0x01;
	ut16 translen  = (inst >> 22) & 0x01;
	ut16 direction = (inst >> 23) & 0x01;
	ut16 indexing  = (inst >> 24) & 0x01;
	short offset    = (inst & 0xff) << 2;

	if (!direction) offset *= -1;

	arminsn->str_asm = r_str_concatf(arminsn->str_asm, "%s%s%s", load ? "ldc" : "stc", translen ? "l" : "", get_cond(inst));
	if (indexing)
		arminsn->str_asm = r_str_concatf(arminsn->str_asm, " %u, cr%u, [%s, #%d]%s", CPnum, CRd, tbl_regs[get_nibble(inst, 4)],
				offset, writeback?"!":"");
	else
		arminsn->str_asm = r_str_concatf(arminsn->str_asm, " %u, cr%u, [%s], #%d", CPnum, CRd, tbl_regs[get_nibble(inst, 4)],
				offset);
	return 0;
}

static ut16 thumb_disasm_hireg(struct winedbg_arm_insn *arminsn, ut16 inst) {
	short dst = inst & 0x07;
	short src = (inst >> 3) & 0x07;
	short h2  = (inst >> 6) & 0x01;
	short h1  = (inst >> 7) & 0x01;
	short op  = (inst >> 8) & 0x03;

	if (h1) dst += 8;
	if (h2) src += 8;

	if (op == 2 && dst == src) { /* mov rx, rx */
		arminsn->str_asm = r_str_concatf(arminsn->str_asm, "nop");
		return 0;
	}

	if (op == 3)
		arminsn->str_asm = r_str_concatf(arminsn->str_asm, "b%sx %s", h1?"l":"", tbl_regs[src]);
	else
		arminsn->str_asm = r_str_concatf(arminsn->str_asm, "%s %s, %s", tbl_hiops_t[op], tbl_regs[dst], tbl_regs[src]);

	return 0;
}

static ut16 thumb_disasm_aluop(struct winedbg_arm_insn *arminsn, ut16 inst) {
	short dst = inst & 0x07;
	short src = (inst >> 3) & 0x07;
	short op  = (inst >> 6) & 0x0f;

	arminsn->str_asm = r_str_concatf(arminsn->str_asm, "%s %s, %s", tbl_aluops_t[op], tbl_regs[dst], tbl_regs[src]);
	return 0;
}

static ut16 thumb_disasm_pushpop(struct winedbg_arm_insn *arminsn, ut16 inst) {
	short lrpc = (inst >> 8)  & 0x01;
	short load = (inst >> 11) & 0x01;
	short i;
	short last;

	for (i=7;i>=0;i--)
		if ((inst>>i) & 1) break;
	last = i;

	arminsn->str_asm = r_str_concatf(arminsn->str_asm, "%s {", load ? "pop" : "push");

	for (i=0;i<=7;i++)
		if ((inst>>i) & 1) {
			if (i == last) arminsn->str_asm = r_str_concatf(arminsn->str_asm, "%s", tbl_regs[i]);
			else arminsn->str_asm = r_str_concatf(arminsn->str_asm, "%s, ", tbl_regs[i]);
		}
	if (lrpc)
		arminsn->str_asm = r_str_concatf(arminsn->str_asm, "%s%s", last ? ", " : "", load ? "pc" : "lr");

	arminsn->str_asm = r_str_concatf(arminsn->str_asm, "}");
	return 0;
}

static ut16 thumb_disasm_blocktrans(struct winedbg_arm_insn *arminsn, ut16 inst) {
	short load = (inst >> 11) & 0x01;
	short i;
	short last;

	for (i=7;i>=0;i--)
		if ((inst>>i) & 1) break;
	last = i;

	arminsn->str_asm = r_str_concatf(arminsn->str_asm, "%s %s!, {", load ? "ldmia" : "stmia", tbl_regs[(inst >> 8) & 0x07]);

	for (i=0;i<=7;i++)
		if ((inst>>i) & 1) {
			if (i == last) arminsn->str_asm = r_str_concatf(arminsn->str_asm, "%s", tbl_regs[i]);
			else arminsn->str_asm = r_str_concatf(arminsn->str_asm, "%s, ", tbl_regs[i]);
		}

	arminsn->str_asm = r_str_concatf(arminsn->str_asm, "}");
	return 0;
}

static ut16 thumb_disasm_condbranch(struct winedbg_arm_insn *arminsn, ut16 inst) {
	ut16 offset = inst & 0x00ff;
	arminsn->str_asm = r_str_concatf(arminsn->str_asm, "b%s 0x%"PFMT64x, tbl_cond[(inst >> 8) & 0x0f], arminsn->pc+offset);

	arminsn->jmp = arminsn->pc+offset;
	arminsn->fail = arminsn->pc+4;
	return 0;
}

static ut16 thumb_disasm_uncondbranch(struct winedbg_arm_insn *arminsn, ut16 inst) {
	short offset = (inst & 0x07ff) << 1;

	if (offset & 0x0800) offset |= 0xf000;
	offset += 4;
	arminsn->str_asm = r_str_concatf(arminsn->str_asm, "b 0x%"PFMT64x, arminsn->pc+offset);

	arminsn->jmp = arminsn->pc+offset;
	return 0;
}

static ut16 thumb_disasm_loadadr(struct winedbg_arm_insn *arminsn, ut16 inst) {
	ut16 src = (inst >> 11) & 0x01;
	ut16 offset = (inst & 0xff) << 2;

	arminsn->str_asm = r_str_concatf(arminsn->str_asm, "add %s, %s, #%d", tbl_regs[(inst >> 8) & 0x07], src ? "sp" : "pc",
			offset);
	return 0;
}

static ut16 thumb_disasm_swi(struct winedbg_arm_insn *arminsn, ut16 inst) {
	ut16 comment = inst & 0x00ff;
	arminsn->str_asm = r_str_concatf(arminsn->str_asm, "swi #%d", comment);
	return 0;
}

static ut16 thumb_disasm_nop(struct winedbg_arm_insn *arminsn, ut16 inst) {
	arminsn->str_asm = r_str_concatf(arminsn->str_asm, "nop");
	return 0;
}

static ut16 thumb_disasm_ldrpcrel(struct winedbg_arm_insn *arminsn, ut16 inst) {
	ut16 offset = (inst & 0xff) << 2;
	arminsn->str_asm = r_str_concatf(arminsn->str_asm, "ldr %s, [pc, #%u]", tbl_regs[(inst >> 8) & 0x07], offset);
	return 0;
}

static ut16 thumb_disasm_ldrsprel(struct winedbg_arm_insn *arminsn, ut16 inst) {
	ut16 offset = (inst & 0xff) << 2;
	arminsn->str_asm = r_str_concatf(arminsn->str_asm, "%s %s, [sp, #%u]", (inst & 0x0800)?"ldr":"str",
			tbl_regs[(inst >> 8) & 0x07], offset);
	return 0;
}

static ut16 thumb_disasm_addsprel(struct winedbg_arm_insn *arminsn, ut16 inst) {
	ut16 offset = (inst & 0x7f) << 2;
	if ((inst >> 7) & 0x01)
		arminsn->str_asm = r_str_concatf(arminsn->str_asm, "sub sp, sp, #%u", offset);
	else
		arminsn->str_asm = r_str_concatf(arminsn->str_asm, "add sp, sp, #%u", offset);
	return 0;
}

static ut16 thumb_disasm_ldrimm(struct winedbg_arm_insn *arminsn, ut16 inst) {
	ut16 offset = (inst & 0x07c0) >> 6;
	arminsn->str_asm = r_str_concatf(arminsn->str_asm, "%s%s %s, [%s, #%u]",
			(inst & 0x0800)?"ldr":"str", (inst & 0x1000)?"b":"",
			tbl_regs[inst & 0x07], tbl_regs[(inst >> 3) & 0x07],
			(inst & 0x1000)?offset:(offset << 2));
	return 0;
}

static ut16 thumb_disasm_ldrhimm(struct winedbg_arm_insn *arminsn, ut16 inst) {
	ut16 offset = (inst & 0x07c0) >> 5;
	arminsn->str_asm = r_str_concatf(arminsn->str_asm, "%s %s, [%s, #%u]", (inst & 0x0800)?"ldrh":"strh",
			tbl_regs[inst & 0x07], tbl_regs[(inst >> 3) & 0x07], offset);
	return 0;
}

static ut16 thumb_disasm_ldrreg(struct winedbg_arm_insn *arminsn, ut16 inst) {
	arminsn->str_asm = r_str_concatf(arminsn->str_asm, "%s%s %s, [%s, %s]",
			(inst & 0x0800)?"ldr":"str", (inst & 0x0400)?"b":"",
			tbl_regs[inst & 0x07], tbl_regs[(inst >> 3) & 0x07],
			tbl_regs[(inst >> 6) & 0x07]);
	return 0;
}

static ut16 thumb_disasm_ldrsreg(struct winedbg_arm_insn *arminsn, ut16 inst) {
	arminsn->str_asm = r_str_concatf(arminsn->str_asm, "%s %s, [%s, %s]",
			tbl_sregops_t[(inst >> 10) & 0x03], tbl_regs[inst & 0x07],
			tbl_regs[(inst >> 3) & 0x07], tbl_regs[(inst >> 6) & 0x07]);
	return 0;
}

static ut16 thumb_disasm_immop(struct winedbg_arm_insn *arminsn, ut16 inst) {
	ut16 op = (inst >> 11) & 0x03;
	arminsn->str_asm = r_str_concatf(arminsn->str_asm, "%s %s, #%u", tbl_immops_t[op], tbl_regs[(inst >> 8) & 0x07],
			inst & 0xff);
	return 0;
}

static ut16 thumb_disasm_addsub(struct winedbg_arm_insn *arminsn, ut16 inst) {
	ut16 op = (inst >> 9) & 0x01;
	ut16 immediate = (inst >> 10) & 0x01;

	arminsn->str_asm = r_str_concatf(arminsn->str_asm, "%s %s, %s, ", op ? "sub" : "add",
			tbl_regs[inst & 0x07], tbl_regs[(inst >> 3) & 0x07]);
	if (immediate)
		arminsn->str_asm = r_str_concatf(arminsn->str_asm, "#%d", (inst >> 6) & 0x07);
	else
		arminsn->str_asm = r_str_concatf(arminsn->str_asm, "%s", tbl_regs[(inst >> 6) & 0x07]);
	return 0;
}

static ut16 thumb_disasm_movshift(struct winedbg_arm_insn *arminsn, ut16 inst) {
	ut16 op = (inst >> 11) & 0x03;
	arminsn->str_asm = r_str_concatf(arminsn->str_asm, "%s %s, %s, #%u", tbl_shifts[op],
			tbl_regs[inst & 0x07], tbl_regs[(inst >> 3) & 0x07], (inst >> 6) & 0x1f);
	return 0;
}

static ut32 thumb2_disasm_branchlinked(struct winedbg_arm_insn *arminsn, ut32 inst) {
	ut32 offset = (((inst & 0x07ff0000) >> 4) | ((inst & 0x000007ff) << 1)) + 4;
	arminsn->str_asm = r_str_concatf(arminsn->str_asm, "bl 0x%"PFMT64x, arminsn->pc+offset);

	arminsn->jmp = arminsn->pc+offset;
	return 0;
}

static ut32 thumb2_disasm_misc(struct winedbg_arm_insn *arminsn, ut32 inst) {
	ut16 op1 = (inst >> 20) & 0x03;
	ut16 op2 = (inst >> 4) & 0x03;

	if (get_nibble(inst, 4) != get_nibble(inst, 0))
		return inst;

	if (op1 == 3 && op2 == 0) {
		arminsn->str_asm = r_str_concatf(arminsn->str_asm, "clz %s, %s ", tbl_regs[get_nibble(inst, 2)],
				tbl_regs[get_nibble(inst, 0)]);
		return 0;
	}

	if (op1 == 1) {
		switch (op2) {
		case 0:
			arminsn->str_asm = r_str_concatf(arminsn->str_asm, "rev ");
			break;
		case 1:
			arminsn->str_asm = r_str_concatf(arminsn->str_asm, "rev16 ");
			break;
		case 2:
			arminsn->str_asm = r_str_concatf(arminsn->str_asm, "rbit ");
			break;
		case 3:
			arminsn->str_asm = r_str_concatf(arminsn->str_asm, "revsh ");
			break;
		}
		arminsn->str_asm = r_str_concatf(arminsn->str_asm, "%s, %s ", tbl_regs[get_nibble(inst, 2)], tbl_regs[get_nibble(inst, 0)]);
		return 0;
	}

	return inst;
}

static ut32 thumb2_disasm_mul(struct winedbg_arm_insn *arminsn, ut32 inst) {
	ut16 op1 = (inst >> 20) & 0x07;
	ut16 op2 = (inst >> 4) & 0x03;

	if (op1)
		return inst;

	if (op2 == 0 && get_nibble(inst, 3) != 0xf) {
		arminsn->str_asm = r_str_concatf(arminsn->str_asm, "mla %s, %s, %s, %s ", tbl_regs[get_nibble(inst, 2)],
				tbl_regs[get_nibble(inst, 4)],
				tbl_regs[get_nibble(inst, 0)],
				tbl_regs[get_nibble(inst, 3)]);
		return 0;
	}

	if (op2 == 0 && get_nibble(inst, 3) == 0xf) {
		arminsn->str_asm = r_str_concatf(arminsn->str_asm, "mul %s, %s, %s ", tbl_regs[get_nibble(inst, 2)],
				tbl_regs[get_nibble(inst, 4)],
				tbl_regs[get_nibble(inst, 0)]);
		return 0;
	}

	if (op2 == 1) {
		arminsn->str_asm = r_str_concatf(arminsn->str_asm, "mls %s, %s, %s, %s ", tbl_regs[get_nibble(inst, 2)],
				tbl_regs[get_nibble(inst, 4)],
				tbl_regs[get_nibble(inst, 0)],
				tbl_regs[get_nibble(inst, 3)]);
		return 0;
	}

	return inst;
}

static ut32 thumb2_disasm_longmuldiv(struct winedbg_arm_insn *arminsn, ut32 inst) {
	ut16 op1 = (inst >> 20) & 0x07;
	ut16 op2 = (inst >> 4) & 0x0f;

	if (op2 == 0) {
		switch (op1) {
		case 0:
			arminsn->str_asm = r_str_concatf(arminsn->str_asm, "smull ");
			break;
		case 2:
			arminsn->str_asm = r_str_concatf(arminsn->str_asm, "umull ");
			break;
		case 4:
			arminsn->str_asm = r_str_concatf(arminsn->str_asm, "smlal ");
			break;
		case 6:
			arminsn->str_asm = r_str_concatf(arminsn->str_asm, "umlal ");
			break;
		default:
			return inst;
		}
		arminsn->str_asm = r_str_concatf(arminsn->str_asm, "%s, %s, %s, %s ",
				tbl_regs[get_nibble(inst, 3)], tbl_regs[get_nibble(inst, 2)],
				tbl_regs[get_nibble(inst, 4)], tbl_regs[get_nibble(inst, 0)]);
		return 0;
	}

	if (op2 == 0xffff) {
		switch (op1) {
		case 1:
			arminsn->str_asm = r_str_concatf(arminsn->str_asm, "sdiv ");
			break;
		case 3:
			arminsn->str_asm = r_str_concatf(arminsn->str_asm, "udiv ");
			break;
		default:
			return inst;
		}
		arminsn->str_asm = r_str_concatf(arminsn->str_asm, "%s, %s, %s ", tbl_regs[get_nibble(inst, 2)], tbl_regs[get_nibble(inst, 4)],
				tbl_regs[get_nibble(inst, 0)]);
		return 0;
	}

	return inst;
}

static ut32 thumb2_disasm_coprocmov1(struct winedbg_arm_insn *arminsn, ut32 inst) {
	ut16 opc1 = (inst >> 21) & 0x07;
	ut16 opc2 = (inst >> 5) & 0x07;

	if (opc2)
		arminsn->str_asm = r_str_concatf(arminsn->str_asm,
				"%s%s\tp%u, #%u, %s, cr%u, cr%u, #%u", (inst & 0x00100000)?"mrc":"mcr",
				(inst & 0x10000000)?"2":"", get_nibble(inst, 2), opc1,
				tbl_regs[get_nibble(inst, 3)], get_nibble(inst, 4), get_nibble(inst, 0), opc2);
	else
		arminsn->str_asm = r_str_concatf(arminsn->str_asm,
				"%s%s\tp%u, #%u, %s, cr%u, cr%u", (inst & 0x00100000)?"mrc":"mcr",
				(inst & 0x10000000)?"2":"", get_nibble(inst, 2), opc1,
				tbl_regs[get_nibble(inst, 3)], get_nibble(inst, 4), get_nibble(inst, 0));
	return 0;
}

struct inst_arm {
	ut32 mask;
	ut32 pattern;
	ut32 (*func)(struct winedbg_arm_insn*, ut32);
};

static const struct inst_arm tbl_arm[] = {
	{ 0x0e000000, 0x0a000000, arm_disasm_branch },
	{ 0x0fc000f0, 0x00000090, arm_disasm_mul },
	{ 0x0f8000f0, 0x00800090, arm_disasm_longmul },
	{ 0x0fb00ff0, 0x01000090, arm_disasm_swp },
	{ 0x0e000090, 0x00000090, arm_disasm_halfwordtrans },
	{ 0x0ffffff0, 0x012fff00, arm_disasm_branchreg },
	{ 0x0ffffff0, 0x012fff10, arm_disasm_branchxchg },
	{ 0x0fbf0fff, 0x010f0000, arm_disasm_mrstrans },
	{ 0x0dbef000, 0x0128f000, arm_disasm_msrtrans },
	{ 0x0fb00000, 0x03000000, arm_disasm_wordmov },
	{ 0x0fffffff, 0x0320f000, arm_disasm_nop },
	{ 0x0c000000, 0x00000000, arm_disasm_dataprocessing },
	{ 0x0c000000, 0x04000000, arm_disasm_singletrans },
	{ 0x0e000000, 0x08000000, arm_disasm_blocktrans },
	{ 0x0f000000, 0x0f000000, arm_disasm_swi },
	{ 0x0f000010, 0x0e000010, arm_disasm_coproctrans },
	{ 0x0f000010, 0x0e000000, arm_disasm_coprocdataop },
	{ 0x0e000000, 0x0c000000, arm_disasm_coprocdatatrans },
	{ 0x00000000, 0x00000000, NULL }
};

struct inst_thumb16 {
	ut16 mask;
	ut16 pattern;
	ut16 (*func)(struct winedbg_arm_insn*, ut16);
};

static const struct inst_thumb16 tbl_thumb16[] = {
	{ 0xfc00, 0x4400, thumb_disasm_hireg },
	{ 0xfc00, 0x4000, thumb_disasm_aluop },
	{ 0xf600, 0xb400, thumb_disasm_pushpop },
	{ 0xf000, 0xc000, thumb_disasm_blocktrans },
	{ 0xf000, 0xd000, thumb_disasm_condbranch },
	{ 0xf800, 0xe000, thumb_disasm_uncondbranch },
	{ 0xf000, 0xa000, thumb_disasm_loadadr },
	{ 0xf800, 0x4800, thumb_disasm_ldrpcrel },
	{ 0xf000, 0x9000, thumb_disasm_ldrsprel },
	{ 0xff00, 0xb000, thumb_disasm_addsprel },
	{ 0xe000, 0x6000, thumb_disasm_ldrimm },
	{ 0xf000, 0x8000, thumb_disasm_ldrhimm },
	{ 0xf200, 0x5000, thumb_disasm_ldrreg },
	{ 0xf200, 0x5200, thumb_disasm_ldrsreg },
	{ 0xe000, 0x2000, thumb_disasm_immop },
	{ 0xff00, 0xdf00, thumb_disasm_swi },
	{ 0xff00, 0xbf00, thumb_disasm_nop },
	{ 0xf800, 0x1800, thumb_disasm_addsub },
	{ 0xe000, 0x0000, thumb_disasm_movshift },
	{ 0x0000, 0x0000, NULL }
};

static const struct inst_arm tbl_thumb32[] = {
	{ 0xf800f800, 0xf000f800, thumb2_disasm_branchlinked },
	{ 0xffc0f0c0, 0xfa80f080, thumb2_disasm_misc },
	{ 0xff8000c0, 0xfb000000, thumb2_disasm_mul },
	{ 0xff8000f0, 0xfb800000, thumb2_disasm_longmuldiv },
	{ 0xff8000f0, 0xfb8000f0, thumb2_disasm_longmuldiv },
	{ 0xef100010, 0xee100010, thumb2_disasm_coprocmov1 },
	{ 0xef100010, 0xee000010, thumb2_disasm_coprocmov1 },
	{ 0x00000000, 0x00000000, NULL }
};

void arm_set_pc(struct winedbg_arm_insn *arminsn, ut64 pc) {
	arminsn->pc = pc;
}

void arm_set_input_buffer(struct winedbg_arm_insn *arminsn, const ut8 *buf) {
	arminsn->buf = buf;
}

void arm_set_thumb(struct winedbg_arm_insn *arminsn, int thumb) {
	arminsn->thumb = thumb;
}

char* winedbg_arm_insn_asm(struct winedbg_arm_insn *arminsn) {
	return arminsn->str_asm;
}

char* winedbg_arm_insn_hex(struct winedbg_arm_insn *arminsn) {
	return arminsn->str_hex;
}

void* arm_free(struct winedbg_arm_insn *arminsn) {
	free(arminsn->str_hex);
	free(arminsn->str_asm);
	free(arminsn);
	return NULL;
}

struct winedbg_arm_insn* arm_new() {
	struct winedbg_arm_insn *ret;
	ret = malloc(sizeof(struct winedbg_arm_insn));
	ret->pc = 0;
	ret->thumb = R_FALSE;
	ret->str_hex = NULL;
	ret->str_asm = NULL;
	return ret;
}

int arm_disasm_one_insn(struct winedbg_arm_insn *arminsn) {
	struct inst_arm *a_ptr = (struct inst_arm *)&tbl_arm;
	struct inst_thumb16 *t_ptr = (struct inst_thumb16 *)&tbl_thumb16;
	struct inst_arm *t2_ptr = (struct inst_arm *)&tbl_thumb32;
	ut32 inst;
	ut16 tinst;
	int size;
	int matched = 0;

	arminsn->jmp = arminsn->fail = -1LL;
	if (!arminsn->thumb) {
		size = ARM_INSN_SIZE;
		inst = db_get_inst(arminsn->buf, size);
		while (a_ptr->func) {
			if ((inst & a_ptr->mask) ==  a_ptr->pattern) {
				matched = 1;
				break;
			}
			a_ptr++;
		}

		if (!matched)
			arminsn->str_asm = r_str_concatf(arminsn->str_asm, "Unknown ARM Instruction: %08x", inst);
		else a_ptr->func(arminsn, inst);
		arminsn->str_hex = r_str_concatf(arminsn->str_hex, "%02x%02x%02x%02x",
				*((ut8*)(&inst)), *((ut8*)(&inst)+1),  *((ut8*)(&inst)+2),  *((ut8*)(&inst)+3));
		return size;
	} else {
		tinst = db_get_inst(arminsn->buf, THUMB_INSN_SIZE);
		switch (tinst & 0xf800) {
		case 0xe800:
		case 0xf000:
		case 0xf800:
			size = THUMB2_INSN_SIZE;
			inst = db_get_inst(arminsn->buf+1, THUMB_INSN_SIZE);
			inst |= (tinst << 16);

			while (t2_ptr->func) {
				if ((inst & t2_ptr->mask) ==  t2_ptr->pattern) {
					matched = 1;
					break;
				}
				t2_ptr++;
			}

			if (!matched)
				arminsn->str_asm = r_str_concatf(arminsn->str_asm, "Unknown Thumb2 Instruction: %08x", inst);
			else t2_ptr->func(arminsn, inst);
			arminsn->str_hex = r_str_concatf(arminsn->str_hex, "%02x%02x%02x%02x",
					*((ut8*)(&inst)), *((ut8*)(&inst)+1),  *((ut8*)(&inst)+2),  *((ut8*)(&inst)+3));
			return size;
		default:
			break;
		}

		size = THUMB_INSN_SIZE;
		while (t_ptr->func) {
			if ((tinst & t_ptr->mask) ==  t_ptr->pattern) {
				matched = 1;
				break;
			}
			t_ptr++;
		}

		if (!matched)
			arminsn->str_asm = r_str_concatf(arminsn->str_asm, "Unknown Thumb Instruction: %04x", tinst);
		else t_ptr->func(arminsn, tinst);
		arminsn->str_hex = r_str_concatf(arminsn->str_hex, "%02x%02x", *((ut8*)(&tinst)), *((ut8*)(&tinst)+1));
		return size;
	}
	return size;
}
