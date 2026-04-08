/* radare - MIT - Copyright 2023-2026 - pancake, decaduto */

#include <r_arch.h>
#include <r_lib.h>
#include <sdb/ht_su.h>

#define _GNU_SOURCE
#include <stdio.h>
#include "nds32-opc.h"
#include "nds32-dis.h"

typedef struct plugin_data_t {
	HtSU *insns;
} PluginData;

typedef enum {
	NDS32_ESIL_NONE,
	NDS32_ESIL_EMPTY,
	NDS32_ESIL_SETHI,
	NDS32_ESIL_JRAL5,
	NDS32_ESIL_JRAL,
	NDS32_ESIL_JUMP,
	NDS32_ESIL_RET,
	NDS32_ESIL_IFRET,
	NDS32_ESIL_IFCALL,
	NDS32_ESIL_BEQ,
	NDS32_ESIL_BNE,
	NDS32_ESIL_BEQZ,
	NDS32_ESIL_BNEZ,
	NDS32_ESIL_BNEZS8,
	NDS32_ESIL_STORE_GP1,
	NDS32_ESIL_LOAD_GP1,
	NDS32_ESIL_LOAD_GP4,
	NDS32_ESIL_STORE_GP4,
	NDS32_ESIL_STORE_GP2,
	NDS32_ESIL_STORE_MEM2,
	NDS32_ESIL_ADDI_GP,
	NDS32_ESIL_ADDI_SP,
	NDS32_ESIL_ORI,
	NDS32_ESIL_ADDI,
	NDS32_ESIL_SUBRI,
	NDS32_ESIL_ANDI,
	NDS32_ESIL_ADDI45,
	NDS32_ESIL_XORI,
	NDS32_ESIL_SLLI,
	NDS32_ESIL_SRLI,
	NDS32_ESIL_SRAI,
	NDS32_ESIL_MOV,
	NDS32_ESIL_LWI,
	NDS32_ESIL_SWI,
	NDS32_ESIL_POP25,
	NDS32_ESIL_MADDR32,
	NDS32_ESIL_ADD_SLLI,
	NDS32_ESIL_SUB333,
	NDS32_ESIL_ADD333,
	NDS32_ESIL_ZEH,
	NDS32_ESIL_SRLI45,
	NDS32_ESIL_DIVR,
	NDS32_ESIL_OR33,
	NDS32_ESIL_MUL,
	NDS32_ESIL_SLTS45,
	NDS32_ESIL_SLT45,
	NDS32_ESIL_MUL33,
	NDS32_ESIL_BGTZ,
	NDS32_ESIL_LBI,
	NDS32_ESIL_SBI,
	NDS32_ESIL_PUSH25,
	NDS32_ESIL_FEXTI33,
	NDS32_ESIL_SLTSI45,
	NDS32_ESIL_SLTI45,
	NDS32_ESIL_BEQZS8,
	NDS32_ESIL_BGEZ,
	NDS32_ESIL_BLTZ,
	NDS32_ESIL_BLEZ,
	NDS32_ESIL_BEQZ38,
	NDS32_ESIL_BNEZ38,
	NDS32_ESIL_BEQS38,
	NDS32_ESIL_BNES38,
	NDS32_ESIL_BEQC,
	NDS32_ESIL_BNEC,
	NDS32_ESIL_ADD,
	NDS32_ESIL_SUB,
	NDS32_ESIL_AND,
	NDS32_ESIL_OR,
	NDS32_ESIL_XOR,
	NDS32_ESIL_NOR,
	NDS32_ESIL_SLL,
	NDS32_ESIL_SRL,
	NDS32_ESIL_SRA,
	NDS32_ESIL_SLT,
	NDS32_ESIL_SLTS,
	NDS32_ESIL_SLTI,
	NDS32_ESIL_SLTSI,
	NDS32_ESIL_BITC,
	NDS32_ESIL_CMOVZ,
	NDS32_ESIL_CMOVN,
	NDS32_ESIL_SUB45,
	NDS32_ESIL_SUBI45,
	NDS32_ESIL_SRAI45,
	NDS32_ESIL_SLLI333,
	NDS32_ESIL_NEG33,
	NDS32_ESIL_NOT33,
	NDS32_ESIL_AND33,
	NDS32_ESIL_XOR33,
	NDS32_ESIL_SEB,
	NDS32_ESIL_SEH,
	NDS32_ESIL_ZEB,
	NDS32_ESIL_XLSB,
	NDS32_ESIL_ADDI10S,
	NDS32_ESIL_ROTRI,
} Nds32EsilKind;

typedef struct {
	const char *name;
	Nds32EsilKind esil;
	int type;
	signed char jump_arg;
	bool set_fail;
} Nds32InsnDesc;

typedef struct {
	char *buf;
	char *name;
	char *av[8];
} Nds32Insn;

#define NDS32_OP_NONE (-1)
#define NDS32_DESC(_name, _esil, _type) { _name, NDS32_ESIL_ ## _esil, _type, -1, false }
#define NDS32_JDESC(_name, _esil, _type, _jump_arg, _set_fail) { _name, NDS32_ESIL_ ## _esil, _type, _jump_arg, _set_fail }

static const Nds32InsnDesc nds32_insns[] = {
	NDS32_DESC ("sethi", SETHI, R_ANAL_OP_TYPE_MOV),
	NDS32_DESC ("jral5", JRAL5, R_ANAL_OP_TYPE_RCALL),
	NDS32_JDESC ("jral", JRAL, R_ANAL_OP_TYPE_RCALL, -1, true),
	NDS32_JDESC ("jal", JUMP, R_ANAL_OP_TYPE_CALL, 0, true),
	NDS32_DESC ("jr5", JUMP, R_ANAL_OP_TYPE_RJMP),
	NDS32_DESC ("jr", JUMP, R_ANAL_OP_TYPE_RJMP),
	NDS32_JDESC ("j8", JUMP, R_ANAL_OP_TYPE_JMP, 0, false),
	NDS32_JDESC ("j", JUMP, R_ANAL_OP_TYPE_JMP, 0, false),
	NDS32_DESC ("ret", RET, R_ANAL_OP_TYPE_RET),
	NDS32_DESC ("ret5", RET, R_ANAL_OP_TYPE_RET),
	NDS32_DESC ("iret", NONE, R_ANAL_OP_TYPE_RET),
	NDS32_DESC ("ifret16", IFRET, R_ANAL_OP_TYPE_CRET),
	NDS32_DESC ("ifret", IFRET, R_ANAL_OP_TYPE_CRET),
	NDS32_JDESC ("ifcall", IFCALL, R_ANAL_OP_TYPE_CCALL, 0, true),
	NDS32_JDESC ("bgezal", NONE, R_ANAL_OP_TYPE_CCALL, 1, true),
	NDS32_JDESC ("bltzal", NONE, R_ANAL_OP_TYPE_CCALL, 1, true),
	NDS32_JDESC ("beq", BEQ, R_ANAL_OP_TYPE_CJMP, 2, true),
	NDS32_JDESC ("bne", BNE, R_ANAL_OP_TYPE_CJMP, 2, true),
	NDS32_JDESC ("beqz", BEQZ, R_ANAL_OP_TYPE_CJMP, 1, true),
	NDS32_JDESC ("bnez", BNEZ, R_ANAL_OP_TYPE_CJMP, 1, true),
	NDS32_JDESC ("bnezs8", BNEZS8, R_ANAL_OP_TYPE_CJMP, 0, true),
	NDS32_JDESC ("beqzs8", BEQZS8, R_ANAL_OP_TYPE_CJMP, 0, true),
	NDS32_JDESC ("bgtz", BGTZ, R_ANAL_OP_TYPE_CJMP, 1, true),
	NDS32_JDESC ("bgez", BGEZ, R_ANAL_OP_TYPE_CJMP, 1, true),
	NDS32_JDESC ("bltz", BLTZ, R_ANAL_OP_TYPE_CJMP, 1, true),
	NDS32_JDESC ("blez", BLEZ, R_ANAL_OP_TYPE_CJMP, 1, true),
	NDS32_JDESC ("beqz38", BEQZ38, R_ANAL_OP_TYPE_CJMP, 1, true),
	NDS32_JDESC ("bnez38", BNEZ38, R_ANAL_OP_TYPE_CJMP, 1, true),
	NDS32_JDESC ("beqs38", BEQS38, R_ANAL_OP_TYPE_CJMP, 1, true),
	NDS32_JDESC ("bnes38", BNES38, R_ANAL_OP_TYPE_CJMP, 1, true),
	NDS32_JDESC ("beqc", BEQC, R_ANAL_OP_TYPE_CJMP, 2, true),
	NDS32_JDESC ("bnec", BNEC, R_ANAL_OP_TYPE_CJMP, 2, true),
	NDS32_DESC ("addi", ADDI, R_ANAL_OP_TYPE_ADD),
	NDS32_DESC ("addri", NONE, R_ANAL_OP_TYPE_ADD),
	NDS32_DESC ("addi.gp", ADDI_GP, R_ANAL_OP_TYPE_ADD),
	NDS32_DESC ("addri36.sp", ADDI_SP, R_ANAL_OP_TYPE_ADD),
	NDS32_DESC ("addi10s", ADDI10S, R_ANAL_OP_TYPE_ADD),
	NDS32_DESC ("addi333", ADD333, R_ANAL_OP_TYPE_ADD),
	NDS32_DESC ("addi45", ADDI45, R_ANAL_OP_TYPE_ADD),
	NDS32_DESC ("add333", ADD333, R_ANAL_OP_TYPE_ADD),
	NDS32_DESC ("add45", ADDI45, R_ANAL_OP_TYPE_ADD),
	NDS32_DESC ("add5.pc", NONE, R_ANAL_OP_TYPE_ADD),
	NDS32_DESC ("add_slli", ADD_SLLI, R_ANAL_OP_TYPE_ADD),
	NDS32_DESC ("add_srli", NONE, R_ANAL_OP_TYPE_ADD),
	NDS32_DESC ("add.sc", NONE, R_ANAL_OP_TYPE_ADD),
	NDS32_DESC ("add.wc", NONE, R_ANAL_OP_TYPE_ADD),
	NDS32_DESC ("add", ADD, R_ANAL_OP_TYPE_ADD),
	NDS32_DESC ("subi", NONE, R_ANAL_OP_TYPE_SUB),
	NDS32_DESC ("subri", SUBRI, R_ANAL_OP_TYPE_SUB),
	NDS32_DESC ("sub333", SUB333, R_ANAL_OP_TYPE_SUB),
	NDS32_DESC ("sub45", SUB45, R_ANAL_OP_TYPE_SUB),
	NDS32_DESC ("subi333", SUB333, R_ANAL_OP_TYPE_SUB),
	NDS32_DESC ("subi45", SUBI45, R_ANAL_OP_TYPE_SUB),
	NDS32_DESC ("sub_slli", NONE, R_ANAL_OP_TYPE_SUB),
	NDS32_DESC ("sub_srli", NONE, R_ANAL_OP_TYPE_SUB),
	NDS32_DESC ("sub.sc", NONE, R_ANAL_OP_TYPE_SUB),
	NDS32_DESC ("sub.wc", NONE, R_ANAL_OP_TYPE_SUB),
	NDS32_DESC ("sub", SUB, R_ANAL_OP_TYPE_SUB),
	NDS32_DESC ("mul33", MUL33, R_ANAL_OP_TYPE_MUL),
	NDS32_DESC ("mul", MUL, R_ANAL_OP_TYPE_MUL),
	NDS32_DESC ("maddr32", MADDR32, R_ANAL_OP_TYPE_MUL),
	NDS32_DESC ("msubr32", NONE, R_ANAL_OP_TYPE_MUL),
	NDS32_DESC ("madd", NONE, R_ANAL_OP_TYPE_MUL),
	NDS32_DESC ("msub", NONE, R_ANAL_OP_TYPE_MUL),
	NDS32_DESC ("mult", NONE, R_ANAL_OP_TYPE_MUL),
	NDS32_DESC ("divr", DIVR, R_ANAL_OP_TYPE_DIV),
	NDS32_DESC ("divsr", NONE, R_ANAL_OP_TYPE_DIV),
	NDS32_DESC ("divs", NONE, R_ANAL_OP_TYPE_DIV),
	NDS32_DESC ("div", NONE, R_ANAL_OP_TYPE_DIV),
	NDS32_DESC ("ori", ORI, R_ANAL_OP_TYPE_OR),
	NDS32_DESC ("or33", OR33, R_ANAL_OP_TYPE_OR),
	NDS32_DESC ("or_slli", NONE, R_ANAL_OP_TYPE_OR),
	NDS32_DESC ("or_srli", NONE, R_ANAL_OP_TYPE_OR),
	NDS32_DESC ("or", OR, R_ANAL_OP_TYPE_OR),
	NDS32_DESC ("xori", XORI, R_ANAL_OP_TYPE_XOR),
	NDS32_DESC ("xor33", XOR33, R_ANAL_OP_TYPE_XOR),
	NDS32_DESC ("xor_slli", NONE, R_ANAL_OP_TYPE_XOR),
	NDS32_DESC ("xor_srli", NONE, R_ANAL_OP_TYPE_XOR),
	NDS32_DESC ("xor", XOR, R_ANAL_OP_TYPE_XOR),
	NDS32_DESC ("andi", ANDI, R_ANAL_OP_TYPE_AND),
	NDS32_DESC ("and33", AND33, R_ANAL_OP_TYPE_AND),
	NDS32_DESC ("and_slli", NONE, R_ANAL_OP_TYPE_AND),
	NDS32_DESC ("and_srli", NONE, R_ANAL_OP_TYPE_AND),
	NDS32_DESC ("and", AND, R_ANAL_OP_TYPE_AND),
	NDS32_DESC ("bitci", BITC, R_ANAL_OP_TYPE_AND),
	NDS32_DESC ("nor", NOR, R_ANAL_OP_TYPE_NOR),
	NDS32_DESC ("not33", NOT33, R_ANAL_OP_TYPE_NOT),
	NDS32_DESC ("slli", SLLI, R_ANAL_OP_TYPE_SHL),
	NDS32_DESC ("sll", SLL, R_ANAL_OP_TYPE_SHL),
	NDS32_DESC ("slli333", SLLI333, R_ANAL_OP_TYPE_SHL),
	NDS32_DESC ("srli", SRLI, R_ANAL_OP_TYPE_SHR),
	NDS32_DESC ("srl", SRL, R_ANAL_OP_TYPE_SHR),
	NDS32_DESC ("srai", SRAI, R_ANAL_OP_TYPE_SHR),
	NDS32_DESC ("sra", SRA, R_ANAL_OP_TYPE_SHR),
	NDS32_DESC ("srli45", SRLI45, R_ANAL_OP_TYPE_SHR),
	NDS32_DESC ("srai45", SRAI45, R_ANAL_OP_TYPE_SHR),
	NDS32_DESC ("rotri", ROTRI, R_ANAL_OP_TYPE_ROR),
	NDS32_DESC ("rotr", NONE, R_ANAL_OP_TYPE_ROR),
	NDS32_DESC ("lbi.gp", LOAD_GP1, R_ANAL_OP_TYPE_LOAD),
	NDS32_DESC ("lbsi.gp", NONE, R_ANAL_OP_TYPE_LOAD),
	NDS32_DESC ("lwi.gp", LOAD_GP4, R_ANAL_OP_TYPE_LOAD),
	NDS32_DESC ("lhi.gp", NONE, R_ANAL_OP_TYPE_LOAD),
	NDS32_DESC ("lhsi.gp", NONE, R_ANAL_OP_TYPE_LOAD),
	NDS32_DESC ("sbi.gp", STORE_GP1, R_ANAL_OP_TYPE_STORE),
	NDS32_DESC ("swi.gp", STORE_GP4, R_ANAL_OP_TYPE_STORE),
	NDS32_DESC ("shi.gp", STORE_GP2, R_ANAL_OP_TYPE_STORE),
	NDS32_DESC ("lwi", LWI, R_ANAL_OP_TYPE_LOAD),
	NDS32_DESC ("lbi", LBI, R_ANAL_OP_TYPE_LOAD),
	NDS32_DESC ("lhi", NONE, R_ANAL_OP_TYPE_LOAD),
	NDS32_DESC ("ldi", NONE, R_ANAL_OP_TYPE_LOAD),
	NDS32_DESC ("lbsi", NONE, R_ANAL_OP_TYPE_LOAD),
	NDS32_DESC ("lhsi", NONE, R_ANAL_OP_TYPE_LOAD),
	NDS32_DESC ("lwsi", NONE, R_ANAL_OP_TYPE_LOAD),
	NDS32_DESC ("lwi333", NONE, R_ANAL_OP_TYPE_LOAD),
	NDS32_DESC ("lbi333", NONE, R_ANAL_OP_TYPE_LOAD),
	NDS32_DESC ("lhi333", NONE, R_ANAL_OP_TYPE_LOAD),
	NDS32_DESC ("lwi450", NONE, R_ANAL_OP_TYPE_LOAD),
	NDS32_DESC ("lwi37", NONE, R_ANAL_OP_TYPE_LOAD),
	NDS32_DESC ("lwi45", NONE, R_ANAL_OP_TYPE_LOAD),
	NDS32_DESC ("lw", NONE, R_ANAL_OP_TYPE_LOAD),
	NDS32_DESC ("lb", NONE, R_ANAL_OP_TYPE_LOAD),
	NDS32_DESC ("lh", NONE, R_ANAL_OP_TYPE_LOAD),
	NDS32_DESC ("ld", NONE, R_ANAL_OP_TYPE_LOAD),
	NDS32_DESC ("lbs", NONE, R_ANAL_OP_TYPE_LOAD),
	NDS32_DESC ("lhs", NONE, R_ANAL_OP_TYPE_LOAD),
	NDS32_DESC ("lws", NONE, R_ANAL_OP_TYPE_LOAD),
	NDS32_DESC ("llw", NONE, R_ANAL_OP_TYPE_LOAD),
	NDS32_DESC ("lmw", EMPTY, R_ANAL_OP_TYPE_LOAD),
	NDS32_DESC ("lmw.adm", EMPTY, NDS32_OP_NONE),
	NDS32_DESC ("fls", NONE, R_ANAL_OP_TYPE_LOAD),
	NDS32_DESC ("fld", NONE, R_ANAL_OP_TYPE_LOAD),
	NDS32_DESC ("flsi", NONE, R_ANAL_OP_TYPE_LOAD),
	NDS32_DESC ("fldi", NONE, R_ANAL_OP_TYPE_LOAD),
	NDS32_DESC ("swi", SWI, R_ANAL_OP_TYPE_STORE),
	NDS32_DESC ("sbi", SBI, R_ANAL_OP_TYPE_STORE),
	NDS32_DESC ("shi", STORE_MEM2, R_ANAL_OP_TYPE_STORE),
	NDS32_DESC ("sdi", NONE, R_ANAL_OP_TYPE_STORE),
	NDS32_DESC ("swi333", NONE, R_ANAL_OP_TYPE_STORE),
	NDS32_DESC ("sbi333", NONE, R_ANAL_OP_TYPE_STORE),
	NDS32_DESC ("shi333", NONE, R_ANAL_OP_TYPE_STORE),
	NDS32_DESC ("swi450", NONE, R_ANAL_OP_TYPE_STORE),
	NDS32_DESC ("swi37", NONE, R_ANAL_OP_TYPE_STORE),
	NDS32_DESC ("sw", NONE, R_ANAL_OP_TYPE_STORE),
	NDS32_DESC ("sb", NONE, R_ANAL_OP_TYPE_STORE),
	NDS32_DESC ("sd", NONE, R_ANAL_OP_TYPE_STORE),
	NDS32_DESC ("scw", NONE, R_ANAL_OP_TYPE_STORE),
	NDS32_DESC ("smw", EMPTY, R_ANAL_OP_TYPE_STORE),
	NDS32_DESC ("smw.adm", EMPTY, NDS32_OP_NONE),
	NDS32_DESC ("fss", NONE, R_ANAL_OP_TYPE_STORE),
	NDS32_DESC ("fsd", NONE, R_ANAL_OP_TYPE_STORE),
	NDS32_DESC ("fssi", NONE, R_ANAL_OP_TYPE_STORE),
	NDS32_DESC ("fsdi", NONE, R_ANAL_OP_TYPE_STORE),
	NDS32_DESC ("mov55", MOV, R_ANAL_OP_TYPE_MOV),
	NDS32_DESC ("mov", MOV, R_ANAL_OP_TYPE_MOV),
	NDS32_DESC ("movi55", MOV, R_ANAL_OP_TYPE_MOV),
	NDS32_DESC ("movi", MOV, R_ANAL_OP_TYPE_MOV),
	NDS32_DESC ("movpi45", MOV, R_ANAL_OP_TYPE_MOV),
	NDS32_DESC ("movd44", NONE, R_ANAL_OP_TYPE_MOV),
	NDS32_DESC ("mfsr", NONE, R_ANAL_OP_TYPE_MOV),
	NDS32_DESC ("mtsr", NONE, R_ANAL_OP_TYPE_MOV),
	NDS32_DESC ("mfusr", EMPTY, R_ANAL_OP_TYPE_MOV),
	NDS32_DESC ("mtusr", EMPTY, R_ANAL_OP_TYPE_MOV),
	NDS32_DESC ("cmovz", CMOVZ, R_ANAL_OP_TYPE_CMOV),
	NDS32_DESC ("cmovn", CMOVN, R_ANAL_OP_TYPE_CMOV),
	NDS32_DESC ("slt", SLT, R_ANAL_OP_TYPE_CMP),
	NDS32_DESC ("slts", SLTS, R_ANAL_OP_TYPE_CMP),
	NDS32_DESC ("slt45", SLT45, R_ANAL_OP_TYPE_CMP),
	NDS32_DESC ("slts45", SLTS45, R_ANAL_OP_TYPE_CMP),
	NDS32_DESC ("slti", SLTI, R_ANAL_OP_TYPE_CMP),
	NDS32_DESC ("sltsi", SLTSI, R_ANAL_OP_TYPE_CMP),
	NDS32_DESC ("slti45", SLTI45, NDS32_OP_NONE),
	NDS32_DESC ("sltsi45", SLTSI45, NDS32_OP_NONE),
	NDS32_DESC ("zeh", ZEH, R_ANAL_OP_TYPE_MOV),
	NDS32_DESC ("zeh33", ZEH, R_ANAL_OP_TYPE_MOV),
	NDS32_DESC ("zeb", ZEB, R_ANAL_OP_TYPE_MOV),
	NDS32_DESC ("zeb33", ZEB, R_ANAL_OP_TYPE_MOV),
	NDS32_DESC ("seh", SEH, R_ANAL_OP_TYPE_MOV),
	NDS32_DESC ("seh33", SEH, R_ANAL_OP_TYPE_MOV),
	NDS32_DESC ("seb", SEB, R_ANAL_OP_TYPE_MOV),
	NDS32_DESC ("seb33", SEB, R_ANAL_OP_TYPE_MOV),
	NDS32_DESC ("xlsb", XLSB, R_ANAL_OP_TYPE_MOV),
	NDS32_DESC ("xlsb33", XLSB, R_ANAL_OP_TYPE_MOV),
	NDS32_DESC ("push25", PUSH25, R_ANAL_OP_TYPE_PUSH),
	NDS32_DESC ("pop25", POP25, R_ANAL_OP_TYPE_POP),
	NDS32_DESC ("syscall", NONE, R_ANAL_OP_TYPE_SWI),
	NDS32_DESC ("break", NONE, R_ANAL_OP_TYPE_TRAP),
	NDS32_DESC ("trap", NONE, R_ANAL_OP_TYPE_TRAP),
	NDS32_DESC ("teqz", NONE, R_ANAL_OP_TYPE_TRAP),
	NDS32_DESC ("tnez", NONE, R_ANAL_OP_TYPE_TRAP),
	NDS32_DESC ("nop", EMPTY, R_ANAL_OP_TYPE_NOP),
	NDS32_DESC ("neg33", NEG33, R_ANAL_OP_TYPE_SUB),
	NDS32_DESC ("abs", NONE, R_ANAL_OP_TYPE_ABS),
	NDS32_DESC ("dsb", EMPTY, R_ANAL_OP_TYPE_NOP),
	NDS32_DESC ("isb", EMPTY, R_ANAL_OP_TYPE_NOP),
	NDS32_DESC ("msync", EMPTY, R_ANAL_OP_TYPE_NOP),
	NDS32_DESC ("isync", EMPTY, R_ANAL_OP_TYPE_NOP),
	NDS32_DESC ("standby", EMPTY, R_ANAL_OP_TYPE_NOP),
	NDS32_DESC ("cctl", NONE, R_ANAL_OP_TYPE_NOP),
	NDS32_DESC ("fexti33", FEXTI33, NDS32_OP_NONE),
	NDS32_DESC ("ex9.it", EMPTY, NDS32_OP_NONE),
	NDS32_DESC ("bitc", BITC, NDS32_OP_NONE),
};

static void nds32_init_args(char **av, int avsz) {
	int i;
	for (i = 0; i < avsz; i++) {
		av[i] = "";
	}
}

static void nds32_parse_insn(Nds32Insn *insn, const char *mnemonic) {
	R_RETURN_IF_FAIL (insn);
	memset (insn, 0, sizeof (*insn));
	nds32_init_args (insn->av, R_ARRAY_SIZE (insn->av));
	insn->buf = strdup (mnemonic? mnemonic: "");
	if (!insn->buf) {
		insn->name = "";
		return;
	}
	insn->name = insn->buf;
	char *args = strchr (insn->buf, ' ');
	if (!args) {
		return;
	}
	*args++ = 0;
	for (; *args == ' '; args++) {
	}
	int i = 0;
	while (*args && i < R_ARRAY_SIZE (insn->av)) {
		char *next = strchr (args, ',');
		if (next) {
			*next++ = 0;
		}
		r_str_trim (args);
		insn->av[i++] = args;
		if (!next) {
			break;
		}
		args = next;
		for (; *args == ' '; args++) {
		}
	}
}

static void nds32_fini_insn(Nds32Insn *insn) {
	free (insn->buf);
}

static const Nds32InsnDesc *nds32_lookup_insn(RArchSession *as, const char *name) {
	PluginData *pd = as? as->data: NULL;
	bool found = false;
	if (!pd || !pd->insns || R_STR_ISEMPTY (name)) {
		return NULL;
	}
	ut64 value = ht_su_find (pd->insns, name, &found);
	return found? (const Nds32InsnDesc *)(size_t)value: NULL;
}

static bool nds32_build_insn_db(HtSU *db) {
	int i;
	for (i = 0; i < R_ARRAY_SIZE (nds32_insns); i++) {
		if (!ht_su_insert (db, nds32_insns[i].name, (ut64)(size_t)&nds32_insns[i])) {
			return false;
		}
	}
	return true;
}

static char *parse_gp_off(char *off) {
	r_str_trim (off);
	if (*off == '[') {
		off++;
	}
	if (*off == '+') {
		off++;
	}
	char *end = strchr (off, ']');
	if (end) {
		*end = 0;
	}
	r_str_trim (off);
	return off;
}

static char *parse_mem_addr(char *addr) {
	r_str_trim (addr);
	if (*addr == '[') {
		addr++;
	}
	char *end = strchr (addr, ']');
	if (end) {
		*end = 0;
	}
	r_str_trim (addr);
	return addr;
}

static bool split_mem_addr(char *addr, char **reg, char **off) {
	char *base = parse_mem_addr (addr);
	if (!*base) {
		return false;
	}
	char *plus = strstr (base, " + ");
	if (!plus) {
		*reg = base;
		*off = NULL;
		return true;
	}
	*plus = 0;
	*reg = base;
	*off = plus + 3;
	r_str_trim (*reg);
	r_str_trim (*off);
	return true;
}

static void set_esil_empty(RAnalOp *op) {
	r_strbuf_set (&op->esil, "");
}

static void set_esil_assign(RAnalOp *op, const char *src, const char *dst) {
	r_strbuf_setf (&op->esil, "%s,%s,:=", src, dst);
}

static void set_esil_binop(RAnalOp *op, const char *lhs, const char *rhs, const char *esilop, const char *dst) {
	r_strbuf_setf (&op->esil, "%s,%s,%s,%s,:=", lhs, rhs, esilop, dst);
}

static void set_esil_gp_store(RAnalOp *op, const char *src, char *offarg, int size) {
	char *off = parse_gp_off (offarg);
	if (*off) {
		r_strbuf_setf (&op->esil, "%s,gp,%s,+,=[%d]", src, off, size);
	}
}

static void set_esil_gp_load(RAnalOp *op, char *offarg, const char *dst, int size) {
	char *off = parse_gp_off (offarg);
	if (*off) {
		r_strbuf_setf (&op->esil, "gp,%s,+,[%d],%s,:=", off, size, dst);
	}
}

static void set_esil_mem_store(RAnalOp *op, const char *src, char *addrarg, int size) {
	char *reg, *off;
	if (!split_mem_addr (addrarg, &reg, &off)) {
		return;
	}
	if (off && *off) {
		r_strbuf_setf (&op->esil, "%s,%s,%s,+,=[%d]", src, reg, off, size);
	} else {
		r_strbuf_setf (&op->esil, "%s,%s,=[%d]", src, reg, size);
	}
}

static void set_esil_mem_load(RAnalOp *op, char *addrarg, const char *dst, int size) {
	char *reg, *off;
	if (!split_mem_addr (addrarg, &reg, &off)) {
		return;
	}
	if (off && *off) {
		r_strbuf_setf (&op->esil, "%s,%s,+,[%d],%s,:=", reg, off, size, dst);
	} else {
		r_strbuf_setf (&op->esil, "%s,[%d],%s,:=", reg, size, dst);
	}
}

static int info(RArchSession *as, ut32 q) {
	switch (q) {
	case R_ARCH_INFO_MAXOP_SIZE:
		return 6;
	case R_ARCH_INFO_MINOP_SIZE:
		return 2;
	case R_ARCH_INFO_FUNC_ALIGN:
		return 4;
	case R_ARCH_INFO_CODE_ALIGN:
		return 2;
	case R_ARCH_INFO_INVOP_SIZE:
		return 2;
	}
	return 0;
}

static int nds32_buffer_read_memory(bfd_vma memaddr, bfd_byte *myaddr, ut32 length, struct disassemble_info *info) {
	int delta = (memaddr - info->buffer_vma);
	if (delta < 0) {
		return -1; // disable backward reads
	}
	if ((delta + length) > 4) {
		return -1;
	}
	ut8 *bytes = info->buffer;
	memcpy (myaddr, bytes + delta, length);
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

static bool _init(RArchSession *as) {
	R_RETURN_VAL_IF_FAIL (as, false);
	if (as->data) {
		R_LOG_WARN ("Already initialized");
		return false;
	}

	PluginData *pd = R_NEW0 (PluginData);
	if (!pd) {
		return false;
	}
	pd->insns = ht_su_new0 ();
	if (!pd->insns || !nds32_build_insn_db (pd->insns)) {
		ht_su_free (pd->insns);
		free (pd);
		return false;
	}
	as->data = pd;
	return true;
}

static bool fini(RArchSession *as) {
	R_RETURN_VAL_IF_FAIL (as, false);
	PluginData *pd = as->data;
	if (pd) {
		ht_su_free (pd->insns);
	}
	R_FREE (as->data);
	return true;
}

static void decode_esil(RAnalOp *op, const Nds32InsnDesc *desc, char **av) {
	if (!desc) {
		return;
	}
	switch (desc->esil) {
	case NDS32_ESIL_NONE:
		break;
	case NDS32_ESIL_EMPTY:
		set_esil_empty (op);
		break;
	case NDS32_ESIL_SETHI:
		r_strbuf_setf (&op->esil, "12,%s,<<,%s,:=", av[1], av[0]);
		break;
	case NDS32_ESIL_JRAL5:
		r_strbuf_setf (&op->esil, "pc,2,+,lp,:=,%s,pc,:=", av[0]);
		break;
	case NDS32_ESIL_JRAL:
		r_strbuf_setf (&op->esil, "pc,4,+,%s,:=,%s,pc,:=", av[0], av[1]);
		break;
	case NDS32_ESIL_JUMP:
		r_strbuf_setf (&op->esil, "%s,pc,:=", av[0]);
		break;
	case NDS32_ESIL_RET:
		r_strbuf_set (&op->esil, "lp,pc,:=");
		break;
	case NDS32_ESIL_IFRET:
		r_strbuf_set (&op->esil, "ifc_on,?{,ifc_lp,pc,:=,0,ifc_on,:=,}");
		break;
	case NDS32_ESIL_IFCALL:
		r_strbuf_setf (&op->esil, "pc,%d,+,ifc_lp,:=,1,ifc_on,:=,%s,pc,:=", op->size, av[0]);
		break;
	case NDS32_ESIL_BEQ:
		r_strbuf_setf (&op->esil, "%s,%s,==,$z,?{,%s,pc,:=,}", av[0], av[1], av[2]);
		break;
	case NDS32_ESIL_BNE:
		r_strbuf_setf (&op->esil, "%s,%s,==,$z,!,?{,%s,pc,:=,}", av[0], av[1], av[2]);
		break;
	case NDS32_ESIL_BEQZ:
		r_strbuf_setf (&op->esil, "%s,0,==,$z,?{,%s,pc,:=,}", av[0], av[1]);
		break;
	case NDS32_ESIL_BNEZ:
		r_strbuf_setf (&op->esil, "%s,0,==,$z,!,?{,%s,pc,:=,}", av[0], av[1]);
		break;
	case NDS32_ESIL_BNEZS8:
		r_strbuf_setf (&op->esil, "r5,0,==,$z,!,?{,%s,pc,:=,}", av[0]);
		break;
	case NDS32_ESIL_STORE_GP1:
		set_esil_gp_store (op, av[0], av[1], 1);
		break;
	case NDS32_ESIL_LOAD_GP1:
		set_esil_gp_load (op, av[1], av[0], 1);
		break;
	case NDS32_ESIL_LOAD_GP4:
		set_esil_gp_load (op, av[1], av[0], 4);
		break;
	case NDS32_ESIL_STORE_GP4:
		set_esil_gp_store (op, av[0], av[1], 4);
		break;
	case NDS32_ESIL_STORE_GP2:
		set_esil_gp_store (op, av[0], av[1], 2);
		break;
	case NDS32_ESIL_STORE_MEM2:
		set_esil_mem_store (op, av[0], av[1], 2);
		break;
	case NDS32_ESIL_ADDI_GP:
		r_strbuf_setf (&op->esil, "gp,%s,+,%s,:=", av[1], av[0]);
		break;
	case NDS32_ESIL_ADDI_SP:
		r_strbuf_setf (&op->esil, "sp,%s,+,%s,:=", av[1], av[0]);
		break;
	case NDS32_ESIL_ORI:
		set_esil_binop (op, av[2], av[1], "|", av[0]);
		break;
	case NDS32_ESIL_ADDI:
	case NDS32_ESIL_ADD333:
	case NDS32_ESIL_ADD:
		set_esil_binop (op, av[2], av[1], "+", av[0]);
		break;
	case NDS32_ESIL_SLLI333:
		set_esil_binop (op, av[2], av[1], "<<", av[0]);
		break;
	case NDS32_ESIL_SUBRI:
		set_esil_binop (op, av[1], av[2], "-", av[0]);
		break;
	case NDS32_ESIL_ANDI:
		set_esil_binop (op, av[2], av[1], "&", av[0]);
		break;
	case NDS32_ESIL_ADDI45:
		set_esil_binop (op, av[1], av[0], "+", av[0]);
		break;
	case NDS32_ESIL_XORI:
		set_esil_binop (op, av[2], av[1], "^", av[0]);
		break;
	case NDS32_ESIL_SLLI:
	case NDS32_ESIL_SLL:
		set_esil_binop (op, av[2], av[1], "<<", av[0]);
		break;
	case NDS32_ESIL_SRLI:
	case NDS32_ESIL_SRL:
		set_esil_binop (op, av[2], av[1], ">>", av[0]);
		break;
	case NDS32_ESIL_SRAI:
	case NDS32_ESIL_SRA:
		set_esil_binop (op, av[2], av[1], "ASR", av[0]);
		break;
	case NDS32_ESIL_MOV:
		set_esil_assign (op, av[1], av[0]);
		break;
	case NDS32_ESIL_LWI:
		r_strbuf_setf (&op->esil, "%s,[4],%s,:=", av[1], av[0]);
		break;
	case NDS32_ESIL_SWI:
		r_strbuf_setf (&op->esil, "%s,%s,=[4]", av[0], av[1]);
		break;
	case NDS32_ESIL_POP25:
		r_strbuf_setf (&op->esil, "sp,[4],%s,:=,sp,4,+,sp,:=", av[0]);
		break;
	case NDS32_ESIL_MADDR32:
		r_strbuf_setf (&op->esil, "%s,%s,*,%s,+,%s,:=", av[2], av[1], av[0], av[0]);
		break;
	case NDS32_ESIL_ADD_SLLI:
		r_strbuf_setf (&op->esil, "%s,%s,<<,%s,+,%s,:=", av[3], av[2], av[1], av[0]);
		break;
	case NDS32_ESIL_SUB333:
	case NDS32_ESIL_SUB:
		set_esil_binop (op, av[2], av[1], "-", av[0]);
		break;
	case NDS32_ESIL_ZEH:
		r_strbuf_setf (&op->esil, "0xffff,%s,&,%s,:=", av[1], av[0]);
		break;
	case NDS32_ESIL_SRLI45:
		set_esil_binop (op, av[1], av[0], ">>", av[0]);
		break;
	case NDS32_ESIL_DIVR:
		set_esil_binop (op, av[2], av[1], "/", av[0]);
		break;
	case NDS32_ESIL_OR33:
		set_esil_binop (op, av[1], av[0], "|", av[0]);
		break;
	case NDS32_ESIL_MUL:
		set_esil_binop (op, av[2], av[1], "*", av[0]);
		break;
	case NDS32_ESIL_SLTS45:
	case NDS32_ESIL_SLTI45:
		r_strbuf_setf (&op->esil, "%s,%s,<,ta,:=", av[1], av[0]);
		break;
	case NDS32_ESIL_SLT45:
	case NDS32_ESIL_SLTSI45:
		r_strbuf_setf (&op->esil, "%s,%s,<,ta,:=", av[1], av[0]);
		break;
	case NDS32_ESIL_MUL33:
		set_esil_binop (op, av[1], av[0], "*", av[0]);
		break;
	case NDS32_ESIL_BGTZ:
		r_strbuf_setf (&op->esil, "%s,0,>,?{,%s,pc,:=,}", av[0], av[1]);
		break;
	case NDS32_ESIL_LBI:
		set_esil_mem_load (op, av[1], av[0], 1);
		break;
	case NDS32_ESIL_SBI:
		r_strbuf_setf (&op->esil, "%s,%s,=[1]", av[0], av[1]);
		break;
	case NDS32_ESIL_PUSH25:
		r_strbuf_setf (&op->esil, "sp,4,-,sp,:=,%s,sp,=[4]", av[0]);
		break;
	case NDS32_ESIL_FEXTI33:
		r_strbuf_setf (&op->esil, "1,%s,<<,1,-,%s,&,%s,:=", av[1], av[0], av[0]);
		break;
	case NDS32_ESIL_BEQZS8:
		r_strbuf_setf (&op->esil, "r5,!,?{,%s,pc,:=,}", av[0]);
		break;
	case NDS32_ESIL_BGEZ:
		r_strbuf_setf (&op->esil, "31,%s,>>,!,?{,%s,pc,:=,}", av[0], av[1]);
		break;
	case NDS32_ESIL_BLTZ:
		r_strbuf_setf (&op->esil, "31,%s,>>,?{,%s,pc,:=,}", av[0], av[1]);
		break;
	case NDS32_ESIL_BLEZ:
		r_strbuf_setf (&op->esil, "%s,!,31,%s,>>,|,?{,%s,pc,:=,}", av[0], av[0], av[1]);
		break;
	case NDS32_ESIL_BEQZ38:
		r_strbuf_setf (&op->esil, "%s,!,?{,%s,pc,:=,}", av[0], av[1]);
		break;
	case NDS32_ESIL_BNEZ38:
		r_strbuf_setf (&op->esil, "%s,?{,%s,pc,:=,}", av[0], av[1]);
		break;
	case NDS32_ESIL_BEQS38:
		r_strbuf_setf (&op->esil, "%s,r5,==,$z,?{,%s,pc,:=,}", av[0], av[1]);
		break;
	case NDS32_ESIL_BNES38:
		r_strbuf_setf (&op->esil, "%s,r5,==,$z,!,?{,%s,pc,:=,}", av[0], av[1]);
		break;
	case NDS32_ESIL_BEQC:
		r_strbuf_setf (&op->esil, "%s,%s,==,$z,?{,%s,pc,:=,}", av[1], av[0], av[2]);
		break;
	case NDS32_ESIL_BNEC:
		r_strbuf_setf (&op->esil, "%s,%s,==,$z,!,?{,%s,pc,:=,}", av[1], av[0], av[2]);
		break;
	case NDS32_ESIL_AND:
		set_esil_binop (op, av[2], av[1], "&", av[0]);
		break;
	case NDS32_ESIL_OR:
		set_esil_binop (op, av[2], av[1], "|", av[0]);
		break;
	case NDS32_ESIL_XOR:
		set_esil_binop (op, av[2], av[1], "^", av[0]);
		break;
	case NDS32_ESIL_NOR:
		r_strbuf_setf (&op->esil, "%s,%s,|,~,%s,:=", av[2], av[1], av[0]);
		break;
	case NDS32_ESIL_SLT:
	case NDS32_ESIL_SLTS:
	case NDS32_ESIL_SLTI:
	case NDS32_ESIL_SLTSI:
		r_strbuf_setf (&op->esil, "%s,%s,<,%s,:=", av[2], av[1], av[0]);
		break;
	case NDS32_ESIL_BITC:
		r_strbuf_setf (&op->esil, "%s,~,%s,&,%s,:=", av[2], av[1], av[0]);
		break;
	case NDS32_ESIL_CMOVZ:
		r_strbuf_setf (&op->esil, "%s,!,?{,%s,%s,:=,}", av[2], av[1], av[0]);
		break;
	case NDS32_ESIL_CMOVN:
		r_strbuf_setf (&op->esil, "%s,?{,%s,%s,:=,}", av[2], av[1], av[0]);
		break;
	case NDS32_ESIL_SUB45:
	case NDS32_ESIL_SUBI45:
		set_esil_binop (op, av[1], av[0], "-", av[0]);
		break;
	case NDS32_ESIL_SRAI45:
		set_esil_binop (op, av[1], av[0], "ASR", av[0]);
		break;
	case NDS32_ESIL_NEG33:
		r_strbuf_setf (&op->esil, "0,%s,-,%s,:=", av[1], av[0]);
		break;
	case NDS32_ESIL_NOT33:
		r_strbuf_setf (&op->esil, "%s,~,%s,:=", av[1], av[0]);
		break;
	case NDS32_ESIL_AND33:
		set_esil_binop (op, av[1], av[0], "&", av[0]);
		break;
	case NDS32_ESIL_XOR33:
		set_esil_binop (op, av[1], av[0], "^", av[0]);
		break;
	case NDS32_ESIL_SEB:
		r_strbuf_setf (&op->esil, "24,%s,<<,24,ASR,%s,:=", av[1], av[0]);
		break;
	case NDS32_ESIL_SEH:
		r_strbuf_setf (&op->esil, "16,%s,<<,16,ASR,%s,:=", av[1], av[0]);
		break;
	case NDS32_ESIL_ZEB:
		r_strbuf_setf (&op->esil, "0xff,%s,&,%s,:=", av[1], av[0]);
		break;
	case NDS32_ESIL_XLSB:
		r_strbuf_setf (&op->esil, "1,%s,&,%s,:=", av[1], av[0]);
		break;
	case NDS32_ESIL_ADDI10S:
		r_strbuf_setf (&op->esil, "%s,sp,+,sp,:=", av[0]);
		break;
	case NDS32_ESIL_ROTRI:
		r_strbuf_setf (&op->esil, "%s,%s,>>>,%s,:=", av[2], av[1], av[0]);
		break;
	}
}

static bool decode(RArchSession *as, RAnalOp *op, RArchDecodeMask mask) {
	const ut64 addr = op->addr;
	const int len = op->size;
	const ut8 *buf = op->bytes;
	ut8 bytes[8] = { 0 };
	struct disassemble_info disasm_obj = { 0 };
	RStrBuf *sb = r_strbuf_new (NULL);
	memcpy (bytes, buf, R_MIN (sizeof (bytes), len)); // TODO handle thumb
	/* prepare disassembler */
	disasm_obj.buffer = bytes;
	disasm_obj.buffer_vma = addr;
	disasm_obj.read_memory_func = &nds32_buffer_read_memory;
	disasm_obj.symbol_at_address_func = &symbol_at_address;
	disasm_obj.memory_error_func = &memory_error_func;
	disasm_obj.print_address_func = &generic_print_address_func;
	disasm_obj.endian = !R_ARCH_CONFIG_IS_BIG_ENDIAN (as->config);
	disasm_obj.fprintf_func = &generic_fprintf_func;
	disasm_obj.stream = sb;
	disasm_obj.mach = 0; // TODO: detect_cpu (as->config->cpu);
	op->size = print_insn_nds32 ((bfd_vma)addr, &disasm_obj);

	if (true) { // mask & R_ARCH_OP_MASK_DISASM) {
		op->mnemonic = r_strbuf_drain (sb);
		sb = NULL;
		r_str_replace_ch (op->mnemonic, '\t', ' ', true);
	}
	int left = R_MIN (len, op->size);
	if (left < 1 || (left > 0 && !memcmp (buf, "\xff\xff\xff\xff\xff\xff\xff\xff", left))) {
		free (op->mnemonic);
		op->type = R_ANAL_OP_TYPE_ILL;
		op->mnemonic = strdup ("invalid");
		r_strbuf_free (sb);
		return true;
	}
	if (*op->mnemonic == 0) {
		// probably instructions not implemented
		free (op->mnemonic);
		op->type = R_ANAL_OP_TYPE_NOP;
		op->mnemonic = strdup ("invalid?");
		r_strbuf_free (sb);
		return true;
	}
	if (strstr (op->mnemonic, "unknown")) {
		free (op->mnemonic);
		op->type = R_ANAL_OP_TYPE_ILL;
		op->mnemonic = strdup ("invalid");
		r_strbuf_free (sb);
		return true;
	}
	if (as->config->syntax == R_ARCH_SYNTAX_INTEL) {
		r_str_replace_in (op->mnemonic, -1, "$", "", true);
		r_str_replace_in (op->mnemonic, -1, "#", "", true);
		r_str_replace_in (op->mnemonic, -1, "+ -", "-", true);
	}
	Nds32Insn insn;
	nds32_parse_insn (&insn, op->mnemonic);
	const Nds32InsnDesc *desc = nds32_lookup_insn (as, insn.name);
	if (mask & R_ARCH_OP_MASK_ESIL) {
		decode_esil (op, desc, insn.av);
	}
	if (desc) {
		if (desc->type != NDS32_OP_NONE) {
			op->type = desc->type;
		}
		if (desc->jump_arg >= 0) {
			const char *arg = insn.av[(int)desc->jump_arg];
			op->jump = *arg? r_num_get (NULL, arg): op->addr;
		}
		if (desc->set_fail) {
			op->fail = addr + op->size;
		}
	}
	nds32_fini_insn (&insn);
	r_strbuf_free (sb);
	return op->size > 0;
}

static char *regs(RArchSession *as) {
	const char *p =
		"=PC	pc\n"
		"=SP	sp\n"
		"=BP	fp\n"
		"=LR	lr\n"
		"=SN	r0\n"
		"=R0	r0\n"
		"=A0	r0\n"
		"=A1	r1\n"
		"=A2	r2\n"
		"gpr	r0	4	0	0\n"
		"gpr	a0	4	0	0\n"
		"gpr	r1	4	4	0\n"
		"gpr	a1	4	4	0\n"
		"gpr	r2	4	8	0\n"
		"gpr	a2	4	8	0\n"
		"gpr	r3	4	12	0\n"
		"gpr	a3	4	12	0\n"
		"gpr	r4	4	16	0\n"
		"gpr	a4	4	16	0\n"
		"gpr	r5	4	20	0\n"
		"gpr	a5	4	20	0\n"
		"gpr	r6	4	24	0\n"
		"gpr	s0	4	24	0\n"
		"gpr	r7	4	28	0\n"
		"gpr	s1	4	28	0\n"
		"gpr	r8	4	32	0\n"
		"gpr	s2	4	32	0\n"
		"gpr	r9	4	36	0\n"
		"gpr	s3	4	36	0\n"
		"gpr	h9	4	36	0\n"
		"gpr	r10	4	40	0\n"
		"gpr	s4	4	40	0\n"
		"gpr	r11	4	44	0\n"
		"gpr	s5	4	44	0\n"
		"gpr	r12	4	48	0\n"
		"gpr	s6	4	48	0\n"
		"gpr	r13	4	52	0\n"
		"gpr	s7	4	52	0\n"
		"gpr	r14	4	56	0\n"
		"gpr	s8	4	56	0\n"
		"gpr	r15	4	60	0\n"
		"gpr	ta	4	60	0\n"
		"gpr	r16	4	64	0\n"
		"gpr	t0	4	64	0\n"
		"gpr	h12	4	64	0\n"
		"gpr	r17	4	68	0\n"
		"gpr	t1	4	68	0\n"
		"gpr	h13	4	68	0\n"
		"gpr	r18	4	72	0\n"
		"gpr	t2	4	72	0\n"
		"gpr	h14	4	72	0\n"
		"gpr	r19	4	76	0\n"
		"gpr	t3	4	76	0\n"
		"gpr	h15	4	76	0\n"
		"gpr	r20	4	80	0\n"
		"gpr	t4	4	80	0\n"
		"gpr	r21	4	84	0\n"
		"gpr	t5	4	84	0\n"
		"gpr	r22	4	88	0\n"
		"gpr	t6	4	88	0\n"
		"gpr	r23	4	92	0\n"
		"gpr	t7	4	92	0\n"
		"gpr	r24	4	96	0\n"
		"gpr	t8	4	96	0\n"
		"gpr	r25	4	100	0\n"
		"gpr	t9	4	100	0\n"
		"gpr	r26	4	104	0\n"
		"gpr	p0	4	104	0\n"
		"gpr	r27	4	108	0\n"
		"gpr	p1	4	108	0\n"
		"gpr	r28	4	112	0\n"
		"gpr	s9	4	112	0\n"
		"gpr	fp	4	112	0\n"
		"gpr	r29	4	116	0\n"
		"gpr	gp	4	116	0\n"
		"gpr	r30	4	120	0\n"
		"gpr	lp	4	120	0\n"
		"gpr	lr	4	120	0\n"
		"gpr	r31	4	124	0\n"
		"gpr	sp	4	124	0\n"
		"gpr	pc	4	128	0\n"
		"gpr	ifc_lp	4	132	0\n"
		"gpr	ifc_on	4	136	0\n";
	return strdup (p);
}

static bool nds32_encode(RArchSession *as, RAnalOp *op, RArchEncodeMask mask) {
	const char *str = op->mnemonic;
	if (r_str_startswith (str, "ifcall")) {
		const char *arg = str + strlen ("ifcall");
		const char *space = strchr (arg, ' ');
		if (space) {
			ut64 num = r_num_get (NULL, space + 1);
			st64 disp = ((st64)num - op->addr) >> 1;
			if (disp < -256 || disp > 255) {
				R_LOG_ERROR ("Out of range");
				return false;
			}
			ut16 imm = (ut16)disp & 0x1FF;
			ut8 bytes[2] = { 0xf8 | ((imm >> 8) & 1), imm & 0xFF };
			op->size = 2;
			free (op->bytes);
			op->bytes = r_mem_dup (bytes, 2);
			return true;
		}
		return false;
	}
	if (r_str_startswith (str, "ifret")) {
		ut8 bytes[2] = { 0x83, 0xff };
		op->size = 2;
		free (op->bytes);
		op->bytes = r_mem_dup (bytes, 2);
		return true;
	}
	if (r_str_startswith (str, "ex9.it ")) {
		char *arg = (char *)str + 7; // skip "ex9.it "
		ut8 val = (ut8) r_num_get (NULL, arg);
		ut8 bytes[2] = { 0xea, val };
		op->size = 2;
		free (op->bytes);
		op->bytes = r_mem_dup (bytes, 2);
		return true;
	}
	return false;
}

const RArchPlugin r_arch_plugin_nds32 = {
	.meta = {
		.name = "nds32",
		.author = "decaduto,pancake",
		.license = "GPL-3.0-only",
		.desc = "AndesTar v3 NDS32 (binutils)",
	},
	.arch = "nds32",
	.bits = R_SYS_BITS_PACK1 (32),
	.endian = R_SYS_ENDIAN_LITTLE,
	.encode = &nds32_encode,
	.decode = &decode,
	.regs = regs,
	.init = &_init,
	.fini = fini,
	.info = &info,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ARCH,
	.data = &r_arch_plugin_nds32,
};
#endif
