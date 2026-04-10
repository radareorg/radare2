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

// esil: NULL=no esil, ""=empty, "$0"-"$7" expanded to av[0]-av[7], "@X"=special
typedef struct {
	const char *name;
	const char *esil;
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
#define NDS32_DESC(_name, _esil, _type) { _name, _esil, _type, -1, false }
#define NDS32_JDESC(_name, _esil, _type, _jump_arg, _set_fail) { _name, _esil, _type, _jump_arg, _set_fail }

static const Nds32InsnDesc nds32_insns[] = {
	NDS32_DESC ("sethi", "12,$1,<<,$0,:=", R_ANAL_OP_TYPE_MOV),
	NDS32_DESC ("jral5", "pc,2,+,lp,:=,$0,pc,:=", R_ANAL_OP_TYPE_RCALL),
	NDS32_JDESC ("jral", "pc,4,+,$0,:=,$1,pc,:=", R_ANAL_OP_TYPE_RCALL, -1, true),
	NDS32_JDESC ("jal", "$0,pc,:=", R_ANAL_OP_TYPE_CALL, 0, true),
	NDS32_DESC ("jr5", "$0,pc,:=", R_ANAL_OP_TYPE_RJMP),
	NDS32_DESC ("jr", "$0,pc,:=", R_ANAL_OP_TYPE_RJMP),
	NDS32_JDESC ("j8", "$0,pc,:=", R_ANAL_OP_TYPE_JMP, 0, false),
	NDS32_JDESC ("j", "$0,pc,:=", R_ANAL_OP_TYPE_JMP, 0, false),
	NDS32_DESC ("ret", "lp,pc,:=", R_ANAL_OP_TYPE_RET),
	NDS32_DESC ("ret5", "lp,pc,:=", R_ANAL_OP_TYPE_RET),
	NDS32_DESC ("iret", NULL, R_ANAL_OP_TYPE_RET),
	NDS32_DESC ("ifret16", "ifc_on,?{,ifc_lp,pc,:=,0,ifc_on,:=,}", R_ANAL_OP_TYPE_CRET),
	NDS32_DESC ("ifret", "ifc_on,?{,ifc_lp,pc,:=,0,ifc_on,:=,}", R_ANAL_OP_TYPE_CRET),
	NDS32_JDESC ("ifcall", "@ifcall", R_ANAL_OP_TYPE_CCALL, 0, true),
	NDS32_JDESC ("bgezal", NULL, R_ANAL_OP_TYPE_CCALL, 1, true),
	NDS32_JDESC ("bltzal", NULL, R_ANAL_OP_TYPE_CCALL, 1, true),
	NDS32_JDESC ("beq", "$0,$1,==,$z,?{,$2,pc,:=,}", R_ANAL_OP_TYPE_CJMP, 2, true),
	NDS32_JDESC ("bne", "$0,$1,==,$z,!,?{,$2,pc,:=,}", R_ANAL_OP_TYPE_CJMP, 2, true),
	NDS32_JDESC ("beqz", "$0,0,==,$z,?{,$1,pc,:=,}", R_ANAL_OP_TYPE_CJMP, 1, true),
	NDS32_JDESC ("bnez", "$0,0,==,$z,!,?{,$1,pc,:=,}", R_ANAL_OP_TYPE_CJMP, 1, true),
	NDS32_JDESC ("bnezs8", "ta,0,==,$z,!,?{,$0,pc,:=,}", R_ANAL_OP_TYPE_CJMP, 0, true),
	NDS32_JDESC ("beqzs8", "ta,!,?{,$0,pc,:=,}", R_ANAL_OP_TYPE_CJMP, 0, true),
	NDS32_JDESC ("bgtz", "$0,0,>,?{,$1,pc,:=,}", R_ANAL_OP_TYPE_CJMP, 1, true),
	NDS32_JDESC ("bgez", "31,$0,>>,!,?{,$1,pc,:=,}", R_ANAL_OP_TYPE_CJMP, 1, true),
	NDS32_JDESC ("bltz", "31,$0,>>,?{,$1,pc,:=,}", R_ANAL_OP_TYPE_CJMP, 1, true),
	NDS32_JDESC ("blez", "$0,!,31,$0,>>,|,?{,$1,pc,:=,}", R_ANAL_OP_TYPE_CJMP, 1, true),
	NDS32_JDESC ("beqz38", "$0,!,?{,$1,pc,:=,}", R_ANAL_OP_TYPE_CJMP, 1, true),
	NDS32_JDESC ("bnez38", "$0,?{,$1,pc,:=,}", R_ANAL_OP_TYPE_CJMP, 1, true),
	NDS32_JDESC ("beqs38", "$0,ta,==,$z,?{,$1,pc,:=,}", R_ANAL_OP_TYPE_CJMP, 1, true),
	NDS32_JDESC ("bnes38", "$0,ta,==,$z,!,?{,$1,pc,:=,}", R_ANAL_OP_TYPE_CJMP, 1, true),
	NDS32_JDESC ("beqc", "$1,$0,==,$z,?{,$2,pc,:=,}", R_ANAL_OP_TYPE_CJMP, 2, true),
	NDS32_JDESC ("bnec", "$1,$0,==,$z,!,?{,$2,pc,:=,}", R_ANAL_OP_TYPE_CJMP, 2, true),
	NDS32_DESC ("addi", "$2,$1,+,$0,:=", R_ANAL_OP_TYPE_ADD),
	NDS32_DESC ("addri", NULL, R_ANAL_OP_TYPE_ADD),
	NDS32_DESC ("addi.gp", "gp,$1,+,$0,:=", R_ANAL_OP_TYPE_ADD),
	NDS32_DESC ("addri36.sp", "sp,$1,+,$0,:=", R_ANAL_OP_TYPE_ADD),
	NDS32_DESC ("addi10s", "$0,sp,+,sp,:=", R_ANAL_OP_TYPE_ADD),
	NDS32_DESC ("addi333", "$2,$1,+,$0,:=", R_ANAL_OP_TYPE_ADD),
	NDS32_DESC ("addi45", "$1,$0,+,$0,:=", R_ANAL_OP_TYPE_ADD),
	NDS32_DESC ("add333", "$2,$1,+,$0,:=", R_ANAL_OP_TYPE_ADD),
	NDS32_DESC ("add45", "$1,$0,+,$0,:=", R_ANAL_OP_TYPE_ADD),
	NDS32_DESC ("add5.pc", NULL, R_ANAL_OP_TYPE_ADD),
	NDS32_DESC ("add_slli", "$3,$2,<<,$1,+,$0,:=", R_ANAL_OP_TYPE_ADD),
	NDS32_DESC ("add_srli", NULL, R_ANAL_OP_TYPE_ADD),
	NDS32_DESC ("add.sc", NULL, R_ANAL_OP_TYPE_ADD),
	NDS32_DESC ("add.wc", NULL, R_ANAL_OP_TYPE_ADD),
	NDS32_DESC ("add", "$2,$1,+,$0,:=", R_ANAL_OP_TYPE_ADD),
	NDS32_DESC ("subi", NULL, R_ANAL_OP_TYPE_SUB),
	NDS32_DESC ("subri", "$1,$2,-,$0,:=", R_ANAL_OP_TYPE_SUB),
	NDS32_DESC ("sub333", "$2,$1,-,$0,:=", R_ANAL_OP_TYPE_SUB),
	NDS32_DESC ("sub45", "$1,$0,-,$0,:=", R_ANAL_OP_TYPE_SUB),
	NDS32_DESC ("subi333", "$2,$1,-,$0,:=", R_ANAL_OP_TYPE_SUB),
	NDS32_DESC ("subi45", "$1,$0,-,$0,:=", R_ANAL_OP_TYPE_SUB),
	NDS32_DESC ("sub_slli", NULL, R_ANAL_OP_TYPE_SUB),
	NDS32_DESC ("sub_srli", NULL, R_ANAL_OP_TYPE_SUB),
	NDS32_DESC ("sub.sc", NULL, R_ANAL_OP_TYPE_SUB),
	NDS32_DESC ("sub.wc", NULL, R_ANAL_OP_TYPE_SUB),
	NDS32_DESC ("sub", "$2,$1,-,$0,:=", R_ANAL_OP_TYPE_SUB),
	NDS32_DESC ("mul33", "$1,$0,*,$0,:=", R_ANAL_OP_TYPE_MUL),
	NDS32_DESC ("mul", "$2,$1,*,$0,:=", R_ANAL_OP_TYPE_MUL),
	NDS32_DESC ("maddr32", "$2,$1,*,$0,+,$0,:=", R_ANAL_OP_TYPE_MUL),
	NDS32_DESC ("msubr32", NULL, R_ANAL_OP_TYPE_MUL),
	NDS32_DESC ("madd", NULL, R_ANAL_OP_TYPE_MUL),
	NDS32_DESC ("msub", NULL, R_ANAL_OP_TYPE_MUL),
	NDS32_DESC ("mult", NULL, R_ANAL_OP_TYPE_MUL),
	NDS32_DESC ("divr", "$2,$1,/,$0,:=", R_ANAL_OP_TYPE_DIV),
	NDS32_DESC ("divsr", NULL, R_ANAL_OP_TYPE_DIV),
	NDS32_DESC ("divs", NULL, R_ANAL_OP_TYPE_DIV),
	NDS32_DESC ("div", NULL, R_ANAL_OP_TYPE_DIV),
	NDS32_DESC ("ori", "$2,$1,|,$0,:=", R_ANAL_OP_TYPE_OR),
	NDS32_DESC ("or33", "$1,$0,|,$0,:=", R_ANAL_OP_TYPE_OR),
	NDS32_DESC ("or_slli", NULL, R_ANAL_OP_TYPE_OR),
	NDS32_DESC ("or_srli", NULL, R_ANAL_OP_TYPE_OR),
	NDS32_DESC ("or", "$2,$1,|,$0,:=", R_ANAL_OP_TYPE_OR),
	NDS32_DESC ("xori", "$2,$1,^,$0,:=", R_ANAL_OP_TYPE_XOR),
	NDS32_DESC ("xor33", "$1,$0,^,$0,:=", R_ANAL_OP_TYPE_XOR),
	NDS32_DESC ("xor_slli", NULL, R_ANAL_OP_TYPE_XOR),
	NDS32_DESC ("xor_srli", NULL, R_ANAL_OP_TYPE_XOR),
	NDS32_DESC ("xor", "$2,$1,^,$0,:=", R_ANAL_OP_TYPE_XOR),
	NDS32_DESC ("andi", "$2,$1,&,$0,:=", R_ANAL_OP_TYPE_AND),
	NDS32_DESC ("and33", "$1,$0,&,$0,:=", R_ANAL_OP_TYPE_AND),
	NDS32_DESC ("and_slli", NULL, R_ANAL_OP_TYPE_AND),
	NDS32_DESC ("and_srli", NULL, R_ANAL_OP_TYPE_AND),
	NDS32_DESC ("and", "$2,$1,&,$0,:=", R_ANAL_OP_TYPE_AND),
	NDS32_DESC ("bitci", "$2,~,$1,&,$0,:=", R_ANAL_OP_TYPE_AND),
	NDS32_DESC ("nor", "$2,$1,|,~,$0,:=", R_ANAL_OP_TYPE_NOR),
	NDS32_DESC ("not33", "$1,~,$0,:=", R_ANAL_OP_TYPE_NOT),
	NDS32_DESC ("slli", "$2,$1,<<,$0,:=", R_ANAL_OP_TYPE_SHL),
	NDS32_DESC ("sll", "$2,$1,<<,$0,:=", R_ANAL_OP_TYPE_SHL),
	NDS32_DESC ("slli333", "$2,$1,<<,$0,:=", R_ANAL_OP_TYPE_SHL),
	NDS32_DESC ("srli", "$2,$1,>>,$0,:=", R_ANAL_OP_TYPE_SHR),
	NDS32_DESC ("srl", "$2,$1,>>,$0,:=", R_ANAL_OP_TYPE_SHR),
	NDS32_DESC ("srai", "$2,$1,ASR,$0,:=", R_ANAL_OP_TYPE_SHR),
	NDS32_DESC ("sra", "$2,$1,ASR,$0,:=", R_ANAL_OP_TYPE_SHR),
	NDS32_DESC ("srli45", "$1,$0,>>,$0,:=", R_ANAL_OP_TYPE_SHR),
	NDS32_DESC ("srai45", "$1,$0,ASR,$0,:=", R_ANAL_OP_TYPE_SHR),
	NDS32_DESC ("rotri", "$2,$1,>>>,$0,:=", R_ANAL_OP_TYPE_ROR),
	NDS32_DESC ("rotr", NULL, R_ANAL_OP_TYPE_ROR),
	NDS32_DESC ("lbi.gp", "@gl1", R_ANAL_OP_TYPE_LOAD),
	NDS32_DESC ("lbsi.gp", NULL, R_ANAL_OP_TYPE_LOAD),
	NDS32_DESC ("lwi.gp", "@gl4", R_ANAL_OP_TYPE_LOAD),
	NDS32_DESC ("lhi.gp", NULL, R_ANAL_OP_TYPE_LOAD),
	NDS32_DESC ("lhsi.gp", NULL, R_ANAL_OP_TYPE_LOAD),
	NDS32_DESC ("sbi.gp", "@gs1", R_ANAL_OP_TYPE_STORE),
	NDS32_DESC ("swi.gp", "@gs4", R_ANAL_OP_TYPE_STORE),
	NDS32_DESC ("shi.gp", "@gs2", R_ANAL_OP_TYPE_STORE),
	NDS32_DESC ("lwi", "@ml4", R_ANAL_OP_TYPE_LOAD),
	NDS32_DESC ("lbi", "@ml1", R_ANAL_OP_TYPE_LOAD),
	NDS32_DESC ("lhi", NULL, R_ANAL_OP_TYPE_LOAD),
	NDS32_DESC ("ldi", NULL, R_ANAL_OP_TYPE_LOAD),
	NDS32_DESC ("lbsi", NULL, R_ANAL_OP_TYPE_LOAD),
	NDS32_DESC ("lhsi", NULL, R_ANAL_OP_TYPE_LOAD),
	NDS32_DESC ("lwsi", NULL, R_ANAL_OP_TYPE_LOAD),
	NDS32_DESC ("lwi333", NULL, R_ANAL_OP_TYPE_LOAD),
	NDS32_DESC ("lbi333", NULL, R_ANAL_OP_TYPE_LOAD),
	NDS32_DESC ("lhi333", NULL, R_ANAL_OP_TYPE_LOAD),
	NDS32_DESC ("lwi450", NULL, R_ANAL_OP_TYPE_LOAD),
	NDS32_DESC ("lwi37", NULL, R_ANAL_OP_TYPE_LOAD),
	NDS32_DESC ("lwi45", NULL, R_ANAL_OP_TYPE_LOAD),
	NDS32_DESC ("lw", NULL, R_ANAL_OP_TYPE_LOAD),
	NDS32_DESC ("lb", NULL, R_ANAL_OP_TYPE_LOAD),
	NDS32_DESC ("lh", NULL, R_ANAL_OP_TYPE_LOAD),
	NDS32_DESC ("ld", NULL, R_ANAL_OP_TYPE_LOAD),
	NDS32_DESC ("lbs", NULL, R_ANAL_OP_TYPE_LOAD),
	NDS32_DESC ("lhs", NULL, R_ANAL_OP_TYPE_LOAD),
	NDS32_DESC ("lws", NULL, R_ANAL_OP_TYPE_LOAD),
	NDS32_DESC ("llw", NULL, R_ANAL_OP_TYPE_LOAD),
	NDS32_DESC ("lmw", "", R_ANAL_OP_TYPE_LOAD),
	NDS32_DESC ("lmw.adm", "", NDS32_OP_NONE),
	NDS32_DESC ("fls", NULL, R_ANAL_OP_TYPE_LOAD),
	NDS32_DESC ("fld", NULL, R_ANAL_OP_TYPE_LOAD),
	NDS32_DESC ("flsi", NULL, R_ANAL_OP_TYPE_LOAD),
	NDS32_DESC ("fldi", NULL, R_ANAL_OP_TYPE_LOAD),
	NDS32_DESC ("swi", "@ms4", R_ANAL_OP_TYPE_STORE),
	NDS32_DESC ("sbi", "@ms1", R_ANAL_OP_TYPE_STORE),
	NDS32_DESC ("shi", "@ms2", R_ANAL_OP_TYPE_STORE),
	NDS32_DESC ("sdi", NULL, R_ANAL_OP_TYPE_STORE),
	NDS32_DESC ("swi333", NULL, R_ANAL_OP_TYPE_STORE),
	NDS32_DESC ("sbi333", NULL, R_ANAL_OP_TYPE_STORE),
	NDS32_DESC ("shi333", NULL, R_ANAL_OP_TYPE_STORE),
	NDS32_DESC ("swi450", NULL, R_ANAL_OP_TYPE_STORE),
	NDS32_DESC ("swi37", NULL, R_ANAL_OP_TYPE_STORE),
	NDS32_DESC ("sw", NULL, R_ANAL_OP_TYPE_STORE),
	NDS32_DESC ("sb", NULL, R_ANAL_OP_TYPE_STORE),
	NDS32_DESC ("sd", NULL, R_ANAL_OP_TYPE_STORE),
	NDS32_DESC ("scw", NULL, R_ANAL_OP_TYPE_STORE),
	NDS32_DESC ("smw", "", R_ANAL_OP_TYPE_STORE),
	NDS32_DESC ("smw.adm", "", NDS32_OP_NONE),
	NDS32_DESC ("fss", NULL, R_ANAL_OP_TYPE_STORE),
	NDS32_DESC ("fsd", NULL, R_ANAL_OP_TYPE_STORE),
	NDS32_DESC ("fssi", NULL, R_ANAL_OP_TYPE_STORE),
	NDS32_DESC ("fsdi", NULL, R_ANAL_OP_TYPE_STORE),
	NDS32_DESC ("mov55", "$1,$0,:=", R_ANAL_OP_TYPE_MOV),
	NDS32_DESC ("mov", "$1,$0,:=", R_ANAL_OP_TYPE_MOV),
	NDS32_DESC ("movi55", "$1,$0,:=", R_ANAL_OP_TYPE_MOV),
	NDS32_DESC ("movi", "$1,$0,:=", R_ANAL_OP_TYPE_MOV),
	NDS32_DESC ("movpi45", "$1,$0,:=", R_ANAL_OP_TYPE_MOV),
	NDS32_DESC ("movd44", NULL, R_ANAL_OP_TYPE_MOV),
	NDS32_DESC ("mfsr", NULL, R_ANAL_OP_TYPE_MOV),
	NDS32_DESC ("mtsr", NULL, R_ANAL_OP_TYPE_MOV),
	NDS32_DESC ("mfusr", "", R_ANAL_OP_TYPE_MOV),
	NDS32_DESC ("mtusr", "", R_ANAL_OP_TYPE_MOV),
	NDS32_DESC ("cmovz", "$2,!,?{,$1,$0,:=,}", R_ANAL_OP_TYPE_CMOV),
	NDS32_DESC ("cmovn", "$2,?{,$1,$0,:=,}", R_ANAL_OP_TYPE_CMOV),
	NDS32_DESC ("slt", "$2,$1,<,$0,:=", R_ANAL_OP_TYPE_CMP),
	NDS32_DESC ("slts", "$2,$1,<,$0,:=", R_ANAL_OP_TYPE_CMP),
	NDS32_DESC ("slt45", "$1,$0,<,ta,:=", R_ANAL_OP_TYPE_CMP),
	NDS32_DESC ("slts45", "$1,$0,<,ta,:=", R_ANAL_OP_TYPE_CMP),
	NDS32_DESC ("slti", "$2,$1,<,$0,:=", R_ANAL_OP_TYPE_CMP),
	NDS32_DESC ("sltsi", "$2,$1,<,$0,:=", R_ANAL_OP_TYPE_CMP),
	NDS32_DESC ("slti45", "$1,$0,<,ta,:=", NDS32_OP_NONE),
	NDS32_DESC ("sltsi45", "$1,$0,<,ta,:=", NDS32_OP_NONE),
	NDS32_DESC ("zeh", "0xffff,$1,&,$0,:=", R_ANAL_OP_TYPE_MOV),
	NDS32_DESC ("zeh33", "0xffff,$1,&,$0,:=", R_ANAL_OP_TYPE_MOV),
	NDS32_DESC ("zeb", "0xff,$1,&,$0,:=", R_ANAL_OP_TYPE_MOV),
	NDS32_DESC ("zeb33", "0xff,$1,&,$0,:=", R_ANAL_OP_TYPE_MOV),
	NDS32_DESC ("seh", "16,$1,<<,16,ASR,$0,:=", R_ANAL_OP_TYPE_MOV),
	NDS32_DESC ("seh33", "16,$1,<<,16,ASR,$0,:=", R_ANAL_OP_TYPE_MOV),
	NDS32_DESC ("seb", "24,$1,<<,24,ASR,$0,:=", R_ANAL_OP_TYPE_MOV),
	NDS32_DESC ("seb33", "24,$1,<<,24,ASR,$0,:=", R_ANAL_OP_TYPE_MOV),
	NDS32_DESC ("xlsb", "1,$1,&,$0,:=", R_ANAL_OP_TYPE_MOV),
	NDS32_DESC ("xlsb33", "1,$1,&,$0,:=", R_ANAL_OP_TYPE_MOV),
	NDS32_DESC ("push25", "sp,4,-,sp,:=,$0,sp,=[4]", R_ANAL_OP_TYPE_PUSH),
	NDS32_DESC ("pop25", "sp,[4],$0,:=,sp,4,+,sp,:=", R_ANAL_OP_TYPE_POP),
	NDS32_DESC ("syscall", NULL, R_ANAL_OP_TYPE_SWI),
	NDS32_DESC ("break", NULL, R_ANAL_OP_TYPE_TRAP),
	NDS32_DESC ("trap", NULL, R_ANAL_OP_TYPE_TRAP),
	NDS32_DESC ("teqz", NULL, R_ANAL_OP_TYPE_TRAP),
	NDS32_DESC ("tnez", NULL, R_ANAL_OP_TYPE_TRAP),
	NDS32_DESC ("nop", "", R_ANAL_OP_TYPE_NOP),
	NDS32_DESC ("neg33", "0,$1,-,$0,:=", R_ANAL_OP_TYPE_SUB),
	NDS32_DESC ("abs", NULL, R_ANAL_OP_TYPE_ABS),
	NDS32_DESC ("dsb", "", R_ANAL_OP_TYPE_NOP),
	NDS32_DESC ("isb", "", R_ANAL_OP_TYPE_NOP),
	NDS32_DESC ("msync", "", R_ANAL_OP_TYPE_NOP),
	NDS32_DESC ("isync", "", R_ANAL_OP_TYPE_NOP),
	NDS32_DESC ("standby", "", R_ANAL_OP_TYPE_NOP),
	NDS32_DESC ("cctl", NULL, R_ANAL_OP_TYPE_NOP),
	NDS32_DESC ("fexti33", "1,$1,<<,1,-,$0,&,$0,:=", NDS32_OP_NONE),
	NDS32_DESC ("ex9.it", "", NDS32_OP_NONE),
	NDS32_DESC ("bitc", "$2,~,$1,&,$0,:=", NDS32_OP_NONE),
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

// Parse memory operand "[base + off]" / "[base]" / "[off]" in place.
// Strips brackets, whitespace, and optional '+' / '#' immediate-prefix, and
// splits around " + ". *reg holds the base (or sole expression for
// implicit-base forms); *off holds the offset or NULL. Returns false when
// the input is NULL/empty to keep literal "" args from being mutated.
static bool parse_bracket(char *s, char **reg, char **off) {
	if (R_STR_ISEMPTY (s)) {
		return false;
	}
	while (*s == ' ' || *s == '\t' || *s == '[' || *s == '+' || *s == '#') {
		s++;
	}
	char *end = strchr (s, ']');
	if (end) {
		*end = 0;
	}
	char *p = strstr (s, " + ");
	if (p) {
		*p = 0;
		char *o = p + 3;
		while (*o == ' ' || *o == '+' || *o == '#') {
			o++;
		}
		*off = *o? o: NULL;
		if (*off) {
			r_str_trim (*off);
		}
	} else {
		*off = NULL;
	}
	if (*s) {
		r_str_trim (s);
	}
	*reg = s;
	return true;
}

// expand $0-$7 placeholders in ESIL template to av[0]-av[7]
static void apply_esil_template(RAnalOp *op, const char *fmt, char **av) {
	char buf[256];
	char *dst = buf;
	char *end = buf + sizeof (buf) - 1;
	const char *src = fmt;
	while (*src && dst < end) {
		if (src[0] == '$' && src[1] >= '0' && src[1] <= '7') {
			const char *val = av[src[1] - '0'];
			while (*val && dst < end) {
				*dst++ = *val++;
			}
			src += 2;
		} else {
			*dst++ = *src++;
		}
	}
	*dst = 0;
	r_strbuf_set (&op->esil, buf);
}

// handle @-prefixed special ESIL cases that need address parsing
static void apply_esil_special(RAnalOp *op, const char *tag, char **av) {
	const int size = tag[3] - '0';
	const bool load = tag[2] == 'l';
	switch (tag[1]) {
	case 'g': { // @gl1..@gl4, @gs1..@gs4: gp load/store "[+ off]"
		char *reg, *off;
		if (!parse_bracket (av[1], &reg, &off) || !*reg) {
			break;
		}
		if (load) {
			r_strbuf_setf (&op->esil, "gp,%s,+,[%d],%s,:=", reg, size, av[0]);
		} else {
			r_strbuf_setf (&op->esil, "%s,gp,%s,+,=[%d]", av[0], reg, size);
		}
		break;
	}
	case 'm': { // @ml1..@ml4, @ms1..@ms4: mem load/store "[base + off]"
		char *reg, *off;
		if (!parse_bracket (av[1], &reg, &off) || !*reg) {
			break;
		}
		if (load) {
			if (off) {
				r_strbuf_setf (&op->esil, "%s,%s,+,[%d],%s,:=", reg, off, size, av[0]);
			} else {
				r_strbuf_setf (&op->esil, "%s,[%d],%s,:=", reg, size, av[0]);
			}
		} else {
			if (off) {
				r_strbuf_setf (&op->esil, "%s,%s,%s,+,=[%d]", av[0], reg, off, size);
			} else {
				r_strbuf_setf (&op->esil, "%s,%s,=[%d]", av[0], reg, size);
			}
		}
		break;
	}
	case 'i': // @ifcall
		r_strbuf_setf (&op->esil, "pc,%d,+,ifc_lp,:=,1,ifc_on,:=,%s,pc,:=", op->size, av[0]);
		break;
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
	if (!desc || !desc->esil) {
		return;
	}
	if (!*desc->esil) {
		r_strbuf_set (&op->esil, "");
	} else if (desc->esil[0] == '@') {
		apply_esil_special (op, desc->esil, av);
	} else {
		apply_esil_template (op, desc->esil, av);
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
