/* radare - LGPL - Copyright 2015-2025 - pancake, qnix */

#include <r_arch.h>
#include "./riscv-opc.c"
#include "./riscv.c"
#include "./riscvasm.c"
#define RISCVARGSMAX (8)
#define RISCVARGSIZE (64)
#define RISCVARGN(x) ((x)->arg[(x)->num++])
#define RISCVPRINTF(x,...) snprintf (RISCVARGN (args), RISCVARGSIZE, x, __VA_ARGS__)

typedef struct plugin_data_t {
	bool init0;
	const struct riscv_opcode *riscv_hash[OP_MASK_OP + 1];
} PluginData;

typedef struct riscv_args {
	int num;
	char arg[RISCVARGSMAX][RISCVARGSIZE];
} riscv_args_t;

static bool riscv_encode(RArchSession *s, RAnalOp *op, RArchEncodeMask mask) {
	const char *str = op->mnemonic;
	ut8 outbuf[4] = {0};
	int size = riscv_assemble (str, op->addr, outbuf);
	if (size > 0) {
		if (R_ARCH_CONFIG_IS_BIG_ENDIAN (s->config)) {
			r_mem_swapendian (outbuf, outbuf, 4);
		}
		op->size = size;
		free (op->bytes);
		op->bytes = r_mem_dup (outbuf, size);
		return true;
	}
	return false;
}

#define is_any(...) _is_any(name, __VA_ARGS__, NULL)
static bool _is_any(const char *str, ...) {
	char *cur;
	va_list va;
	va_start (va, str);
	while (true) {
		cur = va_arg (va, char *);
		if (!cur) {
			break;
		}
		if (r_str_startswith (str, cur)) {
			va_end (va);
			return true;
		}
	}
	va_end (va);
	return false;
}

static void arg_p2(char *buf, unsigned long val, const char* const* array, size_t size) {
	const char *s = (val >= size || array[val]) ? array[val] : "unknown";
	snprintf (buf, RISCVARGSIZE, "%s", s);
//	r_str_ncpy (buf, s, RISCVARGSIZE);
}

/* Print insn arguments for 32/64-bit code.  */
static void get_riscv_args(riscv_args_t *args, const char *d, insn_t l, ut64 pc) {
	int rs1 = (l >> OP_SH_RS1) & OP_MASK_RS1;
	int rd = (l >> OP_SH_RD) & OP_MASK_RD;
	ut64 target;
	args->num = 0;

	for (; *d != '\0' && args->num < RISCVARGSMAX; d++) {
		switch (*d) {
		/* Xcustom */
		case '^':
			d++;
			switch (*d) {
			case 'd':
				RISCVPRINTF ("%d", rd);
				break;
			case 's':
				RISCVPRINTF ("%d", rs1);
				break;
			case 't':
				RISCVPRINTF ("%d", (int) EXTRACT_OPERAND (RS2, l));
				break;
			case 'j':
				RISCVPRINTF ("%d", (int) EXTRACT_OPERAND (CUSTOM_IMM, l));
				break;
			}
			break;
		case 'C': /* RVC */
			d++;
			switch (*d) {
			case 's': /* RS1 x8-x15 */
			case 'w': /* RS1 x8-x15 */
				RISCVPRINTF ("%s", riscv_gpr_names[EXTRACT_OPERAND (CRS1S, l) + 8]);
				break;
			case 't': /* RS2 x8-x15 */
			case 'x': /* RS2 x8-x15 */
				RISCVPRINTF ("%s", riscv_gpr_names[EXTRACT_OPERAND (CRS2S, l) + 8]);
				break;
			case 'U': /* RS1, constrained to equal RD in CI format*/
				RISCVPRINTF ("%s", riscv_gpr_names[rd]);
				break;
			case 'c': /* RS1, constrained to equal sp */
				RISCVPRINTF ("%s", riscv_gpr_names[X_SP]);
				break;
			case 'V': /* RS2 */
				RISCVPRINTF ("%s", riscv_gpr_names[EXTRACT_OPERAND (CRS2, l)]);
				break;
			case 'i':
				RISCVPRINTF ("%d", (int)EXTRACT_RVC_SIMM3 (l));
				break;
			case 'j':
				RISCVPRINTF ("%d", (int)EXTRACT_RVC_IMM (l));
				break;
			case 'k':
				RISCVPRINTF ("%d", (int)EXTRACT_RVC_LW_IMM (l));
				break;
			case 'l':
				RISCVPRINTF ("%d", (int)EXTRACT_RVC_LD_IMM (l));
				break;
			case 'm':
				RISCVPRINTF ("%d", (int)EXTRACT_RVC_LWSP_IMM (l));
				break;
			case 'n':
				RISCVPRINTF ("%d", (int)EXTRACT_RVC_LDSP_IMM (l));
				break;
			case 'K':
				RISCVPRINTF ("%d", (int)EXTRACT_RVC_ADDI4SPN_IMM (l));
				break;
			case 'L':
				RISCVPRINTF ("%d", (int)EXTRACT_RVC_ADDI16SP_IMM (l));
				break;
			case 'M':
				RISCVPRINTF ("%d", (int)EXTRACT_RVC_SWSP_IMM (l));
				break;
			case 'N':
				RISCVPRINTF ("%d", (int)EXTRACT_RVC_SDSP_IMM (l));
				break;
			case 'p':
				target = EXTRACT_RVC_B_IMM (l) + pc;
				RISCVPRINTF ("0x%"PFMT64x, (ut64) target);
				break;
			case 'a':
				target = EXTRACT_RVC_J_IMM (l) + pc;
				RISCVPRINTF ("0x%"PFMT64x, (ut64)target);
				break;
			case 'u':
				RISCVPRINTF ("0x%x", (int) (EXTRACT_RVC_IMM (l) & (RISCV_BIGIMM_REACH - 1)));
				break;
			case '>':
				RISCVPRINTF ("0x%x", (int) EXTRACT_RVC_IMM (l) & 0x3f);
				break;
			case '<':
				RISCVPRINTF ("0x%x", (int) EXTRACT_RVC_IMM (l) & 0x1f);
				break;
			case 'T': /* floating-point RS2 */
				RISCVPRINTF ("%s", riscv_fpr_names[EXTRACT_OPERAND (CRS2, l)]);
				break;
			case 'D': /* floating-point RS2 x8-x15 */
				RISCVPRINTF ("%s", riscv_fpr_names[EXTRACT_OPERAND (CRS2S, l) + 8]);
				break;
			}
			break;
		case ',':
		case '(':
		case ')':
		case '[':
		case ']':
			break;
		case '0':
			/* Only print constant 0 if it is the last argument */
			if (!d[1]) {
				snprintf (RISCVARGN (args), RISCVARGSIZE , "0");
			}
			break;
		case 'b':
		case 's':
			RISCVPRINTF ("%s", riscv_gpr_names[rs1]);
			break;
		case 't':
			RISCVPRINTF ("%s", riscv_gpr_names[EXTRACT_OPERAND (RS2, l)]);
			break;
		case 'u':
			RISCVPRINTF ("0x%x", (unsigned) EXTRACT_UTYPE_IMM (l) >> RISCV_IMM_BITS);
			break;

		case 'm':
			arg_p2 (RISCVARGN (args), EXTRACT_OPERAND (RM, l),
					riscv_rm, ARRAY_SIZE (riscv_rm));
			break;

		case 'P':
			arg_p2 (RISCVARGN (args), EXTRACT_OPERAND (PRED, l),
					riscv_pred_succ, ARRAY_SIZE (riscv_pred_succ));
			break;

		case 'Q':
			arg_p2 (RISCVARGN (args), EXTRACT_OPERAND (SUCC, l),
					riscv_pred_succ, ARRAY_SIZE (riscv_pred_succ));
			break;
		case 'o':
		case 'j':
			RISCVPRINTF ("%d", (int) EXTRACT_ITYPE_IMM (l));
			break;
		case 'q':
			RISCVPRINTF ("%d", (int) EXTRACT_STYPE_IMM (l));
			break;
		case 'a':
			target = EXTRACT_UJTYPE_IMM (l) + pc;
			RISCVPRINTF ("0x%"PFMT64x, (ut64)target);
			break;
		case 'p':
			target = EXTRACT_SBTYPE_IMM (l) + pc;
			RISCVPRINTF ("0x%"PFMT64x, (ut64)target);
			break;
		case 'd':
			RISCVPRINTF ("%s", riscv_gpr_names[rd]);
			break;
		case 'z':
			RISCVPRINTF ("%s", riscv_gpr_names[0]);
			break;
		case '>':
			RISCVPRINTF ("0x%x", (int) EXTRACT_OPERAND (SHAMT, l));
			break;
		case '<':
			RISCVPRINTF ("0x%x", (int) EXTRACT_OPERAND (SHAMTW, l));
			break;
		case 'S':
		case 'U':
			RISCVPRINTF ("%s", riscv_fpr_names[rs1]);
			break;
		case 'T':
			RISCVPRINTF ("%s", riscv_fpr_names[EXTRACT_OPERAND (RS2, l)]);
			break;
		case 'D':
			RISCVPRINTF ("%s", riscv_fpr_names[rd]);
			break;
		case 'R':
			RISCVPRINTF ("%s", riscv_fpr_names[EXTRACT_OPERAND (RS3, l)]);
			break;
		case 'E':
			{
				const char* csr_name = NULL;
				unsigned int csr = EXTRACT_OPERAND (CSR, l);
				switch (csr) {
#define DECLARE_CSR(name, num) case num: csr_name = #name; break;
#undef RISCV_ENCODING_H
#include "./riscv-opc.h"
#undef DECLARE_CSR
				}
				if (csr_name) {
					RISCVPRINTF ("%s", csr_name);
				} else {
					RISCVPRINTF ("0x%x", csr);
				}
				break;
			}
		case 'Z':
			RISCVPRINTF ("%d", rs1);
			break;
		default:
			/* xgettext:c-format */
			RISCVPRINTF ("# internal error, undefined modifier (%c)", *d);
			return;
		}
	}
}

static const char* arg_n(riscv_args_t* args, int n) {
	if (n >= args->num || !strcmp (args->arg[n], "zero")) {
		return "0";
	}
	return args->arg[n];
}

static struct riscv_opcode *riscv_get_opcode(PluginData *pd, insn_t word) {
	struct riscv_opcode *op = NULL;

#define OP_HASH_IDX(i) ((i) & (riscv_insn_length (i) == 2 ? 3 : OP_MASK_OP))
	if (!pd->init0) {
		size_t i;
		for (i = 0; i < OP_MASK_OP + 1; i++) {
			pd->riscv_hash[i] = 0;
		}
		for (op = riscv_opcodes; op <= &riscv_opcodes[NUMOPCODES - 1]; op++) {
			if (!pd->riscv_hash[OP_HASH_IDX (op->match)]) {
				pd->riscv_hash[OP_HASH_IDX (op->match)] = op;
			}
		}
		pd->init0 = true;
	}
	return (struct riscv_opcode *) pd->riscv_hash[OP_HASH_IDX (word)];
}

static char *riscv_disassemble(RArchSession *s, ut64 addr, const ut8 *buf, int len) {//insn_t word, int xlen, int len) {
	if (len < 2) {
		return NULL;
	}
	ut8 word_bytes[8] = {0};
	memcpy (word_bytes, buf, R_MIN (8, len));
	insn_t word = r_read_le64 (word_bytes);
	int xlen = s->config->bits;
	int ilen = riscv_insn_length (word);
	if (len < ilen) {
		return NULL;
	}
	const bool no_alias = false;
	PluginData *pd = s->data;
	const struct riscv_opcode *op = riscv_get_opcode (pd, word);
	if (!op) {
		return NULL;
	}
	for (; op < &riscv_opcodes[NUMOPCODES]; op++) {
		if (!(op->match_func)(op, word) ) {
			continue;
		}
		if (no_alias && (op->pinfo & INSN_ALIAS)) {
			continue;
		}
		if (isdigit ((ut8)op->subset[0]) && atoi (op->subset) != xlen) {
			continue;
		}
		if (op->name && op->args) {
			char opasm [128];
			r_str_ncpy (opasm, op->name, sizeof (opasm));
			get_insn_args (opasm, op->args, word, addr);
			return strdup (opasm);
		}
		break;
	}
	return NULL;
}

static bool riscv_decode(RArchSession *s, RAnalOp *op, RArchDecodeMask mask) {
	ut64 addr = op->addr;
	const ut8 *buf = op->bytes;
	int len = op->size;
	const int no_alias = 1;
	riscv_args_t args = {0};
	ut64 word = 0;
	const int xlen = s->config->bits;
	op->type = R_ANAL_OP_TYPE_UNK;
	op->size = 4;
	const bool be = R_ARCH_CONFIG_IS_BIG_ENDIAN (s->config);
	if (len < 2) {
		op->size = 2;
		free (op->mnemonic);
		op->type = R_ANAL_OP_TYPE_ILL;
		op->mnemonic = strdup ("truncated");
		return false;
	}

	if (len >= sizeof (ut64)) {
		word = r_read_ble64 (buf, be);
	} else if (len >= sizeof (ut32)) {
		word = r_read_ble32 (buf, be);
	} else {
		word = r_read_ble16 (buf, be);
#if 0
		word = r_read_ble32 (buf, be);
		op->type = R_ANAL_OP_TYPE_ILL;
		free (op->mnemonic);
		op->mnemonic = r_str_newf ("truncated %d", len);
		return -1;
#endif
	}

	PluginData *pd = s->data;
	struct riscv_opcode *o = riscv_get_opcode (pd, word);
	if (word == UT64_MAX) {
		op->type = R_ANAL_OP_TYPE_ILL;
		return false;
	}
	if (!o || !o->name) {
		return op->size;
	}
	if (true) { // necessary for analysis // mask & R_ARCH_OP_MASK_DISASM) {
		op->mnemonic = riscv_disassemble (s, addr, buf, len);
		if (!op->mnemonic) {
			op->mnemonic = strdup ("invalid");
		}
	}

	for (; o <= &riscv_opcodes[NUMOPCODES - 1]; o++) {
		if (no_alias && (o->pinfo & INSN_ALIAS)) {
			continue;
		}
		if (isdigit ((ut8)(o->subset[0])) && atoi (o->subset) != xlen) {
			continue;
		}
		if (o->match_func && !(o->match_func)(o, word)) {
			continue;
		}
		break;
	}

	if (o > &riscv_opcodes[NUMOPCODES - 1]) {
		return false;
	}

	const char *name = o->name;
	if (op->mnemonic) {
		name = op->mnemonic;
	}
	const char *arg = strstr (name, "0x");
	if (!arg) {
		arg = strstr (name, ", ");
		if (arg) {
			arg++;
		} else {
			arg = strchr (name, ' ');
			if (arg) {
				arg++;
			}
		}
	}
	if (r_str_startswith (o->name, "c.")) {
		op->size = 2;
	} else {
		op->size = 4;
	}
	if (mask & R_ARCH_OP_MASK_ESIL) {
		// Test for compressed instruction
#undef ARG
#define ARG(x) (arg_n (&args, (x)))
		get_riscv_args (&args, o->args, word, addr);
		if (is_any ("nop")) {
			esilprintf (op, ",");
		}
		// math
		else if (r_str_startswith (name, "addi16sp")) {
			esilprintf (op, "%s,sp,+,%s,=", ARG (1), ARG (0));
			if (!strcmp (ARG (0), riscv_gpr_names[X_SP])) {
				op->stackop = R_ANAL_STACK_INC;
				op->stackptr = r_num_math (NULL, ARG (1));
			}
		} else if (is_any ("ret")) {
			esilprintf (op, "ra,pc,:=");
			op->type = R_ANAL_OP_TYPE_RET;
		} else if (r_str_startswith (name, "addiw")) {
			r_strbuf_appendf (&op->esil, "%s,0xffffffff,%s,&,", ARG (2), ARG (1));
			r_strbuf_appendf (&op->esil, "+,%s,=,", ARG (0));
			r_strbuf_appendf (&op->esil, "32,%s,~=", ARG (0));
			if (!strcmp (ARG (0), riscv_gpr_names[X_SP]) &&
					!strcmp (ARG (1), riscv_gpr_names[X_SP])) {
				op->stackop = R_ANAL_STACK_INC;
				op->stackptr = r_num_math (NULL, ARG (2));
			}
		} else if (r_str_startswith (name, "addw")) {
			esilprintf (op, "0xffffffff,%s,&,", ARG (2));
			r_strbuf_appendf (&op->esil, "0xffffffff,%s,&,", ARG (1));
			r_strbuf_appendf (&op->esil, "+,%s,=,", ARG (0));
			r_strbuf_appendf (&op->esil, "32,%s,~=", ARG (0));
		} else if (r_str_startswith (name, "add")) {
			esilprintf (op, "%s,%s,+,%s,=", ARG (2), ARG (1), ARG (0));
			if (name[3] == 'i' && !strcmp (ARG (0), riscv_gpr_names[X_SP]) &&
					!strcmp (ARG (1), riscv_gpr_names[X_SP])) {
				op->stackop = R_ANAL_STACK_INC;
				op->stackptr = -(signed)r_num_math (NULL, ARG (2));
			}
		} else if (r_str_startswith (name, "subw")) {
			esilprintf (op, "0xffffffff,%s,&,", ARG (2));
			r_strbuf_appendf (&op->esil, "0xffffffff,%s,&,", ARG (1));
			r_strbuf_appendf (&op->esil, "-,%s,=,", ARG (0));
			r_strbuf_appendf (&op->esil, "32,%s,~=", ARG (0));
		} else if (r_str_startswith (name, "sub")) {
			esilprintf (op, "%s,%s,-,%s,=", ARG (2), ARG (1), ARG (0));
			if (name[3] == 'i' && !strcmp (ARG (0), riscv_gpr_names[X_SP]) &&
					!strcmp (ARG (1), riscv_gpr_names[X_SP])) {
				op->stackop = R_ANAL_STACK_INC;
				op->stackptr = r_num_math (NULL, ARG (2));
			}
		} else if (r_str_startswith (name, "mulw")) {
			esilprintf (op, "0xffffffff,%s,&,", ARG (2));
			r_strbuf_appendf (&op->esil, "0xffffffff,%s,&,", ARG (1));
			r_strbuf_appendf (&op->esil, "*,%s,=,", ARG (0));
			r_strbuf_appendf (&op->esil, "32,%s,~=", ARG (0));
		} else if (r_str_startswith (name, "mul")) {
			esilprintf (op, "%s,%s,*,%s,=", ARG (2), ARG (1), ARG (0));
		} else if (r_str_startswith (name, "div")) {
			esilprintf (op, "%s,%s,/,%s,=", ARG (2), ARG (1), ARG (0));
		} else if (r_str_startswith (name, "rm")) {
			esilprintf (op, "%s,%s,%%,%s,=", ARG (2), ARG (1), ARG (0));
		} else if (r_str_startswith (name, "xor")) {
			esilprintf (op, "%s,%s,^,%s,=", ARG (2), ARG (1), ARG (0));
		} else if (r_str_startswith (name, "or")) {
			esilprintf (op, "%s,%s,|,%s,=", ARG (2), ARG (1), ARG (0));
		} else if (r_str_startswith (name, "and")) {
			esilprintf (op, "%s,%s,&,%s,=", ARG (2), ARG (1), ARG (0));
		} else if (r_str_startswith (name, "auipc")) {
			esilprintf (op, "%s000,0x%"PFMT64x",+,%s,=", ARG (1), addr, ARG (0));
		} else if (r_str_startswith (name, "sll")) {
			esilprintf (op, "%s,%s,<<,%s,=", ARG (2), ARG (1), ARG (0));
			if (name[3] == 'w' || !strncmp (name, "slliw", 5)) {
				r_strbuf_appendf (&op->esil, ",32,%s,~=", ARG (0));
			}
		} else if (is_any ("srlw", "srliw")) {
			esilprintf (op, "%s,0xffffffff,%s,&,>>,%s,=", ARG (2), ARG (1), ARG (0));
		} else if (r_str_startswith (name, "srl")) {
			esilprintf (op, "%s,%s,>>,%s,=", ARG (2), ARG (1), ARG (0));
		} else if (is_any ("sraiw")) {
			esilprintf (op, "%s,%s,>>>>,%s,=,", ARG (2), ARG (1), ARG (0));
			r_strbuf_appendf (&op->esil, "%s,64,-,%s,~=", ARG (2), ARG(0));
		} else if (r_str_startswith (name, "sra")) {
			esilprintf (op, "%s,%s,>>>>,%s,=", ARG (2), ARG (1), ARG (0));
		}
		// assigns
		else if (r_str_startswith (name, "mv")) {
			esilprintf (op, "%s,%s,=", ARG (1), ARG (0));
			op->type = R_ANAL_OP_TYPE_MOV;
		} else if (r_str_startswith (name, "li")) {
			esilprintf (op, "%s,%s,=", ARG (2), ARG (0));
		} else if (r_str_startswith (name, "lui")) {
			esilprintf (op, "%s000,%s,=", ARG (1), ARG (0));
			if (s->config->bits == 64) {
				//r_strbuf_appendf (&op->esil, ",32,%s,~=", ARG (0));
			}
		// csr instrs
		// <csr op> rd, rs1, CSR
		} else if (r_str_startswith (name, "csrrw")) {
			// Writes rs1 into CSR, places the old value in rd
			esilprintf (op, "%s,0,+,%s,%s,=,%s,=", ARG (1), ARG (2), ARG (1), ARG (0));
		} else if (r_str_startswith (name, "csrrs")) {
			// Ors rs1 with CSR, places old value in rd
			esilprintf (op, "%s,0,+,%s,%s,|=,%s,=", ARG (1), ARG (2), ARG (1), ARG (0));
		} else if (r_str_startswith (name, "csrrc")) {
			// Ands the inverse of rs1 with CSR, places old value in rd
			esilprintf (op, "%s,0,+,%s,1,+,0,-,%s,&=,%s,=", ARG (1), ARG (1), ARG (2), ARG (0));
		}
		// stores
		else if (is_any ("sd ", "sdsp")) {
			esilprintf (op, "%s,%s,%s,+,=[8]", ARG (0), ARG (2), ARG (1));
		} else if (is_any ("sw ", "swsp")) {
			esilprintf (op, "%s,%s,%s,+,=[4]", ARG (0), ARG (2), ARG (1));
		} else if (is_any ("sh ", "shsp")) {
			esilprintf (op, "%s,%s,%s,+,=[2]", ARG (0), ARG (2), ARG (1));
		} else if (is_any ("sb ", "sbsp")) {
			esilprintf (op, "%s,%s,%s,+,=[1]", ARG (0), ARG (2), ARG (1));
		} else if (is_any ("fsq ", "fsqsp")) {
			esilprintf (op, "%s,%s,+,[16],%s,=", ARG (2), ARG (1), ARG (0));
		} else if (is_any ("fsd ", "fsdsp")) {
			esilprintf (op, "%s,%s,%s,+,=[8]", ARG (0), ARG (2), ARG (1));
		} else if (is_any ("fsw ", "fswsp")) {
			esilprintf (op, "%s,%s,%s,+,=[4]", ARG (0), ARG (2), ARG (1));
		} else if (is_any ("fsh ", "fshsp")) {
			esilprintf (op, "%s,%s,%s,+,=[2]", ARG (0), ARG (2), ARG (1));
		} else if (is_any ("fsb ", "fsbsp")) {
			esilprintf (op, "%s,%s,%s,+,=[1]", ARG (0), ARG (2), ARG (1));
		}
		// loads
		else if (is_any ("ld ", "ldsp ")) {
			esilprintf (op, "%s,%s,+,[8],%s,=", ARG (2), ARG (1), ARG (0));
		} else if (is_any ("lw ", "lwu ", "lwsp")) {
			esilprintf (op, "%s,%s,+,[4],%s,=", ARG (2), ARG (1), ARG (0));
			if ((s->config->bits == 64) && is_any ("lwu ")) {
				r_strbuf_appendf (&op->esil, ",32,%s,~=", ARG (0));
			}
		} else if (is_any ("lh ", "lhu ", "lhsp")) {
			esilprintf (op, "%s,%s,+,[2],%s,=", ARG (2), ARG (1), ARG (0));
			if (!is_any ("lhu")) {
				r_strbuf_appendf (&op->esil, ",16,%s,~=", ARG (0));
			}
		} else if (is_any ("lb ", "lbu ", "lbsp")) {
			esilprintf (op, "%s,%s,+,[1],%s,=", ARG (2), ARG (1), ARG (0));
			if (!is_any ("lbu")) {
				r_strbuf_appendf (&op->esil, ",8,%s,~=", ARG (0));
			}
		} else if (is_any ("lfq ", "lfqsp")) {
			esilprintf (op, "%s,%s,+,[16],%s,=", ARG (2), ARG (1), ARG (0));
		} else if (is_any ("lfd ", "lfdsp")) {
			esilprintf (op, "%s,%s,+,[8],%s,=", ARG (2), ARG (1), ARG (0));
		} else if (is_any ("lfw ", "lfwsp")) {
			esilprintf (op, "%s,%s,+,[4],%s,=", ARG (2), ARG (1), ARG (0));
		} else if (is_any ("lfh ", "lfhsp")) {
			esilprintf (op, "%s,%s,+,[2],%s,=", ARG (2), ARG (1), ARG (0));
		} else if (is_any ("lfb ", "lfbsp")) {
			esilprintf (op, "%s,%s,+,[1],%s,=", ARG (2), ARG (1), ARG (0));
		}
		// jumps
		else if (is_any ("jalr")) {
			if (strcmp (ARG (0), "0")) {
				esilprintf (op, "%s,%s,+,pc,:=,0x%"PFMT64x",%s,=", ARG (2), ARG (1), addr + op->size, ARG (0));
			} else {
				esilprintf (op, "%s,%s,+,pc,:=", ARG (2), ARG (1));
			}
		} else if (is_any ("jal ")) {
			if (strcmp (ARG (0), "0")) {
				if (args.num == 1) {
					//esilprintf (op, "%d,$$,+,ra,=,%s,pc,:=", op->size, ARG (0));
					esilprintf (op, "pc,ra,:=,%s,pc,:=", ARG (0));
				} else {
					esilprintf (op, "0x%"PFMT64x",%s,:=,%s,pc,:=", addr + op->size, ARG (0), ARG (1));
				}
			} else {
				esilprintf (op, "%s,pc,:=", ARG (1));
			}
		} else if (is_any ("jr ", "j ")) {
			esilprintf (op, "%s,pc,:=", ARG (1));
		} else if (is_any ("ecall", "ebreak")) {
			esilprintf (op, "TRAP");
		}
		// Branches & cmps
		else if (is_any ("beq ")) {
			esilprintf (op, "%s,%s,==,$z,?{,%s,pc,:=,},", ARG (1), ARG (0), ARG (2));
		} else if (is_any ("bne ")) {
			esilprintf (op, "%s,%s,==,$z,!,?{,%s,pc,:=,},", ARG (1), ARG (0), ARG (2));
		} else if (is_any ("ble ", "bleu")) {
			esilprintf (op, "%s,%s,<=,?{,%s,pc,:=,},", ARG (1), ARG (0), ARG (2));
		} else if (is_any ("blt ", "bltu")) {
			esilprintf (op, "%s,%s,<,?{,%s,pc,:=,},", ARG (1), ARG (0), ARG (2));
		} else if (is_any ("bge ", "bgeu")) {
			esilprintf (op, "%s,%s,>=,?{,%s,pc,:=,},", ARG (1), ARG (0), ARG (2));
		} else if (is_any ("bgt ", "bgtu")) {
			esilprintf (op, "%s,%s,>,?{,%s,pc,:=,},", ARG (1), ARG (0), ARG (2));
		} else if (is_any ("beqz ")) {
			esilprintf (op, "%s,0,==,$z,?{,%s,pc,:=,},", ARG (0), ARG (1));
		} else if (is_any ("bnez ")) {
			esilprintf (op, "%s,0,==,$z,!,?{,%s,pc,:=,},", ARG (0), ARG (1));
		} else if (is_any ("bjez ")) {
			esilprintf (op, "%s,0,<=,?{,%s,pc,:=,},", ARG (0), ARG (1));
		} else if (is_any ("bjtz ")) {
			esilprintf (op, "%s,0,<,?{,%s,pc,:=,},", ARG (0), ARG (1));
		} else if (is_any ("bjez ")) {
			esilprintf (op, "%s,0,>=,?{,%s,pc,:=,},", ARG (0), ARG (1));
		} else if (is_any ("bgtz ")) {
			esilprintf (op, "%s,0,>,?{,%s,pc,:=,},", ARG (0), ARG (1));
		} else if (is_any ("seq ")) {
			esilprintf (op, "%s,%s,==,%s,=", ARG (2), ARG (1), ARG (0));
		} else if (is_any ("sne ")) {
			esilprintf (op, "%s,%s,!=,%s,=", ARG (2), ARG (1), ARG (0));
		} else if (is_any ("sle ")) {
			esilprintf (op, "%s,%s,<=,%s,=", ARG (2), ARG (1), ARG (0));
		} else if (is_any ("slt ")) {
			esilprintf (op, "%s,%s,<,%s,=", ARG (2), ARG (1), ARG (0));
		} else if (is_any ("sge ")) {
			esilprintf (op, "%s,%s,>=,%s,=", ARG (2), ARG (1), ARG (0));
		} else if (is_any ("sgt ")) {
			esilprintf (op, "%s,%s,>,%s,=", ARG (2), ARG (1), ARG (0));
		}
		// debug
		//else if (strcmp (name, "unimp") != 0 && name[0] != 'f' && name[1] != 'm') {
		//	int i;
		//	eprintf("[esil] missing risc v esil: %s", name);
		//	for (i = 0; i < args.num; i++) {
		//		eprintf(" %s", ARG(i));
		//	}
		//	eprintf("\n");
		//}
#undef ARG
	}
	// branch/jumps/calls/rets
	if (is_any ("ret")) {
		op->type = R_ANAL_OP_TYPE_RET;
	} else if (is_any ("c.jr")) {
		op->type = R_ANAL_OP_TYPE_RET;
	} else if (is_any ("jal ")) {
		op->type = R_ANAL_OP_TYPE_CALL;
		op->jump = arg? r_num_get (NULL, arg): op->addr;
		op->fail = addr + op->size;
	} else if (is_any ("j ")) {
		// decide whether it's jump or call
		// int rd = (word >> OP_SH_RD) & OP_MASK_RD;
		op->type = R_ANAL_OP_TYPE_JMP;
		op->jump = arg? r_num_get (NULL, arg): op->addr;
	} else if (is_any ("jalr")) {
		// decide whether it's ret or call
		int rd = (word >> OP_SH_RD) & OP_MASK_RD;
		op->type = (rd == 0) ? R_ANAL_OP_TYPE_RET: R_ANAL_OP_TYPE_UCALL;
	} else if (is_any ("c.jal ")) {
		op->type = R_ANAL_OP_TYPE_CALL;
		op->jump = EXTRACT_RVC_IMM (word) + addr;
		op->fail = addr + op->size;
	} else if (is_any ("jr ")) {
		op->type = R_ANAL_OP_TYPE_RJMP;
	} else if (is_any ("c.j ", "jump ")) {
		op->type = R_ANAL_OP_TYPE_JMP;
		op->jump = EXTRACT_RVC_J_IMM (word) + addr;
	} else if (is_any ("c.ret")) {
		op->type = R_ANAL_OP_TYPE_RET;
	} else if (is_any ("c.jalr")) {
		op->type = R_ANAL_OP_TYPE_UCALL;
	} else if (is_any ("beqz", "beq", "blez", "bgez", "ble",
				"bleu", "bge", "bgeu", "bltz", "bgtz", "blt", "bltu",
				"bgt", "bgtu", "bnez", "bne ")) {
		op->type = R_ANAL_OP_TYPE_CJMP;
		// op->jump = EXTRACT_SBTYPE_IMM (word) + addr;
		op->jump = arg? r_num_get (NULL, arg): op->addr;
		op->fail = addr + op->size;
	} else if (is_any ("c.beqz", "c.bnez")) {
		op->type = R_ANAL_OP_TYPE_CJMP;
		// op->jump = EXTRACT_RVC_B_IMM (word) + addr;
		op->jump = arg? r_num_get (NULL, arg): op->addr;
		op->fail = addr + op->size;
		// math
	} else if (is_any ("auipc")) {
		op->type = R_ANAL_OP_TYPE_LEA;
	} else if (is_any ("addi", "addw", "addiw", "add", "c.addi",
				"c.addw", "c.add", "c.addiw", "c.addi4spn", "c.addi16sp")) {
		if (strstr (name, ", zero,")) {
			op->type = R_ANAL_OP_TYPE_MOV;
		} else {
			op->type = R_ANAL_OP_TYPE_ADD;
		}
	} else if (is_any ("ret")) {
		op->type = R_ANAL_OP_TYPE_RET;
	} else if (is_any ("c.mv", "csrrw", "csrrc", "csrrs")) {
		op->type = R_ANAL_OP_TYPE_MOV;
	} else if (is_any ("subi", "subw", "sub", "c.sub", "c.subw")) {
		op->type = R_ANAL_OP_TYPE_SUB;
	} else if (is_any ("xori", "xor", "c.xor")) {
		op->type = R_ANAL_OP_TYPE_XOR;
	} else if (is_any ("andi", "and", "c.andi", "c.and")) {
		op->type = R_ANAL_OP_TYPE_AND;
	} else if (is_any ("ori", "or", "c.or")) {
		op->type = R_ANAL_OP_TYPE_OR;
	} else if (is_any ("not")) {
		op->type = R_ANAL_OP_TYPE_NOT;
	} else if (is_any ("c.nop", "nop", "cnop")) {
		op->type = R_ANAL_OP_TYPE_NOP;
	} else if (is_any ("mul", "mulh", "mulhu", "mulhsu", "mulw")) {
		op->type = R_ANAL_OP_TYPE_MUL;
	} else if (is_any ("div", "divu", "divw", "divuw")) {
		op->type = R_ANAL_OP_TYPE_DIV;
	} else if (is_any ("sll", "slli", "sllw", "slliw", "c.slli")) {
		op->type = R_ANAL_OP_TYPE_SHL;
	} else if (is_any ("srl", "srlw", "srliw", "c.srli")) {
		op->type = R_ANAL_OP_TYPE_SHR;
	} else if (is_any ("sra", "sra", "srai", "sraiw", "c.srai")) {
		op->type = R_ANAL_OP_TYPE_SAR;
		// memory
	} else if (is_any ("sd", "sb", "sh", "sw", "c.sd", "c.sw",
				"c.swsp", "c.sdsp")) {
		op->type = R_ANAL_OP_TYPE_STORE;
	} else if (is_any ("li", "c.li", "lui", "c.lui")) {
		op->type = R_ANAL_OP_TYPE_MOV;
	} else if (is_any ("ld", "lw", "lwu",
				"lb", "lbu", "lh", "lhu", "la", "lla", "c.ld",
				"c.lw", "c.lwsp")) {
		op->type = R_ANAL_OP_TYPE_LOAD;
	}
	if (mask & R_ARCH_OP_MASK_VAL && args.num) {
		int i = 1;
		RAnalValue *dst, *src;
		dst = r_vector_push (&op->dsts, NULL);
		char *argf = strdup (o->args);
		r_str_split (argf, ',');
		char *comma = argf;
		if (comma && strchr (comma, '(')) {
			dst->delta = (st64)r_num_get (NULL, args.arg[0]);
			// dst->reg = args.arg[1];
			// dst->reg = r_reg_get (anal->reg, args.arg[1], -1);
			i = 2;
		} else if (isdigit ((ut8)args.arg[i][0])) {
			dst->imm = r_num_get (NULL, args.arg[0]);
		} else {
			// dst->reg = args.arg[1];
			// dst->reg = r_reg_get (anal->reg, args.arg[0], -1);
		}
		comma = r_str_tok_next (comma);
		for (; i < args.num; i++) {
			src = r_vector_push (&op->srcs, NULL);
			if (comma && strchr (comma, '(')) {
				src->delta = (st64)r_num_get (NULL, args.arg[i]);
				// src->reg = args.arg[1];
				// src->reg = r_reg_get (anal->reg, args.arg[j + 1], -1);
				i++;
			} else if (isalpha ((ut8)args.arg[i][0])) {
				// src->reg = args.arg[1];
				// src->reg = r_reg_get (anal->reg, args.arg[j], -1);
			} else {
				src->imm = r_num_get (NULL, args.arg[i]);
			}
			comma = r_str_tok_next (comma);
		}
		free (argf);
	}
	if (r_str_startswith (name, "ill")) {
		op->type = R_ANAL_OP_TYPE_ILL;
	}
	return op->size > 0;
}

static char *get_reg_profile(RArchSession *s) {
	const char *p = NULL;
	switch (s->config->bits) {
		case 32: p =
			 "=PC	pc\n"
				 "=A0	a0\n"
				 "=A1	a1\n"
				 "=A2	a2\n"
				 "=A3	a3\n"
				 "=A4	a4\n"
				 "=A5	a5\n"
				 "=A6	a6\n"
				 "=A7	a7\n"
				 "=TR	tp\n"
				 "=R0	a0\n"
				 "=R1	a1\n"
				 "=SP	sp\n" // ABI: stack pointer
				 "=LR	ra\n" // ABI: return address
				 "=BP	s0\n" // ABI: frame pointer
				 "=SN	a7\n" // ABI: syscall numer
				 "gpr	pc	.32	0	0\n"
				 // RV32I regs (ABI names)
				 // From user-Level ISA Specification, section 2.1
				 // "zero" has been left out as it ignores writes and always reads as zero
				 "gpr	ra	.32	4	0\n" // =x1
				 "gpr	sp	.32	8	0\n" // =x2
				 "gpr	gp	.32	12	0\n" // =x3
				 "gpr	tp	.32	16	0\n" // =x4
				 "gpr	t0	.32	20	0\n" // =x5
				 "gpr	t1	.32	24	0\n" // =x6
				 "gpr	t2	.32	28	0\n" // =x7
				 "gpr	s0	.32	32	0\n" // =x8
				 "gpr	s1	.32	36	0\n" // =x9
				 "gpr	a0	.32	40	0\n" // =x10
				 "gpr	a1	.32	44	0\n" // =x11
				 "gpr	a2	.32	48	0\n" // =x12
				 "gpr	a3	.32	52	0\n" // =x13
				 "gpr	a4	.32	56	0\n" // =x14
				 "gpr	a5	.32	60	0\n" // =x15
				 "gpr	a6	.32	64	0\n" // =x16
				 "gpr	a7	.32	68	0\n" // =x17
				 "gpr	s2	.32	72	0\n" // =x18
				 "gpr	s3	.32	76	0\n" // =x19
				 "gpr	s4	.32	80	0\n" // =x20
				 "gpr	s5	.32	84	0\n" // =x21
				 "gpr	s6	.32	88	0\n" // =x22
				 "gpr	s7	.32	92	0\n" // =x23
				 "gpr	s8	.32	96	0\n" // =x24
				 "gpr	s9	.32	100	0\n" // =x25
				 "gpr	s10	.32	104	0\n" // =x26
				 "gpr	s11	.32	108	0\n" // =x27
				 "gpr	t3	.32	112	0\n" // =x28
				 "gpr	t4	.32	116	0\n" // =x29
				 "gpr	t5	.32	120	0\n" // =x30
				 "gpr	t6	.32	124	0\n" // =x31
				 // RV32F/D regs (ABI names)
				 // From user-Level ISA Specification, section 8.1 and 9.1
				 "fpu	ft0	.64	128	0\n" // =f0
				 "fpu	ft1	.64	136	0\n" // =f1
				 "fpu	ft2	.64	144	0\n" // =f2
				 "fpu	ft3	.64	152	0\n" // =f3
				 "fpu	ft4	.64	160	0\n" // =f4
				 "fpu	ft5	.64	168	0\n" // =f5
				 "fpu	ft6	.64	176	0\n" // =f6
				 "fpu	ft7	.64	184	0\n" // =f7
				 "fpu	fs0	.64	192	0\n" // =f8
				 "fpu	fs1	.64	200	0\n" // =f9
				 "fpu	fa0	.64	208	0\n" // =f10
				 "fpu	fa1	.64	216	0\n" // =f11
				 "fpu	fa2	.64	224	0\n" // =f12
				 "fpu	fa3	.64	232	0\n" // =f13
				 "fpu	fa4	.64	240	0\n" // =f14
				 "fpu	fa5	.64	248	0\n" // =f15
				 "fpu	fa6	.64	256	0\n" // =f16
				 "fpu	fa7	.64	264	0\n" // =f17
				 "fpu	fs2	.64	272	0\n" // =f18
				 "fpu	fs3	.64	280	0\n" // =f19
				 "fpu	fs4	.64	288	0\n" // =f20
				 "fpu	fs5	.64	296	0\n" // =f21
				 "fpu	fs6	.64	304	0\n" // =f22
				 "fpu	fs7	.64	312	0\n" // =f23
				 "fpu	fs8	.64	320	0\n" // =f24
				 "fpu	fs9	.64	328	0\n" // =f25
				 "fpu	fs10	.64	336	0\n" // =f26
				 "fpu	fs11	.64	344	0\n" // =f27
				 "fpu	ft8	.64	352	0\n" // =f28
				 "fpu	ft9	.64	360	0\n" // =f29
				 "fpu	ft10	.64	368	0\n" // =f30
				 "fpu	ft11	.64	376	0\n" // =f31
				 "fpu	fcsr	.32	384	0\n"
				 "flg	nx	.1	3072	0\n"
				 "flg	uf	.1	3073	0\n"
				 "flg	of	.1	3074	0\n"
				 "flg	dz	.1	3075	0\n"
				 "flg	nv	.1	3076	0\n"
				 "flg	frm	.3	3077	0\n"
				 ;
			 break;
		case 64: p =
			 "=PC	pc\n"
				 "=SP	sp\n" // ABI: stack pointer
				 "=LR	ra\n" // ABI: return address
				 "=BP	s0\n" // ABI: frame pointer
				 "=A0	a0\n"
				 "=A1	a1\n"
				 "=A2	a2\n"
				 "=A3	a3\n"
				 "=A4	a4\n"
				 "=A5	a5\n"
				 "=A6	a6\n"
				 "=A7	a7\n"
				 "=R0	a0\n"
				 "=R1	a1\n"
				 "=SN	a7\n" // ABI: syscall numer
				 "gpr	pc	.64	0	0\n"
				 // RV64I regs (ABI names)
				 // From user-Level ISA Specification, section 2.1 and 4.1
				 // "zero" has been left out as it ignores writes and always reads as zero
				 "gpr	ra	.64	8	0\n" // =x1
				 "gpr	sp	.64	16	0\n" // =x2
				 "gpr	gp	.64	24	0\n" // =x3
				 "gpr	tp	.64	32	0\n" // =x4 // thread pointer register
				 "gpr	t0	.64	40	0\n" // =x5
				 "gpr	t1	.64	48	0\n" // =x6
				 "gpr	t2	.64	56	0\n" // =x7
				 "gpr	s0	.64	64	0\n" // =x8
				 "gpr	s1	.64	72	0\n" // =x9
				 "gpr	a0	.64	80	0\n" // =x10
				 "gpr	a1	.64	88	0\n" // =x11
				 "gpr	a2	.64	96	0\n" // =x12
				 "gpr	a3	.64	104	0\n" // =x13
				 "gpr	a4	.64	112	0\n" // =x14
				 "gpr	a5	.64	120	0\n" // =x15
				 "gpr	a6	.64	128	0\n" // =x16
				 "gpr	a7	.64	136	0\n" // =x17
				 "gpr	s2	.64	144	0\n" // =x18
				 "gpr	s3	.64	152	0\n" // =x19
				 "gpr	s4	.64	160	0\n" // =x20
				 "gpr	s5	.64	168	0\n" // =x21
				 "gpr	s6	.64	176	0\n" // =x22
				 "gpr	s7	.64	184	0\n" // =x23
				 "gpr	s8	.64	192	0\n" // =x24
				 "gpr	s9	.64	200	0\n" // =x25
				 "gpr	s10	.64	208	0\n" // =x26
				 "gpr	s11	.64	216	0\n" // =x27
				 "gpr	t3	.64	224	0\n" // =x28
				 "gpr	t4	.64	232	0\n" // =x29
				 "gpr	t5	.64	240	0\n" // =x30
				 "gpr	t6	.64	248	0\n" // =x31
				 // RV64F/D regs (ABI names)
				 "fpu	ft0	.64	256	0\n" // =f0
				 "fpu	ft1	.64	264	0\n" // =f1
				 "fpu	ft2	.64	272	0\n" // =f2
				 "fpu	ft3	.64	280	0\n" // =f3
				 "fpu	ft4	.64	288	0\n" // =f4
				 "fpu	ft5	.64	296	0\n" // =f5
				 "fpu	ft6	.64	304	0\n" // =f6
				 "fpu	ft7	.64	312	0\n" // =f7
				 "fpu	fs0	.64	320	0\n" // =f8
				 "fpu	fs1	.64	328	0\n" // =f9
				 "fpu	fa0	.64	336	0\n" // =f10
				 "fpu	fa1	.64	344	0\n" // =f11
				 "fpu	fa2	.64	352	0\n" // =f12
				 "fpu	fa3	.64	360	0\n" // =f13
				 "fpu	fa4	.64	368	0\n" // =f14
				 "fpu	fa5	.64	376	0\n" // =f15
				 "fpu	fa6	.64	384	0\n" // =f16
				 "fpu	fa7	.64	392	0\n" // =f17
				 "fpu	fs2	.64	400	0\n" // =f18
				 "fpu	fs3	.64	408	0\n" // =f19
				 "fpu	fs4	.64	416	0\n" // =f20
				 "fpu	fs5	.64	424	0\n" // =f21
				 "fpu	fs6	.64	432	0\n" // =f22
				 "fpu	fs7	.64	440	0\n" // =f23
				 "fpu	fs8	.64	448	0\n" // =f24
				 "fpu	fs9	.64	456	0\n" // =f25
				 "fpu	fs10	.64	464	0\n" // =f26
				 "fpu	fs11	.64	472	0\n" // =f27
				 "fpu	ft8	.64	480	0\n" // =f28
				 "fpu	ft9	.64	488	0\n" // =f29
				 "fpu	ft10	.64	496	0\n" // =f30
				 "fpu	ft11	.64	504	0\n" // =f31
				 "fpu	fcsr	.32	512	0\n"
				 "flg	nx	.1	4096	0\n"
				 "flg	uf	.1	4097	0\n"
				 "flg	of	.1	4098	0\n"
				 "flg	dz	.1	4099	0\n"
				 "flg	nv	.1	4100	0\n"
				 "flg	frm	.3	4101	0\n"
				 ;

			 break;
	}
	return R_STR_ISNOTEMPTY (p)? strdup (p): NULL;
}

static int info(RArchSession *s, ut32 q) {
	switch (q) {
	case R_ARCH_INFO_CODE_ALIGN:
		return 2;
	case R_ARCH_INFO_MAXOP_SIZE:
		return 4;
	case R_ARCH_INFO_INVOP_SIZE:
		return 2;
	case R_ARCH_INFO_MINOP_SIZE:
		return 2;
	}
	return 0;
}

static bool _init(RArchSession *as) {
	R_RETURN_VAL_IF_FAIL (as, false);
	if (as->data) {
		R_LOG_WARN ("Already initialized");
		return false;
	}

	as->data = R_NEW0 (PluginData);
	return !!as->data;
}

static bool _fini(RArchSession *as) {
	R_RETURN_VAL_IF_FAIL (as, false);
	R_FREE (as->data);
	return true;
}

const RArchPlugin r_arch_plugin_riscv = {
	.meta = {
		.name = "riscv",
		.desc = "RISC-V ISA architecture",
		.author = "pancake,qnix",
		.license = "GPL-3.0-only",
	},
	.arch = "riscv",
	.endian = R_SYS_ENDIAN_LITTLE | R_SYS_ENDIAN_BIG,
	.bits = R_SYS_BITS_PACK2 (32, 64),
	.encode = riscv_encode,
	.decode = riscv_decode,
	.info = info,
	.regs = get_reg_profile,
	.init = _init,
	.fini = _fini,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ARCH,
	.data = &r_arch_plugin_riscv,
	.version = R2_VERSION
};
#endif
