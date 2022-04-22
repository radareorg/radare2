/* RISC-V disassembler
   Copyright 2011-2015 Free Software Foundation, Inc.
   Contributed by Andrew Waterman (waterman@cs.berkeley.edu) at UC Berkeley.
   Based on MIPS target.
   This file is part of the GNU opcodes library.
   This library is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3, or (at your option)
   any later version.
   It is distributed in the hope that it will be useful, but WITHOUT
   ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
   or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
   License for more details.
   You should have received a copy of the GNU General Public License
   along with this program; see the file COPYING3. If not,
   see <http://www.gnu.org/licenses/>.

   - Code changes to make r2 friendly (qnix@0x80.org)
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <ctype.h>
#include <stdarg.h>
#include <r_asm.h>
#include <r_lib.h>
#include <string.h>

#include "riscv-opc.h"
#include "riscv.h"

#define ARRAY_SIZE(a) (sizeof(a) / sizeof(*a))

// TODO : an conf to chose between abi or numeric
static const char *const *riscv_gpr_names = riscv_gpr_names_abi;
static const char *const *riscv_fpr_names = riscv_fpr_names_abi;
static int init = 0;

static void arg_p(char *buf, unsigned long val, const char* const* array, size_t size) {
	const char *s = (val >= size || array[val]) ? array[val] : "unknown";
	sprintf (buf+strlen (buf), "%s", s);
}

/* Print insn arguments for 32/64-bit code.  */
static void get_insn_args(char *buf, const char *d, insn_t l, uint64_t pc) {
	int rs1 = (l >> OP_SH_RS1) & OP_MASK_RS1;
	int rd = (l >> OP_SH_RD) & OP_MASK_RD;
	uint64_t target;

	if (*d != '\0') {
		sprintf (buf+strlen (buf), " ");
	}

	for (; *d != '\0'; d++) {
		switch (*d) {
			/* Xcustom */
		case '^':
			switch (*++d) {
			case 'd':
				sprintf (buf+strlen (buf), "%d", rd);
				break;
			case 's':
				sprintf (buf+strlen (buf), "%d", rs1);
				break;
			case 't':
				sprintf (buf+strlen (buf), "%d", (int) EXTRACT_OPERAND (RS2, l));
				break;
			case 'j':
				sprintf (buf+strlen (buf), "%d", (int) EXTRACT_OPERAND (CUSTOM_IMM, l));
				break;
			}
			break;

		case 'C': /* RVC */
			switch (*++d) {
			case 's': /* RS1 x8-x15 */
			case 'w': /* RS1 x8-x15 */
				sprintf (buf+strlen (buf), "%s",
				  riscv_gpr_names[EXTRACT_OPERAND (CRS1S, l) + 8]);
				break;
			case 't': /* RS2 x8-x15 */
			case 'x': /* RS2 x8-x15 */
				sprintf (buf+strlen (buf), "%s",
				  riscv_gpr_names[EXTRACT_OPERAND (CRS2S, l) + 8]);
				break;
			case 'U': /* RS1, constrained to equal RD */
				sprintf (buf+strlen (buf), "%s", riscv_gpr_names[rd]);
				break;
			case 'c': /* RS1, constrained to equal sp */
				sprintf (buf+strlen (buf), "%s", riscv_gpr_names[X_SP]);
				break;
			case 'V': /* RS2 */
				sprintf (buf+strlen (buf), "%s",
				  riscv_gpr_names[EXTRACT_OPERAND (CRS2, l)]);
				break;
			case 'i':
				sprintf (buf+strlen (buf), "%d", (int)EXTRACT_RVC_SIMM3 (l));
				break;
			case 'j':
				sprintf (buf+strlen (buf), "%d", (int)EXTRACT_RVC_IMM (l));
				break;
			case 'k':
				sprintf (buf+strlen (buf), "%d", (int)EXTRACT_RVC_LW_IMM (l));
				break;
			case 'l':
				sprintf (buf+strlen (buf), "%d", (int)EXTRACT_RVC_LD_IMM (l));
				break;
			case 'm':
				sprintf (buf+strlen (buf), "%d", (int)EXTRACT_RVC_LWSP_IMM (l));
				break;
			case 'n':
				sprintf (buf+strlen (buf), "%d", (int)EXTRACT_RVC_LDSP_IMM (l));
				break;
			case 'K':
				sprintf (buf+strlen (buf), "%d", (int)EXTRACT_RVC_ADDI4SPN_IMM (l));
				break;
			case 'L':
				sprintf (buf+strlen (buf), "%d", (int)EXTRACT_RVC_ADDI16SP_IMM (l));
				break;
			case 'M':
				sprintf (buf+strlen (buf), "%d", (int)EXTRACT_RVC_SWSP_IMM (l));
				break;
			case 'N':
				sprintf (buf+strlen (buf), "%d", (int)EXTRACT_RVC_SDSP_IMM (l));
				break;
			case 'p':
				target = EXTRACT_RVC_B_IMM (l) + pc;
				sprintf (buf+strlen (buf), "0x%"PFMT64x, (ut64) target);
				break;
			case 'a':
				target = EXTRACT_RVC_J_IMM (l) + pc;
				sprintf (buf+strlen (buf), "0x%"PFMT64x, (ut64)target);
				break;
			case 'u':
				sprintf (buf+strlen (buf), "0x%x",
				  (int) (EXTRACT_RVC_IMM (l) & (RISCV_BIGIMM_REACH-1)));
				break;
			case '>':
				sprintf (buf+strlen (buf), "0x%x", (int) EXTRACT_RVC_IMM (l) & 0x3f);
				break;
			case '<':
				sprintf (buf+strlen (buf), "0x%x", (int) EXTRACT_RVC_IMM (l) & 0x1f);
				break;
			case 'T': /* floating-point RS2 */
				sprintf (buf+strlen (buf), "%s",
				  riscv_fpr_names[EXTRACT_OPERAND (CRS2, l)]);
				break;
			case 'D': /* floating-point RS2 x8-x15 */
				sprintf (buf+strlen (buf), "%s",
				  riscv_fpr_names[EXTRACT_OPERAND (CRS2S, l) + 8]);
				break;
			}
			break;

		case ',':
			sprintf (buf+strlen (buf), "%c ", *d);
			break;
		case '(':
		case ')':
		case '[':
		case ']':
			sprintf (buf+strlen (buf), "%c", *d);
			break;
		case '0':
			/* Only print constant 0 if it is the last argument */
			if (!d[1]) {
				sprintf (buf+strlen (buf), "0");
			}
			break;

		case 'b':
		case 's':
			sprintf (buf+strlen (buf), "%s", riscv_gpr_names[rs1]);
			break;

		case 't':
			sprintf (buf+strlen (buf), "%s",
			  riscv_gpr_names[EXTRACT_OPERAND (RS2, l)]);
			break;

		case 'u':
			sprintf (buf+strlen (buf), "0x%x",
			  (unsigned) EXTRACT_UTYPE_IMM (l) >> RISCV_IMM_BITS);
			break;

		case 'm':
			arg_p (buf, EXTRACT_OPERAND (RM, l),
			  riscv_rm, ARRAY_SIZE (riscv_rm));
			break;

		case 'P':
			arg_p (buf, EXTRACT_OPERAND (PRED, l),
			  riscv_pred_succ, ARRAY_SIZE (riscv_pred_succ));
			break;

		case 'Q':
			arg_p (buf, EXTRACT_OPERAND (SUCC, l),
			  riscv_pred_succ, ARRAY_SIZE (riscv_pred_succ));
			break;
		case 'o':
		case 'j':
			sprintf (buf+strlen (buf), "%d", (int) EXTRACT_ITYPE_IMM (l));
			break;
		case 'q':
			sprintf (buf+strlen (buf), "%d", (int) EXTRACT_STYPE_IMM (l));
			break;
		case 'a':
			target = EXTRACT_UJTYPE_IMM (l) + pc;
			sprintf (buf+strlen (buf), "0x%"PFMT64x, (ut64)target);
			break;
		case 'p':
			target = EXTRACT_SBTYPE_IMM (l) + pc;
			sprintf (buf+strlen (buf), "0x%"PFMT64x, (ut64)target);
			break;
		case 'd':
			sprintf (buf+strlen (buf), "%s", riscv_gpr_names[rd]);
			break;
		case 'z':
			sprintf (buf+strlen (buf), "%s", riscv_gpr_names[0]);
			break;
		case '>':
			sprintf (buf+strlen (buf), "0x%x", (int) EXTRACT_OPERAND (SHAMT, l));
			break;
		case '<':
			sprintf (buf+strlen (buf), "0x%x", (int) EXTRACT_OPERAND (SHAMTW, l));
			break;
		case 'S':
		case 'U':
			sprintf (buf+strlen (buf), "%s", riscv_fpr_names[rs1]);
			break;
		case 'T':
			sprintf (buf+strlen (buf), "%s", riscv_fpr_names[EXTRACT_OPERAND (RS2, l)]);
			break;
		case 'D':
			sprintf (buf+strlen (buf), "%s", riscv_fpr_names[rd]);
			break;
		case 'R':
			sprintf (buf+strlen (buf), "%s", riscv_fpr_names[EXTRACT_OPERAND (RS3, l)]);
			break;
		case 'E':
			{
				const char* csr_name = NULL;
				unsigned int csr = EXTRACT_OPERAND (CSR, l);
				switch (csr)
				 {
#define DECLARE_CSR(name, num) case num: csr_name = #name; break;
#include "riscv-opc.h"
#undef DECLARE_CSR
				 }
				if (csr_name) {
					sprintf (buf+strlen (buf), "%s", csr_name);
				} else {
					sprintf (buf+strlen (buf), "0x%x", csr);
				}
				break;
			}
		case 'Z':
			sprintf (buf+strlen (buf), "%d", rs1);
			break;
		default:
			/* xgettext:c-format */
			sprintf (buf+strlen (buf), "# internal error, undefined modifier (%c)",
			  *d);
			return;
		}
	}
}

static struct riscv_opcode *get_opcode(insn_t word) {
	struct riscv_opcode *op;
	static const struct riscv_opcode *riscv_hash[OP_MASK_OP + 1] = {0};

#define OP_HASH_IDX(i) ((i) & (riscv_insn_length (i) == 2 ? 3 : OP_MASK_OP))

	if (!init) {
		for (op=riscv_opcodes; op < &riscv_opcodes[NUMOPCODES]; op++) {
			if (!riscv_hash[OP_HASH_IDX (op->match)]) {
				riscv_hash[OP_HASH_IDX (op->match)] = op;
			}
		}
		init = 1;
	}

	return (struct riscv_opcode *)riscv_hash[OP_HASH_IDX (word)];
}

static int riscv_disassemble(RAsm *a, RAsmOp *rop, insn_t word, int xlen, int len) {
	const bool no_alias = false;
	const struct riscv_opcode *op = get_opcode (word);
	if (!op) {
		return -1;
	}
	for (; op < &riscv_opcodes[NUMOPCODES]; op++) {
		if ( !(op->match_func)(op, word) ) {
			continue;
		}
		if (no_alias && (op->pinfo & INSN_ALIAS)) {
			continue;
		}
		if (isdigit ((ut8)op->subset[0]) && atoi (op->subset) != xlen ) {
			continue;
		}
		if (op->name && op->args) {
			r_asm_op_set_asm (rop, op->name);
			get_insn_args (r_asm_op_get_asm (rop), op->args, word, a->pc);
			return 0;
		}
		r_strf_buffer (32);
		r_asm_op_set_asm (rop, r_strf ("invalid word(%"PFMT64x")", (ut64)word));
		return -1;
	}
	return 0;
}

static int riscv_dis(RAsm *a, RAsmOp *rop, const ut8 *buf, ut64 len) {
	insn_t insn = {0};
	if (len < 2) {
		return -1;
	}
	memcpy (&insn, buf, R_MIN (sizeof (insn), len));
	int insn_len = riscv_insn_length(insn);
	if (len < insn_len) {
		return -1;
	}
	riscv_disassemble (a, rop, insn, a->config->bits, len);
	return insn_len;
}
