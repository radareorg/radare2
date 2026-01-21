/* RISC-V disassembler 2011-2015 - FSF */

#if 0
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
see <https://www.gnu.org/licenses/>.

- Code changes to make r2 friendly (qnix@0x80.org)
#endif

#include <r_asm.h>

#include "riscv-opc.h"
#include "riscv.h"

#define ARRAY_SIZE(a) (sizeof (a) / sizeof (*a))

// TODO : an conf to choose between abi or numeric (move to PluginData struct)
const char * const * const riscv_gpr_names = riscv_gpr_names_abi;
const char * const * const riscv_fpr_names = riscv_fpr_names_abi;

static void arg_p(RStrBuf *sb, unsigned long val, const char* const* array, size_t size) {
	const char *s = (val >= size || array[val]) ? array[val] : "unknown";
	r_strbuf_appendf (sb, "%s", s);
}

/* Print insn arguments for 32/64-bit code.  */
static void get_insn_args(RStrBuf *sb, const char *d, insn_t l, uint64_t pc) {
	int rs1 = (l >> OP_SH_RS1) & OP_MASK_RS1;
	int rd = (l >> OP_SH_RD) & OP_MASK_RD;
	uint64_t target;

	if (*d != '\0') {
		r_strbuf_append (sb, " ");
	}

	for (; *d != '\0'; d++) {
		switch (*d) {
			/* Xcustom */
		case '^':
			switch (*++d) {
			case 'd':
				r_strbuf_appendf (sb, "%d", rd);
				break;
			case 's':
				r_strbuf_appendf (sb, "%d", rs1);
				break;
			case 't':
				r_strbuf_appendf (sb, "%d", (int) EXTRACT_OPERAND (RS2, l));
				break;
			case 'j':
				r_strbuf_appendf (sb, "%d", (int) EXTRACT_OPERAND (CUSTOM_IMM, l));
				break;
			}
			break;

		case 'C': /* RVC */
			switch (*++d) {
			case 's': /* RS1 x8-x15 */
			case 'w': /* RS1 x8-x15 */
				r_strbuf_appendf (sb, "%s",
				  riscv_gpr_names[EXTRACT_OPERAND (CRS1S, l) + 8]);
				break;
			case 't': /* RS2 x8-x15 */
			case 'x': /* RS2 x8-x15 */
				r_strbuf_appendf (sb, "%s",
				  riscv_gpr_names[EXTRACT_OPERAND (CRS2S, l) + 8]);
				break;
			case 'U': /* RS1, constrained to equal RD */
				r_strbuf_appendf (sb, "%s", riscv_gpr_names[rd]);
				break;
			case 'c': /* RS1, constrained to equal sp */
				r_strbuf_appendf (sb, "%s", riscv_gpr_names[X_SP]);
				break;
			case 'V': /* RS2 */
				r_strbuf_appendf (sb, "%s",
				  riscv_gpr_names[EXTRACT_OPERAND (CRS2, l)]);
				break;
			case 'i':
				r_strbuf_appendf (sb, "%d", (int)EXTRACT_RVC_SIMM3 (l));
				break;
			case 'j':
				r_strbuf_appendf (sb, "%d", (int)EXTRACT_RVC_IMM (l));
				break;
			case 'k':
				r_strbuf_appendf (sb, "%d", (int)EXTRACT_RVC_LW_IMM (l));
				break;
			case 'l':
				r_strbuf_appendf (sb, "%d", (int)EXTRACT_RVC_LD_IMM (l));
				break;
			case 'm':
				r_strbuf_appendf (sb, "%d", (int)EXTRACT_RVC_LWSP_IMM (l));
				break;
			case 'n':
				r_strbuf_appendf (sb, "%d", (int)EXTRACT_RVC_LDSP_IMM (l));
				break;
			case 'K':
				r_strbuf_appendf (sb, "%d", (int)EXTRACT_RVC_ADDI4SPN_IMM (l));
				break;
			case 'L':
				r_strbuf_appendf (sb, "%d", (int)EXTRACT_RVC_ADDI16SP_IMM (l));
				break;
			case 'M':
				r_strbuf_appendf (sb, "%d", (int)EXTRACT_RVC_SWSP_IMM (l));
				break;
			case 'N':
				r_strbuf_appendf (sb, "%d", (int)EXTRACT_RVC_SDSP_IMM (l));
				break;
			case 'p':
				target = EXTRACT_RVC_B_IMM (l) + pc;
				r_strbuf_appendf (sb, "0x%"PFMT64x, (ut64) target);
				break;
			case 'a':
				target = EXTRACT_RVC_J_IMM (l) + pc;
				r_strbuf_appendf (sb, "0x%"PFMT64x, (ut64)target);
				break;
			case 'u':
				r_strbuf_appendf (sb, "0x%x",
				  (int) (EXTRACT_RVC_IMM (l) & (RISCV_BIGIMM_REACH-1)));
				break;
			case '>':
				r_strbuf_appendf (sb, "0x%x", (int) EXTRACT_RVC_IMM (l) & 0x3f);
				break;
			case '<':
				r_strbuf_appendf (sb, "0x%x", (int) EXTRACT_RVC_IMM (l) & 0x1f);
				break;
			case 'T': /* floating-point RS2 */
				r_strbuf_appendf (sb, "%s",
				  riscv_fpr_names[EXTRACT_OPERAND (CRS2, l)]);
				break;
			case 'D': /* floating-point RS2 x8-x15 */
				r_strbuf_appendf (sb, "%s",
				  riscv_fpr_names[EXTRACT_OPERAND (CRS2S, l) + 8]);
				break;
			}
			break;

		case ',':
			r_strbuf_appendf (sb, "%c ", *d);
			break;
		case '(':
		case ')':
		case '[':
		case ']':
			r_strbuf_appendf (sb, "%c", *d);
			break;
		case '0':
			/* Only print constant 0 if it is the last argument */
			if (!d[1]) {
				r_strbuf_append (sb, "0");
			}
			break;

		case 'b':
		case 's':
			r_strbuf_appendf (sb, "%s", riscv_gpr_names[rs1]);
			break;

		case 't':
			r_strbuf_appendf (sb, "%s",
			  riscv_gpr_names[EXTRACT_OPERAND (RS2, l)]);
			break;

		case 'u':
			r_strbuf_appendf (sb, "0x%x",
			  (unsigned) EXTRACT_UTYPE_IMM (l) >> RISCV_IMM_BITS);
			break;

		case 'm':
			arg_p (sb, EXTRACT_OPERAND (RM, l),
			  riscv_rm, ARRAY_SIZE (riscv_rm));
			break;

		case 'P':
			arg_p (sb, EXTRACT_OPERAND (PRED, l),
			  riscv_pred_succ, ARRAY_SIZE (riscv_pred_succ));
			break;

		case 'Q':
			arg_p (sb, EXTRACT_OPERAND (SUCC, l),
			  riscv_pred_succ, ARRAY_SIZE (riscv_pred_succ));
			break;
		case 'o':
		case 'j':
			r_strbuf_appendf (sb, "%d", (int) EXTRACT_ITYPE_IMM (l));
			break;
		case 'q':
			r_strbuf_appendf (sb, "%d", (int) EXTRACT_STYPE_IMM (l));
			break;
		case 'a':
			target = EXTRACT_UJTYPE_IMM (l) + pc;
			r_strbuf_appendf (sb, "0x%"PFMT64x, (ut64)target);
			break;
		case 'p':
			target = EXTRACT_SBTYPE_IMM (l) + pc;
			r_strbuf_appendf (sb, "0x%"PFMT64x, (ut64)target);
			break;
		case 'd':
			r_strbuf_appendf (sb, "%s", riscv_gpr_names[rd]);
			break;
		case 'z':
			r_strbuf_appendf (sb, "%s", riscv_gpr_names[0]);
			break;
		case '>':
			r_strbuf_appendf (sb, "0x%x", (int) EXTRACT_OPERAND (SHAMT, l));
			break;
		case '<':
			r_strbuf_appendf (sb, "0x%x", (int) EXTRACT_OPERAND (SHAMTW, l));
			break;
		case 'S':
		case 'U':
			r_strbuf_appendf (sb, "%s", riscv_fpr_names[rs1]);
			break;
		case 'T':
			r_strbuf_appendf (sb, "%s", riscv_fpr_names[EXTRACT_OPERAND (RS2, l)]);
			break;
		case 'D':
			r_strbuf_appendf (sb, "%s", riscv_fpr_names[rd]);
			break;
		case 'R':
			r_strbuf_appendf (sb, "%s", riscv_fpr_names[EXTRACT_OPERAND (RS3, l)]);
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
					r_strbuf_appendf (sb, "%s", csr_name);
				} else {
					r_strbuf_appendf (sb, "0x%x", csr);
				}
				break;
			}
		case 'Z':
			r_strbuf_appendf (sb, "%d", rs1);
			break;
		default:
			/* xgettext:c-format */
			r_strbuf_appendf (sb, "# internal error, undefined modifier (%c)", *d);
			return;
		}
	}
}
