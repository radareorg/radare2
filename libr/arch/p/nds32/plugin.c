/* radare - MIT - Copyright 2023-2025 - pancake, decaduto */

#include <r_arch.h>
#include <r_lib.h>

#define _GNU_SOURCE
#include <stdio.h>
#include "nds32-opc.h"
#include "nds32-dis.h"

typedef uint32_t insn_t;
#define OP_MASK_OP 0x7f

typedef struct plugin_data_t {
	bool init0;
	const struct nds32_opcode *nds32_hash[OP_MASK_OP + 1];
} PluginData;

#define is_any(...) _is_any (name, __VA_ARGS__, NULL)
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

static void fill_args(RList *args, char **av, int avsz) {
	RListIter *iter;
	char *arg;
	int i;
	for (i = 0; i < avsz; i++) {
		av[i] = "";
	}
	i = 0;
	r_list_foreach (args, iter, arg) {
		if (i >= avsz) {
			break;
		}
		r_str_trim (arg);
		av[i++] = arg;
	}
}

static char *parse_gp_off(char *off) {
	if (!off || !*off) {
		return "";
	}
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
	if (!addr || !*addr) {
		return "";
	}
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

	as->data = R_NEW0 (PluginData);
	return !!as->data;
}

static void decode_esil(RAnalOp *op) {
	char *name = strdup (op->mnemonic);
	char *space = strchr (name, ' ');
	RList *args = NULL;
	char *av[8];
	if (space) {
		*space++ = 0;
		args = r_str_split_list (space, ",", 0);
	} else {
		args = r_list_new ();
	}
	fill_args (args, av, R_ARRAY_SIZE (av));
	if (is_any ("sethi")) {
		char *dr = av[0];
		char *si = av[1];
		r_strbuf_setf (&op->esil, "12,%s,<<,%s,:=", si, dr);
	} else if (is_any ("jral5")) {
		char *dr = av[0];
		r_strbuf_setf (&op->esil, "pc,2,+,lp,:=,%s,pc,:=", dr);
	} else if (is_any ("jral")) {
		// jral rt, rb: rt = pc + 4, pc = rb
		char *rt = av[0];
		char *rb = av[1];
		r_strbuf_setf (&op->esil, "pc,4,+,%s,:=,%s,pc,:=", rt, rb);
	} else if (is_any ("jal")) {
		char *addr = av[0];
		r_strbuf_setf (&op->esil, "pc,4,+,lp,:=,%s,pc,:=", addr);
	} else if (is_any ("jr5")) {
		char *dr = av[0];
		r_strbuf_setf (&op->esil, "%s,pc,:=", dr);
	} else if (is_any ("jr")) {
		char *dr = av[0];
		r_strbuf_setf (&op->esil, "%s,pc,:=", dr);
	} else if (is_any ("j8", "j")) {
		char *di = av[0];
		r_strbuf_setf (&op->esil, "%s,pc,:=", di);
	} else if (is_any ("ret", "ret5")) {
		r_strbuf_set (&op->esil, "lp,pc,:=");
	} else if (is_any ("beq")) {
		char *s0 = av[0];
		char *s1 = av[1];
		char *di = av[2];
		r_strbuf_setf (&op->esil, "%s,%s,==,$z,?{,%s,pc,:=,}", s0, s1, di);
	} else if (is_any ("bne")) {
		char *s0 = av[0];
		char *s1 = av[1];
		char *di = av[2];
		r_strbuf_setf (&op->esil, "%s,%s,==,$z,!,?{,%s,pc,:=,}", s0, s1, di);
	} else if (is_any ("beqz")) {
		char *s0 = av[0];
		char *di = av[1];
		r_strbuf_setf (&op->esil, "%s,0,==,$z,?{,%s,pc,:=,}", s0, di);
	} else if (is_any ("bnez")) {
		char *s0 = av[0];
		char *di = av[1];
		r_strbuf_setf (&op->esil, "%s,0,==,$z,!,?{,%s,pc,:=,}", s0, di);
	} else if (is_any ("bnezs8")) {
		char *di = av[0];
		r_strbuf_setf (&op->esil, "r5,0,==,$z,!,?{,%s,pc,:=,}", di);
	} else if (is_any ("sbi.gp")) {
		char *val = av[0];
		char *num = parse_gp_off (av[1]);
		if (*num) {
			r_strbuf_setf (&op->esil, "%s,gp,%s,+,=[1]", val, num);
		}
	} else if (is_any ("lbi.gp")) {
		char *reg = av[0];
		char *num = parse_gp_off (av[1]);
		if (*num) {
			r_strbuf_setf (&op->esil, "gp,%s,+,[1],%s,:=", num, reg);
		}
	} else if (is_any ("lwi.gp")) {
		char *reg = av[0];
		char *num = parse_gp_off (av[1]);
		if (*num) {
			r_strbuf_setf (&op->esil, "gp,%s,+,[4],%s,:=", num, reg);
		}
	} else if (is_any ("swi.gp")) {
		char *val = av[0];
		char *num = parse_gp_off (av[1]);
		if (*num) {
			r_strbuf_setf (&op->esil, "%s,gp,%s,+,=[4]", val, num);
		}
	} else if (is_any ("shi.gp")) {
		char *val = av[0];
		char *num = parse_gp_off (av[1]);
		if (*num) {
			r_strbuf_setf (&op->esil, "%s,gp,%s,+,=[2]", val, num);
		}
	} else if (is_any ("shi")) {
		char *val = av[0];
		char *addr = parse_mem_addr (av[1]);
		if (*addr) {
			char *plus = strstr (addr, " + ");
			if (plus) {
				*plus = 0;
				char *reg = addr;
				char *off = plus + 3;
				r_str_trim (reg);
				r_str_trim (off);
				r_strbuf_setf (&op->esil, "%s,%s,%s,+,=[2]", val, reg, off);
			} else {
				r_strbuf_setf (&op->esil, "%s,%s,=[2]", val, addr);
			}
		}
	} else if (is_any ("addi.gp")) {
		char *reg = av[0];
		char *imm = av[1];
		r_strbuf_setf (&op->esil, "gp,%s,+,%s,:=", imm, reg);
	} else if (is_any ("addri36.sp")) {
		char *reg = av[0];
		char *imm = av[1];
		r_strbuf_setf (&op->esil, "sp,%s,+,%s,:=", imm, reg);
	} else if (is_any ("ori")) {
		char *dr = av[0];
		char *sr = av[1];
		char *si = av[2];
		r_strbuf_setf (&op->esil, "%s,%s,|,%s,:=", si, sr, dr);
	} else if (is_any ("addi")) {
		char *dr = av[0];
		char *sr = av[1];
		char *si = av[2];
		r_strbuf_setf (&op->esil, "%s,%s,+,%s,:=", si, sr, dr);
	} else if (is_any ("subri")) {
		char *dr = av[0];
		char *sr = av[1];
		char *si = av[2];
		r_strbuf_setf (&op->esil, "%s,%s,-,%s,:=", sr, si, dr);
	} else if (is_any ("andi")) {
		char *dr = av[0];
		char *sr = av[1];
		char *si = av[2];
		r_strbuf_setf (&op->esil, "%s,%s,&,%s,:=", si, sr, dr);
	} else if (is_any ("addi45")) {
		char *rt = av[0];
		char *imm = av[1];
		r_strbuf_setf (&op->esil, "%s,%s,+,%s,:=", imm, rt, rt);
	} else if (is_any ("xori")) {
		char *dr = av[0];
		char *sr = av[1];
		char *si = av[2];
		r_strbuf_setf (&op->esil, "%s,%s,^,%s,:=", si, sr, dr);
	} else if (is_any ("slli")) {
		char *dr = av[0];
		char *sr = av[1];
		char *si = av[2];
		r_strbuf_setf (&op->esil, "%s,%s,<<,%s,:=", si, sr, dr);
	} else if (is_any ("srli")) {
		char *dr = av[0];
		char *sr = av[1];
		char *si = av[2];
		r_strbuf_setf (&op->esil, "%s,%s,>>,%s,:=", si, sr, dr);
	} else if (is_any ("srai")) {
		char *dr = av[0];
		char *sr = av[1];
		char *si = av[2];
		r_strbuf_setf (&op->esil, "%s,%s,ASR,%s,:=", si, sr, dr);
	} else if (is_any ("movi")) {
		char *dr = av[0];
		char *si = av[1];
		r_strbuf_setf (&op->esil, "%s,%s,:=", si, dr);
	} else if (is_any ("mov")) {
		char *dr = av[0];
		char *sr = av[1];
		r_strbuf_setf (&op->esil, "%s,%s,:=", sr, dr);
	} else if (is_any ("lwi")) {
		char *dr = av[0];
		char *sr = av[1];
		r_strbuf_setf (&op->esil, "%s,[4],%s,:=", sr, dr);
	} else if (is_any ("swi")) {
		char *sr = av[0];
		char *dr = av[1];
		r_strbuf_setf (&op->esil, "%s,%s,=[4]", sr, dr);
		// else if (is_any ("addi", "addri"))
	} else if (is_any ("pop25")) {
		char *reg = av[0];
		// pop reg from stack: reg = [sp], sp += 4
		r_strbuf_setf (&op->esil, "sp,[4],%s,:=,sp,4,+,sp,:=", reg);
	} else if (is_any ("maddr32")) {
		char *rt = av[0];
		char *ra = av[1];
		char *rb = av[2];
		r_strbuf_setf (&op->esil, "%s,%s,*,%s,+,%s,:=", rb, ra, rt, rt);
	} else if (is_any ("add_slli")) {
		char *rt = av[0];
		char *ra = av[1];
		char *rb = av[2];
		char *sh = av[3];
		r_strbuf_setf (&op->esil, "%s,%s,<<,%s,+,%s,:=", sh, rb, ra, rt);
	} else if (is_any ("sub333")) {
		char *rt = av[0];
		char *ra = av[1];
		char *rb = av[2];
		r_strbuf_setf (&op->esil, "%s,%s,-,%s,:=", rb, ra, rt);
	} else if (is_any ("add333")) {
		char *rt = av[0];
		char *ra = av[1];
		char *rb = av[2];
		r_strbuf_setf (&op->esil, "%s,%s,+,%s,:=", rb, ra, rt);
	} else if (is_any ("lmw.adm")) {
		r_strbuf_set (&op->esil, "");
	} else if (is_any ("smw.adm")) {
		r_strbuf_set (&op->esil, "");
	} else if (is_any ("subi333")) {
		char *rt = av[0];
		char *ra = av[1];
		char *imm = av[2];
		r_strbuf_setf (&op->esil, "%s,%s,-,%s,:=", imm, ra, rt);
	} else if (is_any ("mtusr")) {
		r_strbuf_set (&op->esil, "");
	} else if (is_any ("zeh33")) {
		char *rt = av[0];
		char *ra = av[1];
		r_strbuf_setf (&op->esil, "0xffff,%s,&,%s,:=", ra, rt);
	} else if (is_any ("srli45")) {
		char *rt = av[0];
		char *imm = av[1];
		r_strbuf_setf (&op->esil, "%s,%s,>>,%s,:=", imm, rt, rt);
	} else if (is_any ("divr")) {
		char *rt = av[0];
		char *ra = av[1];
		char *rb = av[2];
		r_strbuf_setf (&op->esil, "%s,%s,/,%s,:=", rb, ra, rt);
	} else if (is_any ("or33")) {
		char *rt = av[0];
		char *ra = av[1];
		r_strbuf_setf (&op->esil, "%s,%s,|,%s,:=", ra, rt, rt);
	} else if (is_any ("mul")) {
		char *rt = av[0];
		char *ra = av[1];
		char *rb = av[2];
		r_strbuf_setf (&op->esil, "%s,%s,*,%s,:=", rb, ra, rt);
	} else if (is_any ("slts45")) {
		// slts45 rt, ra: ta = (rt <s ra) ? 1 : 0 (signed)
		char *rt = av[0];
		char *ra = av[1];
		r_strbuf_setf (&op->esil, "%s,%s,<,ta,:=", ra, rt);
	} else if (is_any ("slt45")) {
		// slt45 rt, ra: ta = (rt < ra) ? 1 : 0 (unsigned)
		char *rt = av[0];
		char *ra = av[1];
		r_strbuf_setf (&op->esil, "%s,%s,<,ta,:=", ra, rt);
	} else if (is_any ("mul33")) {
		char *rt = av[0];
		char *ra = av[1];
		r_strbuf_setf (&op->esil, "%s,%s,*,%s,:=", ra, rt, rt);
	} else if (is_any ("isb")) {
		r_strbuf_set (&op->esil, "");
	} else if (is_any ("bgtz")) {
		char *reg = av[0];
		char *addr = av[1];
		r_strbuf_setf (&op->esil, "%s,0,>,?{,%s,pc,:=,}", reg, addr);
	} else if (is_any ("lbi")) {
		char *dr = av[0];
		char *addr = parse_mem_addr (av[1]);
		if (*addr) {
			char *plus = strstr (addr, " + ");
			if (plus) {
				*plus = 0;
				char *reg = addr;
				char *off = plus + 3;
				r_str_trim (reg);
				r_str_trim (off);
				r_strbuf_setf (&op->esil, "%s,%s,+,[1],%s,:=", reg, off, dr);
			} else {
				r_strbuf_setf (&op->esil, "%s,[1],%s,:=", addr, dr);
			}
		}
	} else if (is_any ("sbi")) {
		char *sr = av[0];
		char *dr = av[1];
		r_strbuf_setf (&op->esil, "%s,%s,=[1]", sr, dr);
	} else if (is_any ("push25")) {
		char *reg = av[0];
		// push reg to stack: sp -= 4, [sp] = reg
		r_strbuf_setf (&op->esil, "sp,4,-,sp,:=,%s,sp,=[4]", reg);
	} else if (is_any ("ex9.it")) {
		// execute IT instruction, probably no ESIL effect
		r_strbuf_set (&op->esil, "");
	} else if (is_any ("fexti33")) {
		char *rt = av[0];
		char *imm = av[1];
		// field extract: assume rt = rt &((1 << imm) - 1)
		r_strbuf_setf (&op->esil, "1,%s,<<,1,-,%s,&,%s,:=", imm, rt, rt);
	} else if (is_any ("sltsi45")) {
		// sltsi45 rt, imm: ta = (rt <s imm) ? 1 : 0 (signed)
		char *rt = av[0];
		char *imm = av[1];
		r_strbuf_setf (&op->esil, "%s,%s,<,ta,:=", imm, rt);
	} else if (is_any ("slti45")) {
		// slti45 rt, imm: ta = (rt < imm) ? 1 : 0 (unsigned)
		char *rt = av[0];
		char *imm = av[1];
		r_strbuf_setf (&op->esil, "%s,%s,<,ta,:=", imm, rt);
	// --- missing branch ESIL ---
	} else if (is_any ("beqzs8")) {
		char *di = av[0];
		r_strbuf_setf (&op->esil, "r5,!,?{,%s,pc,:=,}", di);
	} else if (is_any ("bgez")) {
		char *reg = av[0];
		char *addr = av[1];
		// branch if reg >= 0: sign bit (bit 31) is 0
		r_strbuf_setf (&op->esil, "31,%s,>>,!,?{,%s,pc,:=,}", reg, addr);
	} else if (is_any ("bltz")) {
		char *reg = av[0];
		char *addr = av[1];
		// branch if reg < 0: sign bit (bit 31) is 1
		r_strbuf_setf (&op->esil, "31,%s,>>,?{,%s,pc,:=,}", reg, addr);
	} else if (is_any ("blez")) {
		char *reg = av[0];
		char *addr = av[1];
		// branch if reg <= 0: reg == 0 or sign bit set
		r_strbuf_setf (&op->esil, "%s,!,31,%s,>>,|,?{,%s,pc,:=,}", reg, reg, addr);
	} else if (is_any ("beqz38")) {
		char *reg = av[0];
		char *addr = av[1];
		r_strbuf_setf (&op->esil, "%s,!,?{,%s,pc,:=,}", reg, addr);
	} else if (is_any ("bnez38")) {
		char *reg = av[0];
		char *addr = av[1];
		r_strbuf_setf (&op->esil, "%s,?{,%s,pc,:=,}", reg, addr);
	} else if (is_any ("beqs38")) {
		char *reg = av[0];
		char *addr = av[1];
		r_strbuf_setf (&op->esil, "%s,r5,==,$z,?{,%s,pc,:=,}", reg, addr);
	} else if (is_any ("bnes38")) {
		char *reg = av[0];
		char *addr = av[1];
		r_strbuf_setf (&op->esil, "%s,r5,==,$z,!,?{,%s,pc,:=,}", reg, addr);
	} else if (is_any ("beqc")) {
		char *reg = av[0];
		char *imm = av[1];
		char *addr = av[2];
		r_strbuf_setf (&op->esil, "%s,%s,==,$z,?{,%s,pc,:=,}", imm, reg, addr);
	} else if (is_any ("bnec")) {
		char *reg = av[0];
		char *imm = av[1];
		char *addr = av[2];
		r_strbuf_setf (&op->esil, "%s,%s,==,$z,!,?{,%s,pc,:=,}", imm, reg, addr);
	// --- missing ALU 3-reg ESIL ---
	} else if (is_any ("add ")) {
		char *rt = av[0];
		char *ra = av[1];
		char *rb = av[2];
		r_strbuf_setf (&op->esil, "%s,%s,+,%s,:=", rb, ra, rt);
	} else if (is_any ("sub ")) {
		char *rt = av[0];
		char *ra = av[1];
		char *rb = av[2];
		r_strbuf_setf (&op->esil, "%s,%s,-,%s,:=", rb, ra, rt);
	} else if (is_any ("and ")) {
		char *rt = av[0];
		char *ra = av[1];
		char *rb = av[2];
		r_strbuf_setf (&op->esil, "%s,%s,&,%s,:=", rb, ra, rt);
	} else if (is_any ("or ")) {
		char *rt = av[0];
		char *ra = av[1];
		char *rb = av[2];
		r_strbuf_setf (&op->esil, "%s,%s,|,%s,:=", rb, ra, rt);
	} else if (is_any ("xor ")) {
		char *rt = av[0];
		char *ra = av[1];
		char *rb = av[2];
		r_strbuf_setf (&op->esil, "%s,%s,^,%s,:=", rb, ra, rt);
	} else if (is_any ("nor ")) {
		char *rt = av[0];
		char *ra = av[1];
		char *rb = av[2];
		r_strbuf_setf (&op->esil, "%s,%s,|,~,%s,:=", rb, ra, rt);
	} else if (is_any ("sll ")) {
		char *rt = av[0];
		char *ra = av[1];
		char *rb = av[2];
		r_strbuf_setf (&op->esil, "%s,%s,<<,%s,:=", rb, ra, rt);
	} else if (is_any ("srl ")) {
		char *rt = av[0];
		char *ra = av[1];
		char *rb = av[2];
		r_strbuf_setf (&op->esil, "%s,%s,>>,%s,:=", rb, ra, rt);
	} else if (is_any ("sra ")) {
		char *rt = av[0];
		char *ra = av[1];
		char *rb = av[2];
		r_strbuf_setf (&op->esil, "%s,%s,ASR,%s,:=", rb, ra, rt);
	} else if (is_any ("slt ")) {
		// slt rt, ra, rb: rt = (ra < rb) ? 1 : 0 (unsigned)
		char *rt = av[0];
		char *ra = av[1];
		char *rb = av[2];
		r_strbuf_setf (&op->esil, "%s,%s,<,%s,:=", rb, ra, rt);
	} else if (is_any ("slts ")) {
		// slts rt, ra, rb: rt = (ra <s rb) ? 1 : 0 (signed)
		char *rt = av[0];
		char *ra = av[1];
		char *rb = av[2];
		r_strbuf_setf (&op->esil, "%s,%s,<,%s,:=", rb, ra, rt);
	} else if (is_any ("slti ")) {
		// slti rt, ra, imm: rt = (ra < imm) ? 1 : 0
		char *rt = av[0];
		char *ra = av[1];
		char *imm = av[2];
		r_strbuf_setf (&op->esil, "%s,%s,<,%s,:=", imm, ra, rt);
	} else if (is_any ("sltsi ")) {
		char *rt = av[0];
		char *ra = av[1];
		char *imm = av[2];
		r_strbuf_setf (&op->esil, "%s,%s,<,%s,:=", imm, ra, rt);
	} else if (is_any ("bitc")) {
		// bitc rt, ra, rb: rt = ra & ~rb
		char *rt = av[0];
		char *ra = av[1];
		char *rb = av[2];
		r_strbuf_setf (&op->esil, "%s,~,%s,&,%s,:=", rb, ra, rt);
	} else if (is_any ("bitci")) {
		// bitci rt, ra, imm: rt = ra & ~imm
		char *rt = av[0];
		char *ra = av[1];
		char *imm = av[2];
		r_strbuf_setf (&op->esil, "%s,~,%s,&,%s,:=", imm, ra, rt);
	} else if (is_any ("cmovz")) {
		// cmovz rt, ra, rb: if rb == 0 then rt = ra
		char *rt = av[0];
		char *ra = av[1];
		char *rb = av[2];
		r_strbuf_setf (&op->esil, "%s,!,?{,%s,%s,:=,}", rb, ra, rt);
	} else if (is_any ("cmovn")) {
		// cmovn rt, ra, rb: if rb != 0 then rt = ra
		char *rt = av[0];
		char *ra = av[1];
		char *rb = av[2];
		r_strbuf_setf (&op->esil, "%s,?{,%s,%s,:=,}", rb, ra, rt);
	// --- missing 16-bit compact ESIL ---
	} else if (is_any ("mov55")) {
		char *rt = av[0];
		char *ra = av[1];
		r_strbuf_setf (&op->esil, "%s,%s,:=", ra, rt);
	} else if (is_any ("movi55")) {
		char *rt = av[0];
		char *imm = av[1];
		r_strbuf_setf (&op->esil, "%s,%s,:=", imm, rt);
	} else if (is_any ("add45")) {
		char *rt = av[0];
		char *ra = av[1];
		r_strbuf_setf (&op->esil, "%s,%s,+,%s,:=", ra, rt, rt);
	} else if (is_any ("sub45")) {
		char *rt = av[0];
		char *ra = av[1];
		r_strbuf_setf (&op->esil, "%s,%s,-,%s,:=", ra, rt, rt);
	} else if (is_any ("subi45")) {
		char *rt = av[0];
		char *imm = av[1];
		r_strbuf_setf (&op->esil, "%s,%s,-,%s,:=", imm, rt, rt);
	} else if (is_any ("srai45")) {
		char *rt = av[0];
		char *imm = av[1];
		r_strbuf_setf (&op->esil, "%s,%s,ASR,%s,:=", imm, rt, rt);
	} else if (is_any ("slli333")) {
		char *rt = av[0];
		char *ra = av[1];
		char *imm = av[2];
		r_strbuf_setf (&op->esil, "%s,%s,<<,%s,:=", imm, ra, rt);
	} else if (is_any ("addi333")) {
		char *rt = av[0];
		char *ra = av[1];
		char *imm = av[2];
		r_strbuf_setf (&op->esil, "%s,%s,+,%s,:=", imm, ra, rt);
	} else if (is_any ("neg33")) {
		char *rt = av[0];
		char *ra = av[1];
		r_strbuf_setf (&op->esil, "0,%s,-,%s,:=", ra, rt);
	} else if (is_any ("not33")) {
		char *rt = av[0];
		char *ra = av[1];
		r_strbuf_setf (&op->esil, "%s,~,%s,:=", ra, rt);
	} else if (is_any ("and33")) {
		char *rt = av[0];
		char *ra = av[1];
		r_strbuf_setf (&op->esil, "%s,%s,&,%s,:=", ra, rt, rt);
	} else if (is_any ("xor33")) {
		char *rt = av[0];
		char *ra = av[1];
		r_strbuf_setf (&op->esil, "%s,%s,^,%s,:=", ra, rt, rt);
	} else if (is_any ("seb33")) {
		// sign extend byte
		char *rt = av[0];
		char *ra = av[1];
		r_strbuf_setf (&op->esil, "24,%s,<<,24,ASR,%s,:=", ra, rt);
	} else if (is_any ("seh33")) {
		// sign extend halfword
		char *rt = av[0];
		char *ra = av[1];
		r_strbuf_setf (&op->esil, "16,%s,<<,16,ASR,%s,:=", ra, rt);
	} else if (is_any ("seb ")) {
		char *rt = av[0];
		char *ra = av[1];
		r_strbuf_setf (&op->esil, "24,%s,<<,24,ASR,%s,:=", ra, rt);
	} else if (is_any ("seh ")) {
		char *rt = av[0];
		char *ra = av[1];
		r_strbuf_setf (&op->esil, "16,%s,<<,16,ASR,%s,:=", ra, rt);
	} else if (is_any ("zeh ")) {
		// zero extend halfword
		char *rt = av[0];
		char *ra = av[1];
		r_strbuf_setf (&op->esil, "0xffff,%s,&,%s,:=", ra, rt);
	} else if (is_any ("zeb33")) {
		// zero extend byte
		char *rt = av[0];
		char *ra = av[1];
		r_strbuf_setf (&op->esil, "0xff,%s,&,%s,:=", ra, rt);
	} else if (is_any ("xlsb33")) {
		// extract LSB
		char *rt = av[0];
		char *ra = av[1];
		r_strbuf_setf (&op->esil, "1,%s,&,%s,:=", ra, rt);
	} else if (is_any ("movpi45")) {
		char *rt = av[0];
		char *imm = av[1];
		r_strbuf_setf (&op->esil, "%s,%s,:=", imm, rt);
	} else if (is_any ("addi10s")) {
		char *imm = av[0];
		r_strbuf_setf (&op->esil, "%s,sp,+,sp,:=", imm);
	} else if (is_any ("rotri")) {
		char *rt = av[0];
		char *ra = av[1];
		char *imm = av[2];
		r_strbuf_setf (&op->esil, "%s,%s,>>>,%s,:=", imm, ra, rt);
	} else if (is_any ("nop")) {
		r_strbuf_set (&op->esil, "");
	} else if (is_any ("dsb", "msync", "isync", "standby")) {
		r_strbuf_set (&op->esil, "");
	} else if (is_any ("mfusr")) {
		r_strbuf_set (&op->esil, "");
	} else if (is_any ("lmw", "smw")) {
		// complex multi-register load/store - skip ESIL
		r_strbuf_set (&op->esil, "");
	}
	r_list_free (args);
	free (name);
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
	char *name = strdup (op->mnemonic);
#if 0
	PluginData *pd = as->data;
	struct nds32_opcode *o = nds32_get_opcode (pd, word);
	if (o) {
		if (op->mnemonic) {
			name = op->mnemonic;
		}
	}
#endif

	const char *arg = strstr (name, "0x");
	if (!arg) {
		arg = strstr (name, ", ");
		if (arg) {
			arg += 2;
		} else {
			arg = strchr (name, ' ');
			if (arg) {
				arg++;
			}
		}
	}
	if (mask & R_ARCH_OP_MASK_ESIL) {
		decode_esil (op);
	}
	// control flow
	if (is_any ("jral5")) {
		op->type = R_ANAL_OP_TYPE_RCALL;
	} else if (is_any ("jral ")) {
		op->type = R_ANAL_OP_TYPE_RCALL;
		op->fail = addr + op->size;
	} else if (is_any ("jr5")) {
		op->type = R_ANAL_OP_TYPE_RJMP;
	} else if (is_any ("jr ")) {
		op->type = R_ANAL_OP_TYPE_RJMP;
	} else if (is_any ("jal ")) {
		op->type = R_ANAL_OP_TYPE_CALL;
		op->jump = arg? r_num_get (NULL, arg): op->addr;
		op->fail = addr + op->size;
	} else if (is_any ("j8", "j ")) {
		op->type = R_ANAL_OP_TYPE_JMP;
		op->jump = arg? r_num_get (NULL, arg): op->addr;
	} else if (is_any ("ret", "iret")) {
		op->type = R_ANAL_OP_TYPE_RET;
	} else if (is_any ("bgezal", "bltzal")) {
		op->type = R_ANAL_OP_TYPE_CCALL;
		op->jump = arg? r_num_get (NULL, arg): op->addr;
		op->fail = addr + op->size;
	} else if (is_any ("ifcall")) {
		op->type = R_ANAL_OP_TYPE_CCALL;
		op->jump = arg? r_num_get (NULL, arg): op->addr;
		op->fail = addr + op->size;
	} else if (is_any ("beqz", "bnez", "beq", "bne ", "blez", "bgez", "bltz", "bgtz",
			"beqs38", "bnes38", "beqz38", "bnez38", "beqzs8", "bnezs8",
			"beqc", "bnec")) {
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = arg? r_num_get (NULL, arg): op->addr;
		op->fail = addr + op->size;
	// arithmetic
	} else if (is_any ("addi", "addri", "addi.gp", "addri36.sp", "addi10s", "addi333", "addi45",
			"add333", "add45", "add5.pc", "add_slli", "add_srli", "add.sc", "add.wc", "add ")) {
		op->type = R_ANAL_OP_TYPE_ADD;
	} else if (is_any ("subi", "subri", "sub333", "sub45", "subi333", "subi45",
			"sub_slli", "sub_srli", "sub.sc", "sub.wc", "sub ")) {
		op->type = R_ANAL_OP_TYPE_SUB;
	} else if (is_any ("mul33", "mul ", "maddr32", "msubr32", "madd", "msub", "mult")) {
		op->type = R_ANAL_OP_TYPE_MUL;
	} else if (is_any ("divr", "divsr", "divs", "div ")) {
		op->type = R_ANAL_OP_TYPE_DIV;
	// bitwise
	} else if (is_any ("ori", "or33", "or_slli", "or_srli", "or ")) {
		op->type = R_ANAL_OP_TYPE_OR;
	} else if (is_any ("xori", "xor33", "xor_slli", "xor_srli", "xor ")) {
		op->type = R_ANAL_OP_TYPE_XOR;
	} else if (is_any ("andi", "and33", "and_slli", "and_srli", "and ", "bitci")) {
		op->type = R_ANAL_OP_TYPE_AND;
	} else if (is_any ("nor ")) {
		op->type = R_ANAL_OP_TYPE_NOR;
	} else if (is_any ("not33")) {
		op->type = R_ANAL_OP_TYPE_NOT;
	// shifts
	} else if (is_any ("slli", "sll ", "slli333")) {
		op->type = R_ANAL_OP_TYPE_SHL;
	} else if (is_any ("srli", "srl ", "srai", "sra ", "srli45", "srai45")) {
		op->type = R_ANAL_OP_TYPE_SHR;
	} else if (is_any ("rotri", "rotr ")) {
		op->type = R_ANAL_OP_TYPE_ROR;
	// load/store - more specific first to avoid startswith issues
	} else if (is_any ("lbi.gp", "lbsi.gp", "lwi.gp", "lhi.gp", "lhsi.gp")) {
		op->type = R_ANAL_OP_TYPE_LOAD;
	} else if (is_any ("sbi.gp", "swi.gp", "shi.gp")) {
		op->type = R_ANAL_OP_TYPE_STORE;
	} else if (is_any ("lwi", "lbi", "lhi", "ldi", "lbsi", "lhsi", "lwsi",
			"lwi333", "lbi333", "lhi333", "lwi450", "lwi37", "lwi45",
			"lw ", "lb ", "lh ", "ld ", "lbs", "lhs", "lws", "llw",
			"lmw", "fls", "fld", "flsi", "fldi")) {
		op->type = R_ANAL_OP_TYPE_LOAD;
	} else if (is_any ("swi", "sbi", "shi", "sdi",
			"swi333", "sbi333", "shi333", "swi450", "swi37",
			"sw ", "sb ", "sd ", "scw",
			"smw", "fss", "fsd", "fssi", "fsdi")) {
		op->type = R_ANAL_OP_TYPE_STORE;
	// move
	} else if (is_any ("mov55", "mov ", "movi55", "movi", "movpi45", "movd44",
			"sethi", "mfsr", "mtsr", "mfusr")) {
		op->type = R_ANAL_OP_TYPE_MOV;
	} else if (is_any ("cmovz", "cmovn")) {
		op->type = R_ANAL_OP_TYPE_CMOV;
	// compare
	} else if (is_any ("slt ", "slts ", "slt45", "slts45", "slti", "sltsi")) {
		op->type = R_ANAL_OP_TYPE_CMP;
	// sign/zero extend
	} else if (is_any ("zeh", "zeb", "seh", "seb", "xlsb")) {
		op->type = R_ANAL_OP_TYPE_MOV;
	// stack
	} else if (is_any ("push25")) {
		op->type = R_ANAL_OP_TYPE_PUSH;
	} else if (is_any ("pop25")) {
		op->type = R_ANAL_OP_TYPE_POP;
	// system
	} else if (is_any ("syscall")) {
		op->type = R_ANAL_OP_TYPE_SWI;
	} else if (is_any ("break", "trap", "teqz", "tnez")) {
		op->type = R_ANAL_OP_TYPE_TRAP;
	} else if (is_any ("nop")) {
		op->type = R_ANAL_OP_TYPE_NOP;
	} else if (is_any ("neg33")) {
		op->type = R_ANAL_OP_TYPE_SUB;
	} else if (is_any ("abs ")) {
		op->type = R_ANAL_OP_TYPE_ABS;
	} else if (is_any ("dsb", "isb", "msync", "isync", "standby", "cctl")) {
		op->type = R_ANAL_OP_TYPE_NOP;
	} else if (is_any ("mtusr")) {
		op->type = R_ANAL_OP_TYPE_MOV;
	}
	free (name);
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
		"gpr	pc	4	128	0\n";
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
	.info = &info,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ARCH,
	.data = &r_arch_plugin_nds32,
};
#endif
