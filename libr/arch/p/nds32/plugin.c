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

static int info(RArchSession *as, ut32 q) {
	switch (q) {
	case R_ARCH_INFO_MAXOP_SIZE:
		return 6;
	case R_ARCH_INFO_MINOP_SIZE:
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
	RList *args = r_list_new ();
	if (space) {
		*space++ = 0;
		args = r_str_split_list (space, ",", 0);
	} else {
		args = r_list_new ();
	}
	if (is_any ("sethi")) {
		char *dr = r_list_get_n (args, 0);
		char *si = r_list_get_n (args, 1);
		r_strbuf_setf (&op->esil, "12,%s,<<,%s,:=", si, dr);
	} else if (is_any ("j")) {
		char *di = r_list_get_n (args, 0);
		r_strbuf_setf (&op->esil, "%s,pc,:=", di);
	} else if (is_any ("jr")) {
		char *dr = r_list_get_n (args, 0);
		r_strbuf_setf (&op->esil, "%s,pc,:=", dr);
	} else if (is_any ("ret", "ret5")) {
		r_strbuf_set (&op->esil, "lp,pc,:=");
	} else if (is_any ("beq")) {
		char *s0 = r_list_get_n (args, 0);
		char *s1 = r_list_get_n (args, 1);
		char *di = r_list_get_n (args, 2);
		r_strbuf_setf (&op->esil, "%s,%s,==,$z,?{,%s,pc,:=,}", s0, s1, di);
	} else if (is_any ("bne")) {
		char *s0 = r_list_get_n (args, 0);
		char *s1 = r_list_get_n (args, 1);
		char *di = r_list_get_n (args, 2);
		r_strbuf_setf (&op->esil, "%s,%s,==,$z,!,?{,%s,pc,:=,}", s0, s1, di);
	} else if (is_any ("beqz")) {
		char *s0 = r_list_get_n (args, 0);
		char *di = r_list_get_n (args, 1);
		r_strbuf_setf (&op->esil, "%s,0,==,$z,?{,%s,pc,:=,}", s0, di);
	} else if (is_any ("bnez")) {
		char *s0 = r_list_get_n (args, 0);
		char *di = r_list_get_n (args, 1);
		r_strbuf_setf (&op->esil, "%s,0,==,$z,!,?{,%s,pc,:=,}", s0, di);
	} else if (is_any ("bnezs8")) {
		char *di = r_list_get_n (args, 0);
		r_strbuf_setf (&op->esil, "r5,0,==,$z,!,?{,%s,pc,:=,}", di);
	} else if (is_any ("sbi.gp")) {
		char *val = r_list_get_n (args, 0);
		char *off = r_list_get_n (args, 1);
		if (off) {
			r_str_trim (off);
			// assume format [+num] or num
			char *num = off;
			if (*num == '[') {
				num++;
			}
			if (*num == '+') {
				num++;
			}
			char *end = strchr (num, ']');
			if (end) {
				*end = 0;
			}
			r_strbuf_setf (&op->esil, "%s,gp,%s,+,[1],:=", val, num);
		}
	} else if (is_any ("lbi.gp")) {
		char *reg = r_list_get_n (args, 0);
		char *off = r_list_get_n (args, 1);
		if (off) {
			r_str_trim (off);
			char *num = off;
			if (*num == '[') {
				num++;
			}
			if (*num == '+') {
				num++;
			}
			char *end = strchr (num, ']');
			if (end) {
				*end = 0;
			}
			r_str_trim (num);
			r_strbuf_setf (&op->esil, "gp,%s,+,[1],%s,:=", num, reg);
		}
	} else if (is_any ("lwi.gp")) {
		char *reg = r_list_get_n (args, 0);
		char *off = r_list_get_n (args, 1);
		if (off) {
			r_str_trim (off);
			char *num = off;
			if (*num == '[') {
				num++;
			}
			if (*num == '+') {
				num++;
			}
			char *end = strchr (num, ']');
			if (end) {
				*end = 0;
			}
			r_strbuf_setf (&op->esil, "gp,%s,+,[4],%s,:=", num, reg);
		}
	} else if (is_any ("swi.gp")) {
		char *val = r_list_get_n (args, 0);
		char *off = r_list_get_n (args, 1);
		if (off) {
			r_str_trim (off);
			char *num = off;
			if (*num == '[') {
				num++;
			}
			if (*num == '+') {
				num++;
			}
			char *end = strchr (num, ']');
			if (end) {
				*end = 0;
			}
			r_strbuf_setf (&op->esil, "%s,gp,%s,+,[4],:=", val, num);
		}
	} else if (is_any ("shi.gp")) {
		char *val = r_list_get_n (args, 0);
		char *off = r_list_get_n (args, 1);
		if (off) {
			r_str_trim (off);
			char *num = off;
			if (*num == '[') {
				num++;
			}
			if (*num == '+') {
				num++;
			}
			char *end = strchr (num, ']');
			if (end) {
				*end = 0;
			}
			r_strbuf_setf (&op->esil, "%s,gp,%s,+,[2],:=", val, num);
		}
	} else if (is_any ("shi")) {
		char *val = r_list_get_n (args, 0);
		char *addr = r_list_get_n (args, 1);
		if (addr) {
			r_str_trim (addr);
			if (*addr == '[') addr++;
			char *plus = strstr (addr, " + ");
			if (plus) {
				*plus = 0;
				char *reg = addr;
				char *off = plus + 3;
				char *end = strchr (off, ']');
				if (end) *end = 0;
				r_strbuf_setf (&op->esil, "%s,%s,%s,+,[2],:=", val, reg, off);
			} else {
				char *end = strchr (addr, ']');
				if (end) *end = 0;
				r_strbuf_setf (&op->esil, "%s,%s,[2],:=", val, addr);
			}
		}
	} else if (is_any ("addi.gp")) {
		char *reg = r_list_get_n (args, 0);
		char *imm = r_list_get_n (args, 1);
		r_strbuf_setf (&op->esil, "gp,%s,+,%s,:=", imm, reg);
	} else if (is_any ("addri36.sp")) {
		char *reg = r_list_get_n (args, 0);
		char *imm = r_list_get_n (args, 1);
		r_strbuf_setf (&op->esil, "sp,%s,+,%s,:=", imm, reg);
	} else if (is_any ("ori")) {
		char *dr = r_list_get_n (args, 0);
		char *sr = r_list_get_n (args, 1);
		char *si = r_list_get_n (args, 2);
		r_strbuf_setf (&op->esil, "%s,%s,|,%s,:=", si, sr, dr);
	} else if (is_any ("addi")) {
		char *dr = r_list_get_n (args, 0);
		char *sr = r_list_get_n (args, 1);
		char *si = r_list_get_n (args, 2);
		r_strbuf_setf (&op->esil, "%s,%s,+,%s,:=", si, sr, dr);
	} else if (is_any ("subri")) {
		char *dr = r_list_get_n (args, 0);
		char *sr = r_list_get_n (args, 1);
		char *si = r_list_get_n (args, 2);
		r_strbuf_setf (&op->esil, "%s,%s,-,%s,:=", sr, si, dr);
	} else if (is_any ("andi")) {
		char *dr = r_list_get_n (args, 0);
		char *sr = r_list_get_n (args, 1);
		char *si = r_list_get_n (args, 2);
		r_strbuf_setf (&op->esil, "%s,%s,&,%s,:=", si, sr, dr);
	} else if (is_any ("addi45")) {
		char *rt = r_list_get_n (args, 0);
		char *imm = r_list_get_n (args, 1);
		r_strbuf_setf (&op->esil, "%s,%s,+,%s,:=", imm, rt, rt);
	} else if (is_any ("xori")) {
		char *dr = r_list_get_n (args, 0);
		char *sr = r_list_get_n (args, 1);
		char *si = r_list_get_n (args, 2);
		r_strbuf_setf (&op->esil, "%s,%s,^,%s,:=", si, sr, dr);
	} else if (is_any ("slli")) {
		char *dr = r_list_get_n (args, 0);
		char *sr = r_list_get_n (args, 1);
		char *si = r_list_get_n (args, 2);
		r_strbuf_setf (&op->esil, "%s,%s,<<,%s,:=", si, sr, dr);
	} else if (is_any ("srli")) {
		char *dr = r_list_get_n (args, 0);
		char *sr = r_list_get_n (args, 1);
		char *si = r_list_get_n (args, 2);
		r_strbuf_setf (&op->esil, "%s,%s,>>,%s,:=", si, sr, dr);
	} else if (is_any ("srai")) {
		char *dr = r_list_get_n (args, 0);
		char *sr = r_list_get_n (args, 1);
		char *si = r_list_get_n (args, 2);
		r_strbuf_setf (&op->esil, "%s,%s,>>>>,%s,:=", si, sr, dr);
	} else if (is_any ("movi")) {
		char *dr = r_list_get_n (args, 0);
		char *si = r_list_get_n (args, 1);
		r_strbuf_setf (&op->esil, "%s,%s,:=", si, dr);
	} else if (is_any ("mov")) {
		char *dr = r_list_get_n (args, 0);
		char *sr = r_list_get_n (args, 1);
		r_strbuf_setf (&op->esil, "%s,%s,:=", sr, dr);
	} else if (is_any ("lwi")) {
		char *dr = r_list_get_n (args, 0);
		char *sr = r_list_get_n (args, 1);
		r_strbuf_setf (&op->esil, "%s,[4],%s,:=", sr, dr);
	} else if (is_any ("swi")) {
		char *sr = r_list_get_n (args, 0);
		char *dr = r_list_get_n (args, 1);
		r_strbuf_setf (&op->esil, "%s,%s,[4],:=", sr, dr);
	// else if (is_any ("addi", "addri"))
	} else if (is_any ("pop25")) {
		char *reg = r_list_get_n (args, 0);
		// pop reg from stack: reg = [sp], sp += 4
		r_strbuf_setf (&op->esil, "sp,[4],%s,:=,sp,4,+,sp,:=", reg);
	} else if (is_any ("maddr32")) {
		char *rt = r_list_get_n (args, 0);
		char *ra = r_list_get_n (args, 1);
		char *rb = r_list_get_n (args, 2);
		r_strbuf_setf (&op->esil, "%s,%s,*,%s,+,%s,:=", rb, ra, rt, rt);
	} else if (is_any ("add_slli")) {
		char *rt = r_list_get_n (args, 0);
		char *ra = r_list_get_n (args, 1);
		char *rb = r_list_get_n (args, 2);
		char *sh = r_list_get_n (args, 3);
		r_strbuf_setf (&op->esil, "%s,%s,<<,%s,+,%s,:=", sh, rb, ra, rt);
	} else if (is_any ("sub333")) {
		char *rt = r_list_get_n (args, 0);
		char *ra = r_list_get_n (args, 1);
		char *rb = r_list_get_n (args, 2);
		r_strbuf_setf (&op->esil, "%s,%s,-,%s,:=", rb, ra, rt);
	} else if (is_any ("add333")) {
		char *rt = r_list_get_n (args, 0);
		char *ra = r_list_get_n (args, 1);
		char *rb = r_list_get_n (args, 2);
		r_strbuf_setf (&op->esil, "%s,%s,+,%s,:=", rb, ra, rt);
	} else if (is_any ("lmw.adm")) {
		r_strbuf_set (&op->esil, "");
	} else if (is_any ("smw.adm")) {
		r_strbuf_set (&op->esil, "");
	} else if (is_any ("subi333")) {
		char *rt = r_list_get_n (args, 0);
		char *ra = r_list_get_n (args, 1);
		char *imm = r_list_get_n (args, 2);
		r_strbuf_setf (&op->esil, "%s,%s,-,%s,:=", imm, ra, rt);
	} else if (is_any ("mtusr")) {
		r_strbuf_set (&op->esil, "");
	} else if (is_any ("zeh33")) {
		char *rt = r_list_get_n (args, 0);
		char *ra = r_list_get_n (args, 1);
		r_strbuf_setf (&op->esil, "0xffff,%s,&,%s,:=", ra, rt);
	} else if (is_any ("srli45")) {
		char *rt = r_list_get_n (args, 0);
		char *imm = r_list_get_n (args, 1);
		r_strbuf_setf (&op->esil, "%s,%s,>>,%s,:=", imm, rt, rt);
	} else if (is_any ("divr")) {
		char *rt = r_list_get_n (args, 0);
		char *ra = r_list_get_n (args, 1);
		char *rb = r_list_get_n (args, 2);
		r_strbuf_setf (&op->esil, "%s,%s,/,%s,:=", rb, ra, rt);
	} else if (is_any ("or33")) {
		char *rt = r_list_get_n (args, 0);
		char *ra = r_list_get_n (args, 1);
		r_strbuf_setf (&op->esil, "%s,%s,|,%s,:=", ra, rt, rt);
	} else if (is_any ("mul")) {
		char *rt = r_list_get_n (args, 0);
		char *ra = r_list_get_n (args, 1);
		char *rb = r_list_get_n (args, 2);
		r_strbuf_setf (&op->esil, "%s,%s,*,%s,:=", rb, ra, rt);
	} else if (is_any ("slt45")) {
		char *rt = r_list_get_n (args, 0);
		char *ra = r_list_get_n (args, 1);
		r_strbuf_setf (&op->esil, "%s,%s,<,?{,1,0,},%s,:=", rt, ra, rt);
	} else if (is_any ("mul33")) {
		char *rt = r_list_get_n (args, 0);
		char *ra = r_list_get_n (args, 1);
		r_strbuf_setf (&op->esil, "%s,%s,*,%s,:=", ra, rt, rt);
	} else if (is_any ("isb")) {
		r_strbuf_set (&op->esil, "");
	} else if (is_any ("bgtz")) {
		char *reg = r_list_get_n (args, 0);
		char *addr = r_list_get_n (args, 1);
		r_strbuf_setf (&op->esil, "%s,0,>,?{,%s,pc,:=,}", reg, addr);
	} else if (is_any ("lbi")) {
		char *dr = r_list_get_n (args, 0);
		char *addr = r_list_get_n (args, 1);
		if (addr && *addr == '[') {
			r_str_trim (addr);
			addr++;
			char *plus = strstr (addr, " + ");
			if (plus) {
				*plus = 0;
				char *reg = addr;
				char *off = plus + 3;
				char *end = strchr (off, ']');
				if (end) *end = 0;
				r_strbuf_setf (&op->esil, "%s,%s,+,[1],%s,:=", reg, off, dr);
			} else {
				char *end = strchr (addr, ']');
				if (end) *end = 0;
				r_strbuf_setf (&op->esil, "%s,[1],%s,:=", addr, dr);
			}
		} else {
			r_strbuf_setf (&op->esil, "%s,[1],%s,:=", addr, dr);
		}
	} else if (is_any ("sbi")) {
		char *sr = r_list_get_n (args, 0);
		char *dr = r_list_get_n (args, 1);
		r_strbuf_setf (&op->esil, "%s,%s,[1],:=", sr, dr);
	} else if (is_any ("push25")) {
		char *reg = r_list_get_n (args, 0);
		// push reg to stack: sp -= 4, [sp] = reg
		r_strbuf_setf (&op->esil, "sp,4,-,sp,:=,%s,sp,[4],:=", reg);
	} else if (is_any ("ex9.it")) {
		// execute IT instruction, probably no ESIL effect
		r_strbuf_set (&op->esil, "");
	} else if (is_any ("fexti33")) {
		char *rt = r_list_get_n (args, 0);
		char *imm = r_list_get_n (args, 1);
		// field extract: assume rt = rt &((1 << imm) - 1)
		r_strbuf_setf (&op->esil, "1,%s,<<,1,-,%s,&,%s,:=", imm, rt, rt);
	} else if (is_any ("slti45")) {
		char *rt = r_list_get_n (args, 0);
		char *imm = r_list_get_n (args, 1);
		// set if less than immediate: rt = (rt < imm)? 1: 0
		r_strbuf_setf (&op->esil, "%s,%s,<,?{,1,0,},%s,:=", rt, imm, rt);
	}
	r_list_free (args);
	free (name);
}

static bool decode(RArchSession *as, RAnalOp *op, RArchDecodeMask mask) {
	const ut64 addr = op->addr;
	const int len = op->size;
	const ut8 *buf = op->bytes;
	ut8 bytes[8] = { 0 };
	insn_t word = { 0 };
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
	if (is_any ("jral5")) {
		op->type = R_ANAL_OP_TYPE_RJMP; // call?
		// jump to register r1.. if .. 5?
	} else if (is_any ("jal ", "jral ", "j ")) {
// decide whether it's jump or call
#ifndef OP_MASK_RD
#define OP_MASK_RD 0x1f
#define OP_SH_RD 11
#endif
		int rd = (word >> OP_SH_RD) & OP_MASK_RD;
		op->type = (rd == 0)? R_ANAL_OP_TYPE_JMP: R_ANAL_OP_TYPE_CALL;
		// op->jump = EXTRACT_UJTYPE_IMM (word) + addr;
		op->jump = arg? r_num_get (NULL, arg): op->addr;
		if (op->type == R_ANAL_OP_TYPE_CALL) {
			op->fail = addr + op->size;
		}
	}
	if (mask & R_ARCH_OP_MASK_ESIL) {
		decode_esil (op);
	}
	if (is_any ("jr ")) {
		op->type = R_ANAL_OP_TYPE_RJMP;
	} else if (is_any ("jral ")) {
		op->type = R_ANAL_OP_TYPE_RCALL;
	} else if (is_any ("swi")) {
		op->type = R_ANAL_OP_TYPE_SWI;
	} else if (is_any ("ori")) {
		op->type = R_ANAL_OP_TYPE_OR;
	} else if (is_any ("ret", "iret")) {
		op->type = R_ANAL_OP_TYPE_RET;
	} else if (is_any ("add45")) {
		op->type = R_ANAL_OP_TYPE_ADD;
	} else if (is_any ("smw.bi")) {
		op->type = R_ANAL_OP_TYPE_STORE;
	}
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
