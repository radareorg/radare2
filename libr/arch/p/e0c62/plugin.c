/* radare2 - LGPL-3.0-only - Copyright 2026 - pancake */

#include <r_arch.h>
#include <ctype.h>
#include "opcodes.inc.c"

// Harvard data space: one nibble per byte, separate from the word ROM.
#define DATA "0x10000"

#define INVALID 0xff

static bool init(RArchSession *session) {
	ut8 *slots = malloc (0x1000);
	if (!slots) {
		return false;
	}
	memset (slots, INVALID, 0x1000);
	ut16 word;
	size_t i;
	for (word = 0; word < 0x1000; word++) {
		for (i = 0; i < R_ARRAY_SIZE (instructions); i++) {
			if ((word & instructions[i].mask) == instructions[i].code) {
				slots[word] = i;
				break;
			}
		}
	}
	session->data = slots;
	return true;
}

static bool fini(RArchSession *session) {
	R_FREE (session->data);
	return true;
}

static void operand(const char *spec, ut16 word, char out[8]) {
	static const char *rq[] = { "a", "b", "mx", "my" };
	const char *text = spec? spec: "";
	unsigned bits = 0;
	if (*text == '[') {
		snprintf (out, 8, "[0x%x]", word & 15);
		return;
	}
	if (*text && !text[1]) {
		switch (*text) {
		case 'R':
			text = rq[(word >> 4) & 3];
			break;
		case 'r':
			text = rq[(word >> 2) & 3];
			break;
		case 'q':
			text = rq[word & 3];
			break;
		case 'i':
			bits = 15;
			break;
		case 'p':
			bits = 31;
			break;
		case 's':
			bits = 255;
			break;
		}
	}
	if (bits) {
		snprintf (out, 8, "0x%x", word & bits);
	} else {
		snprintf (out, 8, "%s", text);
	}
}

// compact form drops spaces to match normalized assembler input
static void mnemonic(const E0cInsn *in, const char *dst, const char *src, bool compact, char out[24]) {
	snprintf (out, 24, "%s%s%s%s%s", in->name, (*dst && !compact)? " ": "", dst, *src? (compact? ",": ", "): "", src);
}

static bool is_mem(const char *arg) {
	return *arg == '[' || !strcmp (arg, "mx") || !strcmp (arg, "my");
}

// length of the address inside "[0xN]" or the index register name of "mx"/"my"
static int mem_len(const char *arg) {
	return *arg == '['? (int)strlen (arg) - 2: 1;
}

static void read_operand(const char *arg, char out[24]) {
	if (is_mem (arg)) {
		snprintf (out, 24, DATA ",%.*s,+,[1]", mem_len (arg), arg + 1);
	} else {
		snprintf (out, 24, "%s", arg);
	}
}

static void store_operand(RStrBuf *esil, const char *arg) {
	if (is_mem (arg)) {
		r_strbuf_appendf (esil, "," DATA ",%.*s,+,=[1]", mem_len (arg), arg + 1);
	} else {
		r_strbuf_appendf (esil, ",%s,=", arg);
	}
}

static void increment_index(RStrBuf *esil, char reg) {
	r_strbuf_appendf (esil, "0xf00,%c,&,1,%c,+,0xff,&,|,%c,=", reg, reg, reg);
}

static void store_pair(RStrBuf *esil, ut16 word) {
	r_strbuf_appendf (esil, "%u," DATA ",x,+,=[1],", word & 15);
	increment_index (esil, 'x');
	r_strbuf_appendf (esil, ",%u," DATA ",x,+,=[1],", (word >> 4) & 15);
	increment_index (esil, 'x');
}

static void push(RStrBuf *esil, const char *value) {
	r_strbuf_appendf (esil, "0xff,1,sp,-,&,sp,=,%s," DATA ",sp,+,=[1]", value);
}

static void pop(RStrBuf *esil, const char *dst) {
	r_strbuf_append (esil, DATA ",sp,+,[1]");
	store_operand (esil, dst);
	r_strbuf_append (esil, ",0xff,1,sp,+,&,sp,=");
}

// PCP:PCS is a 12-bit counter, so stepping past the last word wraps within the bank
static ut64 next_pc(ut64 addr) {
	return (addr & 0x2000) | ((addr + 2) & 0x1ffe);
}

static void return_pc(RStrBuf *esil, ut64 addr) {
	r_strbuf_appendf (esil, DATA ",sp,+,[1],4," DATA ",0xff,1,sp,+,&,+,[1],<<,|,8," DATA ",0xff,2,sp,+,&,+,[1],<<,|,2,*,0x%x,|,pc,=,0xff,3,sp,+,&,sp,=", (unsigned)(addr & 0x2000));
}

static void arithmetic(RStrBuf *esil, E0cKind kind, const char *lhs, const char *rhs, const char *dst) {
	bool sub = kind == E_SUB || kind == E_SBC || kind == E_SCPX || kind == E_SCPY || kind == E_CP || kind == E_DEC;
	bool carry = kind == E_ADC || kind == E_ADCI || kind == E_SBC || kind == E_ACPX || kind == E_ACPY || kind == E_SCPX || kind == E_SCPY;
	bool decimal = kind != E_ADCI && kind != E_INC && kind != E_DEC && kind != E_CP;
	r_strbuf_appendf (esil, "%s,%s,%s", rhs, lhs, sub? "-": "+");
	if (carry) {
		r_strbuf_append (esil, sub? ",C,SWAP,-": ",C,+");
	}
	r_strbuf_append (esil, ",0xff,&,t,=");
	if (sub) {
		r_strbuf_append (esil, ",15,t,>,C,=");
		if (decimal) {
			r_strbuf_append (esil, ",D,C,&,?{,6,t,-,t,=,}");
		}
	} else if (decimal) {
		r_strbuf_append (esil, ",D,?{,9,t,>,C,=,C,?{,10,t,-,t,=,},}{,15,t,>,C,=,}");
	} else {
		r_strbuf_append (esil, ",15,t,>,C,=");
	}
	if (kind == E_CP) {
		r_strbuf_append (esil, ",15,t,&,!,Z,=");
		return;
	}
	r_strbuf_append (esil, ",15,t,&,t,=,t,!,Z,=,t");
	store_operand (esil, dst);
}

static int op_type(E0cKind kind, const char *dst, const char *src) {
	switch (kind) {
	case E_JP:
		return *src? R_ANAL_OP_TYPE_CJMP: R_ANAL_OP_TYPE_JMP;
	case E_JPBA:
		return R_ANAL_OP_TYPE_UJMP;
	case E_CALL: case E_CALZ:
		return R_ANAL_OP_TYPE_CALL;
	case E_RET: case E_RETS: case E_RETD:
		return R_ANAL_OP_TYPE_RET;
	case E_HALT: case E_SLP: case E_NOP5: case E_NOP7:
		return R_ANAL_OP_TYPE_NOP;
	case E_PUSH:
		return R_ANAL_OP_TYPE_PUSH;
	case E_POP:
		return R_ANAL_OP_TYPE_POP;
	case E_LD: case E_LDPX: case E_LDPY:
		return is_mem (dst)? R_ANAL_OP_TYPE_STORE: is_mem (src)? R_ANAL_OP_TYPE_LOAD: R_ANAL_OP_TYPE_MOV;
	case E_LBPX:
		return R_ANAL_OP_TYPE_STORE;
	case E_INC: case E_ADD: case E_ADC: case E_ADCI: case E_ACPX: case E_ACPY:
		return R_ANAL_OP_TYPE_ADD;
	case E_DEC: case E_SUB: case E_SBC: case E_SCPX: case E_SCPY:
		return R_ANAL_OP_TYPE_SUB;
	case E_CP:
		return R_ANAL_OP_TYPE_CMP;
	case E_FAN:
		return R_ANAL_OP_TYPE_ACMP;
	case E_SET: case E_OR:
		return R_ANAL_OP_TYPE_OR;
	case E_RST: case E_AND:
		return R_ANAL_OP_TYPE_AND;
	case E_XOR: case E_NOT:
		return R_ANAL_OP_TYPE_XOR;
	case E_RLC:
		return R_ANAL_OP_TYPE_ROL;
	case E_RRC:
		return R_ANAL_OP_TYPE_ROR;
	default:
		return R_ANAL_OP_TYPE_MOV;
	}
}

// PSET only applies to the branch right after it (pn holds that address), otherwise NP is the current page
static void branch_page(RStrBuf *e, ut64 addr, bool uses_np) {
	if (uses_np) {
		r_strbuf_appendf (e, "%u,pn,-,?{,%u,np,=,},", (unsigned)(addr & 0x3fff), (unsigned)((addr >> 9) & 31));
	}
	r_strbuf_append (e, "0,pn,=,");
}

static void esil(RStrBuf *e, const E0cInsn *in, ut16 word, ut64 addr, const char *dst, const char *src) {
	char lhs[24], rhs[24];
	read_operand (dst, lhs);
	read_operand (src, rhs);
	if (((addr >> 1) & 0xfff) == 0xfff) {
		r_strbuf_appendf (e, "%u,pc,=,", (unsigned)next_pc (addr));
	}
	switch (in->kind) {
	case E_PSET:
		r_strbuf_appendf (e, "%u,np,=,%u,pn,=", word & 31, (unsigned)next_pc (addr));
		break;
	case E_JP:
		branch_page (e, addr, true);
		if (*src) {
			r_strbuf_appendf (e, "%s,%s?{,", (word & 0x400)? "Z": "C", (word & 0x100)? "!,": "");
		}
		r_strbuf_appendf (e, "%u,9,np,<<,|,pc,=", (word & 255) << 1);
		if (*src) {
			r_strbuf_append (e, ",}");
		}
		break;
	case E_JPBA:
		branch_page (e, addr, true);
		r_strbuf_append (e, "1,a,<<,5,b,<<,|,9,np,<<,|,pc,=");
		break;
	case E_CALL: case E_CALZ:
		{
			ut64 next = next_pc (addr);
			char nibble[4];
			branch_page (e, addr, in->kind == E_CALL);
			int shift;
			for (shift = 9; shift > 0; shift -= 4) {
				snprintf (nibble, sizeof (nibble), "%u", (unsigned)((next >> shift) & 15));
				push (e, nibble);
				r_strbuf_append (e, ",");
			}
			unsigned target = (addr & 0x2000) | ((word & 255) << 1);
			r_strbuf_appendf (e, in->kind == E_CALL? "%u,9,15,np,&,<<,|,pc,=": "%u,pc,=", target);
		}
		break;
	case E_RET: case E_RETS: case E_RETD:
		branch_page (e, addr, false);
		return_pc (e, addr);
		if (in->kind == E_RETS) {
			r_strbuf_append (e, ",0x2000,pc,&,0x1ffe,2,pc,+,&,|,pc,=");
		} else if (in->kind == E_RETD) {
			r_strbuf_append (e, ",");
			store_pair (e, word);
		}
		break;
	case E_HALT: case E_SLP:
		r_strbuf_append (e, in->kind == E_SLP? "1,halted,=,1,sleeping,=": "1,halted,=");
		break;
	case E_LD: case E_LDPX: case E_LDPY:
		r_strbuf_append (e, rhs);
		if (!strcmp (dst, "x") || !strcmp (dst, "y")) {
			r_strbuf_appendf (e, ",0xf00,%s,&,|", dst);
		}
		store_operand (e, dst);
		if (in->kind != E_LD) {
			r_strbuf_append (e, ",");
			increment_index (e, in->kind == E_LDPX? 'x': 'y');
		}
		break;
	case E_LBPX:
		store_pair (e, word);
		break;
	case E_SET: case E_RST:
		r_strbuf_appendf (e, "%u,f,%s=", word & 15, in->kind == E_SET? "|": "&");
		break;
	case E_PUSH:
		push (e, lhs);
		break;
	case E_POP:
		pop (e, dst);
		break;
	case E_INC: case E_DEC:
		if (!strcmp (dst, "sp")) {
			r_strbuf_appendf (e, "0xff,1,sp,%s,&,sp,=", in->kind == E_INC? "+": "-");
		} else if (!strcmp (dst, "x") || !strcmp (dst, "y")) {
			increment_index (e, *dst);
		} else {
			arithmetic (e, in->kind, lhs, "1", dst);
		}
		break;
	case E_ADD: case E_ADC: case E_ADCI: case E_SUB: case E_SBC: case E_CP:
	case E_ACPX: case E_ACPY: case E_SCPX: case E_SCPY:
		arithmetic (e, in->kind, lhs, rhs, dst);
		if (in->kind == E_ACPX || in->kind == E_SCPX || in->kind == E_ACPY || in->kind == E_SCPY) {
			r_strbuf_append (e, ",");
			increment_index (e, dst[1]);
		}
		break;
	case E_AND: case E_OR: case E_XOR: case E_FAN: case E_NOT:
		{
			// NOT is the immediate XOR alias with an implicit all-ones operand
			const char *value = in->kind == E_NOT? "15": rhs;
			const char *logic = in->kind == E_OR? "|": (in->kind == E_XOR || in->kind == E_NOT)? "^": "&";
			r_strbuf_appendf (e, "%s,%s,%s,t,=,t,!,Z,=", value, lhs, logic);
			if (in->kind != E_FAN) {
				r_strbuf_append (e, ",t");
				store_operand (e, dst);
			}
		}
		break;
	// the summary table marks Z for RLC/RRC, but the detailed pages say it is not affected
	case E_RLC:
		r_strbuf_appendf (e, "%s,t,=,1,t,<<,C,|,3,t,>>,C,=,15,&", lhs);
		store_operand (e, dst);
		break;
	case E_RRC:
		r_strbuf_appendf (e, "%s,t,=,1,t,>>,3,C,<<,|,1,t,&,C,=", lhs);
		store_operand (e, dst);
		break;
	default:
		break;
	}
	// NOPs leave the separator of the bank wrap prefix dangling
	size_t len = r_strbuf_length (e);
	if (len && r_strbuf_get (e)[len - 1] == ',') {
		r_strbuf_slice (e, 0, len - 1);
	}
}

static bool decode(RArchSession *session, RAnalOp *op, RArchDecodeMask mask) {
	if (op->size < 2) {
		return false;
	}
	const ut8 *slots = session->data;
	ut16 word = r_read_le16 (op->bytes);
	op->size = 2;
	if (word > 0xfff || slots[word] == INVALID) {
		op->type = R_ANAL_OP_TYPE_ILL;
		if (mask & R_ARCH_OP_MASK_DISASM) {
			op->mnemonic = strdup ("invalid");
		}
		return false;
	}
	const E0cInsn *in = &instructions[slots[word]];
	char dst[8], src[8];
	operand (in->dst, word, dst);
	operand (in->src, word, src);
	op->cycles = in->cycles;
	op->type = op_type (in->kind, dst, src);
	if (in->kind == E_JP || in->kind == E_CALL || in->kind == E_CALZ) {
		// assume no preceding PSET: NP holds the current bank and page
		ut64 page = (op->addr >> 1) & (in->kind == E_CALZ? 0x1000: 0x1f00);
		op->jump = (page | (word & 255)) << 1;
		if (*src || in->kind != E_JP) {
			op->fail = next_pc (op->addr);
		}
	}
	if (mask & R_ARCH_OP_MASK_DISASM) {
		char text[24];
		mnemonic (in, dst, src, false, text);
		op->mnemonic = strdup (text);
	}
	if (mask & R_ARCH_OP_MASK_ESIL) {
		esil (&op->esil, in, word, op->addr, dst, src);
	}
	return true;
}

static char *regs(RArchSession *session) {
	return strdup (
		"=PC pc\n=SP sp\n=A0 a\n=A1 b\n"
		"gpr pc .16 0 0\n"
		"gpr x .16 2 0\ngpr xl .4 .16 0\ngpr xh .4 .20 0\ngpr xp .4 .24 0\n"
		"gpr y .16 4 0\ngpr yl .4 .32 0\ngpr yh .4 .36 0\ngpr yp .4 .40 0\n"
		"gpr a .4 6 0\ngpr b .4 7 0\ngpr f .4 8 0\n"
		"gpr C .1 .64 0\ngpr Z .1 .65 0\ngpr D .1 .66 0\ngpr I .1 .67 0\n"
		"gpr sp .8 9 0\ngpr spl .4 .72 0\ngpr sph .4 .76 0\n"
		"gpr np .8 10 0\ngpr halted .8 11 0\ngpr sleeping .8 12 0\ngpr pn .16 14 0\ngpr t .64 16 0\n");
}

static bool normalize(const char *input, char *out, size_t size) {
	size_t used = 0;
	while (*input) {
		if (isspace ((ut8)*input) || *input == '#') {
			input++;
			continue;
		}
		if (isdigit ((ut8)*input)) {
			char *end;
			ut64 n = strtoull (input, &end, r_str_startswith (input, "0x") || r_str_startswith (input, "0X")? 16: 10);
			int len = snprintf (out + used, size - used, "0x%"PFMT64x, n);
			if (len < 0 || (size_t)len >= size - used) {
				return false;
			}
			used += len;
			input = end;
			continue;
		}
		// identifiers keep their digits, e.g. nop5
		bool identifier = isalpha ((ut8)*input);
		do {
			if (used + 1 >= size) {
				return false;
			}
			out[used++] = tolower ((ut8)*input++);
		} while (identifier && isalnum ((ut8)*input));
	}
	out[used] = 0;
	return true;
}

static bool encode(RArchSession *session, RAnalOp *op, RArchEncodeMask mask) {
	char wanted[32], candidate[24], dst[8], src[8];
	if (!op->mnemonic || !normalize (op->mnemonic, wanted, sizeof (wanted))) {
		return false;
	}
	size_t i;
	// try every entry so aliases like "xor a, 0xf" and "set f, 1" assemble
	for (i = 0; i < R_ARRAY_SIZE (instructions); i++) {
		const E0cInsn *in = &instructions[i];
		if (!r_str_startswith (wanted, in->name)) {
			continue;
		}
		ut16 operand_bits = ~in->mask & 0xfff;
		ut16 bits = 0;
		do {
			ut16 word = in->code | bits;
			operand (in->dst, word, dst);
			operand (in->src, word, src);
			mnemonic (in, dst, src, true, candidate);
			if (!strcmp (wanted, candidate)) {
				ut8 bytes[2];
				r_write_le16 (bytes, word);
				return r_anal_op_set_bytes (op, op->addr, bytes, sizeof (bytes));
			}
			bits = (bits - operand_bits) & operand_bits;
		} while (bits);
	}
	return false;
}

static int archinfo(RArchSession *session, ut32 query) {
	switch (query) {
	case R_ARCH_INFO_MINOP_SIZE:
	case R_ARCH_INFO_MAXOP_SIZE:
	case R_ARCH_INFO_CODE_ALIGN:
		return 2;
	}
	return 0;
}

const RArchPlugin r_arch_plugin_e0c62 = {
	.meta = {
		.name = "e0c62",
		.author = "pancake",
		.desc = "Epson E0C62 family 4-bit microcontroller (E0C6200 core)",
		.license = "LGPL-3.0-only"
	},
	.arch = "e0c62",
	.bits = R_SYS_BITS_PACK1 (16),
	.endian = R_SYS_ENDIAN_LITTLE,
	.init = init,
	.fini = fini,
	.info = archinfo,
	.regs = regs,
	.decode = decode,
	.encode = encode,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ARCH,
	.data = &r_arch_plugin_e0c62,
	.version = R2_VERSION,
	.abiversion = R2_ABIVERSION
};
#endif
