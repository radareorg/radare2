/* radare - LGPL - Copyright 2010-2014 - pancake */

#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>

/* Return a mapping from the register number i.e. $0 .. $31 to string name */
static const char* mips_reg_decode(unsigned reg_num)
{
/* See page 36 of "See Mips Run Linux, 2e, D. Sweetman, 2007"*/
	static const char *REGISTERS[32] = {
		"zero", "at", "v0", "v1", "a0", "a1", "a2", "a3",
		"t0", "t1", "t2", "t3", "t4", "t5", "t6", "t7",
		"s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7",
		"t8", "t9", "k0", "k1", "gp", "sp", "fp", "ra"
	};
	if (reg_num < 32) return REGISTERS[reg_num];
	return NULL;
}

static int mips_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *b_in, int len) {
	unsigned int opcode;
	ut8 b[4];
	// WIP char buf[10]; int reg; int family;
	int optype, oplen = (anal->bits==16)?2:4;

	if (op == NULL)
		return oplen;

	memset (op, 0, sizeof (RAnalOp));
	op->type = R_ANAL_OP_TYPE_UNK;
	op->size = oplen;
	op->delay = 0;
	op->addr = addr;
	r_strbuf_init (&op->esil);

	// Reminder: r_mem_copyendian swaps if arg `endian` ==0 ...
	// When anal->big_endian is "false", as for mipsel architecture, we NEED to swap here for the below analysis to work.
	r_mem_copyendian ((ut8*)&opcode, b_in, 4, anal->big_endian ? 1 : 0);
	r_mem_copyendian (b, b_in, 4, anal->big_endian ? 1 : 0);

	// eprintf ("MIPS: %02x %02x %02x %02x (after endian: big=%d)\n", b[0], b[1], b[2], b[3], anal->big_endian);
	if (opcode == 0) {
		op->type = R_ANAL_OP_TYPE_NOP;
		return oplen;
	}

	optype = (b[0]>>2);

	if (optype == 0) {
#if 0
	R-TYPE
	======
	opcode (6)  rs (5)  rt (5)  rd (5)  sa (5)  function (6) 
	rs = register source
	rs = register target
	rd = register destination
	sa = 
	fu =
		
		 |--[0]--|  |--[1]--|  |--[2]--|  |--[3]--|
		 1111 1111  1111 1111  1111 1111  1111 1111
		 \_op__/\_rs__/\_rt_/  \_rd_/\_sa__/\_fun_/
		   |      |      |       |      |      |
		 b[0]>>2  |  (b[1]&31)   |      |   b[3]&63
		          |          (b[2]>>3)  |
		  (b[0]&3)<<3)+(b[1]>>5)   (b[2]&7)+(b[3]>>6)
#endif
#if WIP
		int rs = ((b[0]&3)<<3) + (b[1]>>5);
		int rt = b[1]&31;
		int rd = b[2]>>3;
		int sa = (b[2]&7)+(b[3]>>6);
#endif
		int fun = b[3]&63;
		switch (fun) {
		case 0: // sll
			break;
		case 2: // srl
			break;
		case 3: // sra
			break;
		case 4: // sllv
			break;
		case 6: // srlv
			break;
		case 7: // srav
			break;
		case 8: // jr
			//eprintf ("%llx jr\n", addr);
			// TODO: check return value or gtfo
			if (((b[0]&3)<<3) + (b[1]>>5) == 31) {
				op->type = R_ANAL_OP_TYPE_RET;
			} else {
				op->type = R_ANAL_OP_TYPE_JMP;
			}
			op->delay = 1;
			break;
		case 9: // jalr
			//eprintf ("%llx jalr\n", addr);
			op->type = R_ANAL_OP_TYPE_UCALL;
			op->delay = 1;
			break;
		case 12: // syscall
			op->type = R_ANAL_OP_TYPE_SWI;
			break;
		case 13: // break
			op->type = R_ANAL_OP_TYPE_TRAP;
			break;
		case 16: // mfhi
		case 18: // mflo

		case 17: // mthi
		case 19: // mtlo

		case 24: // mult
		case 25: // multu

		case 26: // div
		case 27: // divu
			op->type = R_ANAL_OP_TYPE_DIV;
			break;
		case 32: // add
		case 33: // addu
			op->type = R_ANAL_OP_TYPE_ADD;
			break;
		case 34: // sub
		case 35: // subu
			op->type = R_ANAL_OP_TYPE_SUB;
			break;
		case 36: // and
			op->type = R_ANAL_OP_TYPE_AND;
			break;
		case 37: // or
			op->type = R_ANAL_OP_TYPE_OR;
			break;
		case 38: // xor
			op->type = R_ANAL_OP_TYPE_XOR;
			break;
		case 39: // nor
		case 42: // slt
		case 43: // sltu

			break;
		default:
		//	eprintf ("%llx %d\n", addr, optype);
			break;
		}
		//family = 'R';
	} else 
	if ((optype & 0x3e) == 2) {
#if 0
		// J-TYPE
		 |--[0]--|  |--[1]--|  |--[2]--|  |--[3]--|
		 1111 1111  1111 1111  1111 1111  1111 1111
		 \_op__/\______address____________________/
                   |             |
               (b[0]>>2)  ((b[0]&3)<<24)+(b[1]<<16)+(b[2]<<8)+b[3]
#endif
		// FIXME: what happens when addr is using a virtual map?
		// ANS: address will be E 0x000000..0x0ffffffc
		//      but addr could be anywhere
		//      so address needs to be adjusted for that, somehow...
		// MIPS is strange.  For example, the same code memory may be
		// mapped simultaneously to 0x00600000 and 0x80600000.  The program is
		// executing at 0x80600000 if we are operating in 'KSEG0' space
		// (unmapped cached mode) vs 0x00600000 (KUSEG or user space)
		// An immediate jump can only reach within 2^28 bits.
		// HACK: if the user specified a mapping for the program
		// then assume that they know which MIPS segment they
		// are analysing in, and use the high order bits of addr
		// to be add to the jump.
		// WARNING: it is possible that this may not be the case
		// in all situations!
		// Maybe better solution: use a cfg. variable to do
		// the offset... but I dont yet know how to get to that
		// from this static function
		int address = (((b[0]&3)<<24)+(b[1]<<16)+(b[2]<<8)+b[3]) << 2;
		ut64 page_hack = addr & 0xf0000000;
		switch (optype) {
		case 2: // j
			op->type = R_ANAL_OP_TYPE_JMP;
			op->jump = page_hack + address;
			op->delay = 1;
			r_strbuf_setf (&op->esil, "pc=0x%08x", address);
			break;
		case 3: // jal
			op->type = R_ANAL_OP_TYPE_CALL;
			op->jump = page_hack + address;
			op->fail = addr+8;
			op->delay = 1;
			r_strbuf_setf (&op->esil, "lr=pc+4,pc=0x%08x", address);
			break;
		}
		//family = 'J';
	} else 
	if ((optype & 0x10) == 0x1c) {
#if 0
	C-TYPE
	======
	opcode (6) format (5) ft (5) fs (5) fd (5) function (6) 

		 |--[0]--|  |--[1]--|  |--[2]--|  |--[3]--|
		 1111 1111  1111 1111  1111 1111  1111 1111
		 \_op__/\_fmt_/\_ft_/  \_fs_/\_fd__/\_fun_/
		   |      |      |       |      |      |
		 b[0]>>2  |  (b[1]&31)   |      |   b[3]&63
		          |          (b[2]>>3)  |
		  (b[0]&3)<<3)+(b[1]>>5)   (b[2]&7)+(b[3]>>6)
#endif
#if WIP
		int fmt = ((b[0]&3)<<3) + (b[1]>>5);
		int ft = (b[1]&31);
		int fs = (b[2]>>3);
		int fd = (b[2]&7)+(b[3]>>6);
#endif
		int fun = (b[3]&63);
		//family = 'C';
		switch (fun) {
		case 0: // mtc1
			break;
		case 1: // sub.s
			break;
		case 2: // mul.s
			break;
		case 3: // div.s
			break;
		// ....
		}
	} else {
#if 0
	I-TYPE
	======
   	all opcodes but 000000 000001x and 0100xx
	opcode (6)  rs (5)  rt (5) immediate (16) 

		 |--[0]--|  |--[1]--|  |--[2]--|  |--[3]--|
		 1111 1111  1111 1111  1111 1111  1111 1111
		 \_op__/\_rs__/\_rt_/  \_______imm________/
		   |      |      |              |
		 b[0]>>2  |  (b[1]&31)          |
		          |                     |
		 ((b[0]&3)<<3)+(b[1]>>5)   (b[2]<<8)+b[3]
#endif
		int rs = ((b[0]&3)<<3)+(b[1]>>5);
		int rt = b[1]&31;
		int imm = (b[2]<<8)+b[3];
		if (((optype >> 2) ^ 0x3) && (imm & 0x8000))
			imm = 0 - (0x10000 - imm);
		switch (optype) {
		case 1: if (rt) { /* bgez */ } else { /* bltz */ }
		case 4: // beq
		case 5: // bne // also bnez
		case 6: // blez
		case 7: // bgtz
			// XXX: use imm here
			op->type = R_ANAL_OP_TYPE_CJMP;
			op->jump = addr+(imm<<2)+4;
			op->fail = addr+8;
			op->delay = 1;
			break;
		// The following idiom is very common in mips 32 bit:
		//
		//     lui a0,0x8123
		//     ; maybe other opcodes
		//     ; maybe even a jump with branch delay
		//     addui a0,a0,-12345
		//
		// Here, a0 might typically be any a0 or s0 register, and -12345 is a signed 16-bit number
		// This is used to address const or static data in a 64kb page
		// 0x8123 is the upper 16 bits of the register
		// The net result: a0 := 0x8122cfc7
		// The cases vary, so for now leave the smarts in a human generated macro to decide
		// but the macro needs the opcode values as input
		//
		// TODO: this is a stop-gap. Really we need some smarts in here to tie this into the 
		// flags directly, as suggested here: https://github.com/radare/radare2/issues/949#issuecomment-43654922
		case 15: // lui
			op->dst = r_anal_value_new ();
			op->dst->reg = r_reg_get (anal->reg, mips_reg_decode(rt), R_REG_TYPE_GPR);
			// TODO: currently there is no way for the macro to get access to this register
			op->val = imm;
			break;
		case 9: // addiu
			op->dst = r_anal_value_new ();
			op->dst->reg = r_reg_get (anal->reg, mips_reg_decode(rt), R_REG_TYPE_GPR);
			// TODO: currently there is no way for the macro to get access to this register
			op->src[0] = r_anal_value_new ();
			op->src[0]->reg = r_reg_get (anal->reg, mips_reg_decode(rs), R_REG_TYPE_GPR);
			op->val = imm; // Beware: this one is signed... use `?vi $v`
			break;
		case 8: // addi
		case 10: // stli
		case 11: // stliu
		case 12: // andi
		case 13: // ori
		case 14: // xori
		case 32: // lb
		case 33: // lh
		case 35: // lw
		case 36: // lbu
		case 37: // lhu
		case 40: // sb
		case 41: // sh
		case 43: // sw
		case 49: // lwc1
		case 57: // swc1
			break;
		case 29: // jalx
			op->type = R_ANAL_OP_TYPE_CALL;
			op->jump = addr + 4*((b[3] | b[2]<<8 | b[1]<<16));
			op->fail = addr + 8;
			op->delay = 1;
			break;
		}
		//family = 'I';
	}

#if 0
	switch (optype) {
	case 'R': // register only
		op->type = R_ANAL_OP_TYPE_ADD;
		break;
	case 'I': // immediate
		op->type = R_ANAL_OP_TYPE_JMP;
		break;
	case 'J': // memory address jumps
		op->type = R_ANAL_OP_TYPE_CALL;
		break;
	case 'C': // coprocessor
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	}
#endif
	//eprintf ("MIPS: family=%c optype=%d oplen=%d op=>type=%d\n", family, optype, oplen, op->type);
	return oplen;
#if 0
 R - all instructions that only take registers as arguments (jalr, jr)
     opcode 000000
     opcode (6) 	rs (5) 	rt (5) 	rd (5) 	sa (5) 	function (6) 
		add 	rd, rs, rt 	100000
		addu 	rd, rs, rt 	100001
		and 	rd, rs, rt 	100100
		break 		001101
		div 	rs, rt 	011010
		divu 	rs, rt 	011011
		jalr 	rd, rs 	001001
		jr 	rs 	001000

		mfhi 	rd 	010000
		mflo 	rd 	010010
		mthi 	rs 	010001
		mtlo 	rs 	010011
		mult 	rs, rt 	011000
		multu 	rs, rt 	011001

		nor 	rd, rs, rt 	100111
		or 	rd, rs, rt 	100101
		sll 	rd, rt, sa 	000000
		sllv 	rd, rt, rs 	000100
		slt 	rd, rs, rt 	101010
		sltu 	rd, rs, rt 	101011

		sra 	rd, rt, sa 	000011
		srav 	rd, rt, rs 	000111

		srl 	rd, rt, sa 	000010
		srlv 	rd, rt, rs 	000110

		sub 	rd, rs, rt 	100010
		subu 	rd, rs, rt 	100011
		syscall 		001100
		xor 	rd, rs, rt 	100110 
 I - instructions with immediate operand, load/store/..
     all opcodes but 000000 000001x and 0100xx
     opcode (6) 	rs (5) 	rt (5) 	immediate (16) 
		addi 	rt, rs, immediate 	001000 	
		addiu 	rt, rs, immediate 	001001 	
		andi 	rt, rs, immediate 	001100 	
		beq 	rs, rt, label 	000100 	

		bgez 	rs, label 	000001 	rt = 00001

		bgtz 	rs, label 	000111 	rt = 00000
		blez 	rs, label 	000110 	rt = 00000

		bltz 	rs, label 	000001 	rt = 00000
		bne 	rs, rt, label 	000101 	
		lb 	rt, immediate(rs) 	100000 	
		lbu 	rt, immediate(rs) 	100100 	

		lh 	rt, immediate(rs) 	100001 	
		lhu 	rt, immediate(rs) 	100101 	

		lui 	rt, immediate 	 	001111 	

		lw 	rt, immediate(rs) 	100011 	
		lwc1 	rt, immediate(rs) 	110001 	

		ori 	rt, rs, immediate 	001101 	
		sb 	rt, immediate(rs) 	101000 	

		slti 	rt, rs, immediate 	001010 	
		sltiu 	rt, rs, immediate 	001011 	
		sh 	rt, immediate(rs) 	101001 	
		sw 	rt, immediate(rs) 	101011 	
		swc1 	rt, immediate(rs) 	111001 	
		xori 	rt, rs, immediate 	001110 	
 J - require memory address like j, jal
     00001x
     opcode (6) 	target (26) 
		j 	label 	000010 	coded address of label
		jal 	label 	000011 	coded address of label 
 C - coprocessor insutrctions that use cp0, cp1, ..
     0100xx
     opcode (6) 	format (5) 	ft (5) 	fs (5) 	fd (5) 	function (6) 
		add.s 	fd, fs, ft 	000000 	10000
		cvt.s.w	fd, fs, ft 	100000 	10100
		cvt.w.s	fd, fs, ft 	100100 	10000
		div.s 	fd, fs, ft 	000011 	10000
		mfc1 	ft, fs 		000000 	00000
		mov.s 	fd, fs 		000110 	10000
		mtc1 	ft, fs 		000000 	00100
		mul.s 	fd, fs, ft 	000010 	10000
		sub.s 	fd, fs, ft 	000001 	10000 
#endif
	return op->size;
}

/* Set the profile register */
static int mips_set_reg_profile(RAnal* anal){
     const char *p =
#if 0
          "=pc    pc\n"
	  "=sp    sp\n"
	  "=a0    a0\n"
	  "=a1    a1\n"
	  "=a2    a2\n"
	  "=a3    a3\n"
	  "gpr	zero	.32	0	0\n"
	  "gpr	at	.32	4	0\n"
	  "gpr	v0	.32	8	0\n"
	  "gpr	v1	.32	12	0\n"
	  "gpr	a0	.32	16	0\n"
	  "gpr	a1	.32	20	0\n"
	  "gpr	a2	.32	24	0\n"
	  "gpr	a3	.32	28	0\n"
	  "gpr	t0	.32	32	0\n"
	  "gpr	t1	.32	36	0\n"
	  "gpr	t2 	.32	40	0\n"
	  "gpr	t3 	.32	44	0\n"
	  "gpr	t4 	.32	48	0\n"
	  "gpr	t5 	.32	52	0\n"
	  "gpr	t6 	.32	56	0\n"
	  "gpr	t7 	.32	60	0\n"
	  "gpr	s0	.32	64	0\n"
	  "gpr	s1	.32	68	0\n"
	  "gpr	s2 	.32	72	0\n"
	  "gpr	s3 	.32	76	0\n"
	  "gpr	s4 	.32	80	0\n"
	  "gpr	s5 	.32	84	0\n"
	  "gpr	s6 	.32	88	0\n"
	  "gpr	s7 	.32	92	0\n"
	  "gpr	t8 	.32	96	0\n"
	  "gpr	t9 	.32	100	0\n"
	  "gpr	k0 	.32	104	0\n"
	  "gpr	k1 	.32	108	0\n"
	  "gpr	gp 	.32	112	0\n"
	  "gpr	sp	.32	116	0\n"
	  "gpr	fp	.32	120	0\n"
	  "gpr	ra	.32	124	0\n"
	  "gpr	pc	.32	128	0\n";
#else
     // take the one from the debugger //
	"=pc	pc\n"
	"=sp	sp\n"
	"=bp	fp\n"
	"=a0	a0\n"
	"=a1	a1\n"
	"=a2	a2\n"
	"=a3	a3\n"
	"gpr	zero	.64	0	0\n"
	// XXX DUPPED CAUSES FAILURE "gpr	at	.32	8	0\n"
	"gpr	at	.64	8	0\n"
	"gpr	v0	.64	16	0\n"
	"gpr	v1	.64	24	0\n"
	/* args */
	"gpr	a0	.64	32	0\n"
	"gpr	a1	.64	40	0\n"
	"gpr	a2	.64	48	0\n"
	"gpr	a3	.64	56	0\n"
	/* tmp */
	"gpr	t0	.64	64	0\n"
	"gpr	t1	.64	72	0\n"
	"gpr	t2	.64	80	0\n"
	"gpr	t3	.64	88	0\n"
	"gpr	t4	.64	96	0\n"
	"gpr	t5	.64	104	0\n"
	"gpr	t6	.64	112	0\n"
	"gpr	t7	.64	120	0\n"
	/* saved */
	"gpr	s0	.64	128	0\n"
	"gpr	s1	.64	136	0\n"
	"gpr	s2	.64	144	0\n"
	"gpr	s3	.64	152	0\n"
	"gpr	s4	.64	160	0\n"
	"gpr	s5	.64	168	0\n"
	"gpr	s6	.64	176	0\n"
	"gpr	s7	.64	184	0\n"
	"gpr	s8	.64	192	0\n"
	"gpr	s9	.64	200	0\n"
	/* special */
	"gpr	k0	.64	208	0\n"
	"gpr	k1	.64	216	0\n"
	"gpr	gp	.64	224	0\n"
	"gpr	sp	.64	232	0\n"
	"gpr	fp	.64	240	0\n"
	"gpr	ra	.64	248	0\n"
	/* extra */
	"gpr	pc	.64	272	0\n"
	;
#endif
	return r_reg_set_profile_string (anal->reg, p);
}

struct r_anal_plugin_t r_anal_plugin_mips_gnu = {
	.name = "mips.gnu",
	.desc = "MIPS code analysis plugin",
	.license = "LGPL3",
	.arch = R_SYS_ARCH_MIPS,
	.bits = 32,
	.esil = R_TRUE,
	.init = NULL,
	.fini = NULL,
	.op = &mips_op,
	.set_reg_profile = mips_set_reg_profile,
	.fingerprint_bb = NULL,
	.fingerprint_fcn = NULL,
	.diff_bb = NULL,
	.diff_fcn = NULL,
	.diff_eval = NULL
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
        .type = R_LIB_TYPE_ANAL,
        .data = &r_anal_plugin_mips_gnu
};
#endif
