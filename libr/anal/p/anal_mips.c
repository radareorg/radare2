/* radare - LGPL - Copyright 2010-2012 - pancake */

#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>

static int mips_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *b, int len) {
	unsigned int opcode;
	char buf[10];
	int family, reg, optype, oplen = (anal->bits==16)?2:4;

        if (op == NULL)
		return oplen;

        memset (op, 0, sizeof (RAnalOp));
        op->type = R_ANAL_OP_TYPE_UNK;
	op->length = oplen;
	op->delay = 4;

	//r_mem_copyendian ((ut8*)&opcode, b, 4, !anal->big_endian);
	memcpy (&opcode, b, 4);

//eprintf ("%02x %02x %02x %02x\n", b[0], b[1], b[2], b[3]);
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
		
		 |--[0]--|  |--[1]--|  |--[2]--|  |--[3]--|
		 1111 1111  1111 1111  1111 1111  1111 1111
		 \_op__/\_rs__/\_rt_/  \_rd_/\_sa__/\_fun_/
		   |      |      |       |      |      |
		 b[0]>>2  |  (b[1]&31)   |      |   b[3]&63
		          |          (b[2]>>3)  |
		  (b[0]&3)<<3)+(b[1]>>5)   (b[2]&7)+(b[3]>>6)
#endif
		int rs = ((b[0]&3)<<3) + (b[1]>>5);
		int rt = b[1]&31;
		int rd = b[2]>>3;
		int sa = (b[2]&7)+(b[3]>>6);
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
		case 9: // jalr
			//eprintf ("%llx jalr\n", addr);
			op->type = R_ANAL_OP_TYPE_UCALL;
			break;
		case 8: // jr
			//eprintf ("%llx jr\n", addr);
			// TODO: check return value or gtfo
			op->type = R_ANAL_OP_TYPE_RET;
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
		family = 'R';
	} else 
	if ((optype & 0x3e) == 2) {
#if 0
		 |--[0]--|  |--[1]--|  |--[2]--|  |--[3]--|
		 1111 1111  1111 1111  1111 1111  1111 1111
		 \_op__/\______address____________________/
                   |             |
               (b[0]>>2)  ((b[0]&3)<<24)+(b[1]<<16)+(b[2]<<8)+b[3]
#endif
		int address = ((b[0]&3)<<24)+(b[1]<<16)+(b[2]<<8)+b[3];
		switch (optype) {
		case 2: // j
			op->type = R_ANAL_OP_TYPE_JMP;
			op->jump = address;
			break;
		case 3: // jal
			op->type = R_ANAL_OP_TYPE_CALL;
			op->jump = address;
			op->fail = addr+8;
			break;
		}
		family = 'J';
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
		int fmt = ((b[0]&3)<<3) + (b[1]>>5);
		int ft = (b[1]&31);
		int fs = (b[2]>>3);
		int fd = (b[2]&7)+(b[3]>>6);
		int fun = (b[3]&63);
		family = 'C';
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
			break;
		case 8: // addi
		case 9: // addiu
		case 10: // stli
		case 11: // stliu
		case 12: // andi
		case 13: // ori
		case 14: // xori
		case 15: // lui
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
		}
		family = 'I';
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
	return op->length;
}

struct r_anal_plugin_t r_anal_plugin_mips = {
	.name = "mips",
	.desc = "MIPS code analysis plugin",
	.arch = R_SYS_ARCH_MIPS,
	.bits = 32,
	.init = NULL,
	.fini = NULL,
	.op = &mips_op,
	.set_reg_profile = NULL,
	.fingerprint_bb = NULL,
	.fingerprint_fcn = NULL,
	.diff_bb = NULL,
	.diff_fcn = NULL,
	.diff_eval = NULL
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
        .type = R_LIB_TYPE_ANAL,
        .data = &r_anal_plugin_mips
};
#endif
