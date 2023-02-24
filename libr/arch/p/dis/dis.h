/* radare2 - MIT - Copyright 2023 - keegan */

#ifndef DIS_DIS_H
#define DIS_DIS_H

#include <r_types.h>
#include <r_util/r_buf.h>
#include <sdb/ht_uu.h>

#define XMAGIC 0xc8030
#define SMAGIC 0xe1722

struct dis_header {
	st32 magic;
	st32 runtime_flags;
	st32 stack_extent;
	// number of instructions
	st32 code_size;
	// size of data in bytes
	st32 data_size;
	// number of type descriptors
	st32 type_size;
	// number of external link directives
	st32 link_size;
	// points to the beginning of the entry function
	st32 entry_pc;
	// index of the type descriptor that corresponds to entry function
	st32 entry_type;
};

typedef struct r_bin_dis_obj_t {
	struct dis_header header;
	size_t header_size;
	// real code section size
	size_t code_size;
	// real type section size
	size_t type_size;
	size_t module_name_size;
	// real link section size
	size_t link_size;
	// map of pcs -> addresses
	HtUU *pcs; // <ut32, ut64>
} RBinDisObj;

enum dis_operand {
	DIS_OPERAND_NONE,
	DIS_OPERAND_IMM,
	DIS_OPERAND_IND_FP,
	DIS_OPERAND_IND_MP,
	// double-indirect from fp
	DIS_OPERAND_DIND_FP,
	// double-indirect from mp
	DIS_OPERAND_DIND_MP
};

enum dis_op {
	DIS_OP_NOP,
	DIS_OP_ALT,
	DIS_OP_NBALT,
	DIS_OP_GOTO,
	DIS_OP_CALL,
	DIS_OP_FRAME,
	DIS_OP_SPAWN,
	DIS_OP_RUNT,
	DIS_OP_LOAD,
	DIS_OP_MCALL,
	DIS_OP_MSPAWN,
	DIS_OP_MFRAME,
	DIS_OP_RET,
	DIS_OP_JMP,
	DIS_OP_CASE,
	DIS_OP_EXIT,
	DIS_OP_NEW,
	DIS_OP_NEWA,
	DIS_OP_NEWCB,
	DIS_OP_NEWCW,
	DIS_OP_NEWCF,
	DIS_OP_NEWCP,
	DIS_OP_NEWCM,
	DIS_OP_NEWCMP,
	DIS_OP_SEND,
	DIS_OP_RECV,
	DIS_OP_CONSB,
	DIS_OP_CONSW,
	DIS_OP_CONSP,
	DIS_OP_CONSF,
	DIS_OP_CONSM,
	DIS_OP_CONSMP,
	DIS_OP_HEADB,
	DIS_OP_HEADW,
	DIS_OP_HEADP,
	DIS_OP_HEADF,
	DIS_OP_HEADM,
	DIS_OP_HEADMP,
	DIS_OP_TAIL,
	DIS_OP_LEA,
	DIS_OP_INDX,
	DIS_OP_MOVP,
	DIS_OP_MOVM,
	DIS_OP_MOVMP,
	DIS_OP_MOVB,
	DIS_OP_MOVW,
	DIS_OP_MOVF,
	DIS_OP_CVTBW,
	DIS_OP_CVTWB,
	DIS_OP_CVTFW,
	DIS_OP_CVTWF,
	DIS_OP_CVTCA,
	DIS_OP_CVTAC,
	DIS_OP_CVTWC,
	DIS_OP_CVTCW,
	DIS_OP_CVTFC,
	DIS_OP_CVTCF,
	DIS_OP_ADDB,
	DIS_OP_ADDW,
	DIS_OP_ADDF,
	DIS_OP_SUBB,
	DIS_OP_SUBW,
	DIS_OP_SUBF,
	DIS_OP_MULB,
	DIS_OP_MULW,
	DIS_OP_MULF,
	DIS_OP_DIVB,
	DIS_OP_DIVW,
	DIS_OP_DIVF,
	DIS_OP_MODW,
	DIS_OP_MODB,
	DIS_OP_ANDB,
	DIS_OP_ANDW,
	DIS_OP_ORB,
	DIS_OP_ORW,
	DIS_OP_XORB,
	DIS_OP_XORW,
	DIS_OP_SHLB,
	DIS_OP_SHLW,
	DIS_OP_SHRB,
	DIS_OP_SHRW,
	DIS_OP_INSC,
	DIS_OP_INDC,
	DIS_OP_ADDC,
	DIS_OP_LENC,
	DIS_OP_LENA,
	DIS_OP_LENL,
	DIS_OP_BEQB,
	DIS_OP_BNEB,
	DIS_OP_BLTB,
	DIS_OP_BLEB,
	DIS_OP_BGTB,
	DIS_OP_BGEB,
	DIS_OP_BEQW,
	DIS_OP_BNEW,
	DIS_OP_BLTW,
	DIS_OP_BLEW,
	DIS_OP_BGTW,
	DIS_OP_BGEW,
	DIS_OP_BEQF,
	DIS_OP_BNEF,
	DIS_OP_BLTF,
	DIS_OP_BLEF,
	DIS_OP_BGTF,
	DIS_OP_BGEF,
	DIS_OP_BEQC,
	DIS_OP_BNEC,
	DIS_OP_BLTC,
	DIS_OP_BLEC,
	DIS_OP_BGTC,
	DIS_OP_BGEC,
	DIS_OP_SLICEA,
	DIS_OP_SLICELA,
	DIS_OP_SLICEC,
	DIS_OP_INDW,
	DIS_OP_INDF,
	DIS_OP_INDB,
	DIS_OP_NEGF,
	DIS_OP_MOVL,
	DIS_OP_ADDL,
	DIS_OP_SUBL,
	DIS_OP_DIVL,
	DIS_OP_MODL,
	DIS_OP_MULL,
	DIS_OP_ANDL,
	DIS_OP_ORL,
	DIS_OP_XORL,
	DIS_OP_SHLL,
	DIS_OP_SHRL,
	DIS_OP_BNEL,
	DIS_OP_BLTL,
	DIS_OP_BLEL,
	DIS_OP_BGTL,
	DIS_OP_BGEL,
	DIS_OP_BEQL,
	DIS_OP_CVTLF,
	DIS_OP_CVTFL,
	DIS_OP_CVTLW,
	DIS_OP_CVTWL,
	DIS_OP_CVTLC,
	DIS_OP_CVTCL,
	DIS_OP_HEADL,
	DIS_OP_CONSL,
	DIS_OP_NEWCL,
	DIS_OP_CASEC,
	DIS_OP_INDL,
	DIS_OP_MOVPC,
	DIS_OP_TCMP,
	DIS_OP_MNEWZ,
	DIS_OP_CVTRF,
	DIS_OP_CVTFR,
	DIS_OP_CVTWS,
	DIS_OP_CVTSW,
	DIS_OP_LSRW,
	DIS_OP_LSRL,
	DIS_OP_ECLR,
	DIS_OP_NEWZ,
	DIS_OP_NEWAZ,
	DIS_OP_RAISE,
	DIS_OP_CASEL,
	DIS_OP_MULX,
	DIS_OP_DIVX,
	DIS_OP_CVTXX,
	DIS_OP_MULX0,
	DIS_OP_DIVX0,
	DIS_OP_CVTXX0,
	DIS_OP_MULX1,
	DIS_OP_DIVX1,
	DIS_OP_CVTXX1,
	DIS_OP_CVTFX,
	DIS_OP_CVTXF,
	DIS_OP_EXPW,
	DIS_OP_EXPL,
	DIS_OP_EXPF,
	DIS_OP_SELF,
	DIS_OP_INVALID,
};

struct dis_instr {
	enum dis_op opcode;
	enum dis_operand mop;
	st32 mop_imm;
	enum dis_operand sop;
	// double-indirect addressing means we can have 2 operands
	st32 sop_imm1;
	st32 sop_imm2;
	enum dis_operand dop;
	st32 dop_imm1;
	st32 dop_imm2;
};

struct dis_type {
	st32 desc_number;
	st32 size;
	st32 number_ptrs;
	ut8 *array;
};

struct dis_link {
	st32 pc;
	st32 desc_number;
	st32 sig;
	ut8 *name;
};

static bool dis_read_operand(RBuffer *buf, st32 *n);
static bool dis_read_instr(RBuffer *buf, struct dis_instr *instr);
static bool dis_read_type(RBuffer *buf, struct dis_type *typ);
static bool dis_read_link(RBuffer *buf, struct dis_link *link);

static const char *const dis_opcodes[256];

#endif	/* DIS_DIS_H */