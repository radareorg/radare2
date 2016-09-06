/* radare - LGPL - Copyright 2016 - bobby.smiles32@gmail.com */
#ifndef R_ASM_ARCH_RSP_RSP_IDEC_H
#define R_ASM_ARCH_RSP_RSP_IDEC_H

#include <r_types.h>


extern const char* rsp_gp_reg_soft_names[];
extern const char* rsp_c0_reg_soft_names[];
extern const char* rsp_gp_reg_names[];
extern const char* rsp_c0_reg_names[];
extern const char* rsp_c2_creg_names[];
extern const char* rsp_c2_accu_names[];
extern const char* rsp_c2_vreg_names[];
extern const char* rsp_c2_vreg_element_names[];


enum {
	RSP_DMEM_OFFSET = 0x0000,
	RSP_IMEM_OFFSET = 0x1000
};

/* restrict address inside rsp MEM */
static inline ut64 rsp_mem_addr(ut64 addr, ut64 base) { addr &= 0xfff; addr |= base; return addr; }


typedef enum {
	RSP_OP_INVALID,
	RSP_OP_NOP,
	RSP_OP_SLL,
	RSP_OP_SRL,
	RSP_OP_SRA,
	RSP_OP_SLLV,
	RSP_OP_SRLV,
	RSP_OP_SRAV,
	RSP_OP_JR,
	RSP_OP_BREAK,
	RSP_OP_ADD,
	RSP_OP_ADDU,
	RSP_OP_SUB,
	RSP_OP_SUBU,
	RSP_OP_AND,
	RSP_OP_OR,
	RSP_OP_XOR,
	RSP_OP_NOR,
	RSP_OP_SLT,
	RSP_OP_SLTU,
	RSP_OP_BLTZ,
	RSP_OP_BGEZ,
	RSP_OP_BLTZAL,
	RSP_OP_BGEZAL,
	RSP_OP_MFC0,
	RSP_OP_MTC0,
	RSP_OP_MFC2,
	RSP_OP_MTC2,
	RSP_OP_CFC2,
	RSP_OP_CTC2,
	RSP_OP_VMULF,
	RSP_OP_VMULU,
	RSP_OP_VMUDL,
	RSP_OP_VMUDM,
	RSP_OP_VMUDN,
	RSP_OP_VMUDH,
	RSP_OP_VMACF,
	RSP_OP_VMACU,
	RSP_OP_VMADL,
	RSP_OP_VMADM,
	RSP_OP_VMADN,
	RSP_OP_VMADH,
	RSP_OP_VADD,
	RSP_OP_VSUB,
	RSP_OP_VABS,
	RSP_OP_VADDC,
	RSP_OP_VSUBC,
	RSP_OP_VSAR,
	RSP_OP_VLT,
	RSP_OP_VEQ,
	RSP_OP_VNE,
	RSP_OP_VGE,
	RSP_OP_VCL,
	RSP_OP_VCH,
	RSP_OP_VCR,
	RSP_OP_VMRG,
	RSP_OP_VAND,
	RSP_OP_VNAND,
	RSP_OP_VOR,
	RSP_OP_VNOR,
	RSP_OP_VXOR,
	RSP_OP_VNXOR,
	RSP_OP_VRCP,
	RSP_OP_VRCPL,
	RSP_OP_VRCPH,
	RSP_OP_VMOV,
	RSP_OP_VRSQ,
	RSP_OP_VRSQL,
	RSP_OP_VRSQH,
	RSP_OP_VNOP,
	RSP_OP_LBV,
	RSP_OP_LSV,
	RSP_OP_LLV,
	RSP_OP_LDV,
	RSP_OP_LQV,
	RSP_OP_LRV,
	RSP_OP_LPV,
	RSP_OP_LUV,
	RSP_OP_LHV,
	RSP_OP_LFV,
	RSP_OP_LTV,
	RSP_OP_SBV,
	RSP_OP_SSV,
	RSP_OP_SLV,
	RSP_OP_SDV,
	RSP_OP_SQV,
	RSP_OP_SRV,
	RSP_OP_SPV,
	RSP_OP_SUV,
	RSP_OP_SHV,
	RSP_OP_SFV,
	RSP_OP_SWV,
	RSP_OP_STV,
	RSP_OP_J,
	RSP_OP_JAL,
	RSP_OP_BEQ,
	RSP_OP_BNE,
	RSP_OP_BLEZ,
	RSP_OP_BGTZ,
	RSP_OP_ADDI,
	RSP_OP_ADDIU,
	RSP_OP_SLTI,
	RSP_OP_SLTIU,
	RSP_OP_ANDI,
	RSP_OP_ORI,
	RSP_OP_XORI,
	RSP_OP_LUI,
	RSP_OP_LB,
	RSP_OP_LH,
	RSP_OP_LW,
	RSP_OP_LBU,
	RSP_OP_LHU,
	RSP_OP_SB,
	RSP_OP_SH,
	RSP_OP_SW
} rsp_opcode;

typedef enum {
	RSP_OPND_GP_REG,           /* u=reg_num */
	RSP_OPND_TARGET,           /* u=imem_address */
	RSP_OPND_OFFSET,           /* u=imem_address, s=offset */
	RSP_OPND_ZIMM,             /* u=zero-extended imm */
	RSP_OPND_SIMM,             /* s=sign extended imm */
	RSP_OPND_SHIFT_AMOUNT,     /* u=shift amount */
	RSP_OPND_BASE_OFFSET,      /* u=reg_numm, s=offset */
	RSP_OPND_C0_REG,           /* u=reg_num */
	RSP_OPND_C2_CREG,          /* u=reg_num */
	RSP_OPND_C2_ACCU,          /* u=reg_num */
	RSP_OPND_C2_VREG,          /* u=reg_num */
	RSP_OPND_C2_VREG_BYTE,     /* u=reg_num, s=byte element (0-15) */
	RSP_OPND_C2_VREG_SCALAR,   /* u=reg_num, s=scalar element (0-7) */
	RSP_OPND_C2_VREG_ELEMENT   /* u=reg_num, s=element (0-15) */
} rsp_operand_type;

typedef struct {
	rsp_operand_type type;
	ut64 u;
	st64 s;
} rsp_operand;

enum { RSP_MAX_OPNDS = 3 };

typedef struct {
	const char* mnemonic;
	rsp_opcode opcode;
	int noperands;
	rsp_operand operands[RSP_MAX_OPNDS];
} rsp_instruction;

rsp_instruction rsp_instruction_decode(ut64 pc, ut32 iw);

#endif
