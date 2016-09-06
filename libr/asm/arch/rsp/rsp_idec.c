/* radare - LGPL - Copyright 2016 - bobby.smiles32@gmail.com */

#include "rsp_idec.h"


const char* rsp_gp_reg_soft_names[] = {
	"zero", "at", "v0", "v1", "a0", "a1", "a2", "a3",
	"t0", "t1", "t2", "t3", "t4", "t5", "t6", "t7",
	"s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7",
	"t8", "t9", "k0", "k1", "gp", "sp", "s8", "ra"
};

const char* rsp_c0_reg_soft_names[] = {
	"SP_MEM_ADDR", "SP_DRAM_ADDR", "SP_RD_LEN",     "SP_WR_LEN",
	"SP_STATUS",   "SP_DMA_FULL",  "SP_DMA_BUSY",   "SP_SEMAPHORE",
	"DPC_START",   "DPC_END",      "DPC_CURRENT",   "DPC_STATUS",
	"DPC_CLOCK",   "DPC_BUF_BUSY", "DPC_PIPE_BUSY", "DPC_TMEM_BUSY"
};

const char* rsp_gp_reg_names[] = {
	"$0",  "$1",  "$2",  "$3",  "$4",  "$5",  "$6",  "$7",
	"$8",  "$9",  "$10", "$11", "$12", "$13", "$14", "$15",
	"$16", "$17", "$18", "$19", "$20", "$21", "$22", "$23",
	"$24", "$25", "$26", "$27", "$28", "$29", "$30", "$31",
};

const char* rsp_c0_reg_names[] = {
	"$c0", "$c1", "$c2",  "$c3",  "$c4",  "$c5",  "$c6",  "$c7",
	"$c8", "$c9", "$c10", "$c11", "$c12", "$c13", "$c14", "$c15"
};

const char* rsp_c2_creg_names[] = {
	"$vco", "$vcc", "$vce", "???"
};

const char* rsp_c2_accu_names[] = {
	"ACC_H", "ACC_M", "ACC_L", "???"
};

const char* rsp_c2_vreg_names[] = {
	"$v0",  "$v1",  "$v2",  "$v3",  "$v4",  "$v5",  "$v6",  "$v7",
	"$v8",  "$v9",  "$v10", "$v11", "$v12", "$v13", "$v14", "$v15",
	"$v16", "$v17", "$v18", "$v19", "$v20", "$v21", "$v22", "$v23",
	"$v24", "$v25", "$v26", "$v27", "$v28", "$v29", "$v30", "$v31"
};

const char* rsp_c2_vreg_element_names[] = {
	"",    "[?]", "[0q]", "[1q]", "[0h]", "[1h]", "[2h]", "[3h]",
	"[0]", "[1]", "[2]",  "[3]",  "[4]",  "[5]",  "[6]",  "[7]"
};

/* Operand decoders description */
#define RS_DECODER              { RSP_OPND_GP_REG,          21, 0x1f,    0, 0, 0, 0, 0 }
#define RT_DECODER              { RSP_OPND_GP_REG,          16, 0x1f,    0, 0, 0, 0, 0 }
#define RD_DECODER              { RSP_OPND_GP_REG,          11, 0x1f,    0, 0, 0, 0, 0 }
#define SA_DECODER              { RSP_OPND_SHIFT_AMOUNT,     6, 0x1f,    0, 0, 0, 0, 0 }
#define LUI_DECODER             { RSP_OPND_ZIMM,             0, 0xffff, 16, 0, 0, 0, 0 }
#define ZIMM_DECODER            { RSP_OPND_ZIMM,             0, 0xffff,  0, 0, 0, 0, 0 }
#define SIMM_DECODER            { RSP_OPND_SIMM,             0, 0,       0, 0, 0xffff, 0x8000, 0 }
#define OFFSET_DECODER          { RSP_OPND_OFFSET,           0, 0,       0, 0, 0xffff, 0x8000, 2 }
#define BASE_OFFSET_DECODER     { RSP_OPND_BASE_OFFSET,     21, 0x1f,    0, 0, 0xffff, 0x8000, 0 }
#define TARGET_DECODER          { RSP_OPND_TARGET,           0, 0x03ff,  2, 0, 0, 0, 0 }
#define C0_REG_DECODER          { RSP_OPND_C0_REG,          11, 0x0f,    0, 0, 0, 0, 0 }
#define C2_CREG_DECODER         { RSP_OPND_C2_CREG,         11, 0x03,    0, 0, 0, 0, 0 }
#define C2_ACCU_DECODER         { RSP_OPND_C2_ACCU,         21, 0x03,    0, 0, 0, 0, 0 }
#define VS_DECODER              { RSP_OPND_C2_VREG,         11, 0x1f,    0, 0, 0, 0, 0 }
#define VD_DECODER              { RSP_OPND_C2_VREG,          6, 0x1f,    0, 0, 0, 0, 0 }
#define VT_BYTE_DECODER         { RSP_OPND_C2_VREG_BYTE,    16, 0x1f,    0, 7, 0xf, 0, 0 }
#define VS_BYTE_DECODER         { RSP_OPND_C2_VREG_BYTE,    11, 0x1f,    0, 7, 0xf, 0, 0 }
#define VT_SCALAR_DECODER       { RSP_OPND_C2_VREG_SCALAR,  16, 0x1f,    0,21, 0x7, 0, 0 }
#define VD_SCALAR_DECODER       { RSP_OPND_C2_VREG_SCALAR,   6, 0x1f,    0,11, 0x7, 0, 0 }
#define VT_ELEMENT_DECODER      { RSP_OPND_C2_VREG_ELEMENT, 16, 0x1f,    0,21, 0xf, 0, 0 }
#define BASE_VOFFSET1_DECODER   { RSP_OPND_BASE_OFFSET,     21, 0x1f,    0, 0, 0x7f, 0x40, 0 }
#define BASE_VOFFSET2_DECODER   { RSP_OPND_BASE_OFFSET,     21, 0x1f,    0, 0, 0x7f, 0x40, 1 }
#define BASE_VOFFSET4_DECODER   { RSP_OPND_BASE_OFFSET,     21, 0x1f,    0, 0, 0x7f, 0x40, 2 }
#define BASE_VOFFSET8_DECODER   { RSP_OPND_BASE_OFFSET,     21, 0x1f,    0, 0, 0x7f, 0x40, 3 }
#define BASE_VOFFSET16_DECODER  { RSP_OPND_BASE_OFFSET,     21, 0x1f,    0, 0, 0x7f, 0x40, 4 }

/* Operands description */
#define OPNDS_NONE              0,
#define OPNDS_TARGET            1, { TARGET_DECODER }
#define OPNDS_RS_OFFSET         2, { RS_DECODER, OFFSET_DECODER }
#define OPNDS_RS_RT_OFFSET      3, { RS_DECODER, RT_DECODER, OFFSET_DECODER }
#define OPNDS_RT_BASE_OFFSET    2, { RT_DECODER, BASE_OFFSET_DECODER }
#define OPNDS_RS                1, { RS_DECODER }
#define OPNDS_RT_LUI            2, { RT_DECODER, LUI_DECODER }
#define OPNDS_RT_RS_SIMM        3, { RT_DECODER, RS_DECODER, SIMM_DECODER }
#define OPNDS_RT_RS_ZIMM        3, { RT_DECODER, RS_DECODER, ZIMM_DECODER }
#define OPNDS_RD_RT_SA          3, { RD_DECODER, RT_DECODER, SA_DECODER }
#define OPNDS_RD_RT_RS          3, { RD_DECODER, RT_DECODER, RS_DECODER }
#define OPNDS_RD_RS_RT          3, { RD_DECODER, RS_DECODER, RT_DECODER }
#define OPNDS_RT_C0_REG         2, { RT_DECODER, C0_REG_DECODER }
#define OPNDS_RT_C2_CREG        2, { RT_DECODER, C2_CREG_DECODER }
#define OPNDS_RT_VSB            2, { RT_DECODER, VS_BYTE_DECODER }
#define OPNDS_VDS_VTS           2, { VD_SCALAR_DECODER, VT_SCALAR_DECODER }
#define OPNDS_VTB_BASE_OFFSET1  2, { VT_BYTE_DECODER, BASE_VOFFSET1_DECODER }
#define OPNDS_VTB_BASE_OFFSET2  2, { VT_BYTE_DECODER, BASE_VOFFSET2_DECODER }
#define OPNDS_VTB_BASE_OFFSET4  2, { VT_BYTE_DECODER, BASE_VOFFSET4_DECODER }
#define OPNDS_VTB_BASE_OFFSET8  2, { VT_BYTE_DECODER, BASE_VOFFSET8_DECODER }
#define OPNDS_VTB_BASE_OFFSET16 2, { VT_BYTE_DECODER, BASE_VOFFSET16_DECODER }
#define OPNDS_VD_VS_C2_ACCU     3, { VD_DECODER, VS_DECODER, C2_ACCU_DECODER }
#define OPNDS_VD_VS_VTE         3, { VD_DECODER, VS_DECODER, VT_ELEMENT_DECODER }

/* Instructions description */
#define INVALID { "invalid", RSP_OP_INVALID,   OPNDS_NONE }
#define NOP     { "nop",     RSP_OP_NOP,       OPNDS_NONE }
#define SLL     { "sll",     RSP_OP_SLL,       OPNDS_RD_RT_SA }
#define SRL     { "srl",     RSP_OP_SRL,       OPNDS_RD_RT_SA }
#define SRA     { "sra",     RSP_OP_SRA,       OPNDS_RD_RT_SA }
#define SLLV    { "sllv",    RSP_OP_SLLV,      OPNDS_RD_RT_RS }
#define SRLV    { "srlv",    RSP_OP_SRLV,      OPNDS_RD_RT_RS }
#define SRAV    { "srav",    RSP_OP_SRAV,      OPNDS_RD_RT_RS }
#define JR      { "jr",      RSP_OP_JR,        OPNDS_RS }
#define BREAK   { "break",   RSP_OP_BREAK,     OPNDS_NONE }
#define ADD     { "add",     RSP_OP_ADD,       OPNDS_RD_RS_RT }
#define ADDU    { "addu",    RSP_OP_ADDU,      OPNDS_RD_RS_RT }
#define SUB     { "sub",     RSP_OP_SUB,       OPNDS_RD_RS_RT }
#define SUBU    { "subu",    RSP_OP_SUBU,      OPNDS_RD_RS_RT }
#define AND     { "and",     RSP_OP_AND,       OPNDS_RD_RS_RT }
#define OR      { "or",      RSP_OP_OR,        OPNDS_RD_RS_RT }
#define XOR     { "xor",     RSP_OP_XOR,       OPNDS_RD_RS_RT }
#define NOR     { "nor",     RSP_OP_NOR,       OPNDS_RD_RS_RT }
#define SLT     { "slt",     RSP_OP_SLT,       OPNDS_RD_RS_RT }
#define SLTU    { "sltu",    RSP_OP_SLTU,      OPNDS_RD_RS_RT }
#define BLTZ    { "bltz",    RSP_OP_BLTZ,      OPNDS_RS_OFFSET }
#define BGEZ    { "bgez",    RSP_OP_BGEZ,      OPNDS_RS_OFFSET }
#define BLTZAL  { "bltzal",  RSP_OP_BLTZAL,    OPNDS_RS_OFFSET }
#define BGEZAL  { "bgezal",  RSP_OP_BGEZAL,    OPNDS_RS_OFFSET }
#define MFC0    { "mfc0",    RSP_OP_MFC0,      OPNDS_RT_C0_REG }
#define MTC0    { "mtc0",    RSP_OP_MTC0,      OPNDS_RT_C0_REG }
#define MFC2    { "mfc2",    RSP_OP_MFC2,      OPNDS_RT_VSB }
#define MTC2    { "mtc2",    RSP_OP_MTC2,      OPNDS_RT_VSB }
#define CFC2    { "cfc2",    RSP_OP_CFC2,      OPNDS_RT_C2_CREG }
#define CTC2    { "ctc2",    RSP_OP_CTC2,      OPNDS_RT_C2_CREG }
#define VMULF   { "vmulf",   RSP_OP_VMULF,     OPNDS_VD_VS_VTE }
#define VMULU   { "vmulu",   RSP_OP_VMULU,     OPNDS_VD_VS_VTE }
#define VMUDL   { "vmudl",   RSP_OP_VMUDL,     OPNDS_VD_VS_VTE }
#define VMUDM   { "vmudm",   RSP_OP_VMUDM,     OPNDS_VD_VS_VTE }
#define VMUDN   { "vmudn",   RSP_OP_VMUDN,     OPNDS_VD_VS_VTE }
#define VMUDH   { "vmudh",   RSP_OP_VMUDH,     OPNDS_VD_VS_VTE }
#define VMACF   { "vmacf",   RSP_OP_VMACF,     OPNDS_VD_VS_VTE }
#define VMACU   { "vmacu",   RSP_OP_VMACU,     OPNDS_VD_VS_VTE }
#define VMADL   { "vmadl",   RSP_OP_VMADL,     OPNDS_VD_VS_VTE }
#define VMADM   { "vmadm",   RSP_OP_VMADM,     OPNDS_VD_VS_VTE }
#define VMADN   { "vmadn",   RSP_OP_VMADN,     OPNDS_VD_VS_VTE }
#define VMADH   { "vmadh",   RSP_OP_VMADH,     OPNDS_VD_VS_VTE }
#define VADD    { "vadd",    RSP_OP_VADD,      OPNDS_VD_VS_VTE }
#define VSUB    { "vsub",    RSP_OP_VSUB,      OPNDS_VD_VS_VTE }
#define VABS    { "vabs",    RSP_OP_VABS,      OPNDS_VD_VS_VTE }
#define VADDC   { "vaddc",   RSP_OP_VADDC,     OPNDS_VD_VS_VTE }
#define VSUBC   { "vsubc",   RSP_OP_VSUBC,     OPNDS_VD_VS_VTE }
#define VSAR    { "vsar",    RSP_OP_VSAR,      OPNDS_VD_VS_C2_ACCU }
#define VLT     { "vlt",     RSP_OP_VLT,       OPNDS_VD_VS_VTE }
#define VEQ     { "veq",     RSP_OP_VEQ,       OPNDS_VD_VS_VTE }
#define VNE     { "vne",     RSP_OP_VNE,       OPNDS_VD_VS_VTE }
#define VGE     { "vge",     RSP_OP_VGE,       OPNDS_VD_VS_VTE }
#define VCL     { "vcl",     RSP_OP_VCL,       OPNDS_VD_VS_VTE }
#define VCH     { "vch",     RSP_OP_VCH,       OPNDS_VD_VS_VTE }
#define VCR     { "vcr",     RSP_OP_VCR,       OPNDS_VD_VS_VTE }
#define VMRG    { "vmrg",    RSP_OP_VMRG,      OPNDS_VD_VS_VTE }
#define VAND    { "vand",    RSP_OP_VAND,      OPNDS_VD_VS_VTE }
#define VNAND   { "vnand",   RSP_OP_VNAND,     OPNDS_VD_VS_VTE }
#define VOR     { "vor",     RSP_OP_VOR,       OPNDS_VD_VS_VTE }
#define VNOR    { "vnor",    RSP_OP_VNOR,      OPNDS_VD_VS_VTE }
#define VXOR    { "vxor",    RSP_OP_VXOR,      OPNDS_VD_VS_VTE }
#define VNXOR   { "vnxor",   RSP_OP_VNXOR,     OPNDS_VD_VS_VTE }
#define VRCP    { "vrcp",    RSP_OP_VRCP,      OPNDS_VDS_VTS }
#define VRCPL   { "vrcpl",   RSP_OP_VRCPL,     OPNDS_VDS_VTS }
#define VRCPH   { "vrcph",   RSP_OP_VRCPH,     OPNDS_VDS_VTS }
#define VMOV    { "vmov",    RSP_OP_VMOV,      OPNDS_VDS_VTS }
#define VRSQ    { "vrsq",    RSP_OP_VRSQ,      OPNDS_VDS_VTS }
#define VRSQL   { "vrsql",   RSP_OP_VRSQL,     OPNDS_VDS_VTS }
#define VRSQH   { "vrsqh",   RSP_OP_VRSQH,     OPNDS_VDS_VTS }
#define VNOP    { "vnop",    RSP_OP_VNOP,      OPNDS_NONE }
#define LBV     { "lbv",     RSP_OP_LBV,       OPNDS_VTB_BASE_OFFSET1 }
#define LSV     { "lsv",     RSP_OP_LSV,       OPNDS_VTB_BASE_OFFSET2 }
#define LLV     { "llv",     RSP_OP_LLV,       OPNDS_VTB_BASE_OFFSET4 }
#define LDV     { "ldv",     RSP_OP_LDV,       OPNDS_VTB_BASE_OFFSET8 }
#define LQV     { "lqv",     RSP_OP_LQV,       OPNDS_VTB_BASE_OFFSET16 }
#define LRV     { "lrv",     RSP_OP_LRV,       OPNDS_VTB_BASE_OFFSET16 }
#define LPV     { "lpv",     RSP_OP_LPV,       OPNDS_VTB_BASE_OFFSET8 }
#define LUV     { "luv",     RSP_OP_LUV,       OPNDS_VTB_BASE_OFFSET8 }
#define LHV     { "lhv",     RSP_OP_LHV,       OPNDS_VTB_BASE_OFFSET16 }
#define LFV     { "lfv",     RSP_OP_LFV,       OPNDS_VTB_BASE_OFFSET16 }
#define LTV     { "ltv",     RSP_OP_LTV,       OPNDS_VTB_BASE_OFFSET16 }
#define SBV     { "sbv",     RSP_OP_SBV,       OPNDS_VTB_BASE_OFFSET1 }
#define SSV     { "ssv",     RSP_OP_SSV,       OPNDS_VTB_BASE_OFFSET2 }
#define SLV     { "slv",     RSP_OP_SLV,       OPNDS_VTB_BASE_OFFSET4 }
#define SDV     { "sdv",     RSP_OP_SDV,       OPNDS_VTB_BASE_OFFSET8 }
#define SQV     { "sqv",     RSP_OP_SQV,       OPNDS_VTB_BASE_OFFSET16 }
#define SRV     { "srv",     RSP_OP_SRV,       OPNDS_VTB_BASE_OFFSET8 }
#define SPV     { "spv",     RSP_OP_SPV,       OPNDS_VTB_BASE_OFFSET8 }
#define SUV     { "suv",     RSP_OP_SUV,       OPNDS_VTB_BASE_OFFSET16 }
#define SHV     { "shv",     RSP_OP_SHV,       OPNDS_VTB_BASE_OFFSET16 }
#define SFV     { "sfv",     RSP_OP_SFV,       OPNDS_VTB_BASE_OFFSET16 }
#define SWV     { "swv",     RSP_OP_SWV,       OPNDS_VTB_BASE_OFFSET16 }
#define STV     { "stv",     RSP_OP_STV,       OPNDS_VTB_BASE_OFFSET16 }
#define J       { "j",       RSP_OP_J,         OPNDS_TARGET }
#define JAL     { "jal",     RSP_OP_JAL,       OPNDS_TARGET }
#define BEQ     { "beq",     RSP_OP_BEQ,       OPNDS_RS_RT_OFFSET }
#define BNE     { "bne",     RSP_OP_BNE,       OPNDS_RS_RT_OFFSET }
#define BLEZ    { "blez",    RSP_OP_BLEZ,      OPNDS_RS_RT_OFFSET }
#define BGTZ    { "bgtz",    RSP_OP_BGTZ,      OPNDS_RS_RT_OFFSET }
#define ADDI    { "addi",    RSP_OP_ADDI,      OPNDS_RT_RS_SIMM }
#define ADDIU   { "addiu",   RSP_OP_ADDIU,     OPNDS_RT_RS_SIMM }
#define SLTI    { "slti",    RSP_OP_SLTI,      OPNDS_RT_RS_SIMM }
#define SLTIU   { "sltiu",   RSP_OP_SLTIU,     OPNDS_RT_RS_SIMM }
#define ANDI    { "andi",    RSP_OP_ANDI,      OPNDS_RT_RS_ZIMM }
#define ORI     { "ori",     RSP_OP_ORI,       OPNDS_RT_RS_ZIMM }
#define XORI    { "xori",    RSP_OP_XORI,      OPNDS_RT_RS_ZIMM }
#define LUI     { "lui",     RSP_OP_LUI,       OPNDS_RT_LUI }
#define LB      { "lb",      RSP_OP_LB,        OPNDS_RT_BASE_OFFSET }
#define LH      { "lh",      RSP_OP_LH,        OPNDS_RT_BASE_OFFSET }
#define LW      { "lw",      RSP_OP_LW,        OPNDS_RT_BASE_OFFSET }
#define LBU     { "lbu",     RSP_OP_LBU,       OPNDS_RT_BASE_OFFSET }
#define LHU     { "lhu",     RSP_OP_LHU,       OPNDS_RT_BASE_OFFSET }
#define SB      { "sb",      RSP_OP_SB,        OPNDS_RT_BASE_OFFSET }
#define SH      { "sh",      RSP_OP_SH,        OPNDS_RT_BASE_OFFSET }
#define SW      { "sw",      RSP_OP_SW,        OPNDS_RT_BASE_OFFSET }

typedef struct {
	rsp_operand_type type;
	unsigned int u_shift;
	ut32 u_mask;
	unsigned int u_lshift;
	unsigned int s_shift;
	ut32 s_mask;
	ut32 s_smask;
	unsigned int s_lshift;
} rsp_operand_decoder;

typedef struct {
	const char* mnemonic;
	rsp_opcode opcode;
	int noperands;
	rsp_operand_decoder odecs[RSP_MAX_OPNDS];
} rsp_instruction_priv;

static const rsp_instruction_priv rsp_op_table[] = {
/* SPECIAL opcodes table
 * 0-63
 */
	SLL,     INVALID, SRL,     SRA,     SLLV,    INVALID, SRLV,    SRAV,
	JR,      INVALID, INVALID, INVALID, INVALID, BREAK,   INVALID, INVALID,
	INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID,
	INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID,
	ADD,     ADDU,    SUB,     SUBU,    AND,     OR,      XOR,     NOR,
	INVALID, INVALID, SLT,     SLTU,    INVALID, INVALID, INVALID, INVALID,
	INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID,
	INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID,
/* REGIMM opcodes table
* 64-95
*/
	BLTZ,    BGEZ,    INVALID, INVALID, INVALID, INVALID, INVALID, INVALID,
	INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID,
	BLTZAL,  BGEZAL,  INVALID, INVALID, INVALID, INVALID, INVALID, INVALID,
	INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID,
/* COP0 opcodes table
* 96-127
*/
	MFC0,    INVALID, INVALID, INVALID, MTC0,    INVALID, INVALID, INVALID,
	INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID,
	INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID,
	INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID,
/* COP2/1 opcodes table
* 128-159
*/
	MFC2,    INVALID, CFC2,    INVALID, MTC2,    INVALID, CTC2,    INVALID,
	INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID,
	INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID,
	INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID,
/* COP2/2 opcodes table
* 160-223
*/
	VMULF,   VMULU,   INVALID, INVALID, VMUDL,   VMUDM,   VMUDN,   VMUDH,
	VMACF,   VMACU,   INVALID, INVALID, VMADL,   VMADM,   VMADN,   VMADH,
	VADD,    VSUB,    INVALID, VABS,    VADDC,   VSUBC,   INVALID, INVALID,
	INVALID, INVALID, INVALID, INVALID, INVALID, VSAR,    INVALID, INVALID,
	VLT,     VEQ,     VNE,     VGE,     VCL,     VCH,     VCR,     VMRG,
	VAND,    VNAND,   VOR,     VNOR,    VXOR,    VNXOR,   INVALID, INVALID,
	VRCP,    VRCPL,   VRCPH,   VMOV,    VRSQ,    VRSQL,   VRSQH,   VNOP,
	INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID,
/* LWC2 opcodes table
* 224-255
*/
	LBV,     LSV,     LLV,     LDV,     LQV,     LRV,     LPV,     LUV,
	LHV,     LFV,     INVALID, LTV,     INVALID, INVALID, INVALID, INVALID,
	INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID,
	INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID,
/* SWC2 opcodes table
* 256-287
*/
	SBV,     SSV,     SLV,     SDV,     SQV,     SRV,     SPV,     SUV,
	SHV,     SFV,     SWV,     STV,     INVALID, INVALID, INVALID, INVALID,
	INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID,
	INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID,
/* Main opcodes table
* 288-351
*/
	INVALID, INVALID, J,       JAL,     BEQ,     BNE,     BLEZ,    BGTZ,
	ADDI,    ADDIU,   SLTI,    SLTIU,   ANDI,    ORI,     XORI,    LUI,
	INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID,
	INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID,
	LB,      LH,      INVALID, LW,      LBU,     LHU,     INVALID, INVALID,
	SB,      SH,      INVALID, SW,      INVALID, INVALID, INVALID, INVALID,
	INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID,
	INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID, INVALID,
/* Pseudo opcodes
* 352 - ???
*/
	NOP
};

#define SPECIAL   { 0,    0, 0x3f }
#define REGIMM    { 64,  16, 0x1f }
#define COP0      { 96,  21, 0x1f }
#define COP2      { 128, 21, 0x1f }
#define VECTOP    { 160,  0, 0x3f }
#define LWC2      { 224, 11, 0x1f }
#define SWC2      { 256, 11, 0x1f }
#define MAIN      { 288, 26, 0x3f }

typedef struct {
	ut16 offset;
	ut8 shift;
	ut8 mask;
} rsp_op_escape;

static const rsp_op_escape rsp_escapes_table[] = {
	SPECIAL, SPECIAL, REGIMM,  REGIMM, MAIN,    MAIN,    MAIN,    MAIN,
	MAIN,    MAIN,    MAIN,    MAIN,   MAIN,    MAIN,    MAIN,    MAIN,
	MAIN,    MAIN,    MAIN,    MAIN,   MAIN,    MAIN,    MAIN,    MAIN,
	MAIN,    MAIN,    MAIN,    MAIN,   MAIN,    MAIN,    MAIN,    MAIN,
	COP0,    COP0,    MAIN,    MAIN,   COP2,    VECTOP,  MAIN,    MAIN,
	MAIN,    MAIN,    MAIN,    MAIN,   MAIN,    MAIN,    MAIN,    MAIN,
	MAIN,    MAIN,    MAIN,    MAIN,   MAIN,    MAIN,    MAIN,    MAIN,
	MAIN,    MAIN,    MAIN,    MAIN,   MAIN,    MAIN,    MAIN,    MAIN,
	MAIN,    MAIN,    MAIN,    MAIN,   MAIN,    MAIN,    MAIN,    MAIN,
	MAIN,    MAIN,    MAIN,    MAIN,   MAIN,    MAIN,    MAIN,    MAIN,
	MAIN,    MAIN,    MAIN,    MAIN,   MAIN,    MAIN,    MAIN,    MAIN,
	MAIN,    MAIN,    MAIN,    MAIN,   MAIN,    MAIN,    MAIN,    MAIN,
	MAIN,    MAIN,    MAIN,    MAIN,   LWC2,    LWC2,    MAIN,    MAIN,
	MAIN,    MAIN,    MAIN,    MAIN,   MAIN,    MAIN,    MAIN,    MAIN,
	MAIN,    MAIN,    MAIN,    MAIN,   SWC2,    SWC2,    MAIN,    MAIN,
	MAIN,    MAIN,    MAIN,    MAIN,   MAIN,    MAIN,    MAIN,    MAIN
};


static const rsp_instruction_priv* rsp_decode_priv(ut32 iw) {
	const rsp_op_escape* escape;

	/* handle NOP pseudo instruction */
	if (iw == 0) {
		return &rsp_op_table[352];
	}

	escape = &rsp_escapes_table[(iw >> 25)];
	return &rsp_op_table[escape->offset + ((iw >> escape->shift) & escape->mask)];
}

static inline st32 rsp_sign_extend(st32 x, st32 m)
{
	/* assume that bits of x above the m are already zeros
	* which is the case when called from rsp_operand_decode
	*/
	return (x ^ m) - m;
}

static rsp_operand rsp_operand_decode(ut64 pc, ut32 iw, const rsp_operand_decoder* odec) {
	rsp_operand opnd;

	opnd.type = odec->type;
	opnd.u = ((iw >> odec->u_shift) & odec->u_mask) << odec->u_lshift;
	opnd.s = rsp_sign_extend ((iw >> odec->s_shift) & odec->s_mask, odec->s_smask) << odec->s_lshift;

	/* handle targets/offsets IMEM addresses */
	switch (opnd.type) {
	case RSP_OPND_TARGET:
		opnd.u = rsp_mem_addr (opnd.u, RSP_IMEM_OFFSET);
		break;
	case RSP_OPND_OFFSET:
		/* +4 for delay slot */
		opnd.u = rsp_mem_addr (pc + 4 + opnd.s, RSP_IMEM_OFFSET);
		break;
	default: /* do nothing */ break;
	}

	return opnd;
}

rsp_instruction rsp_instruction_decode(ut64 pc, ut32 iw) {
	int opnd;
	const rsp_instruction_priv* priv = rsp_decode_priv (iw);

	rsp_instruction r_instr;

	r_instr.mnemonic = priv->mnemonic;
	r_instr.opcode = priv->opcode;
	r_instr.noperands = priv->noperands;
	for (opnd = 0; opnd < r_instr.noperands; ++opnd) {
		r_instr.operands[opnd] = rsp_operand_decode (pc, iw, &priv->odecs[opnd]);
	}

	return r_instr;
}
