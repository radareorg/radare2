#include <stdio.h>
#include <stdbool.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_util.h>
#include <r_asm.h>
#include "hexagon.h"

// TODO: Handle also control reg pairs
char* hex_get_cntl_reg(int opreg){
	switch (opreg) {
		case HEX_REG_SA0:
			return "SA0";
		case HEX_REG_LC0:
			return "LC0";
		case HEX_REG_SA1:
			return "SA1";
		case HEX_REG_LC1:
			return "LC1";
		case HEX_REG_P:
			return "P";
		case HEX_REG_M0:
			return "M0";
		case HEX_REG_M1:
			return "M1";
		case HEX_REG_USR:
			return "USR";
		case HEX_REG_PC:
			return "PC";
		case HEX_REG_UGP:
			return "UGP";
		case HEX_REG_GP:
			return "GP";
		case HEX_REG_CS0:
			return "CS0";
		case HEX_REG_CS1:
			return "CS1";
		case HEX_REG_UPCYCLELO:
			return "UPCYCLELO";
		case HEX_REG_UPCYCLEHI:
			return "UPCYCLEHI";
		case HEX_REG_FRAMELIMIT:
			return "FRAMELIMIT";
		case HEX_REG_FRAMEKEY:
			return "FRAMEKEY";
		case HEX_REG_PKTCOUNTLO:
			return "PKTCOUNTLO";
		case HEX_REG_PKTCOUNTHI:
			return "PKTCOUNTHI";
		case HEX_REG_UTIMERLO:
			return "UTIMERLO";
		case HEX_REG_UTIMERHI:
			return "UTIMERHI";
		default:
			return "<CRerr>";
	}
}

char* hex_get_sys_reg(int opreg)
{
	static char tmp[5];
	switch (opreg) {
		case HEX_REG_SGP0:
			return "SGP0";
		case HEX_REG_SGP1:
			return "SGP1";
		case HEX_REG_STID:
			return "STID";
		case HEX_REG_ELR:
			return "ELR";
		case HEX_REG_BADVA0:
			return "BADVA0";
		case HEX_REG_BADVA1:
			return "BADVA1";
		case HEX_REG_SSR:
			return "SSR";
		case HEX_REG_CCR:
			return "CCR";
		case HEX_REG_HTID:
			return "HTID";
		case HEX_REG_BADVA:
			return "BADVA";
		case HEX_REG_IMASK:
			return "IMASK";
		case HEX_REG_EVB:
			return "EVB";
		case HEX_REG_MODECTL:
			return "MODECTL";
		case HEX_REG_SYSCFG:
			return "SYSCFG";
		case HEX_REG_IPEND:
			return "IPEND";
		case HEX_REG_VID:
			return "VID";
		case HEX_REG_IAD:
			return "IAD";
		case HEX_REG_IEL:
			return "IEL";
		case HEX_REG_IAHL:
			return "IAHL";
		case HEX_REG_CFGBASE:
			return "CFGBASE";
		case HEX_REG_DIAG:
			return "DIAG";
		case HEX_REG_REV:
			return "REV";
		case HEX_REG_PCYCLELO:
			return "PCYCLELO";
		case HEX_REG_PCYCLEHI:
			return "PCYCLEHI";
		case HEX_REG_ISDBST:
			return "ISDBST";
		case HEX_REG_ISDBCFG0:
			return "ISDBCFG0";
		case HEX_REG_ISDBCFG1:
			return "ISDBCFG1";
		case HEX_REG_BRKPTPC0:
			return "BRKPTPC0";
		case HEX_REG_BRKPTCFG0:
			return "BRKPTCFG0";
		case HEX_REG_BRKPTPC1:
			return "BRKPTPC1";
		case HEX_REG_BRKPTCFG1:
			return "BRKPTCFG1";
		case HEX_REG_ISDBMBXIN:
			return "ISDBMBXIN";
		case HEX_REG_ISDBMBXOUT:
			return "ISDBMBXOUT";
		case HEX_REG_ISDBEN:
			return "ISDBEN";
		case HEX_REG_ISDBGPR:
			return "ISDBGPR";
		case HEX_REG_PMUCNT0:
			return "PMUCNT0";
		case HEX_REG_PMUCNT1:
			return "PMUCNT1";
		case HEX_REG_PMUCNT2:
			return "PMUCNT2";
		case HEX_REG_PMUCNT3:
			return "PMUCNT3";
		case HEX_REG_PMUEVTCFG:
			return "PMUEVTCFG";
		case HEX_REG_PMUCFG:
			return "PMUCFG";
		default:
			sprintf(tmp, "S%d", opreg);
			return tmp;
	}
}

char* hex_get_sub_reg(int opreg)
{
	switch (opreg) {
		case HEX_SUB_REG_R0:
			return "R0";
		case HEX_SUB_REG_R1:
			return "R1";
		case HEX_SUB_REG_R2:
			return "R2";
		case HEX_SUB_REG_R3:
			return "R3";
		case HEX_SUB_REG_R4:
			return "R4";
		case HEX_SUB_REG_R5:
			return "R5";
		case HEX_SUB_REG_R6:
			return "R6";
		case HEX_SUB_REG_R7:
			return "R7";
		case HEX_SUB_REG_R16:
			return "R16";
		case HEX_SUB_REG_R17:
			return "R17";
		case HEX_SUB_REG_R18:
			return "R18";
		case HEX_SUB_REG_R19:
			return "R19";
		case HEX_SUB_REG_R20:
			return "R20";
		case HEX_SUB_REG_R21:
			return "R21";
		case HEX_SUB_REG_R22:
			return "R22";
		case HEX_SUB_REG_R23:
			return "R23";
		default:
			return "<err>";
	}
}

char* hex_get_sub_regpair(int opreg)
{
	switch (opreg) {
		case HEX_SUB_REGPAIR_R1_R0:
			return "R1:R0";
		case HEX_SUB_REGPAIR_R3_R2:
			return "R3:R2";
		case HEX_SUB_REGPAIR_R5_R4:
			return "R5:R4";
		case HEX_SUB_REGPAIR_R7_R6:
			return "R7:R6";
		case HEX_SUB_REGPAIR_R17_R16:
			return "R17:R16";
		case HEX_SUB_REGPAIR_R19_R18:
			return "R19:R18";
		case HEX_SUB_REGPAIR_R21_R20:
			return "R21:R20";
		case HEX_SUB_REGPAIR_R23_R22:
			return "R23:R22";
		default:
			return "<err>";
	}
}

inline bool hex_if_duplex(uint32_t insn_word)
{
	if ((insn_word & (3 << 14)) == 0) {
		return true;
	}
	return false;
}

// Constant extender value
ut32 constant_extender = 1;

void hex_op_extend(HexOp *op)
{
	if ((constant_extender != 1) && (op->type == HEX_OP_TYPE_IMM)) {
		op->op.imm = ((op->op.imm) & 0x3F) | (constant_extender);
	}
	constant_extender = 1;
}

void hex_op_extend_off(HexOp *op, int offset)
{
	if ((constant_extender != 1) && (op->type == HEX_OP_TYPE_IMM)) {
		op->op.imm = (op->op.imm) >> offset;
		hex_op_extend(op);
	}
}


