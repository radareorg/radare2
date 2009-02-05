#ifndef _INCLUDE_R_REG_H_
#define _INCLUDE_R_REG_H_

#include <r_types.h>
#include <r_asm.h>

enum {
	R_REG_X86_EAX,
	R_REG_X86_AX,
	R_REG_X86_AL,
	R_REG_X86_AH,
	R_REG_X86_EBX,
	R_REG_X86_ECX,
	R_REG_X86_EDX,
	R_REG_X86_EBP,
	R_REG_X86_ESP,
	R_REG_X86_EIP,
};

struct r_reg_t {
	int nregs;
	char **regs;
};

#endif
