#ifndef _INCLUDE_R_REG_H_
#define _INCLUDE_R_REG_H_

#include <r_types.h>
#include <list.h>

// XXX this must be in plugins
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

struct r_reg_handle_t {
	int (*is_arch)(int arch, int bits);
	struct list_head list;
};

struct r_reg_t {
	int nregs;
	char **regs;
	struct r_reg_handle_t *h;
	struct list_head handlers;
};

#define R_REG_NAME_MAX 16
struct r_reg_item_t {
	char name[R_REG_NAME_MAX];
	union {
		ut64 value;
		float fvalue;
		double dvalue;
	};
	int offset;
	int isfloat;
};

struct r_regset_t {
	int nregs;
	struct r_reg_item_t *regs;
};

int r_reg_set_arch(struct r_reg_t *reg, int arch, int bits);

#endif
