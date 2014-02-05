/*
 * TMS320 disassembly analizer
 *
 * Written by Ilya V. Matveychikov <i.matveychikov@milabs.ru>
 *
 * Distributed under LGPL
 */

#include <r_anal.h>

#include "../../asm/arch/tms320/tms320_dasm.h"

typedef int (* anal_op_t)(RAnal *, RAnalOp *, ut64, ut8 *, int);

int tms320_c54x_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf, int len);
int tms320_c55x_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf, int len);
int tms320_c55plus_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf, int len);

int tms320_c54x_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf, int len)
{
	// TODO: add the implementation
	return 0;
}

int tms320_c55x_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf, int len)
{
	// TODO: add the implementation
	return 0;
}

int tms320_op(RAnal * anal, RAnalOp * op, ut64 addr, const ut8 * buf, int len)
{
	anal_op_t aop = tms320_c55x_op;

	if (anal->cpu && strcasecmp(anal->cpu, "C54X") == 0)
		aop = tms320_c54x_op;
	if (anal->cpu && strcasecmp(anal->cpu, "C55X") == 0)
		aop = tms320_c55x_op;
	if (anal->cpu && strcasecmp(anal->cpu, "C55PLUS") == 0)
		aop = tms320_c55plus_op;

	return aop(anal, op, addr, buf, len);
}

struct r_anal_plugin_t r_anal_plugin_tms320 = {
	.name = "tms320",
	.arch = R_SYS_ARCH_TMS320,
	.bits = 32,
	.desc = "TMS320 DSP family code analisys plugin",
	.license = "LGPLv3",
	.op = &tms320_op,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_tms320,
};
#endif
