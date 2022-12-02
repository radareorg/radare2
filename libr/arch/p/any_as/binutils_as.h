#ifndef BINUTILS_AS_H
#define BINUTILS_AS_H

#include <r_types.h>
#include <r_asm.h>

int binutils_assemble(RArchSession *arch, RAnalOp *op, const char *buf, const char *as, const char *env, const char *header, const char *cmd_opt);

#endif
