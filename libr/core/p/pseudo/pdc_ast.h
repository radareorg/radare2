/* radare - LGPL - Copyright 2026 - pancake, phix33 */

#ifndef R2_PDC_AST_H
#define R2_PDC_AST_H

#include <r_core.h>

// build the structuring region AST for fcn and return its textual dump (pdct)
char *pdc_ast_dump(RCore *core, RAnalFunction *fcn);

#endif
