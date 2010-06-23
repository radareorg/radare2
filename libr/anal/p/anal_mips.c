/* radare - LGPL - Copyright 2010 - pancake<nopcode.org> */

#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>

static int aop(RAnal *anal, RAnalOp *aop, ut64 addr, const ut8 *bytes, int len) {
        ut16 lol, ins;
        int rel = 0;

        if (aop == NULL)
                return 4;

        memset (aop, 0, sizeof (RAnalOp));
        aop->type = R_ANAL_OP_TYPE_UNK;
        aop->length = 4;

        switch (bytes[0]) {
        case 0: // XXX
                aop->type = R_ANAL_OP_TYPE_NOP;
                break;
        default:
                break;
        }
        return aop->length;
}

struct r_anal_plugin_t r_anal_plugin_mips = {
        .name = "mips",
        .desc = "MIPS code analysis plugin",
        .init = NULL,
        .fini = NULL,
        .aop = &aop
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
        .type = R_LIB_TYPE_ANAL,
        .data = &r_anal_plugin_mips
};
#endif
