/* radare - LGPL - Copyright 2018 - user */

#include <stdio.h>
#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
    struct op_cmd cmd = {
        .instr = "",
        .operands = ""
    };
    if (len < 2) return -1;
    int ret = decode_opcode (buf, len, &cmd);
    if (ret > 0) {
        snprintf (op->buf_asm, R_ASM_BUFSIZE, "%s %s",
              cmd.instr, cmd.operands);
    }
    return op->size = ret;
}

RAsmPlugin r_asm_plugin_mycpu = {
    .name = "mycpu",
    .license = "LGPL3",
    .desc = "MYCPU disassembly plugin",
    .arch = "mycpu",
    .bits = 32,
    .endian = R_SYS_ENDIAN_LITTLE,
    .disassemble = &disassemble
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
    .type = R_LIB_TYPE_ASM,
    .data = &r_asm_plugin_mycpu,
    .version = R2_VERSION
};
#endif
