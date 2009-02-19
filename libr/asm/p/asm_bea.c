/* radare - GPL3 - Copyright 2009 nibble<.ds@gmail.com> */

#include <stdio.h>
#include <string.h>

#include <r_types.h>
#include <r_lib.h>
#include <r_util.h>
#include <r_asm.h>

#include "x86/bea/BeaEngine.h"


static int disassemble(struct r_asm_t *a, struct r_asm_aop_t *aop, u8 *buf, u64 len)
{
	DISASM disasm_obj;

	memset(&disasm_obj, '\0', sizeof(DISASM));
	disasm_obj.EIP = (long long)buf;
	disasm_obj.VirtualAddr = a->pc;
	disasm_obj.Archi = ((a->bits == 64) ? 64 : 0);
	disasm_obj.SecurityBlock = len;
	if (a->syntax == R_ASM_SYN_ATT)
		disasm_obj.Options = 0x400;
	else
		disasm_obj.Options = 0;

	aop->inst_len = Disasm(&disasm_obj);

	snprintf(aop->buf_asm, 256, &disasm_obj.CompleteInstr);

	if (aop->inst_len > 0) {
		r_hex_bin2str(buf, aop->inst_len, aop->buf_hex);
		memcpy(aop->buf, buf, aop->inst_len);
	}

	return aop->inst_len;
}

static struct r_asm_handle_t r_asm_plugin_bea = {
	.name = "asm_bea",
	.desc = "X86 disassembly plugin (bea engine)",
	.init = NULL,
	.fini = NULL,
	.disassemble = &disassemble,
	.assemble = NULL
};

struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_bea
};
