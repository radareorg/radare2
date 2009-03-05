/* radare - GPL3 - Copyright 2009 nibble<.ds@gmail.com> */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_asm.h>

#include <java/javasm/javasm.h>


static int disassemble(struct r_asm_t *a, struct r_asm_aop_t *aop, u8 *buf, u64 len)
{
	javasm_init();
	aop->inst_len = java_disasm(buf, aop->buf_asm);
	aop->disasm_obj = NULL;

	if (aop->inst_len > 0) {
		r_hex_bin2str(buf, aop->inst_len, aop->buf_hex);
		memcpy(aop->buf, buf, aop->inst_len);
	}

	return aop->inst_len;
}

static int assemble(struct r_asm_t *a, struct r_asm_aop_t *aop, char *buf)
{
	int i;

	aop->inst_len = java_assemble(aop->buf, buf);
	aop->disasm_obj = NULL;

	aop->buf_hex[0] = '\0';
	if (aop->inst_len > 0)
		for (i=0; i<aop->inst_len; i++)
			sprintf(aop->buf_hex, "%s%x", aop->buf_hex, aop->buf[i]);

	return aop->inst_len;
}

static struct r_asm_handle_t r_asm_plugin_java = {
	.name = "asm_java",
	.desc = "java disassembly plugin",
	.init = NULL,
	.fini = NULL,
	.disassemble = &disassemble,
	.assemble = &assemble
};

struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_java
};
