/* radare - LGPL - Copyright 2009 nibble<.ds@gmail.com> */

#include <stdio.h>
#include <stdlib.h>

#include <r_types.h>
#include <r_asm.h>

int main()
{
	struct r_asm_t a;
	char *buf = "push 0x8059a00";
	int ret;

	r_asm_init(&a);
	r_asm_set_syntax(&a, R_ASM_SYN_OLLY);
	r_asm_set_pc(&a, 0x08049a4b);
	ret = r_asm_asm(&a, buf);
	if (!ret)
		printf("invalid\n");
	else printf("DISASM %s HEX %s\n", a.buf_asm, a.buf_hex);

	return 0;
}
