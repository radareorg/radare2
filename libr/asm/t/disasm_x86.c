/* radare - LGPL - Copyright 2009 nibble<.ds@gmail.com> */

#include <stdio.h>

#include <r_types.h>
#include <r_asm.h>

int main()
{
	struct r_asm_t a;
	char str[256]; 
	u8 *buf = "\x74\x31"
		"\x74\x31"
		"\x74\x31"
		"\xc7\xc0\x04\x00\x00\x00";
	int ret = 0;
	u64 idx = 0, len = 12;

	r_asm_init(&a);
	r_asm_set_arch(&a, R_ASM_ARCH_X86);
	r_asm_set_bits(&a, 32);
	r_asm_set_big_endian(&a, R_FALSE);
	r_asm_set_syntax(&a, R_ASM_SYN_INTEL);
	r_asm_set_parser(&a, R_ASM_PAR_PSEUDO, NULL, str);

	while (idx < len) {
		r_asm_set_pc(&a, 0x8048000 + idx);

		ret = r_asm_disasm(&a, buf+idx, len-idx);
		printf("DISASM %s HEX %s\n", a.buf_asm, a.buf_hex);

		r_asm_parse(&a);
		printf("PAR_PSEUDO %s\n\n", str);

		idx += ret;
	}

	return 0;
}
