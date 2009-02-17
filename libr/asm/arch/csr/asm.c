/* radare - LGPL - Copyright 2009 nibble<.ds@gmail.com> */

#include <stdio.h>

#include <r_types.h>
#include <r_util.h>
#include <r_asm.h>

#include "csr_disasm/dis.h"

int r_asm_csr_disasm(struct r_asm_t *a, u8 *buf, u64 len)
{
	r_hex_bin2str((u8*)buf, 2, a->buf_hex);
	arch_csr_disasm(a->buf_asm, buf, a->pc);
	memcpy(a->buf, buf, 2);
	a->inst_len = 2;

	return a->inst_len;
}
