/* radare - LGPL - Copyright 2009 pancake<nopcode.org> */

#include "r_core.h"

int r_core_yank(struct r_core_t *core, u64 addr, int len)
{
	u64 curseek = core->seek;
	free(core->yank);
	core->yank = (u8 *)malloc(len);
	if (addr != core->seek)
		r_core_seek(core, addr);
	if (len == 0)
		len = core->blocksize;
	if (len > core->blocksize)
		r_core_block_size(core, len);
	else memcpy(core->yank, core->block, len);
	core->yank_off = addr;
	core->yank_len = len;
	if (curseek != addr)
		r_core_seek(core, curseek);
	return R_TRUE;
}

int r_core_yank_paste(struct r_core_t *core, u64 addr, int len)
{
	if (len == 0)
		len = core->yank_len;
	if (len > core->yank_len)
		len = core->yank_len;
	r_core_write_at(core, addr, core->yank, len);
	return R_TRUE;
}
