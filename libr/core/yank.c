/* radare - LGPL - Copyright 2009-2010 pancake<nopcode.org> */

#include "r_core.h"

R_API int r_core_yank(struct r_core_t *core, ut64 addr, int len) {
	ut64 curseek = core->offset;
	free (core->yank);
	core->yank = (ut8 *)malloc (len);
	if (addr != core->offset)
		r_core_seek (core, addr, 1);
	if (len == 0)
		len = core->blocksize;
	if (len > core->blocksize)
		r_core_block_size (core, len);
	else memcpy (core->yank, core->block, len);
	core->yank_off = addr;
	core->yank_len = len;
	if (curseek != addr)
		r_core_seek (core, curseek, 1);
	return R_TRUE;
}

R_API int r_core_yank_paste(struct r_core_t *core, ut64 addr, int len) {
	if (len == 0)
		len = core->yank_len;
	if (len > core->yank_len)
		len = core->yank_len;
	r_core_write_at (core, addr, core->yank, len);
	return R_TRUE;
}
