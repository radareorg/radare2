/* radare - LGPL - Copyright 2009 nibble<.ds@gmail.com> */

#include <r_types.h>
#include <r_list.h>
#include <r_core.h>

R_API int r_core_anal_bb (struct r_core_t *core, ut64 at) {
	struct r_anal_bb_t *bb, *bbi;
	ut8 *buf;
	RListIter *iter = r_list_iterator (core->anal.bbs);

	while (r_list_iter_next (iter)) {
		bbi = r_list_iter_get (iter);
		if (at >= bbi->addr && at < bbi->addr + bbi->size)
			return R_FALSE;
	}
	if (!(buf = malloc (core->blocksize)))
		return R_FALSE;
	if (!(bb = r_anal_bb_new()))
		return R_FALSE;
	if (r_io_read_at (&core->io, at, buf, core->blocksize) == -1)
		return R_FALSE;
	r_list_append (core->anal.bbs, bb);
	if (r_anal_bb (&core->anal, bb, at, buf, core->blocksize)) {
		if (bb->fail != -1)
			r_core_anal_bb (core, bb->fail);
		if (bb->jump != -1)
			r_core_anal_bb (core, bb->jump);
	}
	free (buf);
	return R_TRUE;
}
