/* radare - LGPL - Copyright 2009-2010 pancake<nopcode.org> */

#include <r_debug.h>

R_API ut64 r_debug_mem_alloc(struct r_debug_t *dbg, ut64 size, ut64 addr)
{
	ut64 ret = 0LL;
	if (dbg->h && dbg->h->mem_alloc)
		ret = dbg->h->mem_alloc (dbg, size, addr);
	return ret;
}

R_API int r_debug_mem_free(struct r_debug_t *dbg, ut64 addr)
{
	int ret = R_FALSE;
	if (dbg->h && dbg->h->mem_free)
		ret = dbg->h->mem_free (dbg, addr);
	return ret;
}
