/* radare - LGPL - Copyright 2008-2009 pancake<nopcode.org> */

#include <r_io.h>

R_API int r_io_bind(struct r_io_t *io, struct r_io_bind_t *bnd)
{
	bnd->user = io;
	return R_TRUE;
}

#if 0

this api must be used from r_vm, r_bin ...

#endif
