/* radare - LGPL - Copyright 2008-2009 pancake<nopcode.org> */

#include <r_io.h>

R_API int r_io_bind(struct r_io_t *io, struct r_io_bind_t *bnd)
{
	bnd->user = io;
	return R_TRUE;
}

#if 0
// define callback for other APIs to use with current io
static int _cb_read(struct r_io_t *io, int pid, ut64 addr, ut8 *buf, int len)
{
}

static int _cb_write(struct r_io_t *io, int pid, ut64 addr, const ut8 *buf, int len)
{
}

R_API int r_io_hook(struct r_io_t *io, CB_IO)
{
	return cb_io(user, _cb_read, _cb_write
}
#endif

#if 0

this api must be used from r_vm, r_bin ...

#endif
