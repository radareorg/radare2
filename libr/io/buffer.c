/* radare - LGPL - Copyright 2013 - pancake */

#include "r_io.h"

R_API void r_io_buffer_close(RIO* io) {
	r_cache_flush (io->buffer);
	io->buffer_enabled = 0;
}

R_API int r_io_buffer_load(RIO* io, ut64 addr, int len) {
	ut64 at;
	int i, r;
	ut8 buf[512];
	if (len<1) return R_FALSE;
	io->buffer_enabled = 0;
	for (i=0; i<len; i+=sizeof (buf)) {
		at = addr+i; //r_io_section_vaddr_to_offset (io, addr+i);
		//r_io_seek (io, addr+i, R_IO_SEEK_SET);
		r_io_seek (io, at, R_IO_SEEK_SET);
		memset (buf, 0xff, sizeof (buf));
		r = r_io_read (io, buf, sizeof (buf));
		//eprintf ("r=%d %llx\n", r, addr+i);
		//if (buf[0] !=0xff) eprintf ("STORE %02x %02x %02x\n", buf[0], buf[1], buf[2]);
		if (r<1) break;
		r_cache_set (io->buffer, at, buf, sizeof (buf));
	}
	io->buffer_enabled = 1;
	return R_TRUE;
}

R_API const ut8* r_io_buffer_get (RIO *io, ut64 addr, int *len) {
	return r_cache_get (io->buffer, addr, len);
}

R_API int r_io_buffer_read (RIO *io, ut64 addr, ut8* buf, int len) {
	const ut8 *ret;
	int next, l = 0;
	// align addr if out of buffer if its mapped on io //
	ret = r_cache_get (io->buffer, addr, &l);
	if (!ret) {
		if (l<1) return 0; // no next block in buffer cache
		if (l>len) return 0; // next block too far
		next = l;
		ret = r_cache_get (io->buffer, addr+next+1, &l);
		if (!ret) return 0;
		if (l<len) memset (buf+l, 0xff, (len-l));
		if (l>len) l = len;
		memset (buf, 0xff, next);
		memcpy (buf+next, ret, (len-next));
		return len;
	}
	if (l>len) l = len;
	else if (l<len) memset (buf+l, 0xff, (len-l));
	memcpy (buf, ret, l);
	return l;
}
