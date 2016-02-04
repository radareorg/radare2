/* radare - LGPL - Copyright 2013-2016 - pancake */

#include "r_io.h"

R_API void r_io_buffer_close(RIO* io) {
	if (io->buffer)
		r_cache_flush (io->buffer);
	io->buffer_enabled = 0;
}

R_API int r_io_buffer_load(RIO* io, ut64 addr, int len) {
	ut8 buf[512];
	int i;
	if (len<1) return false;
	io->buffer_enabled = 0;
	for (i=0; i<len; i+=sizeof (buf)) {
		memset (buf, 0xff, sizeof (buf));
		if (!r_io_read_at (io, addr + i, buf, sizeof (buf)))
			break;
		r_cache_set (io->buffer, addr + i, buf, sizeof (buf));
	}
	io->buffer_enabled = 1;
	return true;
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
		if (l < 1) {
			return 0; // no next block in buffer cache
		}
		if (l > len) {
			return 0; // next block too far
		}
		next = l;
		ret = r_cache_get (io->buffer, addr + next + 1, &l);
		if (!ret) {
			return 0;
		}
		if (l < len) {
			memset (buf + l, 0xff, len - l);
		}
		if (l > len) {
			l = len;
		}
		memset (buf, 0xff, next);
		memcpy (buf + next, ret, len - next);
		return len;
	}
	if (l > len) {
		l = len;
	} else if (l < len) {
		memset (buf + l, 0xff, len - l);
	}
	memcpy (buf, ret, l);
	return l;
}
