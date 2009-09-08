/* radare - LGPL - Copyright 2008-2009 pancake<nopcode.org> */

// XXX This has been stolen from r_vm !!! we must adapt this
// XXX to work with r_io correctly
// r_io_cache_t has not been defined

#include "r_io.h"

R_API void r_io_cache_init(struct r_io_t *io)
{
	INIT_LIST_HEAD(&io->cache);
}

R_API int r_io_cache_write(struct r_io_t *io, ut64 addr, const ut8 *buf, int len)
{
	struct r_io_cache_t *ch = MALLOC_STRUCT(struct r_io_cache_t);
	ch->from = addr;
	ch->to = addr + len;
	ch->size = len;
	ch->data = (ut8*)malloc(len);
	memcpy(ch->data, buf, len);
	list_add_tail(&(ch->list), &io->cache);
	return len;
}

R_API int r_io_cache_read(struct r_io_t *io, ut64 addr, ut8 *buf, int len)
{
	struct r_io_cache_t *c;
	struct list_head *pos;

	// TODO: support for unaligned and partial accesses
	list_for_each(pos, &io->cache) {
		c = list_entry(pos, struct r_io_cache_t, list);
		if (addr >= c->from && addr+len <= c->to) {
			memcpy(buf, c->data, len);
			break;
		}
	}
	return len;
}

/*
R_API int r_io_cache_read(struct r_io_t *io, ut64 off, ut8 *data, int len)
{
	if (io->cached && r_io_cache_cache_read(io, off, data, len))
		return len;
	return r_io_read_at(io, off, data, len);
}
*/

#if 0
R_API int r_io_cache_write(struct r_io_t *io, ut64 off, ut8 *data, int len)
{
	if (io->cached)
		return r_io_cache_write(io, off, data, len);
	// XXX: callback for write-at should be userdefined
	return r_io_write_at(io, off, data, len);
}
#endif

R_API void r_io_cache_enable(struct r_io_t *io, int set)
{
	io->cached = set;
}
