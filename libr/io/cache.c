/* radare - LGPL - Copyright 2008-2010 pancake<nopcode.org> */

// XXX This has been stolen from r_vm !!! we must adapt this
// XXX to work with r_io correctly
// r_io_cache_t has not been defined
// TODO: implement a more inteligent way to store cached memory
// TODO: define limit of max mem to cache

#include "r_io.h"

R_API void r_io_cache_init(struct r_io_t *io) {
	io->cached = R_FALSE; // cache write ops
	io->cached_read = R_FALSE; // cached read ops
	INIT_LIST_HEAD (&io->cache);
}

R_API void r_io_cache_enable(struct r_io_t *io, int read, int write) {
	io->cached = read|write;
	io->cached_read = read;
}

R_API void r_io_cache_free(struct r_io_t *io, int set) {
	struct r_io_cache_t *c;
	struct list_head *pos, *n;
	io->cached = set;
	list_for_each_safe(pos, n, &io->cache) {
		c = list_entry (pos, struct r_io_cache_t, list);
		free (c->data);
		free (c);
	}
	// is this necessary at all?
	INIT_LIST_HEAD (&io->cache); 
}

R_API int r_io_cache_invalidate(struct r_io_t *io, ut64 from, ut64 to) {
	int ret = R_FALSE;
	/* TODO: Implement: invalidate ranged cached read ops between from/to */
	return ret;
}

R_API int r_io_cache_write(struct r_io_t *io, ut64 addr, const ut8 *buf, int len) {
	struct r_io_cache_t *ch = R_NEW (struct r_io_cache_t);
	ch->from = addr;
	ch->to = addr + len;
	ch->size = len;
	ch->data = (ut8*)malloc (len);
	memcpy (ch->data, buf, len);
	list_add_tail (&(ch->list), &io->cache);
	return len;
}

R_API int r_io_cache_read(struct r_io_t *io, ut64 addr, ut8 *buf, int len) {
	struct r_io_cache_t *c;
	struct list_head *pos;

	// TODO: support for unaligned and partial accesses
	list_for_each (pos, &io->cache) {
		c = list_entry (pos, struct r_io_cache_t, list);
		if (addr >= c->from && addr+len <= c->to) {
			memcpy(buf, c->data, len);
			break;
		}
	}
	return len;
}
