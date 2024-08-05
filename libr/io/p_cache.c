/* radare2 - LGPL - Copyright 2017-2018 - condret, alvaro */

#include <r_io.h>
#include <r_types.h>
#include <string.h>

const ut64 cleanup_masks[] = {
	0x0000000000000001ULL,
	0x0000000000000003ULL,
	0x0000000000000007ULL,
	0x000000000000000fULL,
	0x000000000000001fULL,
	0x000000000000003fULL,
	0x000000000000007fULL,
	0x00000000000000ffULL,
	0x00000000000001ffULL,
	0x00000000000003ffULL,
	0x00000000000007ffULL,
	0x0000000000000fffULL,
	0x0000000000001fffULL,
	0x0000000000003fffULL,
	0x0000000000007fffULL,
	0x000000000000ffffULL,
	0x000000000001ffffULL,
	0x000000000003ffffULL,
	0x000000000007ffffULL,
	0x00000000000fffffULL,
	0x00000000001fffffULL,
	0x00000000003fffffULL,
	0x00000000007fffffULL,
	0x0000000000ffffffULL,
	0x0000000001ffffffULL,
	0x0000000003ffffffULL,
	0x0000000007ffffffULL,
	0x000000000fffffffULL,
	0x000000001fffffffULL,
	0x000000003fffffffULL,
	0x000000007fffffffULL,
	0x00000000ffffffffULL,
	0x00000001ffffffffULL,
	0x00000003ffffffffULL,
	0x00000007ffffffffULL,
	0x0000000fffffffffULL,
	0x0000001fffffffffULL,
	0x0000003fffffffffULL,
	0x0000007fffffffffULL,
	0x000000ffffffffffULL,
	0x000001ffffffffffULL,
	0x000003ffffffffffULL,
	0x000007ffffffffffULL,
	0x00000fffffffffffULL,
	0x00001fffffffffffULL,
	0x00003fffffffffffULL,
	0x00007fffffffffffULL,
	0x0000ffffffffffffULL,
	0x0001ffffffffffffULL,
	0x0003ffffffffffffULL,
	0x0007ffffffffffffULL,
	0x000fffffffffffffULL,
	0x001fffffffffffffULL,
	0x003fffffffffffffULL,
	0x007fffffffffffffULL,
	0x00ffffffffffffffULL,
	0x01ffffffffffffffULL,
	0x03ffffffffffffffULL,
	0x07ffffffffffffffULL,
	0x0fffffffffffffffULL,
	0x1fffffffffffffffULL,
	0x3fffffffffffffffULL,
	0x7fffffffffffffffULL
};

static void pcache_kv_free(HtUPKv *kv) {
	R_RETURN_IF_FAIL (kv);
	free (kv->value);
}

R_API bool r_io_desc_cache_init(RIODesc *desc) {
	if (!desc || desc->cache) {
		return false;
	}
	return (desc->cache = ht_up_new (NULL, pcache_kv_free, NULL)) ? true : false;
}

R_API int r_io_desc_cache_write(RIODesc *desc, ut64 paddr, const ut8 *buf, int len) {
	RIODescCache *cache;
	ut64 caddr, desc_sz = r_io_desc_size (desc);
	int cbaddr, written = 0;
	if ((len < 1) || !desc || (desc_sz <= paddr) ||
	    !desc->io || (!desc->cache && !r_io_desc_cache_init (desc))) {
		return 0;
	}
	if (len > desc_sz) {
		len = (int)desc_sz;
	}
	if (paddr > (desc_sz - len)) {
		len = (int)(desc_sz - paddr);
	}
	caddr = paddr / R_IO_DESC_CACHE_SIZE;
	cbaddr = paddr % R_IO_DESC_CACHE_SIZE;
	while (written < len) {
		//get an existing desc-cache, if it exists
		if (!(cache = (RIODescCache *)ht_up_find (desc->cache, caddr, NULL))) {
			//create new desc-cache
			cache = R_NEW0 (RIODescCache);
			if (!cache) {
				return 0;
			}
			//feed ht with the new desc-cache
			ht_up_insert (desc->cache, caddr, cache);
		}
		//check if the remaining data fits into the cache
		if ((len - written) > (R_IO_DESC_CACHE_SIZE - cbaddr)) {
			written += (R_IO_DESC_CACHE_SIZE - cbaddr);
			//this can be optimized
			for (; cbaddr < R_IO_DESC_CACHE_SIZE; cbaddr++) {
				//write to cache
				cache->cdata[cbaddr] = *buf;
				//save, that its cached
				cache->cached |= (0x1ULL << cbaddr);
				buf++;
			}
		} else {
			//XXX this looks like very suspicious
			do {
				cache->cdata[cbaddr] = *buf;
				cache->cached |= (0x1ULL << cbaddr);
				buf++;
				written++;
				cbaddr++;
			} while (len > written);
		}
		caddr++;
		cbaddr = 0;
	}
	REventIOWrite iow = { paddr, buf, len };
	r_event_send (desc->io->event, R_EVENT_IO_WRITE, &iow);
	return written;
}

R_API int r_io_desc_cache_read(RIODesc *desc, ut64 paddr, ut8 *buf, int len) {
	RIODescCache *cache;
	ut8 *ptr = buf;
	ut64 caddr, desc_sz = r_io_desc_size (desc);
	int cbaddr, amount = 0;
	if ((len < 1) || !desc || (desc_sz <= paddr) || !desc->io || !desc->cache) {
		return 0;
	}
	if (len > desc_sz) {
		len = (int)desc_sz;
	}
	if (paddr > (desc_sz - len)) {
		len = (int)(desc_sz - paddr);
	}
	caddr = paddr / R_IO_DESC_CACHE_SIZE;
	cbaddr = paddr % R_IO_DESC_CACHE_SIZE;
	while (amount < len) {
		// get an existing desc-cache, if it exists
		if (!(cache = (RIODescCache *)ht_up_find (desc->cache, caddr, NULL))) {
			amount += (R_IO_DESC_CACHE_SIZE - cbaddr);
			ptr += (R_IO_DESC_CACHE_SIZE - cbaddr);
			goto beach;
		}
		if ((len - amount) > (R_IO_DESC_CACHE_SIZE - cbaddr)) {
			amount += (R_IO_DESC_CACHE_SIZE - cbaddr);
			for (; cbaddr < R_IO_DESC_CACHE_SIZE; cbaddr++) {
				if (cache->cached & (0x1ULL << cbaddr)) {
					*ptr = cache->cdata[cbaddr];
				}
				ptr++;
			}
		} else {
			do {
				if (cache->cached & (0x1ULL << cbaddr)) {
					*ptr = cache->cdata[cbaddr];
				}
				ptr++;
				amount++;
				cbaddr++;
			} while (len > amount);
		}
beach:
		caddr++;
		cbaddr = 0;
	}
	return amount;
}

static void __riocache_free(void *user) {
	RIOCache *cache = (RIOCache *) user;
	free (cache);
}

static bool __desc_cache_list_cb(void *user, const ut64 k, const void *v) {
	RList *writes = (RList *)user;
	RIOCacheItem *cache = NULL;
	ut64 blockaddr;
	int byteaddr, i;
	if (!writes) {
		return false;
	}
	const RIODescCache *dcache = v;
	blockaddr = k * R_IO_DESC_CACHE_SIZE;
	for (i = byteaddr = 0; byteaddr < R_IO_DESC_CACHE_SIZE; byteaddr++) {
		if (dcache->cached & (0x1LL << byteaddr)) {
			if (!cache) {
				cache = R_NEW0 (RIOCacheItem);
				if (!cache) {
					return false;
				}
				cache->data = malloc (R_IO_DESC_CACHE_SIZE - byteaddr);
				if (!cache->data) {
					free (cache);
					return false;
				}
				cache->itv.addr = blockaddr + byteaddr;
			}
			cache->data[i] = dcache->cdata[byteaddr];
			i++;
		} else if (cache) {
			ut8 *data = realloc (cache->data, i);
			if (!data) {
				__riocache_free ((void *) cache);
				return false;
			}
			cache->data = data;
			cache->itv.size = i;
			i = 0;
			r_list_push (writes, cache);
			cache = NULL;
		}
	}
	if (cache) {
#if 0
		cache->size = i;
		cache->to = blockaddr + R_IO_DESC_CACHE_SIZE;
#endif
		cache->itv.size = i;
		r_list_push (writes, cache);
	}
	return true;
}

R_API RList *r_io_desc_cache_list(RIODesc *desc) {
	if (!desc || !desc->io || !desc->io->desc || !desc->io->p_cache || !desc->cache) {
		return NULL;
	}
	RList *writes = r_list_newf ((RListFree)__riocache_free);
	if (!writes) {
		return NULL;
	}
	ht_up_foreach (desc->cache, __desc_cache_list_cb, writes);
	RIODesc *current = desc->io->desc;
	desc->io->desc = desc;
	desc->io->p_cache = false;

	RIOCacheItem *c;
	RListIter *iter;
	r_list_foreach (writes, iter, c) {
		const ut64 itvSize = r_itv_size (c->itv);
		c->odata = calloc (1, itvSize);
		if (!c->odata) {
			r_list_free (writes);
			return NULL;
		}
		r_io_pread_at (desc->io, r_itv_begin (c->itv), c->odata, itvSize);
	}
	desc->io->p_cache = true;
	desc->io->desc = current;
	return writes;
}

static bool __desc_cache_commit_cb(void *user, const ut64 k, const void *v) {
	RIODesc *desc = (RIODesc *)user;
	int byteaddr, i;
	ut8 buf[R_IO_DESC_CACHE_SIZE] = {0};
	if (!desc || !desc->io) {
		return false;
	}
	const RIODescCache *dcache = v;
	ut64 blockaddr = R_IO_DESC_CACHE_SIZE * k;
	for (i = byteaddr = 0; byteaddr < R_IO_DESC_CACHE_SIZE; byteaddr++) {
		if (dcache->cached & (1LL << byteaddr)) {
			buf[i] = dcache->cdata[byteaddr];
			i++;
		} else if (i > 0) {
			r_io_pwrite_at (desc->io, blockaddr + byteaddr - i, buf, i);
			i = 0;
		}
	}
	if (i > 0) {
		r_io_pwrite_at (desc->io, blockaddr + R_IO_DESC_CACHE_SIZE - i, buf, i);
	}
	return true;
}

R_API bool r_io_desc_cache_commit(RIODesc *desc) {
	RIODesc *current;
	if (!desc || !(desc->perm & R_PERM_W) || !desc->io || !desc->io->files || !desc->io->p_cache) {
		return false;
	}
	if (!desc->cache) {
		return true;
	}
	current = desc->io->desc;
	desc->io->desc = desc;
	desc->io->p_cache = false;
	ht_up_foreach (desc->cache, __desc_cache_commit_cb, desc);
	ht_up_free (desc->cache);
	desc->cache = NULL;
	desc->io->p_cache = true;
	desc->io->desc = current;
	return true;
}

static bool __desc_cache_cleanup_cb(void *user, const ut64 k, const void *v) {
	RIODesc *desc = (RIODesc *)user;
	ut64 size, blockaddr;
	int byteaddr;
	if (!desc || !desc->cache) {
		return false;
	}
	RIODescCache *cache = (RIODescCache *)v;
	blockaddr = R_IO_DESC_CACHE_SIZE * k;
	size = r_io_desc_size (desc);
	if (size <= blockaddr) {
		ht_up_delete (desc->cache, k);
		return true;
	}
	if (size <= (blockaddr + R_IO_DESC_CACHE_SIZE - 1)) {
		//this looks scary, but it isn't
		byteaddr = (int)(size - blockaddr) - 1;
		cache->cached &= cleanup_masks[byteaddr];
	}
	return true;
}

R_API void r_io_desc_cache_cleanup(RIODesc *desc) {
	if (desc && desc->cache) {
		ht_up_foreach (desc->cache, __desc_cache_cleanup_cb, desc);
	}
}

static bool __desc_fini_cb(void *user, void *data, ut32 id) {
	RIODesc *desc = (RIODesc *)data;
	if (desc->cache) {
		ht_up_free (desc->cache);
		desc->cache = NULL;
	}
	return true;
}

R_API void r_io_desc_cache_fini(RIODesc *desc) {
	__desc_fini_cb (NULL, (void *) desc, 0);
}

R_API void r_io_desc_cache_fini_all(RIO *io) {
	if (io && io->files) {
		r_id_storage_foreach (io->files, __desc_fini_cb, NULL);
	}
}
