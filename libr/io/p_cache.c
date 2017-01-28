#include <r_io.h>
#include <r_db.h>
#include <r_types.h>
#include <string.h>

const ut64 cleanup_masks[] = {
	0x0000000000000001,
	0x0000000000000003,
	0x0000000000000007,
	0x000000000000000f,
	0x000000000000001f,
	0x000000000000003f,
	0x000000000000007f,
	0x00000000000000ff,
	0x00000000000001ff,
	0x00000000000003ff,
	0x00000000000007ff,
	0x0000000000000fff,
	0x0000000000001fff,
	0x0000000000003fff,
	0x0000000000007fff,
	0x000000000000ffff,
	0x000000000001ffff,
	0x000000000003ffff,
	0x000000000007ffff,
	0x00000000000fffff,
	0x00000000001fffff,
	0x00000000003fffff,
	0x00000000007fffff,
	0x0000000000ffffff,
	0x0000000001ffffff,
	0x0000000003ffffff,
	0x0000000007ffffff,
	0x000000000fffffff,
	0x000000001fffffff,
	0x000000003fffffff,
	0x000000007fffffff,
	0x00000000ffffffff,
	0x00000001ffffffff,
	0x00000003ffffffff,
	0x00000007ffffffff,
	0x0000000fffffffff,
	0x0000001fffffffff,
	0x0000003fffffffff,
	0x0000007fffffffff,
	0x000000ffffffffff,
	0x000001ffffffffff,
	0x000003ffffffffff,
	0x000007ffffffffff,
	0x00000fffffffffff,
	0x00001fffffffffff,
	0x00003fffffffffff,
	0x00007fffffffffff,
	0x0000ffffffffffff,
	0x0001ffffffffffff,
	0x0003ffffffffffff,
	0x0007ffffffffffff,
	0x000fffffffffffff,
	0x001fffffffffffff,
	0x003fffffffffffff,
	0x007fffffffffffff,
	0x00ffffffffffffff,
	0x01ffffffffffffff,
	0x03ffffffffffffff,
	0x07ffffffffffffff,
	0x0fffffffffffffff,
	0x1fffffffffffffff,
	0x3fffffffffffffff,
	0x7fffffffffffffff
};

R_API bool r_io_desc_cache_init(RIODesc *desc) {
	if (!desc || desc->cache) {
		return false;
	}
	if ((desc->cache = sdb_new0 ())) {
		return true;
	}
	return false;
}

R_API int r_io_desc_cache_write(RIODesc *desc, ut64 paddr, ut8 *buf, int len) {
	RIODescCache *cache;
	ut64 desc_sz = r_io_desc_size (desc);
	char k[64];
	ut8 *ptr = buf;
	ut64 caddr;
	int cbaddr, written = 0;
	if ((len < 1) || !desc || (desc_sz <= paddr) ||
	    !desc->io || (!desc->cache && !r_io_desc_cache_init (desc))) {
		return 0;
	}
	if (len > desc_sz) {
		len = (int)desc_sz;
	}
	if (paddr > (desc_sz)) {
		len = (int)(desc_sz - paddr);
	}
	caddr = paddr / 64;
	cbaddr = paddr % 64;
	while (written < len) {
		sdb_itoa (caddr, k, 10);
		//get an existing desc-cache, if it exists
		if (!(cache = (RIODescCache *)sdb_num_get (desc->cache, k, NULL))) {
			//create new desc-cache
			cache = R_NEW0 (RIODescCache);
			//feed sdb with the new desc-cache
			sdb_num_set (desc->cache, k, (ut64)cache, 0);
		}
		//check if the remaining data fits into the cache
		if ((len - written) > (64 - cbaddr)) {
			written += (64 - cbaddr);
			//this can be optimized
			for (;cbaddr < 64; cbaddr++) {
				//write to cache
				cache->cdata[cbaddr] = *ptr;
				//save, that its cached
				cache->cached |= (0x1ULL << cbaddr);
				ptr++;
			}
		} else {
			do {
				cache->cdata[cbaddr] = *ptr;
				cache->cached |= (0x1ULL << cbaddr);
				ptr++;
				written++;
				cbaddr++;
			} while (len > written);
		}
		caddr++;
		cbaddr = 0;
	}
	return written;
}

R_API int r_io_desc_cache_read(RIODesc *desc, ut64 paddr, ut8 *buf, int len) {
	RIODescCache *cache;
	char k[64];
	ut8 *ptr = buf;
	ut64 caddr, desc_sz = r_io_desc_size (desc);
	int cbaddr, amount = 0;
	if ((len < 1) || !desc || (desc_sz <= paddr) || !desc->io || !desc->cache) {
		return 0;
	}
	if (len > desc_sz) {
		len = (int)desc_size;
	}
	if (paddr > (desc_sz - len)) {
		len = (int)(desc_sz - paddr);
	}
	caddr = paddr / 64;
	cbaddr = paddr % 64;
	while (amount < len) {
		sdb_itoa (caddr, k, 10);
		//get an existing desc-cache, if it exists
		if (!(cache = (RIODescCache *)sdb_num_get (desc->cache, k, NULL))) {	
			amount += (64 - cbaddr);
			goto beach;
		}
		if ((len - amount) > (64 - cbaddr)) {
			amount += (64 - cbaddr);
			for (;cbaddr < 64; cbaddr++) {
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

static int __desc_cache_list_cb(void *user, const char *k, const char *v) {
	RList *writes = (RList *)user;
	RIODescCache *dcache;
	RIOCache *cache = NULL;
	ut64 blockaddr;
	int byteaddr, i;
	bool prev_written = false;
	if (!writes) {
		return false;
	}
	dcache = (RIODescCache *)(void *)sdb_atoi (v);
	if (!dcache) {
		return false;
	}
	blockaddr = sdb_atoi (k) * 64;
	for (i = byteaddr = 0; byteaddr < 64; byteaddr++) {
		if (dcache->cached & (0x1LL << byteaddr)) {
			if (!prev_written) {
				cache = R_NEW0 (RIOCache);
				if (!cache) {
					return false;
				}
				cache->data = malloc (64 - byteaddr);
				if (!cache->data) {
					free (cache);
					return false;
				}
				prev_written = true;
				cache->from = blockaddr + byteaddr;
			}
			cache->data[i] = dcache->cdata[byteaddr];
			i++;
		} else if (prev_written) {
			prev_written = false;
			cache->size = i;
			cache->to = cache->from + i - 1;
			cache->data = realloc (cache->data, i);
			i = 0;
			r_list_push (writes, cache);
			cache = NULL;
		}
	}
	if (cache) {
		cache->size = i;
		cache->to = blockaddr + 63;
		r_list_push (writes, cache);
	}
	return true;
}

void __riocache_free (void *user) {
	RIOCache *cache = (RIOCache *)user;
	if (cache) {
		free (cache->data);
		free (cache->odata);
	}
	free (cache);
}

R_API RList *r_io_desc_cache_list(RIODesc *desc) {
	RList *writes;
	RIODesc *current;
	RListIter *iter;
	RIOCache *c;
	if (!desc || !desc->io || !desc->io->desc || !desc->io->p_cache || !desc->cache) {
		return NULL;
	}
	writes = r_list_newf ((RListFree)__riocache_free);
	if (!writes) {
		return NULL;
	}
	sdb_foreach (desc->cache, __desc_cache_list_cb, writes);
	current = desc->io->desc;
	r_io_desc_use (desc->io, desc->fd);
	desc->io->p_cache = false;
	r_list_foreach (writes, iter, c) {
		c->odata = malloc (c->size);
		r_io_pread_at (desc->io, c->from, c->odata, c->size);
	}
	desc->io->p_cache = true;
	r_io_desc_use (desc->io, current->fd);
	return writes;
}

static int __desc_cache_commit_cb(void *user, const char *k, const char *v) {
	RIODesc *desc = (RIODesc *)user;
	RIODescCache *cache;
	ut64 blockaddr, paddr;
	int byteaddr, i;
	ut8 *buf = NULL;
	bool prev_written = false;
	if (!desc || !desc->io) {
		return false;
	}
	cache = (RIODescCache *)(void *)sdb_atoi (v);
	if (!cache) {
		return false;
	}
	blockaddr = 64 * sdb_atoi (k);
	for (i = byteaddr = 0; byteaddr < 64; byteaddr++) {
		if (cache->cached & (0x1LL << byteaddr)) {
			if (!prev_written) {
				buf = malloc (64 - byteaddr);
				if (!buf) {
					return false;
				}
				paddr = blockaddr + byteaddr;
			}
			buf[i] = cache->cdata[byteaddr];
			i++;
		} else if (prev_written) {
			prev_written = false;
			r_io_pwrite_at (desc->io, paddr, buf, i);
			free (buf);
			i = 0;
		}
	}
	free (cache);
	return true;
}

R_API bool r_io_desc_cache_commit (RIODesc *desc) {
	RIODesc *current;
	if (!desc || !(desc->flags & R_IO_WRITE) || !desc->io || !desc->io->files || !desc->io->p_cache) {
		return false;
	}
	if (!desc->cache) {
		return true;
	}
	current = desc->io->desc;
	r_io_desc_use (desc->io, desc->fd);
	desc->io->p_cache = false;
	sdb_foreach (desc->cache, __desc_cache_commit_cb, desc);
	sdb_free (desc->cache);
	desc->cache = NULL;
	desc->io->p_cache = true;
	r_io_desc_use (desc->io, current->fd);
	return true;
}

static int __desc_cache_cleanup_cb (void *user, const char *k, const char *v) {
	RIODesc *desc = (RIODesc *)user;
	RIODescCache *cache;
	ut64 size, blockaddr;
	int byteaddr;
	if (!desc || !desc->cache) {
		return false;
	}
	cache = (RIODescCache *) sdb_atoi (v);
	blockaddr = 64 * sdb_atoi (k);
	size = r_io_desc_size (desc);
	if (size <= blockaddr) {
		free (cache);
		sdb_unset (desc->cache, k, 0);
		return true;
	}
	if (size <= (blockaddr + 63)) {
		//this looks scary, but it isn't
		byteaddr = (int)(size - blockaddr) - 1;		
		cache->cached &= cleanup_masks[byteaddr];
	}
	return true;
}

R_API void r_io_desc_cache_cleanup(RIODesc *desc) {
	if (!desc || !desc->cache) {
		return;
	}
	sdb_foreach (desc->cache, __desc_cache_cleanup_cb, desc);
}

static int __desc_cache_free_cb(void *user, const char* k, const char *v) {
	RIODescCache *cache = (RIODescCache *)(void *)sdb_atoi (v);
	free (cache);
	return true;
}

static int __desc_fini_cb(void *user, const char* k, const char *v) {
	RIODesc *desc = (RIODesc *)(void *)sdb_atoi (v);
	if (desc && desc->cache) {
		sdb_foreach (desc->cache, __desc_cache_free_cb, NULL);
		sdb_free (desc->cache);
	}
	desc->cache = NULL;
	return true;
}

R_API void r_io_desc_cache_fini(RIODesc *desc)
{
	if (desc && desc->cache) {
		sdb_foreach (desc->cache, __desc_cache_free_cb, NULL);
		sdb_free (desc->cache);
	}
	desc->cache = NULL;
}

R_API void r_io_desc_cache_fini_all(RIO *io) {
	if (!io || !io->files) {
		return;
	}
	sdb_foreach (io->files, __desc_fini_cb, NULL);
}
