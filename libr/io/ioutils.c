/* radare - LGPL - Copyright 2017-2023 - condret, pancake */

#include <r_io.h>

// Range-based validation cache implementation
#define VALID_CACHE_CAPACITY 64

R_API void r_io_valid_cache_init(RIO *io) {
	R_RETURN_IF_FAIL (io);
	io->valid_cache.ranges = calloc (VALID_CACHE_CAPACITY, sizeof (RIOVALIDRangeCache));
	if (io->valid_cache.ranges) {
		io->valid_cache.capacity = VALID_CACHE_CAPACITY;
		io->valid_cache.count = 0;
		io->valid_cache.last_query_addr = UT64_MAX;
	}
}

R_API void r_io_valid_cache_fini(RIO *io) {
	R_RETURN_IF_FAIL (io);
	if (io->valid_cache.ranges) {
		free (io->valid_cache.ranges);
		memset (&io->valid_cache, 0, sizeof (io->valid_cache));
	}
}

R_API void r_io_valid_cache_invalidate(RIO *io) {
	R_RETURN_IF_FAIL (io);
	io->valid_cache.count = 0;
	io->valid_cache.last_query_addr = UT64_MAX;
}

// Check if address is in cached range
static bool r_io_valid_cache_lookup(RIO *io, ut64 addr, bool *result) {
	RIOVALIDCache *cache = &io->valid_cache;

	// Fast path: same as last query (common for consecutive bytes)
	if (cache->last_query_addr != UT64_MAX && addr == cache->last_query_addr) {
		*result = cache->last_query_result;
		return true;
	}

	// Search through cached ranges
	for (int i = 0; i < cache->count; i++) {
		RIOVALIDRangeCache *range = &cache->ranges[i];
		if (addr >= range->start_addr && addr <= range->end_addr) {
			*result = range->is_valid;
			cache->last_query_addr = addr;
			cache->last_query_result = range->is_valid;
			return true;
		}
	}
	return false;
}

// Add a validation result to cache
static void r_io_valid_cache_add(RIO *io, ut64 addr, bool result) {
	RIOVALIDCache *cache = &io->valid_cache;

	// If cache is full, replace oldest entry (simple FIFO)
	if (cache->count >= cache->capacity) {
		// Shift all entries to make space at the end
		if (cache->count > 0) {
			memmove (&cache->ranges[0], &cache->ranges[1],
				sizeof (RIOVALIDRangeCache) * (cache->count - 1));
		}
		cache->count--;
	}

	// Add new entry - we cache a small range around the address since
	// most accesses are consecutive
	RIOVALIDRangeCache *range = &cache->ranges[cache->count];
	range->start_addr = addr;
	range->end_addr = addr + 1023;  // Cache 1K range
	range->is_valid = result;
	// TODO: Set proper map_id when we can track it

	cache->count++;
	cache->last_query_addr = addr;
	cache->last_query_result = result;
}

//This helper function only check if the given vaddr is mapped, it does not account
//for map perms
R_API bool r_io_addr_is_mapped(RIO *io, ut64 vaddr) {
	R_RETURN_VAL_IF_FAIL (io, false);
	return (io->va && r_io_map_get_at (io, vaddr));
}

// when io.va is true this checks if the highest priorized map at this
// offset has the same or high permissions set. When there is no map it
// check for the current desc permissions and size.
// when io.va is false it only checks for the desc
R_API bool r_io_is_valid_offset(RIO* io, ut64 offset, int hasperm) {
	R_RETURN_VAL_IF_FAIL (io, false);

	// Try cache lookup first for performance optimization
	bool cached_result;
	if (r_io_valid_cache_lookup (io, offset, &cached_result)) {
		return cached_result;
	}

	// Compute actual result
	bool result = false;
	if ((io->cache.mode & R_PERM_X) == R_PERM_X) {
		// io.cache must be set to true for this codeblock to be executed
		ut8 word[4] = { 0xff, 0xff, 0xff, 0xff};
		// TODO: check for (io->cache.mode & R_PERM_S) ?
		(void)r_io_read_at (io, offset, (ut8*)&word, 4);
		if (!r_io_cache_read_at (io, offset, (ut8*)&word, 4)) {
			if (!r_io_read_at (io, offset, (ut8*)&word, 4)) {
				result = false;
			}
		}
		result = memcmp (word, "\xff\xff\xff\xff", 4) != 0;
	} else if (io->mask) {
		if (offset > io->mask && hasperm & R_PERM_X) {
			result = false;
		} else {
			goto check_permissions;
		}
	} else {
check_permissions:
		if (io->va) {
			if (!hasperm) {
				// return r_io_map_is_mapped (io, offset);
				RIOMap* map = r_io_map_get_at (io, offset);
				result = map ? (map->perm & R_PERM_R) : false;
			} else {
				RIOMap* map = r_io_map_get_at (io, offset);
				result = map ? ((map->perm & hasperm) == hasperm) : false;
			}
		} else {
			if (!io->desc) {
				result = false;
			} else if (offset > r_io_desc_size (io->desc)) {
				result = false;
			} else {
				result = ((io->desc->perm & hasperm) == hasperm);
			}
		}
	}

	// Cache the result for future use
	r_io_valid_cache_add (io, offset, result);
	return result;
}

// this is wrong, there is more than big and little endian
R_API bool r_io_read_i(RIO* io, ut64 addr, ut64 *val, int size, bool endian) {
	ut8 buf[8];
	R_RETURN_VAL_IF_FAIL (io && val, false);
	size = R_DIM (size, 1, 8);
	if (!r_io_read_at (io, addr, buf, size)) {
		return false;
	}
	//size says the number of bytes to read transform to bits for r_read_ble
	*val = r_read_ble (buf, endian, size * 8);
	return true;
}

R_API bool r_io_write_i(RIO* io, ut64 addr, ut64 *val, int size, bool endian) {
	ut8 buf[8];
	R_RETURN_VAL_IF_FAIL (io && val, false);
	size = R_DIM (size, 1, 8);
	//size says the number of bytes to read transform to bits for r_read_ble
	r_write_ble (buf, *val, endian, size * 8);
	return r_io_write_at (io, addr, buf, size) == size;
}
