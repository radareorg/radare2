/* radare - LGPL - Copyright 2017 - condret */

#include <r_io.h>
#include <r_util.h>
#include <r_types.h>

static int __access_log_e_cmp (const void *a, const void *b) {
	RIOAccessLogElement *A = (RIOAccessLogElement *)a;
	RIOAccessLogElement *B = (RIOAccessLogElement *)b;
	return (A->buf_idx > B->buf_idx);
}

R_API bool r_io_create_mem_map(RIO *io, RIOSection *sec, ut64 at, bool null) {
	RIOMap *map = NULL;
	RIODesc *desc = NULL;
	char *uri = NULL;

	if (!io || !sec) {
		return false;
	}
	if (null) {
		uri = r_str_newf ("null://%"PFMT64u "", sec->vsize - sec->size);
	} else {
		uri = r_str_newf ("malloc://%"PFMT64u "", sec->vsize - sec->size);
	}
	desc = r_io_open_at (io, uri, sec->flags, 664, at);
	free (uri);
	if (!desc) {
		return false;
	}
	// this works, because new maps are allways born on the top
	map = r_io_map_get (io, at);
	// check if the mapping failed
	if (!map) {
		r_io_desc_close (desc);
		return false;
	}
	// let the section refere to the map as a memory-map
	sec->memmap = map->id;
	map->name = r_str_newf ("mmap.%s", sec->name);
	return true;
}

R_API bool r_io_create_file_map(RIO *io, RIOSection *sec, ut64 size, bool patch) {
	RIOMap *map = NULL;
	int flags = 0;
	RIODesc *desc;
	if (!io || !sec) {
		return false;
	}
	desc = r_io_desc_get (io, sec->fd);
	if (!desc) {
		return false;
	}
	flags = sec->flags;
	//create file map for patching
	if (patch) {
		//add -w to the map for patching if needed
		//if the file was not opened with -w desc->flags won't have that bit active
		flags = flags | desc->flags;
	}
	map = r_io_map_add (io, sec->fd, flags, sec->paddr, sec->vaddr, size, false);
	if (map) {
		sec->filemap = map->id;
		map->name = r_str_newf ("fmap.%s", sec->name);
		return true;
	}
	return false;
}


R_API bool r_io_create_mem_for_section(RIO *io, RIOSection *sec) {
	if (!io || !sec) {
		return false;
	}
	if (sec->vsize - sec->size > 0) {
		ut64 at = sec->vaddr + sec->size;
		if (!r_io_create_mem_map (io, sec, at, false)) {
			return false;
		}
		RIOMap *map = r_io_map_get (io, at);
		r_io_map_set_name (map, sdb_fmt (0, "mem.%s", sec->name));
			
	}
	if (sec->size) {
		if (!r_io_create_file_map (io, sec, sec->size, false)) {
			return false;
		}
		RIOMap *map = r_io_map_get (io, sec->vaddr);
		r_io_map_set_name (map, sdb_fmt (1, "fmap.%s", sec->name));
	}
	return true;
}
//This helper function only check if the given vaddr is mapped, it does not account
//for map perms
R_API bool r_io_addr_is_mapped(RIO *io, ut64 vaddr) {
	if (io) {
		if (io->va && r_io_map_get (io, vaddr)) {
			return true;
		}
	}
	return false;
}

// when io.va is true this checks if the highest priorized map at this
// offset has the same or high permissions set. When there is no map it
// check for the current desc permissions and size.
// when io.va is false it only checks for the desc
R_API bool r_io_is_valid_offset(RIO* io, ut64 offset, int hasperm) {
	RIOMap* map;
	if (!io) {
		return false;
	}
	if (io->va) {
		if ((map = r_io_map_get (io, offset))) {
			return ((map->flags & hasperm) == hasperm);
		}
		return false;
	}
	if (!io->desc) {
		return false;
	}
	if (r_io_desc_size (io->desc) <= offset) {
		return false;
	}
	return ((io->desc->flags & hasperm) == hasperm);
}

// this is wrong, there is more than big and little endian
R_API bool r_io_read_i(RIO* io, ut64 addr, ut64 *val, int size, bool endian) {
	ut8 buf[8];
	if (!val) {
		return false;
	}
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
	if (!val) {
		return false;
	}
	size = R_DIM (size, 1, 8);
	//size says the number of bytes to read transform to bits for r_read_ble
	r_write_ble (buf, *val, endian, size * 8);
	if (!r_io_write_at (io, addr, buf, size)) {
		return false;
	}
	return true;
}

R_API RIOAccessLog *r_io_accesslog_new() {
	RIOAccessLog *log = R_NEW0 (RIOAccessLog);
	if (!log) {
		return NULL;
	}
	if (!(log->log = r_list_newf (free))) {
		free (log);
		return NULL;
	}
	return log;
}

R_API void r_io_accesslog_free(RIOAccessLog *log) {
	if (log) {
		r_list_free (log->log);
	}
	free (log);
}

R_API void r_io_accesslog_sort(RIOAccessLog *log) {
	if (!log || !log->log) {
		return;
	}
	r_list_sort (log->log, __access_log_e_cmp);
}

R_API void r_io_accesslog_sqash_ignore_gaps(RIOAccessLog *log) {
	RListIter *iter, *ator;
	RIOAccessLogElement *ale, *ela;
	if (!log || !log->log || !log->log->length) {
		return;
	}
	if (!log->log->sorted) {
		r_list_sort (log->log, __access_log_e_cmp);
	}
	r_list_foreach_safe (log->log, iter, ator, ale) {
		if (iter->p) {
			ela = (RIOAccessLogElement *)iter->p->data;
			if ((ale->len == ale->expect_len) && (ela->len == ela->expect_len)) {
				if (ela->mapid != ale->mapid) {
					ela->mapid = 0;			//what to do with fd?
				}
				ela->flags &= ale->flags;
				ela->len += (ale->buf_idx - ela->buf_idx) + ale->len;
				r_list_delete (log->log, iter);
			}
		}
	}
}

R_API void r_io_accesslog_sqash_byflags(RIOAccessLog *log, int flags) {
	RListIter *iter, *ator;
	RIOAccessLogElement *ale, *ela;
	if (!log || !log->log || !log->log->length) {
		return;
	}
	if (!log->log->sorted) {
		r_list_sort (log->log, __access_log_e_cmp);
	}
	r_list_foreach_safe (log->log, iter, ator, ale) {
		if (iter->p) {
			ela = (RIOAccessLogElement *)iter->p->data;
			if (((ale->flags & flags) == (ela->flags & flags)) &&
				((ale->flags & flags) == flags) &&
				(ale->len == ale->expect_len) &&	//only sqash on succes
				(ela->len == ela->expect_len) &&
				((ela->buf_idx + ela->len) == ale->buf_idx)) {
				if (ela->mapid != ale->mapid) {
					ela->mapid = 0;			//what to do with fd?
				}
				ela->flags &= (ale->flags & flags);
				ela->len += ale->len;
				r_list_delete (log->log, iter);
			}
		}
	}
}

//gets first buffer that matches with the flags and frees the element
R_API ut8 *r_io_accesslog_getf_buf_byflags(RIOAccessLog *log, int flags, ut64 *addr, int *len) {
	RListIter *iter;
	RIOAccessLogElement *ale;
	ut8 *ret;
	if (!log || !log->log || !log->log->length) {
		return NULL;
	}
	if (!log->log->sorted) {
		r_list_sort (log->log, __access_log_e_cmp);
	}
	r_list_foreach (log->log, iter, ale) {
		if (((ale->flags & flags) == flags) && (ale->len == ale->expect_len)) {
			ret = &log->buf[ale->buf_idx];
			*len = ale->len;
			*addr = ale->vaddr;		//what about pa?
			r_list_delete (log->log, iter);
			return ret;
		}
	}
	return NULL;
}
