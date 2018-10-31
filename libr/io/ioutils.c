/* radare - LGPL - Copyright 2017-2018 - condret */

#include <r_io.h>
#include <r_util.h>
#include <r_types.h>
#include "io_private.h"

// TODO: we may probably take care of this when the binfiles have an associated list of fds
#define REUSE_NULL_MAPS 1

typedef struct {
	const char *uri;
	int perm;
	RIODesc *desc;
} FindFile;

#if REUSE_NULL_MAPS

static bool findFile(void *user, void *data, ut32 id) {
	FindFile *res = (FindFile*)user;
	RIODesc *desc = (RIODesc*)data;
	if (desc->perm && res->perm && !strcmp (desc->uri, res->uri)) {
		res->desc = desc;
		return false;
	}
	return true;
}

static RIODesc *findReusableFile(RIO *io, const char *uri, int perm) {
	FindFile arg = {
		.uri = uri,
		.perm = perm,
		.desc = NULL,
	};
	r_id_storage_foreach (io->files, findFile, &arg);
	return arg.desc;
}

#else

static RIODesc *findReusableFile(RIO *io, const char *uri, int perm) {
	return NULL;
}

#endif

bool io_create_mem_map(RIO *io, RIOSection *sec, ut64 at, bool null, bool do_skyline) {
	RIODesc *desc = NULL;
	char *uri = NULL;
	bool reused = false;

	if (!io || !sec) {
		return false;
	}
	ut64 gap = sec->vsize - sec->size;
	if (null) {
		uri = r_str_newf ("null://%"PFMT64u, gap);
		desc = findReusableFile (io, uri, sec->perm);
		if (desc) {
			RIOMap *map = r_io_map_get (io, at);
			if (!map) {
				io_map_new (io, desc->fd, desc->perm, 0LL, at, gap, false);
			}
			reused = true;
		}
	} else {
		uri = r_str_newf ("malloc://%"PFMT64u, gap);
	}
	if (!desc) {
		desc = r_io_open_at (io, uri, sec->perm, 0664, at);
	}
	free (uri);
	if (!desc) {
		return false;
	}
	if (do_skyline) {
		io_map_calculate_skyline (io);
	}
	// this works, because new maps are allways born on the top
	RIOMap *map = r_io_map_get (io, at);
	// check if the mapping failed
	if (!map) {
		if (!reused) {
			r_io_desc_close (desc);
		}
		return false;
	}
	// let the section refere to the map as a memory-map
	sec->memmap = map->id;
	map->name = r_str_newf ("mmap.%s", sec->name);
	return true;
}

bool io_create_file_map(RIO *io, RIOSection *sec, ut64 size, bool patch, bool do_skyline) {
	RIOMap *map = NULL;
	int perm = 0;
	RIODesc *desc;
	if (!io || !sec) {
		return false;
	}
	desc = r_io_desc_get (io, sec->fd);
	if (!desc) {
		return false;
	}
	perm = sec->perm;
	//create file map for patching
	if (patch) {
		//add -w to the map for patching if needed
		//if the file was not opened with -w desc->perm won't have that bit active
		perm = perm | desc->perm;
	}
	map = io_map_add (io, sec->fd, perm, sec->paddr, sec->vaddr, size, do_skyline);
	if (map) {
		sec->filemap = map->id;
		map->name = r_str_newf ("fmap.%s", sec->name);
		return true;
	}
	return false;
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
			return ((map->perm & hasperm) == hasperm);
		}
		return false;
	}
	if (!io->desc) {
		return false;
	}
	if (r_io_desc_size (io->desc) <= offset) {
		return false;
	}
	return ((io->desc->perm & hasperm) == hasperm);
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
