/* radare2 - LGPL - Copyright 2017-2018 - condret , alvarofe */

#include <r_io.h>
#include <r_util.h>
#include <sdb.h>
#include <r_types.h>
#include <stdio.h>
#include <string.h>
#include "io_private.h"

static void section_free(void *p) {
	RIOSection *s = (RIOSection *) p;
	if (s) {
		free (s->name);
		free (s);
	}
}

R_API void r_io_section_init(RIO *io) {
	if (io) {
		if (!io->sections) {
			io->sections = ls_newf (section_free);
		}
		if (!io->sec_ids) {
			io->sec_ids = r_id_pool_new (0, UT32_MAX);
		}
	}
}

R_API void r_io_section_fini(RIO *io) {
	if (!io) {
		return;
	}
	ls_free (io->sections);
	r_id_pool_free (io->sec_ids);
	io->sections = NULL;
	io->sec_ids = NULL;
}

R_API RIOSection *r_io_section_add(RIO *io, ut64 paddr, ut64 vaddr, ut64 size,
				    ut64 vsize, int perm, const char *name,
				    ut32 bin_id, int fd) {
	if (!io || !io->sections || !io->sec_ids || !r_io_desc_get (io, fd) ||
		UT64_ADD_OVFCHK (size, paddr) || UT64_ADD_OVFCHK (size, vaddr) || !vsize) {
		return NULL;
	}
	RIOSection *sec = R_NEW0 (RIOSection);
	if (sec) {
		sec->paddr = paddr;
		sec->vaddr = vaddr;
		sec->size = size;
		sec->vsize = vsize;
		sec->perm = perm;
		sec->bin_id = bin_id;
		sec->fd = fd;
		if (!name) {
			sec->name = r_str_newf ("section.0x016%"PFMT64x "", vaddr);
		} else {
			sec->name = strdup (name);
		}
		if (!sec->name) {
			free (sec);
			return NULL;
		}
		if (!r_id_pool_grab_id (io->sec_ids, &sec->id)) {
			free (sec->name);
			free (sec);
			return NULL;
		}
		ls_append (io->sections, sec);
	}
	return sec;
}

R_API void r_io_section_cleanup(RIO *io) {
	if (!io || !io->sections || !io->sec_ids) {
		return;
	}
	if (!io->files) {
		r_io_section_fini (io);
		r_io_section_init (io);
		return;
	}
	RIOSection *s;
	SdbListIter *iter, *ator;
	ls_foreach_safe (io->sections, iter, ator, s) {
		if (!s) {
			ls_delete (io->sections, iter);
		} else if (!r_io_desc_get (io, s->fd)) {
			r_id_pool_kick_id (io->sec_ids, s->id);
			ls_delete (io->sections, iter);
		} else {
			if (!r_io_map_exists_for_id (io, s->filemap)) {
				s->filemap = 0;
			}
			if (!r_io_map_exists_for_id (io, s->memmap)) {
				s->memmap = 0;
			}
		}
	}
}

typedef struct {
	const char *uri;
	int perm;
	RIODesc *desc;
} FindFile;

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

static bool io_create_mem_map(RIO *io, RIOSection *sec, ut64 at) {
	r_return_val_if_fail (io && sec, false);

	bool reused = false;
	ut64 gap = sec->vsize - sec->size;
	char *uri = r_str_newf ("null://%"PFMT64u, gap);
	RIODesc *desc = findReusableFile (io, uri, sec->perm);
	if (desc) {
		RIOMap *map = r_io_map_get (io, at);
		if (!map) {
			io_map_new (io, desc->fd, desc->perm, 0LL, at, gap, false);
		}
		reused = true;
	}
	if (!desc) {
		desc = r_io_open_at (io, uri, sec->perm, 0664, at);
	}
	free (uri);
	if (!desc) {
		return false;
	}
	// this works, because new maps are always born on the top
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
