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

static bool _section_apply_for_anal_patch(RIO *io, RIOSection *sec) {
	if (sec->vsize > sec->size) {
		ut64 at = sec->vaddr + sec->size;
		// in that case, we just have to allocate some memory of the size (vsize-size)
		// craft the uri for the null-fd
		if (!sec->memmap && io_create_mem_map (io, sec, at)) {
			// we need to create this map for transferring the perm, no real remapping here
			if (io_create_file_map (io, sec, sec->size)) {
				return true;
			}
		}
	} else {
		// same as above
		if (!sec->filemap && io_create_file_map (io, sec, sec->vsize)) {
			return true;
		}
	}
	return false;
}

R_API bool r_io_section_apply_bin(RIO *io, ut32 bin_id) {
	RIOSection *sec;
	SdbListIter *iter;
	bool ret = false;
	if (!io || !io->sections) {
		return false;
	}
	ls_foreach_prev (io->sections, iter, sec) {
		if (sec && (sec->bin_id == bin_id)) {
			ret = true;
			_section_apply_for_anal_patch (io, sec);
		}
	}
	io_map_calculate_skyline (io);
	return ret;
}
