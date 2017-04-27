/* radare2 - LGPL - Copyright 2017 - condret */

#include <r_io.h>
#include <r_util.h>
#include <sdb.h>
#include <r_types.h>
#include <stdio.h>
#include <string.h>

static void section_free(void *p) {
	RIOSection *s = (RIOSection *) p;
	if (s) {
		free (s->name);
		free (s);
	}
}

R_API void r_io_section_init(RIO *io) {
	if (io && !io->sections) {
		if (!(io->sections = ls_newf (section_free))) {
			return;
		}
	}
	io->sec_ids = r_id_pool_new (0, 0xffffffff);
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

R_API int r_io_section_exists_for_id(RIO *io, ut32 id) {
	SdbListIter *iter;
	RIOSection *sec;
	if (!io || !io->sections) {
		return false;
	}
	ls_foreach (io->sections, iter, sec) {
		if (sec->id == id) {
			return true;
		}
	}
	return false;
}

// @deprecate
RIOSection *_section_chk_dup(RIO *io, ut64 paddr, ut64 vaddr, ut64 size, ut64 vsize, int flags, const char *name, ut32 bin_id, int fd) {
	RIOSection *sec;
	SdbListIter *iter;
	char sname[32];
	if (!name) {
		snprintf (sname, sizeof (sname) - 1, "section.0x016%"PFMT64x "", vaddr);
	}
	ls_foreach (io->sections, iter, sec) {
		if ((sec->paddr == paddr) && (sec->vaddr == vaddr) && (sec->size == size) &&
		    (sec->vsize == vsize) && (sec->flags == flags) && (sec->bin_id == bin_id) &&
		    (sec->fd == fd) && !strcmp ((name? name: sname), sec->name)) {
			return sec;
		}
	}
	return NULL;
}

R_API RIOSection *r_io_section_add(RIO *io, ut64 paddr, ut64 vaddr, ut64 size,
				    ut64 vsize, int flags, const char *name,
				    ut32 bin_id, int fd) {
	if (!io || !io->sections || !io->sec_ids || !r_io_desc_get (io, fd) ||
		UT64_ADD_OVFCHK (size, paddr) || UT64_ADD_OVFCHK (size, vaddr)) {
		return NULL;
	}
	RIOSection *sec = _section_chk_dup (io, paddr, vaddr, size, vsize, flags, name, bin_id, fd);
	if (!sec) {
		sec = R_NEW0 (RIOSection);
		if (!sec) {
			return NULL;
		}
		if (!r_id_pool_grab_id (io->sec_ids, &sec->id)) {
			free (sec);
			return NULL;
		}
		sec->paddr = paddr;
		sec->vaddr = vaddr;
		sec->size = size;
		sec->vsize = vsize;
		sec->flags = flags;
		sec->bin_id = bin_id;
		sec->fd = fd;
		if (!name) {
			sec->name = r_str_newf ("section.0x016%"PFMT64x "", vaddr);
		} else {
			sec->name = strdup (name);
		}
		ls_append (io->sections, sec);
	}
	return sec;
}

R_API RIOSection *r_io_section_get_i(RIO *io, ut32 id) {
	SdbListIter *iter;
	RIOSection *s;
	if (!io || !io->sections) {
		return NULL;
	}
	ls_foreach (io->sections, iter, s) {
		if (s->id == id) {
			return s;
		}
	}
	return NULL;
}

R_API int r_io_section_rm(RIO *io, ut32 id) {
	SdbListIter *iter;
	RIOSection *s;
	if (!io || !io->sections || !io->sec_ids) {
		return false;
	}
	ls_foreach (io->sections, iter, s) {
		if (s->id == id) {
			ls_delete (io->sections, iter);
			r_id_pool_kick_id (io->sec_ids, id);
			return true;
		}
	}
	return false;
}

//List return does not have assigned free function only 
//the list will be freed. However, caller will might hold
//an old reference
R_API SdbList *r_io_section_bin_get(RIO *io, ut32 bin_id) {
	SdbList *ret = NULL;
	SdbListIter *iter;
	RIOSection *s;
	if (!io || !io->sections) {
		return NULL;
	}
	ls_foreach (io->sections, iter, s) {
		if (s->bin_id == bin_id) {
			if (!ret) {
				ret = ls_new ();
			}
			ls_prepend (ret, s);
		}
	}
	return ret;
}

R_API bool r_io_section_bin_rm(RIO *io, ut32 bin_id) {
	RIOSection *s;
	SdbListIter *iter, *niter;
	int length;
	if (!io || !io->sections || !io->sections->head || !io->sec_ids) {
		return false;
	}
	length = ls_length (io->sections);
	ls_foreach_safe (io->sections, iter, niter, s) {
		if (s->bin_id == bin_id) {
			r_id_pool_kick_id (io->sec_ids, s->id);
			ls_delete (io->sections, iter);
		}
	}
	return (!(length == ls_length (io->sections)));
}


R_API RIOSection *r_io_section_get_name(RIO *io, const char *name) {
	RIOSection *s;
	SdbListIter *iter;
	if (!io || !name || !io->sections) {
		return NULL;
	}
	ls_foreach (io->sections, iter, s) {
		if (s->name && (!strcmp (s->name, name))) {
			return s;
		}
	}
	return NULL;
}

R_API void r_io_section_cleanup(RIO *io) {
	SdbListIter *iter, *ator;
	RIOSection *s;
	if (!io || !io->sections || !io->sec_ids) {
		return;
	}
	if (!io->files) {
		r_io_section_fini (io);
		r_io_section_init (io);
		return;
	}
	ls_foreach_safe (io->sections, iter, ator, s) {
		if (!s) {
			ls_delete (io->sections, iter);
		} else if (!r_io_desc_get (io, s->fd)) {
			r_id_pool_kick_id (io->sec_ids, s->id);
			ls_delete (io->sections, iter);
		} else {
			if (s->filemap && !r_io_map_exists_for_id (io, s->filemap)) {
				s->filemap = 0;
			}
			if (s->memmap && !r_io_map_exists_for_id (io, s->memmap)) {
				s->memmap = 0;
			}
		}
	}
}

R_API SdbList *r_io_sections_get(RIO *io, ut64 paddr) {
	SdbList *ret = NULL;
	SdbListIter *iter;
	RIOSection *s;
	if (!io || !io->sections) {
		return NULL;
	}
	ls_foreach (io->sections, iter, s) {
		if (paddr >= s->paddr && paddr < (s->paddr + s->size)) {
			if (!ret) {
				ret = ls_new ();
			}
			ls_prepend (ret, s);
		}
	}
	return ret;
}

R_API SdbList *r_io_sections_vget(RIO *io, ut64 vaddr) {
	SdbList *ret = NULL;
	SdbListIter *iter;
	RIOSection *s;
	if (!io || !io->sections) {
		return NULL;
	}
	ls_foreach (io->sections, iter, s) {
		if (vaddr >= s->vaddr && vaddr < (s->vaddr + s->vsize)) {
			if (!ret) {
				ret = ls_new ();
			}
			ls_prepend (ret, s);
		}
	}
	return ret;
}

R_API RIOSection* r_io_section_vget(RIO *io, ut64 vaddr) {
	if (io) {
		SdbList *sects = r_io_sections_vget (io, vaddr);
		RIOSection *ret = NULL;
		if (sects) {
			if (ls_length (sects)) {
				ret = ls_pop (sects);
			}
		}
		ls_free (sects);
		return ret;
	}
	return NULL;
}

R_API RIOSection* r_io_section_get(RIO *io, ut64 vaddr) {
	if (io) {
		SdbList *sects = r_io_sections_get (io, vaddr);
		RIOSection *ret = NULL;
		if (sects) {
			if (ls_length (sects)) {
				ret = ls_pop (sects);
			}
		}
		ls_free (sects);
		return ret;
	}
	return NULL;
}

R_API ut64 r_io_section_get_vaddr_at(RIO *io, ut64 paddr) {
	if (io) {
		SdbList *sects = r_io_sections_vget (io, paddr);
		ut64 ret = UT64_MAX;
		if (sects) {
			if (ls_length (sects)) {
				RIOSection *s = ls_pop (sects);
				ret = s->vaddr;
			}
		}
		ls_free (sects);
		return ret;
	}
	return UT64_MAX;
}

R_API ut64 r_io_section_get_paddr_at(RIO *io, ut64 paddr) {
	if (io) {
		SdbList *sects = r_io_sections_get (io, paddr);
		ut64 ret = UT64_MAX;
		if (sects) {
			if (ls_length (sects)) {
				RIOSection *s = ls_pop (sects);
				ret = s->paddr;
			}
		}
		ls_free (sects);
		return ret;
	}
	return UT64_MAX;
}

R_API int r_io_section_set_archbits(RIO *io, ut32 id, const char *arch, int bits) {
	RIOSection *s;
	if (!(s = r_io_section_get_i (io, id))) {
		return false;
	}
	if (arch) {
		s->arch = r_sys_arch_id (arch);
		s->bits = bits;
	} else {
		s->arch = s->bits = 0;
	}
	return true;
}

R_API const char *r_io_section_get_archbits(RIO *io, ut32 id, int *bits) {
	RIOSection *s = r_io_section_get_i (io, id);
	if (!s || !s->arch || !s->bits) {
		return NULL;
	}
	if (s) {
		if (bits) {
			*bits = s->bits;
		}
		return r_sys_arch_str (s->arch);
	}
	return NULL;
}

R_API int r_io_section_bin_set_archbits(RIO *io, ut32 bin_id, const char *arch, int bits) {
	SdbList *bin_sections;
	SdbListIter *iter;
	RIOSection *s;
	if (!(bin_sections = r_io_section_bin_get (io, bin_id))) {
		return false;
	}
	int a = arch? r_sys_arch_id (arch): 0;
	if (a < 1) {
		a = bits = 0;
	}
	ls_foreach (bin_sections, iter, s) {
		s->arch = a;
		s->bits = bits;
	}
	ls_free (bin_sections);
	return true;
}

R_API bool r_io_section_priorize(RIO *io, ut32 id) {
	SdbListIter *iter, *niter;
	RIOSection *sec;
	bool ret = false;
	// assuming id = 0 is invalid
	if (!id) {
		return false;
	}
	if (!io || !io->sections) {
		return false;
	}
	ls_foreach_safe (io->sections, iter, niter, sec) {
		if (sec->id == id) {
			ls_split_iter (io->sections, iter);
			ls_append (io->sections, sec);
			ret = true;
			break;
		}
	}
	if (!ret) {
		return false;
	}
	if (sec->filemap) {
		ret = r_io_map_priorize (io, sec->filemap);
		if (!sec->memmap) {
			return ret; 
		}
	}
	if (!(sec->filemap == sec->memmap)) {
		return ret & r_io_map_priorize (io, sec->memmap);
	}
	return false;
}

R_API bool r_io_section_priorize_bin(RIO *io, ut32 bin_id) {
	SdbList *secs;
	SdbListIter *iter;
	RIOSection *sec;
	r_io_section_cleanup (io);
	if (!(secs = r_io_section_bin_get (io, bin_id))) {
		return false;
	}
	ls_foreach (secs, iter, sec) {
		r_io_map_priorize (io, sec->filemap);
		r_io_map_priorize (io, sec->memmap);
	}
	ls_free (secs);
	return true;
}

static bool _create_null_map(RIO *io, RIOSection *sec, ut64 at) {
	RIOMap *map = NULL;
	RIODesc *desc = NULL;
	char *uri = NULL;

	if (!io || !sec) {
		return false;
	}
	uri = sdb_fmt (2, "null://%"PFMT64u "", sec->vsize - sec->size);
	desc = r_io_open_at (io, uri, sec->flags, 664, at);
	if (!desc) {
		return false;
	}
	// this works, because new maps are allways born on the top
	map = r_io_map_get (io, at);
	// check if the mapping failed
	if (!map) {
		r_io_close (io, desc->fd);
		return false;
	}
	// let the section refere to the map as a memory-map
	sec->memmap = map->id;
	map->name = r_str_newf ("mmap.%s", sec->name);
	return true;
}

static bool _create_file_map(RIO *io, RIOSection *sec, ut64 size, bool patch) {
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
	map = r_io_map_add (io, sec->fd, flags, sec->paddr, sec->vaddr, size);
	if (map) {
		sec->filemap = map->id;
		map->name = r_str_newf ("fmap.%s", sec->name);
		return true;
	}
	return false;
}

static bool _section_apply_for_anal_patch(RIO *io, RIOSection *sec, bool patch) {
	ut64 at;
	if (sec->vsize > sec->size) {
		// in that case, we just have to allocate some memory of the size (vsize-size)
		if (!sec->memmap) {
			// offset,where the memory should be mapped to
			at = sec->vaddr + sec->size;
			// TODO: harden this, handle mapslit
			// craft the uri for the null-fd
			if (!_create_null_map (io, sec, at)) {
				return false;
			}
			// we need to create this map for transfering the flags, no real remapping here
			if (!_create_file_map (io, sec, sec->size, patch)) {
				return false;
			}
			return true;
		} else {
			// the section is already applied
			return false;
		}
	} else {
		// same as above
		if (!sec->filemap) {
			if (_create_file_map (io, sec, sec->vsize, patch)) {
				return true;
			}
		}
		return false;
	}
}

static bool _section_apply_for_emul(RIO *io, RIOSection *sec) {
	RIODesc *desc, *oldesc;
	RIOMap *map;
	char *uri;
	size_t size;
	ut8 *buf = NULL;
	// if the section doesn't allow writing, we don't need to initialize writeable memory
	if (!(sec->flags & R_IO_WRITE)) {
		return _section_apply_for_anal_patch (io, sec, R_IO_SECTION_APPLY_FOR_ANALYSIS);
	}
	if (sec->memmap) {
		return false;
	}
	size = (size_t) (sec->size > sec->vsize)? sec->vsize: sec->size;
	// allocate a buffer for copying from sec->fd to the malloc-map
	buf = calloc (1, size + 1);
	if (!buf) {
		return false;
	}
	// save the current desc
	oldesc = io->desc;
	// copy to the buffer
	r_io_use_desc (io, sec->fd);
	r_io_pread_at (io, sec->paddr, buf, (int)size);
	// craft the uri for the opening the malloc-fd
	uri = sdb_fmt (3, "malloc://%"PFMT64u "", sec->vsize);
	// open the malloc-fd and map it to vaddr
	desc = r_io_open_at (io, uri, sec->flags, 664, sec->vaddr);
	if (!desc) {
		free (buf);
		return false;
	}
	r_io_use_desc (io, desc->fd);
	// copy from buffer to the malloc-fd
	r_io_pwrite_at (io, 0LL, buf, (int) size);
	free (buf);
	// get the malloc-map
	if ((map = r_io_map_get (io, sec->vaddr))) {
		map->name = r_str_newf ("mmap.%s", sec->name);
		// set the flags correctly
		map->flags = sec->flags;
		// restore old RIODesc
		r_io_use_desc (io, oldesc->fd);
		// let the section refere to the map
		sec->filemap = sec->memmap = map->id;
		return true;
	}
	r_io_use_desc (io, oldesc->fd);
	return false;
}

static bool _section_apply(RIO *io, RIOSection *sec, RIOSectionApplyMethod method) {
	switch (method) {
	case R_IO_SECTION_APPLY_FOR_PATCH:
	case R_IO_SECTION_APPLY_FOR_ANALYSIS:
		return _section_apply_for_anal_patch (io, sec, 
					method == R_IO_SECTION_APPLY_FOR_ANALYSIS? false : true);
	case R_IO_SECTION_APPLY_FOR_EMULATOR:
		return _section_apply_for_emul (io, sec);
	default:
		return false;
	}
}
R_API bool r_io_section_apply(RIO *io, ut32 id, RIOSectionApplyMethod method) {
	RIOSection *sec;
	if (!(sec = r_io_section_get_i (io, id))) {
		return false;
	}
	return _section_apply (io, sec, method);
}

static bool _section_reapply_anal_or_patch(RIO *io, RIOSection *sec, RIOSectionApplyMethod method) {
	SdbListIter *iter;
	RIOMap *map;
	if (!sec) {
		return false;
	}
	if (sec->memmap) {
		ls_foreach (io->maps, iter, map) {
			if (map->id == sec->memmap) {
				r_io_close (io, map->fd);
				break;
			}
		}
		r_io_map_del (io, sec->memmap);
		sec->memmap = 0;
	}
	r_io_map_del (io, sec->filemap);
	sec->filemap = 0;
	return _section_apply (io, sec, method);
}

static bool _section_reapply_for_emul(RIO *io, RIOSection *sec) {
	RIOMap *map = NULL;
	SdbListIter *iter;
	char *uri;
	ut8 *buf = NULL;
	size_t size;
	RIODesc *desc, *oldesc;
	// in this case the section was applied for patching
	if (sec->filemap != sec->memmap) {
		if (!sec->memmap) {
			r_io_map_del (io, sec->filemap);
			sec->filemap = 0;
			return _section_apply (io, sec, R_IO_SECTION_APPLY_FOR_EMULATOR);
		}
		ls_foreach (io->maps, iter, map) {
			if (map->id == sec->memmap) {
				break;
			}
		}
		if (!map) {
			r_io_map_del (io, sec->filemap);
			sec->filemap = sec->memmap = 0;
			return _section_apply (io, sec, R_IO_SECTION_APPLY_FOR_EMULATOR);
		}
		size = (size_t) (map->to - map->from + 1);
		buf = calloc (1, size + 1);
		if (!buf) {
			return false;
		}
		oldesc = io->desc;
		r_io_use_desc (io, map->fd);
		r_io_pread_at (io, map->delta, buf, (int) size);
		r_io_close (io, map->fd);
		if (sec->size > sec->vsize) {
			size = 0;
		} else if (size > (size_t) (sec->vsize - sec->size)) {
			size = (size_t) (sec->vsize - sec->size);
		}
		uri = sdb_fmt (3, "malloc://%"PFMT64u, sec->vsize);
		r_io_open_at (io, uri, sec->flags | R_IO_WRITE, 664, sec->vaddr);
		map = r_io_map_get (io, sec->vaddr);
		r_io_use_desc (io, map->fd);
		r_io_pwrite_at (io, sec->size, buf, (int) size);
		free (buf);
		if (sec->size > sec->vsize) {
			size = (size_t) sec->vsize;
		} else {
			size = (size_t) sec->size;
		}
		buf = calloc (1, size + 1);
		if (!buf) {
			if (oldesc) {
				r_io_use_desc (io, oldesc->fd);
			}
			return false;
		}
		r_io_use_desc (io, sec->fd);
		r_io_pread_at (io, sec->paddr, buf, (int) size);
		r_io_use_desc (io, map->fd);
		r_io_pwrite_at (io, 0LL, buf, (int) size);
		free (buf);
		if (oldesc) {
			r_io_use_desc (io, oldesc->fd);
		}
		sec->filemap = sec->memmap = map->id;
		return true;
	}
	if (!sec->filemap) {
		return _section_apply (io, sec, R_IO_SECTION_APPLY_FOR_EMULATOR);
	}
	ls_foreach (io->maps, iter, map) {
		if (map->id == sec->memmap) {
			break;
		}
	}
	if (!map) {
		return _section_apply (io, sec, R_IO_SECTION_APPLY_FOR_EMULATOR);
	}
	size = (size_t) (map->to - map->from + 1);
	desc = io->desc;
	r_io_use_desc (io, map->fd);
	if (desc == io->desc) {
		desc = NULL;
	}
	buf = calloc (1, size + 1);
	if (!buf) {
		return false;
	}
	r_io_pread_at (io, map->delta, buf, (int) size);
	r_io_close (io, map->fd);
	r_io_map_cleanup (io);
	if (sec->vsize < (ut64) size) {
		size = (size_t) sec->vsize;
	}
	uri = sdb_fmt (3, "malloc://%"PFMT64u, sec->vsize);
	r_io_open_at (io, uri, sec->flags | R_IO_WRITE, 664, sec->vaddr);
	map = r_io_map_get (io, sec->vaddr);
	r_io_use_desc (io, map->fd);
	r_io_pwrite_at (io, 0LL, buf, (int) size);
	free (buf);
	map->flags = sec->flags;
	if (desc) {
		r_io_use_desc (io, desc->fd);
	}
	return true;
}

static bool _section_reapply(RIO *io, RIOSection *sec, RIOSectionApplyMethod method) {
	r_io_map_cleanup (io);
	switch (method) {
	case R_IO_SECTION_APPLY_FOR_PATCH:
	case R_IO_SECTION_APPLY_FOR_ANALYSIS:
		return _section_reapply_anal_or_patch (io, sec, method);
	case R_IO_SECTION_APPLY_FOR_EMULATOR:
		return _section_reapply_for_emul (io, sec);
	default: 
		return false;
	}
}

R_API bool r_io_section_apply_bin(RIO *io, ut32 bin_id, RIOSectionApplyMethod method) {
	RIOSection *sec;
	SdbListIter *iter;
	bool ret = false;
	if (!io || !io->sections) {
		return false;
	}
	ls_foreach (io->sections, iter, sec) {
		if (sec && (sec->bin_id == bin_id)) {
			ret = true;
			_section_apply (io, sec, method);
		}
	}
	return ret;
}

R_API bool r_io_section_reapply(RIO *io, ut32 id, RIOSectionApplyMethod method) {
	RIOSection *sec;
	if (!io || !io->sections || !io->maps) {
		return false;
	}
	if (!(sec = r_io_section_get_i (io, id))) {
		return false;
	}
	return _section_reapply (io, sec, method);
}

R_API bool r_io_section_reapply_bin(RIO *io, ut32 binid, RIOSectionApplyMethod method) {
	RIOSection *sec;
	SdbListIter *iter;
	bool ret = false;
	if (!io || !io->sections) {
		return false;
	}
	ls_foreach (io->sections, iter, sec) {
		if (sec && (sec->bin_id == binid)) {
			ret = true;
			_section_reapply (io, sec, method);
		}
	}
	return ret;
}
