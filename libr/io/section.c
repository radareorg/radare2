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
		if ((io->sections = ls_new ())) {
			io->sections->free = section_free;
		}
	}
	io->sec_ids = r_id_pool_new (0, 0xffffffff);
}

R_API void r_io_section_fini(RIO *io) {
	if (!io) {
		return;
	}
	ls_free (io->sections);
	io->sections = NULL;
	r_id_pool_free (io->sec_ids);
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


R_API RIOSection *r_io_section_add(RIO *io, ut64 paddr, ut64 vaddr, ut64 size, ut64 vsize, int flags, const char *name, ut32 bin_id, int fd) {
	if (!io || !io->sections || !io->sec_ids || !r_io_desc_get (io, fd) || (((ut64) (UT64_MAX - size)) < paddr) || ((ut64) (UT64_MAX - vsize) < vaddr)) {
		return NULL;
	}
	RIOSection *sec = _section_chk_dup (io, paddr, vaddr, size, vsize, flags, name, bin_id, fd);
	if (!sec) {
		sec = R_NEW0 (RIOSection);
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
	ret->free = NULL;
	return ret;
}

R_API bool r_io_section_bin_rm(RIO *io, ut32 bin_id) {
	RIOSection *s;
	SdbListIter *iter;
	int length;
	if (!io || !io->sections || !io->sections->head || !io->sec_ids) {
		return false;
	}
	length = io->sections->length;
	for (iter = io->sections->head; iter; iter = iter->n) {
		s = (RIOSection *) iter->data;
		if (s->bin_id == bin_id) {
			if (iter->p) {
				iter->p->n = iter->n;
			}
			if (iter->n) {
				iter->n->p = iter->p;
			}
			r_id_pool_kick_id (io->sec_ids, s->id);
			section_free (s);
			free (iter);
			io->sections->length--;
		}
	}
	return (!(length == io->sections->length));
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
	RIOSection *section;
	if (!io || !io->sections || !io->sec_ids) {
		return;
	}
	if (!io->files) {
		r_io_section_fini (io);
		r_io_section_init (io);
		return;
	}
	for (iter = io->sections->head; iter != NULL; iter = ator) {
		section = iter->data;
		ator = iter->n;
		if (!section) {
			ls_delete (io->sections, iter);
		} else if (!r_io_desc_get (io, section->fd)) {
			r_id_pool_kick_id (io->sec_ids, section->id);
			ls_delete (io->sections, iter);
		} else {
			if (section->filemap && !r_io_map_exists_for_id (io, section->filemap)) {
				section->filemap = 0;
			}
			if (section->memmap && !r_io_map_exists_for_id (io, section->memmap)) {
				section->memmap = 0;
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
				ret->free = NULL;
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
	bin_sections->free = NULL; // maybe not needed
	ls_free (bin_sections);
	return true;
}

R_API bool r_io_section_priorize(RIO *io, ut32 id) {
	SdbListIter *iter;
	RIOSection *sec;
	bool ret = false;
	// assuming id = 0 is invalid
	if (!id) {
		return false;
	}
	if (!io || !io->sections) {
		return false;
	}
	ls_foreach (io->sections, iter, sec) {
		if (sec->id == id) {
			if (io->sections->tail == iter) {
				ret = true;
				break;
			}
			if (iter->p) {
				iter->p->n = iter->n;
			}
			if (iter->n) {
				iter->n->p = iter->p;
			}
			if (io->sections->head == iter) {
				io->sections->head = iter->n;
			}
			io->sections->tail->n = iter;
			iter->p = io->sections->tail;
			io->sections->tail = iter;
			iter->n = NULL;
			ret = true;
			break;
		}
	}
	if (!ret) {
		return false;
	}
	sec = (RIOSection *) iter->data;
	if (sec->filemap) {
		if (!sec->memmap) {
			return r_io_map_priorize (io, sec->filemap);
		}
		ret = r_io_map_priorize (io, sec->filemap);
	} else if (!(sec->filemap == sec->memmap)) {
		return r_io_map_priorize (io, sec->memmap);
	}
	if (!(sec->filemap == sec->memmap)) {
		return ret & r_io_map_priorize (io, sec->memmap);
	}
	return false;
}

R_API bool r_io_section_priorize_bin(RIO *io, ut32 bin_id) {
	SdbList *secs;
	RIOSection *sec;
	r_io_section_cleanup (io);
	if (!(secs = r_io_section_bin_get (io, bin_id))) {
		return false;
	}
	while (secs->length) {
		sec = ls_pop (secs);
		r_io_map_priorize (io, sec->filemap);
		r_io_map_priorize (io, sec->memmap);
	}
	ls_free (secs);
	return true;
}

static bool _section_apply(RIO *io, RIOSection *sec, RIOSectionApplyMethod method) {
	RIODesc *desc;
	RIOMap *map;
	ut64 at;
	char uri[64];
	char *name;
	// this is for doing hexeditor-stuff and pure static analysis
	if (method == (R_IO_SECTION_APPLY_FOR_HEXEDITOR || R_IO_SECTION_APPLY_FOR_ANALYSIS)) {
		if (sec->paddr == sec->vaddr) {
			// only for vaddr==addr and vsize > size
			if (sec->vsize > sec->size) {
				// in that case, we just have to allocate some memory of the size (vsize-size)
				if (!sec->memmap) {
					// offset,where the memory should be mapped to
					at = sec->vaddr + sec->size;
					// TODO: harden this, handle mapslit
					// craft the uri for the null-fd
					snprintf (uri, 64, "null://%"PFMT64u "", sec->vsize - sec->size);
					// open the null-fd and map it to vaddr + size
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
					if ((name = calloc (1, strlen (sec->name) + 6))) {
						sprintf (name, "mmap.%s", sec->name);
						map->name = name;
					}
					// we need to create this map for transfering the flags, no real remapping here
					if (method == R_IO_SECTION_APPLY_FOR_ANALYSIS) {
						sec->filemap = r_io_map_add (io, sec->fd, sec->flags, sec->paddr, sec->vaddr, sec->size)->id;
					} else {
						// when addr==vaddr we need no filemap
						sec->filemap = 0;
					}
					return true;
				} else {
					// the section is already applied
					return false;
				}
			} else if (method == R_IO_SECTION_APPLY_FOR_ANALYSIS) {
				// same as above
				if (!sec->filemap) {
					if ((map = r_io_map_add (io, sec->fd, sec->flags, sec->paddr, sec->vaddr, sec->vsize))) {
						sec->filemap = map->id;
						map->name = r_str_newf ("fmap.%s", sec->name);
						return true;
					}
				}
				return false;
			}
		}
		// taken, when the section does a remapping, but no "memory-allocation"
		if (!sec->filemap && sec->size >= sec->vsize) {
			// get the RIODesc that the section belongs to
			if (!r_io_desc_get (io, sec->fd)) {
				// this usually won't happen, but checking against it doesn't hurt
				return false;
			}
			// apply the mapping
			map = r_io_map_add (io, sec->fd, sec->flags, sec->paddr, sec->vaddr, sec->vsize);
			if (map) {
				map->name = r_str_newf ("fmap.%s", sec->name);
				// let the section refere to the new map as a filemap
				sec->filemap = map->id;
				// memmap is 0, because there is no memory allocation here
				sec->memmap = 0;
				return true;
			}
			sec->memmap = 0;
			return false;
		}
		// check if section already got applied
		if (!sec->filemap && !sec->memmap) {
			// get the RIODesc to which the section belongs
			if (!r_io_desc_get (io, sec->fd)) {
				return false;
			}
			// apply the mapping for the filearea
			map = r_io_map_add (io, sec->fd, sec->flags, sec->paddr, sec->vaddr, sec->size);
			if (!map) {
				return false;
			}
			map->name = r_str_newf ("fmap.%s", sec->name);
			// let the section refere to the map as filemap
			sec->filemap = map->id;
			// TODO: harden this, handle mapslit
			at = sec->vaddr + sec->size;
			// craft the uri for the null-fd
			snprintf (uri, 64, "null://%"PFMT64u "", sec->vsize - sec->size);
			// open the null-fd and map it to vaddr+size
			desc = r_io_open_at (io, uri, sec->flags, 664, at);
			if (!desc) {
				return false;
			}
			// get the null-map
			map = r_io_map_get (io, at);
			if (!map) {
				r_io_close (io, desc->fd);
				return false;
			}
			map->name = r_str_newf ("mmap.%s", sec->name);
			// let the section refere to the null-map as a memory-map
			sec->memmap = map->id;
			return true;
		}
	}
	if (method == R_IO_SECTION_APPLY_FOR_EMULATOR) {
		size_t size;
		ut8 *buf = NULL;
		// if the section doesn't allow writing, we don't need to initialize writeable memory
		if (!(sec->flags & R_IO_WRITE)) {
			// TODO: remove recursion
			return _section_apply (io, sec, R_IO_SECTION_APPLY_FOR_ANALYSIS);
		}
		if (sec->memmap) {
			return false;
		}
		size = (size_t) (sec->size > sec->vsize)? sec->vsize: sec->size;
		// allocate a buffer for copying from sec->fd to the malloc-map
		buf = malloc (size);
		// craft the uri for the opening the malloc-fd
		snprintf (uri, 64, "malloc://%"PFMT64u "", sec->vsize);
		// save the current desc
		desc = io->desc;
		// copy to the buffer
		r_io_use_desc (io, sec->fd);
		r_io_pread_at (io, sec->paddr, buf, (int)size);
		// open the malloc-fd and map it to vaddr
		r_io_use_desc (io, (r_io_open_at (io, uri, sec->flags, 664, sec->vaddr))->fd);
		// copy from buffer to the malloc-fd
		r_io_pwrite_at (io, 0LL, buf, (int) size);
		free (buf);
		// get the malloc-map
		if ((map = r_io_map_get (io, sec->vaddr))) {
			if ((name = calloc (1, strlen (sec->name) + 6))) {
				sprintf (name, "mmap.%s", sec->name);
				map->name = name;
			}
			// set the flags correctly
			map->flags = sec->flags;
			// restore old RIODesc
			r_io_use_desc (io, desc->fd);
			// let the section refere to the map
			sec->filemap = sec->memmap = map->id;
			return true;
		}
		r_io_use_desc (io, desc->fd);
		return false;
	}
	return false;
}

static bool _section_reapply(RIO *io, RIOSection *sec, RIOSectionApplyMethod method) {
	RIOMap *m, *map = NULL;
	RIODesc *desc;
	SdbListIter *iter;
	r_io_map_cleanup (io);
	if (method == (R_IO_SECTION_APPLY_FOR_HEXEDITOR ||
	               R_IO_SECTION_APPLY_FOR_ANALYSIS)) {
		if (sec->memmap) {
			ls_foreach (io->maps, iter, m) {
				if (m->id == sec->memmap) {
					r_io_close (io, m->fd);
					break;
				}
			}
			r_io_map_del (io, sec->memmap);
		}
		r_io_map_del (io, sec->filemap);
		return _section_apply (io, sec, method);
	}
	if (method == R_IO_SECTION_APPLY_FOR_EMULATOR) {
		char uri[64];
		ut8 *buf = NULL;
		size_t size;
		// in this case the section was applied for patching
		if (sec->filemap != sec->memmap) {
			if (!sec->memmap) {
				r_io_map_del (io, sec->filemap);
				sec->filemap = 0;
				return _section_apply (io, sec, method);
			}
			ls_foreach (io->maps, iter, m) {
				if (m->id == sec->memmap) {
					map = m;
					break;
				}
			}
			if (!map) {
				r_io_map_del (io, sec->filemap);
				sec->filemap = sec->memmap = 0;
				return _section_apply (io, sec, method);
			}
			size = (size_t) (map->to - map->from + 1);
			buf = malloc (size);
			desc = io->desc;
			r_io_use_desc (io, map->fd);
			r_io_pread_at (io, map->delta, buf, (int) size);
			r_io_close (io, map->fd);
			if (sec->size > sec->vsize) {
				size = 0;
			} else if (size > (size_t) (sec->vsize - sec->size)) {
				size = (size_t) (sec->vsize - sec->size);
			}
			snprintf (uri, 64, "malloc://%"PFMT64u "", sec->vsize);
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
			buf = malloc (size);
			r_io_use_desc (io, sec->fd);
			r_io_pread_at (io, sec->paddr, buf, (int) size);
			r_io_use_desc (io, map->fd);
			r_io_pwrite_at (io, 0LL, buf, (int) size);
			free (buf);
			if (desc) {
				r_io_use_desc (io, desc->fd);
			}
			sec->filemap = sec->memmap = map->id;
			return true;
		}
		if (!sec->filemap) {
			return _section_apply (io, sec, method);
		}
		ls_foreach (io->maps, iter, m) {
			if (m->id == sec->memmap) {
				map = m;
				break;
			}
		}
		if (!map) {
			return _section_apply (io, sec, method);
		}
		size = (size_t) (map->to - map->from + 1);
		desc = io->desc;
		r_io_use_desc (io, map->fd);
		if (desc == io->desc) {
			desc = NULL;
		}
		buf = malloc (size);
		r_io_pread_at (io, map->delta, buf, (int) size);
		r_io_close (io, map->fd);
		r_io_map_cleanup (io);
		if (sec->vsize < (ut64) size) {
			size = (size_t) sec->vsize;
		}
		snprintf (uri, 64, "malloc://%"PFMT64u "", sec->vsize);
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
	return false;
}

R_API bool r_io_section_apply(RIO *io, ut32 id, RIOSectionApplyMethod method) {
	RIOSection *sec;
	if (!(sec = r_io_section_get_i (io, id))) {
		return false;
	}
	return _section_apply (io, sec, method);
}

R_API bool r_io_section_reapply(RIO *io, ut32 id, RIOSectionApplyMethod method) {
	RIOSection *sec;
	if (!io || !io->sections || !io->maps) {
		return false;
	}
	if (!(sec = r_io_section_get_i (io, id))) {
		return false;
	}
	return _section_apply (io, sec, method);
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

R_API bool r_io_section_reapply_bin(RIO *io, ut32 bin_id, RIOSectionApplyMethod method) {
	RIOSection *sec;
	SdbListIter *iter;
	bool ret = false;
	if (!io || !io->sections) {
		return false;
	}
	ls_foreach (io->sections, iter, sec) {
		if (sec && (sec->bin_id == bin_id)) {
			ret = true;
			_section_reapply (io, sec, method);
		}
	}
	return ret;
}
