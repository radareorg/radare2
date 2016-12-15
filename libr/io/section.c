#include <r_io.h>
#include <sdb.h>
#include <r_types.h>
#include <stdio.h>

void section_free (void *p)
{
	RIOSection *s = (RIOSection *)p;
	if (s)
		free (s->name);
	free (s);
}

R_API void r_io_section_init (RIO *io)
{
	if (io && !io->sections) {
		if (io->sections = ls_new ())
			io->sections->free = section_free;
	}
}

R_API void r_io_section_fini (RIO *io)
{
	if (!io)
		return;
	if (io->sections)
		ls_free (io->sections);
	io->sections = NULL;
	if (io->freed_sec_ids)
		ls_free (io->freed_sec_ids);
	io->freed_sec_ids = NULL;
	io->sec_id = 0;
}

R_API int r_io_section_exists_for_id (RIO *io, ut32 id)
{
	SdbListIter *iter;
	RIOSection *sec;
	if (!io || !io->sections)
		return false;
	ls_foreach (io->sections, iter, sec) {
		if (sec->id == id)
			return true;
	}
	return false;
}

R_API RIOSection *r_io_section_add (RIO *io, ut64 addr, ut64 vaddr, ut64 size, ut64 vsize, int flags, const char *name, ut32 bin_id, int fd)
{
	RIOSection *sec;
	if (!io || !io->sections || !r_io_desc_get (io, fd) || !size || (UT64_MAX - size) < addr || (UT64_MAX - vsize) < vaddr)
		return NULL;
	if (!io->freed_sec_ids || io->sec_id == UT32_MAX)
		return NULL;
	sec = R_NEW0 (RIOSection);
	if (io->freed_sec_ids) {
		sec->id = (ut32)(size_t) ls_pop (io->freed_sec_ids);
		if (!io->freed_sec_ids->length) {
			ls_free (io->freed_sec_ids);
			io->freed_sec_ids = NULL;
		}
	} else {
		io->sec_id++;
		sec->id = io->sec_id;
	}
	sec->addr = addr;
	sec->vaddr = vaddr;
	sec->size = size;
	sec->vsize = vsize;
	sec->flags = flags;
	sec->bin_id = bin_id;
	sec->fd = fd;
	if (!name) {
		char buf[32];
		snprintf (buf, 31, "section.0x016%"PFMT64x"", vaddr);
		sec->name = strdup (buf);		//what should happen if that fails
	} else	sec->name = strdup (name);
	ls_append (io->sections, sec);
	return sec;
}

R_API RIOSection *r_io_section_get_i (RIO *io, ut32 id)
{
	SdbListIter *iter;
	RIOSection *s;
	if (!io || !io->sections)
		return NULL;
	ls_foreach (io->sections, iter, s) {
		if (s->id == id)
			return s;
	}
	return NULL;
}

R_API int r_io_section_rm (RIO *io, ut32 id)
{
	SdbListIter *iter;
	RIOSection *s;
	if (!io || !io->sections)
		return false;
	ls_foreach (io->sections, iter, s) {
		if (s->id == id) {
			ls_delete (io->sections, iter);
			if (!io->freed_sec_ids) {
				io->freed_sec_ids = ls_new();
				io->freed_sec_ids->free = NULL;
			}
			ls_prepend (io->freed_map_ids, (void *)(size_t)id);
			return true;
		}
	}
	return false;
}

R_API SdbList *r_io_section_bin_get (RIO *io, ut32 bin_id)
{
	SdbList *ret = NULL;
	SdbListIter *iter;
	RIOSection *s;
	if (!io || !io->sections)
		return NULL;
	ls_foreach (io->sections, iter, s) {
		if (s->bin_id == bin_id) {
			if (!ret)
				ret = ls_new ();
			ls_prepend (ret, s);
		}
	}
	return ret;
}

R_API int r_io_section_bin_rm (RIO *io, ut32 bin_id)
{
	RIOSection *s;
	SdbListIter *iter;
	int length;
	if (!io || !io->sections || !io->sections->head)
		return false;
	length = io->sections->length;
	for (iter = io->sections->head; iter; iter = iter->n) {
		s = (RIOSection *)iter->data;
		if (s->bin_id == bin_id) {
			if (iter->p)
				iter->p->n = iter->n;
			if (iter->n)
				iter->n->p = iter->p;
			if (!io->freed_sec_ids) {
				io->freed_sec_ids = ls_new();
				io->freed_sec_ids->free = NULL;
			}
			ls_prepend (io->freed_sec_ids, (void *)(size_t)s->id);
			section_free (s);
			free (iter);
			io->sections->length--;
		}
	}
	return (!(length == io->sections->length));
}

R_API SdbList *r_io_section_get_secs_at (RIO *io, ut64 addr)
{
	SdbList *ret = NULL;
	SdbListIter *iter;
	RIOSection *s;
	if (!io || !io->sections)
		return NULL;
	ls_foreach (io->sections, iter, s) {
		if (addr >= s->addr && addr < (s->addr + s->size)) {
			if (!ret)
				ret = ls_new ();
			ls_prepend (ret, s);
		}
	}
	return ret;
}

R_API int r_io_section_set_archbits (RIO *io, ut32 id, const char *arch, int bits)
{
	RIOSection *s;
	if (!(s = r_io_section_get_i(io, id)))
		return false;
	if (arch) {
		s->arch = r_sys_arch_id (arch);
		s->bits = bits;
	} else	s->arch = s->bits = 0;
	return true;
}

R_API char *r_io_section_get_archbits (RIO *io, ut32 id, int *bits)
{
	RIOSection *s;
	if (!(s = r_io_section_get_i (io, id)) || !s->arch || !s->bits)
		return NULL;
	if (bits)
		*bits = s->bits;
	return r_sys_arch_str (s->arch);
}

R_API int r_io_section_bin_set_archbits (RIO *io, ut32 bin_id, const char *arch, int bits)
{
	SdbList *bin_sections;
	SdbListIter *iter;
	RIOSection *s;
	int a;
	if (!(bin_sections = r_io_section_bin_get (io, bin_id)))
		return false;
	if (!arch)
		a = bits = 0;
	else	a = r_sys_arch_id (arch);
	ls_foreach (bin_sections, iter, s) {
		s->arch = a;
		s->bits = bits;
	}
	bin_sections->free = NULL;		//maybe not needed
	ls_free (bin_sections);
	return true;
}

R_API int r_io_section_apply (RIO *io, ut32 id, RIOSectionApplyMethod method)
{
	RIOSection *sec;
	RIODesc *desc, *current;
	RIOMap *map;
	ut64 at;
	char uri[64];
	if (!(sec = r_io_section_get_i (io, id)))
		return false;
	if (method == R_IO_SECTION_APPLY_FOR_PATCHING) {
		if (sec->addr == sec->vaddr) {
			if (sec->vsize > sec->size) {
				if (!sec->memmap) {
					at = sec->vaddr + sec->size;		//TODO: harden this, handle mapslit
					snprintf (uri, 64, "malloc://%"PFMT64u"", sec->vsize - sec->size);
					desc = r_io_open_at (io, uri, sec->flags, 664, at);
					if (!desc) return false;
					map = r_io_map_get (io, at);		//this works, because new maps are allways born on the top
					if (!map) {
						r_io_close (io, desc->fd);
						return false;
					}
					sec->memmap = map->id;
					return true;
				} else return false;
			} else return true;
		}
		if (!sec->filemap && sec->size >= sec->vsize) {
			desc = r_io_desc_get (io, sec->fd);
			if (!desc) return false;
			map = r_io_map_add (io, sec->fd, desc->flags, sec->addr, sec->vaddr, sec->vsize);
			if (map) {
				sec->filemap = sec->memmap = map->id;
				return true;
			}
			sec->memmap = 0;
			return false;
		}
		if (!sec->filemap && !sec->memmap) {
			desc = r_io_desc_get (io, sec->fd);
			if (!desc) return false;
			map = r_io_map_add (io, sec->fd, desc->flags, sec->addr, sec->vaddr, sec->size);
			if (!map) return false;
			sec->filemap = map->id;
			at = sec->vaddr + sec->size;				//TODO: harden this, handle mapslit
			snprintf (uri, 64, "malloc://%"PFMT64u"", sec->vsize - sec->size);
			desc = r_io_open_at (io, uri, sec->flags, 664, at);
			if (!desc) return false;
			map = r_io_map_get (io, at);
			if (!map) {
				r_io_close (io, desc->fd);
				return false;
			}
			sec->memmap = map->id;
			return true;
		}
	}
	if (method == R_IO_SECTION_APPLY_AS_MAPPING) {				//needed for emulation
		size_t size;
		ut8 *buf = NULL;
		if (sec->memmap) return false;
		if (sec->size > sec->vsize)
			size = (size_t)sec->vsize;
		else	size = (size_t)sec->size;
		buf = malloc (size);
		snprintf (uri, 64, "malloc://%"PFMT64u"", sec->vsize);
		desc = io->desc;
		r_io_desc_use (io, sec->fd);
		r_io_pread_at (io, sec->addr, buf, (int)size);
		r_io_desc_use (io, (r_io_open_at (io, uri, sec->flags | R_IO_WRITE, 664, sec->vaddr))->fd);
		r_io_pwrite_at (io, 0LL, buf, (int)size);
		free (buf);
		map = r_io_map_get (io, sec->vaddr);
		map->flags = sec->flags;
		r_io_desc_use (io, desc->fd);
		sec->filemap = sec->memmap = map->id;
		return true;
	}
	return false;
}

R_API int r_io_section_reapply (RIO *io, ut32 id, RIOSectionApplyMethod method)
{
	RIOSection *sec;
	RIOMap *m, *map = NULL;
	RIODesc *desc;
	SdbListIter *iter;
	if (!io || !io->sections || !io->maps)
		return false;
	if (!(sec = r_io_section_get_i (io, id)))
		return false;
	r_io_map_cleanup (io);
	if (method == R_IO_SECTION_APPLY_FOR_PATCHING) {
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
		return r_io_section_apply (io, id, method);
	}
	if (method == R_IO_SECTION_APPLY_AS_MAPPING) {
		char uri[64];
		ut8 *buf = NULL;
		size_t size;
		if (sec->filemap != sec->memmap) {
			if (!sec->memmap) {
				r_io_map_del (io, sec->filemap);
				sec->filemap = 0;
				return r_io_section_apply (io, id, method);
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
				return r_io_section_apply (io, id, method);
			}
			size = (size_t)(map->to - map->from + 1);
			buf = malloc (size);
			desc = io->desc;
			r_io_desc_use (io, map->fd);
			r_io_pread_at (io, map->delta, buf, (int)size);
			r_io_close (io, map->fd);
			if (sec->size > sec->vsize)
				size = 0;
			else if (size > (size_t)(sec->vsize - sec->size))
				size = (size_t)(sec->vsize - sec->size);
			snprintf (uri, 64, "malloc://%"PFMT64u"", sec->vsize);
			r_io_open_at (io, uri, sec->flags | R_IO_WRITE, 664, sec->vaddr);
			map = r_io_map_get (io, sec->vaddr);
			r_io_desc_use (io, map->fd);
			r_io_pwrite_at (io, sec->size, buf, (int)size);
			free (buf);
			if (sec->size > sec->vsize)
				size = (size_t)sec->vsize;
			else	size = (size_t)sec->size;
			buf = malloc (size);
			r_io_desc_use (io, sec->fd);
			r_io_pread_at (io, sec->addr, buf, (int)size);
			r_io_desc_use (io, map->fd);
			r_io_pwrite_at (io, 0LL, buf, (int)size);
			free (buf);
			if (desc)
				r_io_desc_use (io, desc->fd);
			sec->filemap = sec->memmap = map->id;
			return true;
		}
		if (!sec->filemap)
			return r_io_section_apply (io, id, method);
		ls_foreach (io->maps, iter, m) {
			if (m->id == sec->memmap) {
				map = m;
				break;
			}
		}
		if (!map)
			return r_io_section_apply (io, id, method);
		size = (size_t)(map->to - map->from + 1);
		desc = io->desc;
		r_io_desc_use (io, map->fd);
		if (desc == io->desc)
			desc = NULL;
		buf = malloc (size);
		r_io_pread_at (io, map->delta, buf, (int)size);
		r_io_close (io, map->fd);
		r_io_map_cleanup (io);
		if (sec->vsize < (ut64)size)
			size = (size_t)sec->vsize;
		snprintf (uri, 64, "malloc://%"PFMT64u"", sec->vsize);
		r_io_open_at (io, uri, sec->flags | R_IO_WRITE, 664, sec->vaddr);
		map = r_io_map_get (io, sec->vaddr);
		r_io_desc_use (io, map->fd);
		r_io_pwrite_at (io, 0LL, buf, (int)size);
		free (buf);
		map->flags = sec->flags;
		if (desc)
			r_io_desc_use (io, desc->fd);
		return true;
	}
	return false;
}
