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
		return R_FALSE;
	ls_foreach (io->sections, iter, sec) {
		if (sec->id == id)
			return R_TRUE;
	}
	return R_FALSE;
}

R_API RIOSection *r_io_section_add (RIO *io, ut64 addr, ut64 vaddr, ut64 size, ut64 vsize, int rwx, const char *name, ut32 bin_id, int fd)
{
	RIOSection *sec;
	if (!io || !io->sections || !r_io_desc_get (io, fd) || !size || (UT64_MAX - size) < addr || (UT64_MAX - vsize) < vaddr)
		return NULL;
	if (!io->freed_sec_ids || io->sec_id == UT32_MAX)
		return NULL;
	sec = R_NEW0 (RIOSection);
	if (io->freed_sec_ids) {
		sec->id = (ut32)(size_t) ls_pop (io->freed_sec_ids);
		if (!io->freed_sec_ids->lenght) {
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
	sec->rwx = rwx;
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
	}
	return NULL;
}

R_API int r_io_section_rm (RIO *io, ut32 id)
{
	SdbListIter *iter;
	RIOSection *s;
	if (!io || !io->sections)
		return R_FALSE;
	ls_foreach (io->sections, iter, s) {
		if (s->id == id) {
			ls_delete (io->sections, iter);
			if (!io->freed_sec_ids) {
				io->freed_sec_ids = ls_new();
				io->freed_sec_ids->free = NULL;
			}
			ls_prepend (io->freed_map_ids, (void *)(size_t)id);
			return R_TRUE;
		}
	}
	return R_FALSE;
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
		return R_FALSE;
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
			io->sections->lenght--;
		}
	}
	return (!(lenght == io->sections->length));
}

R_API int r_io_section_set_archbits (RIO *io, ut32 id, const char *arch, int bits)
{
	RIOSection *s;
	if (!(s = r_io_section_get_i(io, id)))
		return R_FALSE;
	if (arch) {
		s->arch = r_sys_arch_id (arch);
		s->bits = bits;
	} else	s->arch = s->bits = 0;
	return R_TRUE;
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
		return R_FALSE;
	if (!arch)
		a = bits = 0;
	else	a = r_sys_arch_id (arch);
	ls_foreach (bin_sections, iter, s) {
		s->arch = a;
		a->bits = s;
	}
	bin_sections->free = NULL;		//maybe not needed
	ls_free (bin_sections);
	return R_TRUE;
}

R_API int r_io_section_apply (RIO *io, ut32 id, RIOSectionApplyMethod method)
{
	RIOSection *sec;
	RIODesc *desc, *current;
	RIOMap *map;
	ut64 at;
	char uri[64];
	if (!(sec = r_io_section_get_i (io, id)))
		return R_FALSE;
	if (method == R_IO_SECTION_APPLY_FOR_PATCHING) {
		if (sec->addr == sec->vaddr) {
			if (sec->vsize > sec->size) {
				if (!sec->memmap) {
					at = sec->vaddr + sec->size;			//TODO: harden this, handle mapslit
					snprintf (uri, 64, "malloc://%"PFMT64u"", sec->vsize - sec->size);
					desc = r_io_open_at (io, uri, sec->flags, 664, at);
					if (!desc) return R_FALSE;
					map = r_io_map_get (io, at);			//this works, because new maps are allways born on the top
					if (!map) {
						r_io_close (io, desc->fd);
						return R_FALSE;
					}
					sec->memmap = map->id;
					return R_TRUE;
				} else return R_FALSE;
			} else return R_TRUE;
		}
		if (!sec->filemap && sec->size >= sec->vsize) {
			desc = r_io_desc_get (io, sec->fd);
			if (!desc) return R_FALSE;
			map = r_io_map_add (io, sec->fd, desc->flags, sec->addr, sec->vaddr, sec->vsize);
			if (map) {
				sec->filemap = sec->memmap = map->id;
				return R_TRUE;
			}
			sec->memmap = sec->filemap
			return R_FALSE;
		}
		if (!sec->filemap && !sec->memmap) {
			desc = r_io_desc_get (io, sec->fd);
			if (!desc) return R_FALSE;
			map = r_io_map_add (io, sec->fd, desc->flags, sec->addr, sec->vaddr, sec->size);
			if (!map) return R_FALSE;
			sec->filemap = map->id;
			at = sec->vaddr + sec->size;					//TODO: harden this, handle mapslit
			snprintf (uri, 64, "malloc://%"PFMT64u"", sec->vsize - sec->size);
			desc = r_io_open_at (io, uri, sec->flags, 664, at);
			if (!desc) return R_FALSE;
			map = r_io_map_get (io, at);
			if (!map) {
				r_io_close (io, desc->fd);
				return R_FALSE;
			}
			sec->memmap = map->id;
			return R_TRUE;
		}
	}
	if (method == R_IO_SECTION_APPLY_AS_MAPPING) {				//needed for emulation
		size_t size;
		ut8 *buf = NULL;
		if (sec->memmap) return R_FALSE;
		if (sec->size > sec->vsize)
			size = (size_t)sec->vsize;
		else	size = (size_t)sec->size;
		buf = malloc (size);
		snprintf (uri, 64, "malloc://%"PFTM64u"", sec->vsize);
		desc = io->desc;
		r_io_desc_use (io, sec->fd);
		r_io_pread_at (io, sec->addr, buf, (int)size);
		r_io_desc_use (io, (r_io_open_at (io, uri, sec->flags | R_IO_WRITE, 664, sec->vaddr))->fd);
		r_io_pwrite_at (io, 0LL, buf, (int)size);
		R_FREE (buf);
		r_io_map_get (io, sec->vaddr);
		map->flags = sec->flags;
		r_io_desc_use (desc->fd);
		sec->filemap = sec->memmap = map->id;
		return R_TRUE;
	}
	return R_FALSE;
}
