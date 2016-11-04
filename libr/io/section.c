/* radare2 - LGPL - Copyright 2008-2016 - pancake, nibble */

#include "r_io.h"
// no link
#include "r_cons.h"

R_API void r_io_section_init(RIO *io) {
	io->next_section_id = 0;
	io->enforce_rwx = 0; // do not enforce RWX section permissions by default
	io->enforce_seek = 0; // do not limit seeks out of the file by default
	io->sections = r_list_new ();
	if (!io->sections) {
		return;
	}
	io->sections->free = r_io_section_free;
}

#if 0
static int cmpaddr (void *_a, void *_b) {
	RIOSection *a = _a, *b = _b;
	return (a->vaddr > b->vaddr);
}
#endif

R_API RIOSection *r_io_section_get_name(RIO *io, const char *name) {
	RListIter *iter;
	RIOSection *s;
	if (name)
	r_list_foreach (io->sections, iter, s) {
		if (!strcmp (name, s->name)) {
			return s;
		}
	}
	return NULL;
}

// update name and rwx, size is experimental
static RIOSection *findMatching (RIO *io, ut64 paddr, ut64 vaddr, ut64 size, ut64 vsize, int rwx, const char *name) {
	RListIter *iter;
	RIOSection *s;
	r_list_foreach (io->sections, iter, s) {
		if (s->offset != paddr) continue;
		if (s->vaddr != vaddr) continue;
#if 1
		if (s->size != size) continue;
		if (s->vsize != vsize) continue;
#else
		s->size = size;
		s->vsize = vsize;
#endif
		s->rwx = rwx;
		if (name && strcmp (name, s->name)) {
			s->name = strdup (name);
		}
		return s;
	}
	return NULL;
}

R_API RIOSection *r_io_section_add(RIO *io, ut64 offset, ut64 vaddr, ut64 size, ut64 vsize, int rwx, const char *name, ut32 bin_id, int fd) {
	int update = 0;
	RIOSection *s;
	if (!size || size == UT64_MAX || size == UT32_MAX) { //hacky things which might give bad output in case size == UT32_MAX for 64bit elf. Check on basis of size, offset and file size would be a good idea.
#if 0
			eprintf ("Invalid size (0x%08" PFMT64x
				 ") for section '%s' at 0x%08" PFMT64x "\n",
				 size, name, vaddr);
#endif
		return NULL;
	}
	s = findMatching (io, offset, vaddr, size, vsize, rwx, name);
	if (s) {
		return s;
	}
	s = r_io_section_get_name (io, name);
	if (!s) {
		s = R_NEW0 (RIOSection);
		s->id = io->next_section_id++;
	} else {
		update = 1;
	}
	s->offset = offset;
	s->vaddr = vaddr;
	s->size = size;
	s->vsize = vsize;
	s->rwx = rwx;
	s->arch = s->bits = 0;
	s->bin_id = bin_id;
	s->fd = fd;
	if (!update) {
		if (name) s->name = strdup (name);
		else s->name = strdup ("");
		r_list_append (io->sections, s);
	}
	return s;
}

R_API RIOSection *r_io_section_get_i(RIO *io, int idx) {
	RListIter *iter;
	RIOSection *s;
	if (!io || !io->sections)
		return NULL;
	r_list_foreach (io->sections, iter, s) {
		if (s->id == idx) {
			return s;
		}
	}
	return NULL;
}

R_API int r_io_section_rm(RIO *io, int idx) {
	RListIter *iter;
	RIOSection *s;
	if (!io || !io->sections) {
		return false;
	}
	r_list_foreach (io->sections, iter, s) {
		if (s->id == idx) {
			r_list_delete (io->sections, iter);
			return true;
		}
	}
	return false;
}

R_API int r_io_section_rm_all (RIO *io, int fd) {
	RIOSection *section;
	RListIter *iter, *ator;
	if (!io || !io->sections) {
		return false;
	}
	r_list_foreach_safe (io->sections, iter, ator, section) {
		if (section->fd == fd || fd == -1)
			r_list_delete (io->sections, iter);
	}
	return true;
}

R_API void r_io_section_free(void *ptr) {
	RIOSection *s = (RIOSection*)ptr;
	if (s) {
		free (s->name);
		free (s);
	}
}

R_API void r_io_section_clear(RIO *io) {
	r_list_free (io->sections);
	io->sections = r_list_new ();
	if (!io->sections) {
		return;
	}
	io->sections->free = r_io_section_free;
}

// TODO: implement as callback
R_API void r_io_section_list(RIO *io, ut64 offset, int rad) {
	int i = 0;
	RListIter *iter;
	RIOSection *s;

	if (io->va || io->debug)
		offset = r_io_section_vaddr_to_maddr_try (io, offset);
	// XXX - Should this print the section->id or the location in the
	// rio sections array?
	r_list_foreach (io->sections, iter, s) {
		if (rad) {
			char *n = strdup (s->name);
			r_name_filter (n, strlen (n));
			io->cb_printf ("f section.%s %"PFMT64d" 0x%"PFMT64x"\n",
				n, s->size, s->vaddr);
			io->cb_printf ("S 0x%08"PFMT64x" 0x%08"PFMT64x" 0x%08"
				PFMT64x" 0x%08"PFMT64x" %s %s\n", s->offset,
				s->vaddr, s->size, s->vsize, n, r_str_rwx_i (s->rwx));
			free (n);
		} else {
			io->cb_printf ("[%02d] %c 0x%08"PFMT64x" %s va=0x%08"PFMT64x
				" sz=0x%04"PFMT64x" vsz=0x%04"PFMT64x" %s",
			s->id, (offset>=s->offset && offset<s->offset+s->size)?'*':'.',
			s->offset, r_str_rwx_i (s->rwx), s->vaddr, s->size, s->vsize, s->name);
			if (s->arch && s->bits) {
				io->cb_printf ("  ; %s %d\n", r_sys_arch_str (s->arch), s->bits);
			} else {
				io->cb_printf ("\n");
			}
		}
		i++;
	}
}

#define PRINT_CURRENT_SEEK \
	if (i > 0 && len != 0) { \
		if (seek == UT64_MAX) seek = 0; \
		io->cb_printf ("=>  0x%08"PFMT64x" |", seek); \
		for (j = 0; j < width; j++) { \
			io->cb_printf ( \
				((j*mul) + min >= seek && \
				(j*mul) + min <= seek + len) \
				? "^" : "-"); \
		} \
		io->cb_printf ("| 0x%08"PFMT64x"\n", seek+len); \
	}

static void list_section_visual_vaddr (RIO *io, ut64 seek, ut64 len, int use_color, int cols) {
	ut64 mul, min = -1, max = -1;
	RListIter *iter;
	RIOSection *s;
	int j, i = 0;
	int  width = cols - 60;
	if (width < 1) width = 30;
	r_list_foreach (io->sections, iter, s) {
		if (min == -1 || s->vaddr < min) {
			min = s->vaddr;
		}
		if (max == -1 || s->vaddr+s->size > max) {
			max = s->vaddr+s->size;
		}
	}
	mul = (max-min) / width;
	if (min != -1 && mul != 0) {
		const char * color = "", *color_end = "";
		char buf[128];
		i = 0;
		r_list_foreach (io->sections, iter, s) {
			r_num_units (buf, s->size);
			if (use_color) {
				color_end = Color_RESET;
				if (s->rwx & 1) { // exec bit
					color = Color_GREEN;
				} else if (s->rwx & 2) { // write bit
					color = Color_RED;
				} else {
					color = "";
					color_end = "";
				}
			} else {
				color = "";
				color_end = "";
			}
			io->cb_printf ("%02d%c %s0x%08"PFMT64x"%s |", s->id,
					(seek >= s->vaddr && seek < s->vaddr + s->size) ? '*' : ' ',
					//(seek>=s->vaddr && seek<s->vaddr+s->size)?'*':' ',
					color, s->vaddr, color_end);
			for (j = 0; j < width; j++) {
				ut64 pos = min + (j * mul);
				ut64 npos = min + ((j + 1) * mul);
				if (s->vaddr < npos && (s->vaddr + s->size) > pos) {
					io->cb_printf ("#");
				} else {
					io->cb_printf ("-");
				}
			}
			io->cb_printf ("| %s0x%08"PFMT64x"%s %s %s  %04s\n",
				color, s->vaddr + s->size, color_end,
				r_str_rwx_i (s->rwx), s->name, buf);
			i++;
		}
		PRINT_CURRENT_SEEK;
	}
}

static void list_section_visual_paddr (RIO *io, ut64 seek, ut64 len, int use_color, int cols) {
	ut64 mul, min = -1, max = -1;
	RListIter *iter;
	RIOSection *s;
	int j, i = 0;
	int  width = cols - 60;
	if (width < 1) width = 30;
	seek = r_io_section_vaddr_to_maddr_try (io, seek);
	r_list_foreach (io->sections, iter, s) {
		if (min == -1 || s->offset < min)
			min = s->offset;
		if (max == -1 || s->offset+s->size > max)
			max = s->offset+s->size;
	}
	mul = (max-min) / width;
	if (min != -1 && mul != 0) {
		const char * color = "", *color_end = "";
		char buf[128];
		i = 0;
		r_list_foreach (io->sections, iter, s) {
			r_num_units (buf, s->size);
			if (use_color) {
				color_end = Color_RESET;
				if (s->rwx & 1) { // exec bit
					color = Color_GREEN;
				} else if (s->rwx & 2) { // write bit
					color = Color_RED;
				} else {
					color = "";
					color_end = "";
				}
			} else {
				color = "";
				color_end = "";
			}
			io->cb_printf ("%02d%c %s0x%08"PFMT64x"%s |", s->id,
					(seek >= s->offset && seek < s->offset + s->size) ? '*' : ' ',
					color, s->offset, color_end);
			for (j = 0; j < width; j++) {
				ut64 pos = min + (j * mul);
				ut64 npos = min + ((j + 1) * mul);
				if (s->offset < npos && (s->offset + s->size) > pos)
					io->cb_printf ("#");
				else io->cb_printf ("-");
			}
			io->cb_printf ("| %s0x%08"PFMT64x"%s %s %s  %04s\n",
				color, s->offset+s->size, color_end,
				r_str_rwx_i (s->rwx), s->name, buf);

			i++;
			}
		PRINT_CURRENT_SEEK;
	}
}

/* TODO: move to print ??? support pretty print of ranges following an array of offsetof */
R_API void r_io_section_list_visual(RIO *io, ut64 seek, ut64 len, int use_color, int cols) {
	if (io->va) {
		list_section_visual_vaddr (io, seek, len, use_color, cols);
	} else {
		list_section_visual_paddr (io, seek, len, use_color, cols);
	}
}

R_API RIOSection *r_io_section_vget(RIO *io, ut64 vaddr) {
	RListIter *iter;
	RIOSection *s;
	r_list_foreach (io->sections, iter, s) {
		if (vaddr >= s->vaddr && vaddr < s->vaddr + s->vsize) {
			return s;
		}
	}
	return NULL;
}

// maddr == section->offset
R_API RIOSection *r_io_section_mget_in(RIO *io, ut64 maddr) {
	RIOSection *s;
	RListIter *iter;
	r_list_foreach (io->sections, iter, s) {
		if ((maddr >= s->offset && maddr < (s->offset + s->size)))
			return s;
	}
	return NULL;
}

R_API RIOSection *r_io_section_mget_prev(RIO *io, ut64 maddr) {
	RIOSection *s;
	RListIter *iter;
	r_list_foreach_prev (io->sections, iter, s) {
		if ((maddr >= s->offset && maddr < (s->offset + s->size)))
			return s;
	}
	return NULL;
}

// XXX: rename this
R_API ut64 r_io_section_get_offset(RIO *io, ut64 maddr) {
	RIOSection *s = r_io_section_mget_in (io, maddr);
	return s? s->offset: UT64_MAX;
}

// XXX: must be renamed, this is confusing
R_API ut64 r_io_section_get_vaddr(RIO *io, ut64 maddr) {
	RIOSection *s = r_io_section_mget_in (io, maddr);
	return s? s->vaddr: UT64_MAX;
}

// TODO: deprecate
R_API int r_io_section_get_rwx(RIO *io, ut64 offset) {
	RIOSection *s = r_io_section_mget_in (io, offset);
	return s?s->rwx:R_IO_READ|R_IO_WRITE|R_IO_EXEC;
}

R_API int r_io_section_overlaps(RIO *io, RIOSection *s) {
	int i = 0;
	RListIter *iter;
	RIOSection *s2;

	r_list_foreach (io->sections, iter, s2) {
		if (!(s->rwx & R_IO_MAP)) continue;
		if (s != s2) {
			if (s->offset >= s2->offset) {
				if (s2->offset+s2->size < s->offset)
					return i;
			} else {
				if (s->offset+s->size < s2->offset)
					return i;
			}
		}
		i++;
	}
	return -1;
}

/* returns the conversion from vaddr to maddr if the given vaddr is in a mapped
 * region, otherwise it returns the original address */
R_API ut64 r_io_section_vaddr_to_maddr_try(RIO *io, ut64 vaddr) {
	ut64 res = r_io_section_vaddr_to_maddr (io, vaddr);
	return res == UT64_MAX ? vaddr : res;
}

/* returns the conversion from vaddr to maddr if the given vaddr is in a mapped
 * region, UT64_MAX otherwise */
R_API ut64 r_io_section_vaddr_to_maddr(RIO *io, ut64 vaddr) {
	RListIter *iter;
	RIOSection *s;

	r_list_foreach (io->sections, iter, s) {
		if (!(s->rwx & R_IO_MAP)) continue;
		if (vaddr >= s->vaddr && vaddr < s->vaddr + s->vsize) {
			return (vaddr - s->vaddr + s->offset);
		}
	}
	return UT64_MAX;
}

/* returns the conversion from file offset to vaddr if the given offset is
 * mapped somewhere, UT64_MAX otherwise */
R_API ut64 r_io_section_maddr_to_vaddr(RIO *io, ut64 offset) {
	/* Use reverse iterator, since sections that are at the
	 * end of the list are usually the bigger ones */
	RIOSection *s = r_io_section_mget_prev (io, offset);
	if (s) {
		io->section = s;
		return (s->vaddr + offset - s->offset);
	}
	return UT64_MAX;
}

// TODO: deprecate ?
R_API int r_io_section_exists_for_paddr (RIO *io, ut64 paddr, int hasperm) {
	RIOSection *s = r_io_section_mget_in (io, paddr);
	if (s) {
		if (hasperm) {
			return (s->rwx & hasperm);
		}
		return true;
	}
	return false;
}

// TODO: deprecate ?
R_API int r_io_section_exists_for_vaddr (RIO *io, ut64 vaddr, int hasperm) {
	RIOSection *s = r_io_section_vget (io, vaddr);
	if (s) {
		if (hasperm) {
			return (s->rwx & hasperm);
		}
		return true;
	}
	return false;
}

// dupped in vio.c
R_API ut64 r_io_section_next(RIO *io, ut64 o) {
	RListIter *iter;
	RIOSection *s;
	ut64 addr, newsec = UT64_MAX;

	r_list_foreach (io->sections, iter, s) {
		addr = s->vaddr;
		if (s->vaddr > o && s->vaddr < newsec) {
			newsec = s->vaddr;
		}
		addr = s->vaddr + s->vsize;
		if (addr > o && addr < newsec) {
			newsec = s->vaddr;
		}
	}

	return newsec;
}

R_API RList *r_io_section_get_in_paddr_range(RIO *io, ut64 addr, ut64 endaddr) {
	RIOSection *s;
	RListIter *iter;
	RList *sections = r_list_new ();
	if (!sections) return NULL;
	sections->free = r_io_section_free;
	ut64 sec_from, sec_to;
	r_list_foreach (io->sections, iter, s) {
		if (!(s->rwx & R_IO_MAP)) continue;
		sec_from = s->offset;
		sec_to = sec_from + s->size;
		if (sec_from <= addr && addr < sec_to) r_list_append (sections, s);
		if (sec_from < endaddr && endaddr < sec_to) r_list_append (sections, s);
		if (addr <= sec_from && sec_to <= endaddr) r_list_append (sections, s);
	}
	return sections;
}

R_API RList *r_io_section_get_in_vaddr_range(RIO *io, ut64 addr, ut64 endaddr) {
	RIOSection *s;
	RListIter *iter;
	RList *sections = r_list_new ();
	if (!sections) return NULL;
	//Here section->free is not needed and wrong since we are appending into
	//the list sections from io->sections that are widely used so just free the
	//list but not the elements to avoid UAF. r_io_free will free sections for us
	ut64 sec_from, sec_to;
	r_list_foreach (io->sections, iter, s) {
		if (!(s->rwx & R_IO_MAP)) {
			continue;
		}
		sec_from = s->vaddr;
		sec_to = sec_from + s->vsize;
		if (sec_from <= addr && addr < sec_to) r_list_append (sections, s);
		if (sec_from < endaddr && endaddr < sec_to) r_list_append (sections, s);
		if (addr <= sec_from && sec_to <= endaddr) r_list_append (sections, s);
	}
	return sections;
}

R_API RIOSection * r_io_section_get_first_in_paddr_range(RIO *io, ut64 addr, ut64 endaddr) {
	RIOSection *s= NULL;
	RListIter *iter;
	ut64 sec_from, sec_to;
	r_list_foreach (io->sections, iter, s) {
		if (!(s->rwx & R_IO_MAP)) {
			continue;
		}
		sec_to = s->offset + s->size;
		sec_from = s->offset;
		if (sec_from <= addr && addr < sec_to) break;
		//if (map->from == addr && endaddr == sec_to) r_list_append(maps, map);
		if (sec_from < endaddr && endaddr < sec_to) break;
		if (addr <= sec_from && sec_to <= endaddr) break;
		s = NULL;
	}
	return s;
}

R_API RIOSection * r_io_section_get_first_in_vaddr_range(RIO *io, ut64 addr, ut64 endaddr) {
	RIOSection *s= NULL;
	RListIter *iter;
	ut64 sec_from, sec_to;
	r_list_foreach (io->sections, iter, s) {
		if (!(s->rwx & R_IO_MAP)) continue;
		sec_to = s->vaddr + s->vsize;
		sec_from = s->vaddr;
		if (sec_from <= addr && addr < sec_to) break;
		//if (map->from == addr && endaddr == sec_to) r_list_append(maps, map);
		if (sec_from < endaddr && endaddr < sec_to) break;
		if (addr <= sec_from && sec_to <= endaddr) break;
		s = NULL;
	}
	return s;
}

R_API int r_io_section_set_archbits(RIO *io, ut64 addr, const char *arch, int bits) {
	RIOSection *s = r_io_section_vget (io, addr);
	if (!s) return false;
	if (arch) {
		s->arch = r_sys_arch_id (arch);
		s->bits = bits;
	} else {
		s->arch = 0;
		s->bits = 0;
	}
	return true;
}

R_API const char *r_io_section_get_archbits(RIO* io, ut64 addr, int *bits) {
	RIOSection *s = r_io_section_vget (io, addr);
	if (!s || !s->bits || !s->arch) {
		return NULL;
	}
	if (bits) {
		*bits = s->bits;
	}
	return r_sys_arch_str (s->arch);
}

R_API RIOSection *r_io_section_getv_bin_id(RIO *io, ut64 vaddr, ut32 bin_id) {
	RListIter *iter;
	RIOSection *s;
	r_list_foreach (io->sections, iter, s) {
		if (!(s->rwx & R_IO_MAP) || s->bin_id != bin_id) {
			continue;
		}
		if (vaddr >= s->vaddr && vaddr < s->vaddr + s->vsize) {
			return s;
		}
	}
	return NULL;
}

R_API int r_io_section_set_archbits_bin_id(RIO *io, ut64 addr, const char *arch, int bits, ut32 bin_id) {
	RIOSection *s = r_io_section_getv_bin_id (io, addr, bin_id);
	if (s) {
		if (arch) {
			s->arch = r_sys_arch_id (arch);
			s->bits = bits;
		} else {
			s->arch = 0;
			s->bits = 0;
		}
		return true;
	}
	return false;
}
