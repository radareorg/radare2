/* radare - LGPL - Copyright 2008-2011 pancake<nopcode.org> nibble <.ds@gmail.com> */

#include "r_io.h"

R_API void r_io_section_init(RIO *io) {
	io->next_section_id = 0;
	io->enforce_rwx = 0; // do not enforce RWX section permissions by default
	io->enforce_seek = 0; // do not limit seeks out of the file by default
	io->sections = r_list_new ();
}

static int cmpaddr (void *_a, void *_b) {
	RIOSection *a = _a, *b = _b;
	return (a->vaddr > b->vaddr);
}

R_API RIOSection *r_io_section_get_name(RIO *io, const char *name) {
	RListIter *iter;
	RIOSection *s;
	if (name)
	r_list_foreach (io->sections, iter, s) {
		if (!strcmp (name, s->name))
			return s;
	}
	return NULL;
}

R_API void r_io_section_add(RIO *io, ut64 offset, ut64 vaddr, ut64 size, ut64 vsize, int rwx, const char *name) {
	int update = 0;
	RIOSection *s = r_io_section_get_name (io, name);
	if (s == NULL)
		s = R_NEW (RIOSection);
	else update = 1;
	s->offset = offset;
	s->id = io->next_section_id++;
	s->vaddr = vaddr;
	s->size = size;
	s->vsize = vsize;
	s->rwx = rwx;
	if (!update) {
		if (name) strncpy (s->name, name, sizeof (s->name)-4);
		else *s->name = '\0';
		r_list_append (io->sections, s);
		//r_list_prepend (io->sections, s);
		//r_list_add_sorted (io->sections, s, cmpaddr);
	} else {
		// This is a bottleneck.. the sorting must be done at append time
		r_list_sort (io->sections, cmpaddr);
	}
}

R_API RIOSection *r_io_section_get_i(RIO *io, int idx) {
	RListIter *iter;
	RIOSection *s;

	r_list_foreach (io->sections, iter, s) {
		if (s->id == idx)
			return s;
	}
	return NULL;
}

R_API int r_io_section_rm(RIO *io, int idx) {
	return r_list_del_n (io->sections, idx);
}

// TODO: implement as callback
R_API void r_io_section_list(RIO *io, ut64 offset, int rad) {
	int i = 0;
	RListIter *iter;
	RIOSection *s;

	if (io->va || io->debug)
		offset = r_io_section_vaddr_to_offset (io, offset);
	r_list_foreach (io->sections, iter, s) {
		if (rad) io->printf ("S 0x%08"PFMT64x" 0x%08"PFMT64x" 0x%08"PFMT64x" 0x%08"PFMT64x" %s %d\n",
			s->offset, s->vaddr, s->size, s->vsize, s->name, s->rwx);
		else io->printf ("[%.2d] %c 0x%08"PFMT64x" %s va=0x%08"PFMT64x" sz=0x%08"PFMT64x" vsz=%08"PFMT64x" %s\n",
			s->id, (offset>=s->offset && offset<s->offset+s->size)?'*':'.',
			s->offset, r_str_rwx_i (s->rwx), s->vaddr, s->size, s->vsize, s->name);
		i++;
	}
}

/* TODO: move to print ??? support pretty print of ranges following an array of offsetof */
R_API void r_io_section_list_visual(RIO *io, ut64 seek, ut64 len) {
	RListIter *iter;
	RIOSection *s;
	ut64 min = -1;
	ut64 max = -1;
	ut64 mul;
	int j, i, width = 50; //config.width-30;

	seek = (io->va || io->debug) ? r_io_section_vaddr_to_offset (io, seek) : seek;
	r_list_foreach (io->sections, iter, s) {
		if (min == -1 || s->offset < min)
			min = s->offset;
		if (max == -1 || s->offset+s->size > max)
			max = s->offset+s->size;
	}

	mul = (max-min) / width;
	if (min != -1 && mul != 0) {
		i = 0;
		r_list_foreach (io->sections, iter, s) {
			io->printf ("%02d%c 0x%08"PFMT64x" |",
					i, (seek>=s->offset && seek<s->offset+s->size)?'*':' ', s->offset);
			for (j=0; j<width; j++) {
				if ((j*mul)+min >= s->offset && (j*mul)+min <=s->offset+s->size)
					io->printf ("#");
				else io->printf ("-");
			}
			io->printf ("| 0x%08"PFMT64x" %s %s\n", s->offset+s->size, 
				r_str_rwx_i (s->rwx), s->name);
			i++;
		}
		/* current seek */
		if (i>0 && len != 0) {
			if (seek == UT64_MAX)
				seek = 0;
			//len = 8096;//r_io_size (io);
			io->printf ("=>  0x%08"PFMT64x" |", seek);
			for (j=0;j<width;j++) {
				io->printf (
					((j*mul)+min >= seek &&
					 (j*mul)+min <= seek+len)
					?"^":"-");
			}
			io->printf ("| 0x%08"PFMT64x"\n", seek+len);
		}
	}
}

R_API RIOSection *r_io_section_get(RIO *io, ut64 offset) {
	RListIter *iter;
	RIOSection *s;

	r_list_foreach (io->sections, iter, s) {
		if (offset >= s->offset && offset <= s->offset + s->size) {
			//eprintf ("SG: %llx %s\n", offset, s->name);
			return s;
		}
	}
	return NULL;
}

R_API ut64 r_io_section_get_offset(RIO *io, ut64 offset) {
	RIOSection *s = r_io_section_get(io, offset);
	return s? s->offset: -1;
}

R_API ut64 r_io_section_get_vaddr(RIO *io, ut64 offset) {
	RIOSection *s = r_io_section_get (io, offset);
	return s? s->vaddr: -1;
}

// TODO: deprecate
R_API int r_io_section_get_rwx(RIO *io, ut64 offset) {
	RIOSection *s = r_io_section_get (io, offset);
eprintf ("r_io_section_get_rwx: must be deprecated\n");
	return s?s->rwx:R_IO_READ|R_IO_WRITE|R_IO_EXEC;
}

R_API int r_io_section_overlaps(RIO *io, RIOSection *s) {
	int i = 0;
	RListIter *iter;
	RIOSection *s2;

	r_list_foreach (io->sections, iter, s2) {
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

R_API ut64 r_io_section_vaddr_to_offset(RIO *io, ut64 vaddr) {
	RListIter *iter;
	RIOSection *s;

	r_list_foreach (io->sections, iter, s) {
		if (vaddr >= s->vaddr && vaddr < s->vaddr + s->vsize) {
	//		eprintf ("SG: %llx phys=%llx %s\n", vaddr, vaddr-s->vaddr+s->offset, s->name);
			return (vaddr - s->vaddr + s->offset);
		}
	}
	return -1;
}

R_API ut64 r_io_section_offset_to_vaddr(RIO *io, ut64 offset) {
	RListIter *iter;
	RIOSection *s;

	r_list_foreach (io->sections, iter, s) {
		if (offset >= s->offset && offset < s->offset + s->size)
			return (s->vaddr + offset - s->offset);
	}
	return -1;
}

R_API ut64 r_io_section_next(RIO *io, ut64 o) {
	RListIter *iter;
	RIOSection *s;

	r_list_foreach (io->sections, iter, s) {
//eprintf (" o=%llx (%llx) (%llx)\n", o, s->offset, s->size);
		if (o >= s->vaddr && o < (s->vaddr + s->size)) {
			ut64 n = s->vaddr + s->size;
			if (n>o)
				o = n;
#if 0
			if (first) {
				first = 0;
goto restart;
			} else o = s->vaddr;
#endif
		}
	}
	return o;
}
