/* radare - LGPL - Copyright 2008-2014 - pancake */

#include <r_io.h>

#if 0

| io.va |               | io.ff |
.------------------.
|                  |
| VADDR ---> MADDR | ---> PADDR --->  PLUGINS
|                  |   maddr->paddr+fd
`------------------'

virtual addresses are used when io.va is enabled
and it checks for sections in order to find an address
inside a mapped range.

If a virtual address is not found in any section, 
then it looks into the map addresses.

mapped addresses are used to map an RIODesc at a
specific physical address. A file can be opened, but
not mapped, in this case it will not be visible.

cache: where should it
undo api: works at vaddr level too

TODO:
 - How to share data pointers?
 - Load RBuffer as file?

maddr -> vaddr

it is possible to get a list of virtual addresses that
point to a given physical address from a virtual one.

#endif

/* Virtual Addressing API */

/* Return Physical Address and associated RIODesc */
/* RIOmaddr type is used to store the virtual address requested,
   and the associated map address. Which must be used to
   read from the physical address as specified by the map */
typedef struct r_io_maddr_t {
	RIODesc *desc; // NULL if cannot be resolved
	RIOSection *section;
	RIOMap *map;
	ut64 paddr;
	ut64 maddr;
	ut64 vaddr;
	ut64 next_vaddr;
	int has_next;
} RIOmaddr;
R_API int r_io_pread (RIO *io, ut64 paddr, ut8 *buf, int len);

static ut64 r_io_m2p(RIOMap *map, RIOmaddr *m) {
	if (map) {
		if (m->maddr >= map->from && m->maddr < map->to) {
			return m->maddr - map->from + map->delta;
		}
		return UT64_MAX;
	}
	if (!m || !m->desc || !m->map)
		return UT64_MAX;
	if (m->maddr > m->map->from) {
		return m->maddr - m->map->from + m->map->delta;
	}
	return UT64_MAX;
}

static ut64 findNextVaddr (RIO *io, RIOmaddr *ma) {
	ut64 diff, hit, cur = ma->vaddr;
	RListIter *iter;
	RIOSection *s, *_s = NULL;
	RIOMap *m, *_m = NULL;
	
#define foundSectionHit() {_s=s;_m=NULL;hit=diff;}
#define foundMapHit() {_s=NULL;_m=m;hit=diff;}
	hit = UT64_MAX;
	/* find begining of next section */
	r_list_foreach (io->sections, iter, s) {
#define checkSectionHit(x) (cur<x && (diff=x-cur,diff<hit))
		if (checkSectionHit (s->vaddr))
			foundSectionHit ();
		if (checkSectionHit (s->vaddr+s->vsize))
			foundSectionHit ();
	}
#if 0
	/* or map */
	r_list_foreach (io->maps, iter, m) {
		if (cur<m->from) {
			diff = m->from - cur;
			if (diff < hit)
				hit = diff;
		}
		if (cur<m->to) {
			diff = m->to - cur;
			if (diff < hit)
				hit = diff;
		}
	}
#endif
	/* if not found */
	if (hit == UT64_MAX) {
		ma->has_next = R_FALSE;
		return ma->next_vaddr = UT64_MAX;
	}
	ma->has_next = R_TRUE;
	// XX: thi is wrong
	//if (_m) ma->map = _m;
	//if (_s) ma->section = _s;
	return ma->next_vaddr = cur+hit;
}

static RIOmaddr r_io_v2m(RIO *io, ut64 vaddr) {
	RIOmaddr pat = {0};
	RListIter *iter;
	RIOSection *s;
	RIOMap *m;
	int found = 0;
	pat.vaddr = vaddr;
	/* find current */
	r_list_foreach (io->sections, iter, s) {
		if (vaddr >= s->vaddr && vaddr < (s->vaddr+s->size)) {
			found = 1;
			pat.maddr = (vaddr-s->vaddr)+s->offset;
			pat.map = r_io_map_get (io, pat.maddr);
			pat.desc = pat.map? r_io_desc_get (io, pat.map->fd): NULL;
			findNextVaddr (io, &pat);
			pat.section = s;
			pat.paddr = r_io_m2p (NULL, &pat);
		}
	}
	/* if not found in any segment, check the maps */
	if (!found)
	r_list_foreach (io->maps, iter, m) {
		if (vaddr >= m->from && vaddr < m->to) {
			found = 1;
			pat.maddr = (vaddr-m->from)+m->delta;
			pat.map = r_io_map_get (io, pat.maddr);
			pat.desc = pat.map? r_io_desc_get (io, pat.map->fd): NULL;
			findNextVaddr (io, &pat);
			pat.paddr = r_io_m2p (m, &pat);
		}
	}
	return pat;
}

R_API int r_io_vread (RIO *io, ut64 vaddr, ut8 *buf, int len) {
	int bufsz;
	int left = len;
	int ret, skip = 0;
	RIOmaddr pat;
	memset (&pat, 0xff, sizeof (pat));
	if (io->raw)
		return r_io_pread (io, vaddr, buf, len);
	io->ff = 1;
	while (left>0) {
		pat = r_io_v2m (io, vaddr);
		if (pat.has_next)
			bufsz = R_MIN (left, (pat.next_vaddr-vaddr));
		else bufsz = left;
		if (pat.desc) {
			/* read next_vaddr-vaddr from paddr using r_io_pread */
			ret = r_io_pread (io, pat.paddr, buf+skip, bufsz);
			/* if physical address fails to read.. */
			if (ret<1) {
				if (pat.has_next) {
					if (!io->ff) {
						r_io_cache_read (io, vaddr, buf, len);
						return skip;
						return -1; // fix invalid memreads. RCore expects this from vaddr
					}
					memset (buf+skip, 0xff, left);
					//memset (buf+skip, 0xff, bufsz);
				}
				
			}
		} else {
			ret = 0; // avoid infinite loopz
			break;
		}
		skip += ret;
		left -= ret;
		if (!pat.has_next)
			break;
//eprintf ("NEXT 0x%llx -> 0x%llx\n", vaddr, pat.next_vaddr);
		vaddr = pat.next_vaddr;
	}
	if (io->ff) {
		if (left>0) {
			memset (buf+skip, 0xff, left);
	}
		r_io_cache_read (io, vaddr, buf, len);
		return len;
	}
	r_io_cache_read (io, vaddr, buf, len);
	return skip;
}

R_API int r_io_mread (RIO *io, ut64 maddr, ut8 *buf, int len) {
	// resolve paddr for given maddr
	return r_io_pread (io, maddr, buf, len);
}

R_API int r_io_pread (RIO *io, ut64 paddr, ut8 *buf, int len) {
	int bytes_read = 0;
	const char *read_from = NULL;
// TODO: implement cache at physical level
	if (paddr == UT64_MAX) {
		if (io->ff) {
			memset (buf, 0xff, len);
			return len;
		}
		return -1;
	}
	if (io->buffer_enabled){
		read_from = "buffer";
		bytes_read = r_io_buffer_read (io, io->off, buf, len);
	}
	if (io->desc && io->desc->plugin && io->desc->plugin->read){
		read_from = io->desc->plugin->name;
		bytes_read = io->desc->plugin->read (io, io->desc, buf, len);
	} else if (!io->desc) {
		eprintf ("Something really bad has happened, and r2 is going to die soon. sorry! :-(\n");
		read_from = "FAILED";
		bytes_read = 0;
	} else {
		read_from = "File";
		bytes_read = read (io->desc->fd, buf, len);
	}
	return bytes_read;
}

// TODO: Implement vresize, mresize and presize
