/* radare - LGPL - Copyright 2014 - pancake, condret */

#include <r_io.h>

/*

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

*/

/* Virtual Addressing API */

#define isInMapRange(m,x)	((m->from <= x) && (x <= m->to))

/* Idea: At first, get all sections in vrange, meanwhile record all unsectioned area and store it via RIORange in a list,
read all sections via mread, resolve maps for unsectioned areas and fill the gaps. last point must allways prefere using io->desc*/
R_API int r_io_vread (RIO *io, ut64 vaddr, ut8 *buf, int len) {
	int tmp_len = len;
	ut8 *tmp_buf = buf;
	ut64 vendaddr, maddr, tmp_vaddr = vaddr;
	RIOMap *map;
	RIOSection *section;
	RIORange *range;
	RList *sections, *ranges = NULL, *maps;
	RListIter *iter, *ator;
	if (!io->desc) {
		eprintf ("r_io_vread: desc is NULL, WTF!\n");
		return R_ERROR;
	}
	if (len < 0) {
		eprintf ("r_io_vread: wrong usage; len is smaller than 0. len: %i\n", len);
		return R_FAIL;
	}
	sections = r_io_section_get_in_vaddr_range (io, vaddr, vaddr+len);
	if (r_list_length (sections)) {						//check if there is any section
		ranges = r_list_new();
		ranges->free = free;
		r_list_foreach (sections, iter, section) {
			if (section->vaddr > tmp_vaddr) {
				range = r_io_range_new();			//create a new range
				range->from = tmp_vaddr;			//record unsectioned area
				range->to = section->vaddr;
				r_list_append (ranges, range);			//store the range
				tmp_vaddr = section->vaddr;			//prepare for resolving the maddr
				tmp_len -= (tmp_vaddr - vaddr);
				tmp_buf += (tmp_vaddr - vaddr);			//adjust buffer
			}
			vendaddr = tmp_vaddr + tmp_len;				//calculate the virtual end address
			if (vendaddr > (section->vaddr + section->vsize))	//check if the virual end address is in the section too
				vendaddr = section->vaddr + section->vsize;	//if not, size it down
			maddr = tmp_vaddr - section->vaddr + section->offset;	//calculate the map address (address inside the map)
			if (maddr > ( section->offset + section->size)) {	//check if the maddr is inside the physical section, if not, skip some things
			} else {
				if ((vendaddr - section->vaddr + section->offset) > (section->offset + section->size)) {	//check if the virtual part of the section fits into the physical part
					r_io_mread (io, section->fd, maddr, tmp_buf, (section->offset + section->size) - maddr);//if not, read as far as possible
				} else {
					r_io_mread (io, section->fd, maddr, tmp_buf, vendaddr - tmp_vaddr);	//read from the sections fd
				}
			}
			tmp_buf += (vendaddr - tmp_vaddr);			//adjust buffer
			tmp_len -= (vendaddr - tmp_vaddr);			//adjust length
			tmp_vaddr = vendaddr;					//adjust address
		}
	}
	r_list_free (sections);
	if (ranges) {								//this is all might be too slow
		r_list_foreach (ranges, iter, range) {
			maps = r_io_map_get_maps_in_range (io, range->from, range->to - range->from);	//get all maps in the range
			tmp_vaddr = range->from;
			tmp_len = range->to - range->from;			//adjust length
			tmp_buf = buf + (tmp_vaddr - vaddr);			//adjust pointer
			r_list_foreach (maps, ator, map) {			//start filling the gaps
				r_io_mread (io, map->fd, tmp_vaddr, tmp_buf, tmp_len);	//read from maps, the ranges will adjusted in mread
			}
			r_list_free (maps);					//free the list for the next iteration
			r_io_mread (io, io->desc->fd, tmp_vaddr, tmp_buf, tmp_len);	//ensure that io->desc is allways on the top
		}
		r_list_free (ranges);
	} else {
		maps = r_io_map_get_maps_in_range (io, vaddr, vaddr + len);	//get all maps
		r_list_foreach (maps, iter, map) {
			r_io_mread (io, map->fd, vaddr, buf, len);		//read from the maps, the ranges will be adjusted in mread
		}
		r_list_free (maps);						//free the list
		r_io_mread (io, io->desc->fd, vaddr, buf, len);			//ensure that io->desc is allways on the top
	}
	return R_TRUE;
}

/*you can throw any fd on this beast, it's important that len is equal or smaller than the size of buf*/
R_API int r_io_mread (RIO *io, int fd, ut64 maddr, ut8 *buf, int len) {
	int read_bytes = len;
	ut64 endaddr, paddr, d;
	RIODesc *desc;								//desc for tmp use
	RIOMap *map;								//map
	if (len < 0) {								//len must be bigger then -1
		eprintf ("r_io_mread: wrong usage; len is smaller than 0. len: %i\n", len);
		return R_FAIL;
	}
	if ((UT64_MAX - len) < maddr) {						//say no to integer-overflows
		eprintf ("r_io_mread: sorry, but I won't let you overflow this ut64\n");
		read_bytes = UT64_MAX - maddr;					//shrink len/read_bytes
	}
	endaddr = maddr + read_bytes;						//get endaddr
	map = r_io_map_resolve (io, fd);					//resolve map for fd
	if (!map) {								//check if map exists
		eprintf ("r_io_mread: cannot resolve map for fd %i\n", fd);
		return R_ERROR;
	}
	if (endaddr > map->to) {						//check if endaddr is in the map
		if (maddr > map->to)						//check segfault
			return R_FAIL;
		endaddr = map->to;						//adjust endaddr
		read_bytes = endaddr - maddr;					//adjust read_bytes
	}
	if (maddr < map->from) {						//adjusting things here will make vread very easy, because you can just get a list of fds in the range and the throw every fd on this function
		if (endaddr < map->from)					//check segfaults
			return R_FAIL;
		d = map->from - maddr;						//get difference between maddr and start of the map
		if (read_bytes < d)						//check if  adjusting would cause segfaults
			return R_FAIL;
		buf += d;							//adjust buf-ptr
		read_bytes -= d;						//this is dangerous and can overflow
		maddr += d;							//adjust maddr
	}
	paddr = maddr - map->from + map->delta;					//resolve paddr
	desc = io->desc;							//save io->desc
	io->desc =  r_io_desc_get (io, fd);					//resolve desc for fd
	if (!io->desc) {							//check if desc exists
		eprintf ("r_io_mread: cannot get desc for fd %i\n", fd);
		io->desc = desc;						//restore io->desc
		return R_ERROR;
	}
	read_bytes = r_io_pread (io, paddr, buf, read_bytes);			//read
	io->desc = desc;							//restore io->desc
	return read_bytes;							//return bytes read
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
	if (bytes_read<0) {
		eprintf ("pread error: %s\n", read_from);
	}
	return bytes_read;
}

// TODO: Implement vresize, mresize and presize
