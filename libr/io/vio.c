/* radare - LGPL - Copyright 2014 - pancake, condret */

#include <r_io.h>

#define	VIO_DEBUG	0
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
read all sections via mread, resolve maps for unsectioned areas and fill the gaps. last point must always prefere using io->desc*/
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
	if (!r_list_empty (sections)) {						//check if there is any section
		ranges = r_list_new();
		ranges->free = free;
		r_list_foreach (sections, iter, section) {
			if (section->vaddr==0)
				continue;
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
			r_io_mread (io, io->desc->fd, tmp_vaddr, tmp_buf, tmp_len);	//ensure that io->desc is always on the top
		}
		r_list_free (ranges);
	} else {
		maps = r_io_map_get_maps_in_range (io, vaddr, vaddr + len);	//get all maps
		r_list_foreach (maps, iter, map) {
			r_io_mread (io, map->fd, vaddr, buf, len);		//read from the maps, the ranges will be adjusted in mread
		}
		r_list_free (maps);						//free the list
		r_io_mread (io, io->desc->fd, vaddr, buf, len);			//ensure that io->desc is always on the top
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
	map = r_io_map_resolve_in_range (io, maddr, endaddr, fd);		//resolve map for fd in range
	if (!map)
		map = r_io_map_resolve (io, fd);				//try to resolve map if it is not in range
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
#if	VIO_DEBUG
	char *read_from = NULL;
#endif
	if (!io) {
#if	VIO_DEBUG					//show debug-info
		eprintf ("r_io_pread: io is NULL\n"
		"paddr: 0x%016"PFMT64x"\n"
		"len: 0x%x\n", paddr, len);
		r_sys_backtrace();
#endif
		return 0;
	} 
	if (paddr == UT64_MAX) {
		if (io->ff) {
			memset (buf, 0xff, len);
			return len;
		}
		return R_FAIL;
	}
	r_io_seek (io, paddr, R_IO_SEEK_SET);
	if (io->buffer_enabled){
#if	VIO_DEBUG
		read_from = "buffer";
#endif
		bytes_read = r_io_buffer_read (io, io->off, buf, len);
	} else {
		if (io->desc && io->desc->plugin && io->desc->plugin->read){
#if	VIO_DEBUG
			read_from = io->desc->plugin->name;
#endif
			bytes_read = io->desc->plugin->read (io, io->desc, buf, len);
		} else if (!io->desc) {
#if	VIO_DEBUG
			eprintf ("r_io_pread: io->desc is NULL\n"
			"paddr: 0x%016"PFMT64x"\n"
			"len: 0x%x\n", paddr, len);
			r_sys_backtrace();
#endif
			return 0;
		} else {
#if	VIO_DEBUG
			read_from = "File";
#endif
			bytes_read = read (io->desc->fd, buf, len);
		}
		if (bytes_read<0) {
#if	VIO_DEBUG
			eprintf ("r_io_pread: bytes_read %i\n"
			"from: %s\n"
			"paddr: 0x%016"PFMT64x"\n"
			"len: 0x%x\n", bytes_read, read_from, paddr, len);
			r_sys_backtrace();
#endif
		}
	}
	return bytes_read;
}

// This is not so good commented, because it's mostly copy-pasta from mread
R_API int r_io_mwrite (RIO *io, int fd, ut64 maddr, ut8 *buf, int len) {
	int write_bytes = len;
	ut64 endaddr, paddr, d;
	RIODesc *desc;								//desc for tmp use
	RIOMap *map;								//map
	if (len<0) {
		eprintf ("r_io_mwrite: wrong usage; len is smaller than 0, len: %i\n", len);
		return R_FAIL;
	}
	if ((UT64_MAX - len) < maddr) {						//no overflows please
		eprintf ("r_io_mwrite: no, you cannot overflow this ut64\n");
		write_bytes = UT64_MAX - maddr;
	}
	endaddr = maddr + write_bytes;
	map = r_io_map_resolve_in_range (io, maddr, endaddr, fd);
	if (!map)
		map = r_io_map_resolve (io, fd);
	if (!map) {
		eprintf ("r_io_mwrite: cannot resolve map for fd%i\n", fd);
		return R_ERROR;
	}
	if (endaddr > map->to) {
		if (maddr > map->to)
			return R_FAIL;
		endaddr = map->to;
		write_bytes = endaddr - maddr;
	}
	if (maddr < map->from) {
		if (endaddr < map->from)
			return R_FAIL;
		d = map->from - maddr;
		if (write_bytes < d)
			return R_FAIL;
		buf += d;
		write_bytes -= d;
		maddr += d;
	}
	if (!(map->flags & R_IO_WRITE))						//check if the map allows writing
		return write_bytes;
	paddr = maddr - map->from + map->delta;
	desc = io->desc;
	io->desc = r_io_desc_get (io, fd);
	if (!io->desc) {
		eprintf ("r_io_mwrite: cannot get desc for fd %i\n", fd);
		io->desc = desc;
		return R_ERROR;
	}
	write_bytes = r_io_pwrite (io, paddr, buf, write_bytes);
	io->desc = desc;
	return write_bytes;
}

R_API int r_io_pwrite (RIO *io, ut64 paddr, const ut8 *buf, int len)
{
	int bytes_written = 0;
#if	VIO_DEBUG
	char *written_to = NULL;
#endif
	if (!io) {
#if	VIO_DEBUG
		eprintf ("r_io_pwrite: io is NULL\n"
		"paddr: 0x%016"PFMT64x"\n"
		"len: 0x%x\n", paddr, len);
		r_sys_backtrace();
#endif
		return 0;
	}
	if ((UT64_MAX - len) < paddr)			//prevent overflows
		len = UT64_MAX - paddr;
	r_io_seek (io, paddr, R_IO_SEEK_SET);
	if (io->desc && io->desc->plugin && io->desc->plugin->write) {
#if	VIO_DEBUG
		written_to = io->desc->plugin->name;
#endif
		bytes_written = io->desc->plugin->write (io, io->desc, buf, len);
	} else if (!io->desc) {
#if	VIO_DEBUG					//show debug-info
		eprintf ("r_io_pwrite: io->desc is NULL\n"
		"paddr: 0x%016"PFMT64x"\n"
		"len: 0x%x\n", paddr, len);
		r_sys_backtrace();
#endif
		return 0;
	} else {
#if	VIO_DEBUG
		written_to = "File";
#endif
		bytes_written = write (io->desc->fd, buf, len);
	}
	if (bytes_written < 0) {
#if	VIO_DEBUG
		eprintf ("r_io_pwrite: bytes_written: %i\n"
		"to: %s\n"
		"paddr: 0x%016"PFMT64x"\n"
		"len: 0x%x\n", bytes_written, written_to, paddr, len);
		r_sys_backtrace();
#endif
	}
	return bytes_written;
}
