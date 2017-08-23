/* radare - LGPL - Copyright 2017 - condret */

#include <r_io.h>
#include <r_util.h>
#include <r_types.h>

// when io.va is true this checks if the highest priorized map at this
// offset has the same or high permissions set. When there is no map it
// check for the current desc permissions and size.
// when io.va is false it only checks for the desc
R_API bool r_io_is_valid_offset(RIO* io, ut64 offset, int hasperm) {
	RIOMap* map;
	if (!io) {
		return false;
	}
	if (io->va && (map = r_io_map_get (io, offset))) {
		if ((map = r_io_map_get (io, offset))) {
			return ((map->flags & hasperm) == hasperm);
		}
		return false;
	}
	if (!io->desc) {
		return false;
	}
	if (r_io_desc_size (io->desc) <= offset) {
		return false;
	}
	return ((io->desc->flags & hasperm) == hasperm);
}

// this is wrong, there is more than big and little endian
R_API bool r_io_read_i(RIO* io, ut64 addr, ut64 *val, int size, bool endian) {
	ut8 buf[8];
	if (!val) {
		return false;
	}
	size = R_DIM (size, 1, 8);
	if (!r_io_read_at (io, addr, buf, size)) {
		return false;
	}
	*val = r_read_ble (buf, endian, size);
	return true;
}


R_API bool r_io_write_i(RIO* io, ut64 addr, ut64 *val, int size, bool endian) {
	ut8 buf[8];
	if (!val) {
		return false;
	}
	size = R_DIM (size, 1, 8);
	r_write_ble (buf, *val, endian, size);
	if (!r_io_write_at (io, addr, buf, size)) {
		return false;
	}
	return true;
}
