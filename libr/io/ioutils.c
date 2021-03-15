/* radare - LGPL - Copyright 2017-2021 - condret, pancake */

#include <r_io.h>
#include <r_util.h>
#include <r_types.h>
#include "io_private.h"

//This helper function only check if the given vaddr is mapped, it does not account
//for map perms
R_API bool r_io_addr_is_mapped(RIO *io, ut64 vaddr) {
	r_return_val_if_fail (io, false);
	return (io->va && r_io_map_get_at (io, vaddr));
}

// when io.va is true this checks if the highest priorized map at this
// offset has the same or high permissions set. When there is no map it
// check for the current desc permissions and size.
// when io.va is false it only checks for the desc
R_API bool r_io_is_valid_offset(RIO* io, ut64 offset, int hasperm) {
	r_return_val_if_fail (io, false);
	if (io->mask) {
		if (offset > io->mask && hasperm & R_PERM_X) {
			return false;
		}
	}
	if (io->va) {
		if (!hasperm) {
			// return r_io_map_is_mapped (io, offset);
			RIOMap* map = r_io_map_get_at (io, offset);
			return map? map->perm & R_PERM_R: false;
		}
		RIOMap* map = r_io_map_get_at (io, offset);
		return map? (map->perm & hasperm) == hasperm: false;
	}
	if (!io->desc) {
		return false;
	}
	if (offset > r_io_desc_size (io->desc)) {
		return false;
	}
	return ((io->desc->perm & hasperm) == hasperm);
}

// this is wrong, there is more than big and little endian
R_API bool r_io_read_i(RIO* io, ut64 addr, ut64 *val, int size, bool endian) {
	ut8 buf[8];
	r_return_val_if_fail (io && val, false);
	size = R_DIM (size, 1, 8);
	if (!r_io_read_at (io, addr, buf, size)) {
		return false;
	}
	//size says the number of bytes to read transform to bits for r_read_ble
	*val = r_read_ble (buf, endian, size * 8);
	return true;
}

R_API bool r_io_write_i(RIO* io, ut64 addr, ut64 *val, int size, bool endian) {
	ut8 buf[8];
	r_return_val_if_fail (io && val, false);
	size = R_DIM (size, 1, 8);
	//size says the number of bytes to read transform to bits for r_read_ble
	r_write_ble (buf, *val, endian, size * 8);
	return r_io_write_at (io, addr, buf, size) == size;
}
