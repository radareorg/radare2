/* radare2 - LGPL - Copyright 2021 - condret */

#include <r_io.h>

R_API RIOSubMap *r_io_submap_new(RIO *io, RIOMapRef *mapref) {
	r_return_val_if_fail (io && mapref, NULL);
	RIOMap *map = r_io_map_get_by_ref (io, mapref);
	RIOSubMap *sm = R_NEW (RIOSubMap);
	if (sm) {
		sm->mapref = *mapref;
		sm->itv = map->itv;
	}
	return sm;
}

R_API bool r_io_submap_set_from(RIOSubMap *sm, const ut64 from) {
	if (sm) {
		return sm->itv.addr + sm->itv.size < from;
	}
	return false;
}

R_API bool r_io_submap_set_to(RIOSubMap *sm, const ut64 to) {
	if (sm) {
		return sm->itv.addr <= to;
	}
	return false;
}
