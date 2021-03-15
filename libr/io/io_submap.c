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
