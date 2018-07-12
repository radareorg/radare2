#include <r_io.h>
#include <r_types.h>
#include <r_util.h>

static ut64 _map_from(RIOMap *map) {
	return map->itv.addr;
}

static ut64 _map_to(RIOMap *map) {
	return map->itv.addr + map->itv.size - 1;
}

//in - incoming
static bool _submap_find_cb(void *vin, void *vincoming, void *user, int *cmp_res) {
	RIOSubMap *sm = (RIOSubMap *)vin;
	ut64 *off = (ut64 *)vincoming;

	if (off[0] < sm->from) {
		cmp_res[0] = 1;
		goto beach;
	}
	if (off[0] > sm->to) {
		cmp_res[0] = -1;
		goto beach;
	}
	cmp_res[0] = 0;
beach:
	return true;
}

static bool _submap_free_cb(void *user, void *data, ut32 id) {
	free (data);
	return true;
}

//only use this, when no overlapping is guaranteed with the incoming data
static bool _submap_insert_no_overlap_cb(void *vin, void *vincoming, void *user, int *cmp_res) {
	RIOSubMap *sm = (RIOSubMap *)vincoming;

	return _submap_find_cb (vin, &sm->from, user, cmp_res);
}

R_API void r_io_submap_init(RIO *io) {
	if (io && !io->submaps) {
		io->submaps = r_oids_new (0, 0xfffffffe);	//we need to guarantee 1 empty slot
	}
}

R_API void r_io_submap_fini(RIO *io) {
	if (io && io->submaps) {
		r_oids_foreach (io->submaps, _submap_free_cb, NULL);
		r_oids_free (io->submaps);
		io->submaps = NULL;
	}
}

//existing partially overlapping submaps get adjusted,
//so that they don't overlap with the new submap
R_API void r_io_submap_repress(RIO *io, RIOMap *map) {	//change to bool maybe later
/*	RIOSubMap *sm;
	ut32 od;	*/

	if (!io || !io->submaps || !map) {
		return;
	}

	RIOSubMap *sm = R_NEW (RIOSubMap);
	if (!sm) {
		return;
	}
	sm->from = _map_from (map);
	sm->to = _map_to (map);
	sm->id = map->id;
	r_io_submap_cut_out (io, sm->from, sm->to);
	io->submaps->cmp = _submap_insert_no_overlap_cb;
	ut32 od;
	r_oids_insert (io->submaps, sm, &sm->sid, &od, NULL);
}

//cuts out all submaps, so that there is no submap between from and to
R_API bool r_io_submap_cut_out(RIO *io, ut64 from, ut64 to) {
	RIOSubMap *bd, *sm;
	ut32 od;
	if (to < from) {
		if (!r_io_submap_cut_out (io, from, UT64_MAX)) {
			return false;
		}
		from = 0LL;
	}
	if (!io || !io->submaps) {
		return false;
	}
	if (!io->submaps->ptop) {
		return true;
	}
	io->submaps->cmp = _submap_find_cb;
	od = r_oids_find (io->submaps, &from, NULL);
	while ((sm = r_oids_oget (io->submaps, od))) {
//sm->to is guaranteed to be bigger or equal to from,
//because that's how r_oids_find works
		if (sm->from < from) {
			if (sm->to > to) {
//      ##cut this out##
//############sm##############
//becomes
//      ##cut this out##
//##sm##                ##bd##
				bd = R_NEW (RIOSubMap);
				if (!bd) {
					return false;
				}
				bd->from = to + 1;
				bd->to = sm->to;
				bd->id = sm->id;
				sm->to = from - 1;
				io->submaps->cmp = _submap_insert_no_overlap_cb;
				r_oids_insert (io->submaps, bd, &bd->sid, &od, NULL);
				return true;
			}
//    ##cut this out##
//###sm###
//becomes
//    ##cut this out##
//#sm#
			sm->to = from - 1;
			od++;
			continue;
		}
		if (sm->to <= to) {
//     ##cut this out##
//          ####sm####
//sm gets deleted
			free (sm);
			r_oids_odelete (io->submaps, od);
			continue;
		}
		if (sm->from <= to) {
//  ##cut this out##
//            ####sm####
//becomes
//  ##cut this out##
//                  #sm#
			sm->from = to + 1;
//any further submap is going to be bigger than sm,
//no need to continue the loop
		}
		return true;
	}
	return true;
}

//in - incoming
static bool _submap_hack_n_slash_insert(void *vin, void *vincoming, void *user, int *cmp_res) {
	RIOSubMap *in = (RIOSubMap *)vin;
	RIOSubMap *incoming = (RIOSubMap *)vincoming;
	RQueue *todo = (RQueue *)user;
	RIOSubMap *map;
#if 0
	      ########in#########
#incoming#
#endif
	if (in->from > incoming->to) {
		cmp_res[0] = 1;
		return true;
	}
#if 0
########in#########
			#incoming#
#endif
	if (in->to < incoming->from) {
		cmp_res[0] = -1;
		return true;
	}
	if (in->from > incoming->from) {
#if 0
	########in#########
##incoming##
#endif
		if (in->to >= incoming->to) {
			//cut off the intersecting part
			incoming->to = in->from - 1;
			cmp_res[0] = 1;
			return true;
		} else {
#if 0
	########in#########
#############incoming###############
#endif
			//slash submap into 2 submaps, that don't intersect with the existing submap in
			map = R_NEW0 (RIOSubMap);	//check needed
			map->id = incoming->id;
			map->to = incoming->to;
			map->from = in->to + 1;
			r_queue_enqueue (todo, map);	//will be inserted on the later iterations
			incoming->to = in->from - 1;
			cmp_res[0] = 1;
			return true;
		}
	}
#if 0
########in#########
		#incoming#
#endif
	if (in->to < incoming->to) {
		//cut off the intersecting part
		incoming->from = in->to + 1;
		cmp_res[0] = -1;
		return true;
	}
#if 0
    ###############in###############
	########incoming#######
#endif
	//the existing submap in has higher priority
	//the submap incoming should not get inserted
	//abort by returning false
	cmp_res[0] = 0;
	return false;
}

R_API void r_io_submap_sink_in(RIO *io, RIOMap *map) {
/*	RIOSubMap *sm;
	RQueue *todo;
	ut32 od;	*/

	if (!io || !io->submaps || !map) {
		return;
	}
	RQueue *todo = r_queue_new (4);
	if (!todo) {
		return;
	}
	RIOSubMap *sm = R_NEW (RIOSubMap);
	if (!sm) {
		r_queue_free (todo);
		return;
	}
	sm->from = _map_from (map);
	sm->to = _map_to (map);
	sm->id = map->id;
	io->submaps->cmp = _submap_hack_n_slash_insert;

	ut32 od;
	do {
		if (!r_oids_insert (io->submaps, sm, &sm->sid, &od, todo)) {
			free (sm);
		}
	} while ((sm = r_queue_dequeue (todo)));

	r_queue_free(todo);
}

static bool _sink_in_all_cb(void *user, void *data, ut32 id) {
	RIO *io = (RIO *)user;
	RIOMap *map = (RIOMap *)data;
	
	r_io_submap_sink_in (io, map);
	return true;
}

R_API void r_io_submap_sink_in_all(RIO *io) {
	if (!io || !io->maps || !io->submaps) {
		return;
	}
	r_oids_foreach (io->maps, _sink_in_all_cb, io);
}

R_API ut32 r_io_map_get_next(RIO *io, ut64 addr) {
/*	RIOSubMap *sm;
	ut32 od;	*/
	if (!io || !io->maps || !io->submaps) {
		return 0;
	}
	io->submaps->cmp = _submap_find_cb;
	ut32 od = r_oids_find (io->submaps, &addr, NULL);
	RIOSubMap *sm = r_oids_oget (io->submaps, od);
	return sm ? sm->id : 0;
}

R_API RIOMap *r_io_map_get(RIO *io, ut64 addr) {
/*	RIOMap *map;	*/
	ut32 id = r_io_map_get_next (io, addr);

	if (!id) {
		return NULL;
	}
	RIOMap *map = r_oids_get (io->maps, id);
	return r_itv_contain (map->itv, addr) ? map : NULL;
}
