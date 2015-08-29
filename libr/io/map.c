#include <r_io.h>
#include <sdb.h>
#include <stdlib.h>

R_API RIOMap *r_io_map_new (RIO *io, int fd, int flags, ut64 delta, ut64 addr, ut64 size)
{
	RIOMap *map = NULL;
	if (!size || !io || !io->maps || ((UT64_MAX - size + 1) < addr))			//prevent overflow
		return NULL;
	map = R_NEW0 (RIOMap);
	if (io->freed_map_ids) {
		map->id = (ut32)(size_t) ls_pop (io->freed_map_ids);				//revive dead ids to prevent overflows
		if (!io->freed_map_ids->length) {						//and keep ids low number so user don't need to type large numbers
			ls_free (io->freed_map_ids);
			io->freed_map_ids = NULL;						//we are not storing pointers here, so free must be NULL or it will segfault
		}
	} else if (io->map_id != 0xffffffff) {							//part 2 of id-overflow-prevention
		io->map_id++;
		map->id = io->map_id;
	} else {
		free (map);
		return NULL;
	}
	map->fd = fd;
	map->from = addr;
	map->to = addr + size - 1;								//RIOMap describes an interval  of addresses (map->from; map->to)
	map->flags = flags;
	map->delta = delta;
	ls_append (io->maps, map);								//new map lives on the top
	return map;
}

void map_free (SIOMap *map)									//not-public-api
{
	if (map)
		free (map->name);
	free (map);
}

<<<<<<< 5d874bc8d5dd55cf4b06ac56757002cb0e54163a
R_API int r_io_map_write_update(RIO *io, int fd, ut64 addr, ut64 len) {
	int res = false;
	RIOMap *map = NULL;
	RListIter *iter;
	r_list_foreach (io->maps, iter, map) {
		if (map->fd == fd) break;
		map = NULL;
	}

	if (map && map->to < addr+len) {
		res = true;
		map->to = addr+len;
	}
	return res;
}

R_API int r_io_map_truncate_update(RIO *io, int fd, ut64 sz) {
	int res = false;
	RIOMap *map = NULL;
	RListIter *iter;
	r_list_foreach (io->maps, iter, map) {
		if (map->fd == fd) break;
		map = NULL;
	}

	if (map) {
		res = true;
		map->to = map->from+sz;
=======
R_API void r_io_map_init (RIO *io)
{
	if (io) {
		io->maps = ls_new ();
		io->maps->free = map_free;
>>>>>>> so it begins
	}
}

//check if a map with exact the same properties exists
R_API int r_io_map_exists (RIO *io, RIOMap *map)
{
	SdbListIter *iter;
	RIOMap *m;
	if (!io || !io->maps || !map)
		return R_FALSE;
	ls_foreach (io->maps, iter, m) {
		if (!memcmp (m, map, sizeof(RIOMap)))
			return R_TRUE;
	}
	return R_FALSE;
}

//check if a map with specified id exists
R_API int r_io_map_exists_for_id (RIO *io, ut32 id)
{
	SdbListIter *iter;
	RIOMap *map;
	if (!io || !io->maps)
		return R_FALSE;
	ls_foreach (io->maps, iter, map) {
		if (map->id == id)
			return R_TRUE;
	}
	return R_FALSE;
}

//add new map
R_API RIOMap *r_io_map_add (RIO *io, int fd, int flags, ut64 delta, ut64 addr, ut64 size)
{
	RIODesc *desc = r_io_desc_get (io, fd);							//check if desc exists
	if (desc)
		return r_io_map_new (io, fd, flags & desc->flags, delta, addr, size);		//a map cannot have higher permissions than the desc belonging to it
	return NULL;
}

//gets first map where addr fits in
R_API RIOMap *r_io_map_get (RIO *io, ut64 addr)
{
	RIOMap *map;
	SdbListIter *iter;
	if (!io || !io->maps)
		return NULL;
	ls_foreach (io->maps, iter, map) {
		if ((map->from <= addr) && (map->to >= addr))
			return map;
	}
	return NULL;
}

//deletes a map with specified id
R_API int r_io_map_del (RIO *io, ut32 id)
{
	SdbListIter *iter;
	RIOMap *map;
<<<<<<< 5d874bc8d5dd55cf4b06ac56757002cb0e54163a
	RListIter *iter, *tmp;
	ut8 deleted = false;
	if (io && io->maps) {
		r_list_foreach_safe (io->maps, iter, tmp, map) {
			if (fd==-1 || map->fd==fd) {
				r_list_delete (io->maps, iter);
				deleted = true;
			}
		}
	}
	return deleted;
}

R_API ut64 r_io_map_next(RIO *io, ut64 addr) {
	ut64 next = UT64_MAX;
	RIOMap *map;
	RListIter *iter;
	r_list_foreach (io->maps, iter, map) {
		if (map->from > addr)
			if (!next || map->from < next)
				next = map->from;
	}
	return next;
}

R_API int r_io_map_del_at(RIO *io, ut64 addr) {
	RIOMap *map;
	RListIter *iter;
	r_list_foreach (io->maps, iter, map) {
		if (map->from <= addr && addr < map->to) {
			r_list_delete (io->maps, iter);
			return true;
=======
	if (!io || !io->maps)
		return R_FALSE;
	ls_foreach (io->maps, iter, map) {
		if (map->id == id) {
			ls_delete (io->maps, iter);
			if (!io->freed_map_ids) {
				io->freed_map_ids = ls_new ();
				io->freed_map_ids->free = NULL;
			}
			ls_prepend (io->freed_map_ids, (void *)(size_t)id);
			return R_TRUE;
>>>>>>> so it begins
		}
	}
	return false;
}

//delete all maps with specified fd
R_API int r_io_map_del_for_fd (RIO *io, int fd)
{
	SdbListIter *iter, *ator;
	RIOMap *map;
	int ret = R_FALSE;
	if (!io || !io->maps)
		return ret;
	for (iter = io->maps->head; iter != NULL; iter = ator) {
		ator = iter->n;
		map = iter->data;
		if (!map) {									//this is done in r_io_map_cleanup too, but preventing some segfaults here too won't hurt
			ls_delete (io->maps, iter);
		} else if (map->fd == fd) {
			ret = R_TRUE;								//a map with (map->fd == fd) existed/was found and will be deleted now
			if (!io->freed_map_ids) {
				io->freed_map_ids = ls_new ();
				io->freed_map_ids->free = NULL;
			}
			ls_prepend (io->freed_map_ids, (void *)(size_t)fd);
			ls_delete (io->maps, iter);						//delete iter and map
		}
	}
	return ret;
}

//brings map with specified id to the top of of the list
R_API int r_io_map_priorize (RIO *io, ut32 id)
{
	SdbListIter *iter;
	RIOMap *map;
<<<<<<< 5d874bc8d5dd55cf4b06ac56757002cb0e54163a
	RListIter *iter;
	ut64 end_addr = addr + size;
	r_list_foreach (io->maps, iter, map) {
		// XXX - This does not handle when file overflow 0xFFFFFFFF000 -> 0x00000000
		// keeping (fd, to, from) tuples as separate maps
		if ( map->fd == fd && ((map->from <= addr && addr < map->to) ||
			(map->from <= end_addr  && end_addr < map->to)) )
			//return r_io_map_add(io, fd, flags, delta, map->to, size);
			return NULL;
	}
	return r_io_map_new (io, fd, flags, delta, addr, size);
}

R_API int r_io_map_exists_for_offset (RIO *io, ut64 off) {
	int res = false;
	RIOMap *im = NULL;
	RListIter *iter;
	r_list_foreach (io->maps, iter, im) {
		if (im->from <= off && off < im->to) {
			res = true;
			break;
=======
	if (!io || !io->maps)
		return R_FALSE;
	ls_foreach (io->maps, iter, map) {
		if (map->id == id) {								//search for iter with the correct map
			if (io->maps->head == iter)						//check if map is allready at the top
				return R_TRUE;
			if (iter->n)								//bring iter with correct map to the front
				iter->n->p = iter->p;
			if (iter->p)
				iter->p->n = iter->n;
			if (io->maps->tail == iter)
				io->maps->tail = iter->p;
			io->maps->head->p = iter;
			iter->n = io->maps->head;
			io->maps->head = iter;
			iter->p = NULL;
			return R_TRUE;								//TRUE if the map could be priorized
>>>>>>> so it begins
		}
	}
	return R_FALSE;										//FALSE if not
}

//may fix some inconsistencies in io->maps
R_API void r_io_map_cleanup (RIO *io)
{
	SdbListIter *iter, *ator;
	RIOMap *map;
	if (!io || !io->maps)
		return;
	if (!io->files) {									//remove all maps if no descs exist
		r_io_map_fini (io);
		r_io_map_init (io);
		return;
	}
	for (iter = io->maps->head; iter != NULL; iter = ator) {
		map = iter->data;
		ator = iter->n;
		if (!map) {									//remove iter if the map is a null-ptr, this may fix some segfaults
			ls_delete (io->maps, iter);
		} else if (!r_io_desc_get (io, map->fd)) {					//delete map and iter if no desc exists for map->fd in io->files
			if (!io->freed_map_ids) {
				io->freed_map_ids = ls_new ();
				io->freed_map_ids->free = NULL;
			}
			ls_prepend (io->freed_map_ids, (void *)(size_t)map->id);
			ls_delete (io->maps, iter);
		}
	}
}

R_API void r_io_map_fini (RIO *io)
{
	if (!io)
		return;
	if (io->maps)
		ls_free (io->maps);
	io->maps = NULL;
	if (io->freed_map_ids)
		ls_free (io->freed_map_ids);
	io->freed_map_ids = NULL;
	io->map_id = 0;
}

//checks if (from;to) overlaps with (map->from;map->to)
R_API int r_io_map_is_in_range (RIOMap *map, ut64 from, ut64 to)					//rename pls
{
	if (!map || (to < from))
		return R_FALSE;
	if (map->from <= from && from <= map->to)	return R_TRUE;
	if (map->from <= to && to <= map->to)		return R_TRUE;
	if (map->from > from && to > map->to)		return R_TRUE;
	return R_FALSE;
}

<<<<<<< 5d874bc8d5dd55cf4b06ac56757002cb0e54163a
R_API _Bool r_io_map_overlaps (RIO *io, RIODesc *fd, RIOMap *map) {
	RListIter *iter;
	RIOMap *im = NULL;
	ut64 off = map->from;
	if (!fd) return false;
	r_list_foreach (io->maps, iter, im) {
		if (im == map) continue;
		if (off >= im->from && off < im->to) {
			return true;
		}
	}
	return false;
=======
R_API void s_io_map_set_name (SIOMap *map, const char *name)
{
	if (!map || !name)
		return;
	free (map->name);
	map->name = strdup (name);
>>>>>>> so it begins
}

R_API void s_io_map_del_name (SIOMap *map)
{
	if (!map)
		return;
	free (map->name);
	map->name = NULL;
}
