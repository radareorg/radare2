/* radare2 - LGPL - Copyright 2017 - condret */

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

void _map_free (void *p)									//not-public-api
{
	RIOMap *map = (RIOMap *)p;
	if (map)
		free (map->name);
	free (map);
}

R_API void r_io_map_init (RIO *io)
{
	if (io && !io->maps) {
		if ((io->maps = ls_new ()))
			io->maps->free = _map_free;
	}
}

//check if a map with exact the same properties exists
R_API int r_io_map_exists (RIO *io, RIOMap *map)
{
	SdbListIter *iter;
	RIOMap *m;
	if (!io || !io->maps || !map)
		return false;
	ls_foreach (io->maps, iter, m) {
		if (!memcmp (m, map, sizeof(RIOMap)))
			return true;
	}
	return false;
}

//check if a map with specified id exists
R_API int r_io_map_exists_for_id (RIO *io, ut32 id)
{
	return !!(r_io_map_resolve(io, id));
}

R_API RIOMap *r_io_map_resolve (RIO *io, ut32 id)
{
	SdbListIter *iter;
	RIOMap *map;
	if (!io || !io->maps)
		return NULL;
	ls_foreach (io->maps, iter, map) {
		if (map->id == id)
			return map;
	}
	return NULL;
}

//add new map
R_API RIOMap *r_io_map_add (RIO *io, int fd, int flags, ut64 delta, ut64 addr, ut64 size)
{
	RIODesc *desc = r_io_desc_get (io, fd);							//check if desc exists
	if (desc)
		return r_io_map_new (io, fd, (flags & desc->flags) | (flags & R_IO_EXEC), delta, addr, size);	//a map cannot have higher permissions than the desc belonging to it
	return NULL;
}

//gets first map where addr fits in
R_API RIOMap *r_io_map_get (RIO *io, ut64 addr)
{
	RIOMap *map;
	SdbListIter *iter;
	if (!io || !io->maps)
		return NULL;
	ls_foreach_prev (io->maps, iter, map) {
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
	if (!io || !io->maps)
		return false;
	ls_foreach (io->maps, iter, map) {
		if (map->id == id) {
			ls_delete (io->maps, iter);
			if (!io->freed_map_ids) {
				io->freed_map_ids = ls_new ();
				io->freed_map_ids->free = NULL;
			}
			ls_prepend (io->freed_map_ids, (void *)(size_t)id);
			return true;
		}
	}
	return false;
}

//delete all maps with specified fd
R_API int r_io_map_del_for_fd (RIO *io, int fd)
{
	SdbListIter *iter, *ator;
	RIOMap *map;
	int ret = false;
	if (!io || !io->maps)
		return ret;
	for (iter = io->maps->head; iter != NULL; iter = ator) {
		ator = iter->n;
		map = iter->data;
		if (!map) {									//this is done in r_io_map_cleanup too, but preventing some segfaults here too won't hurt
			ls_delete (io->maps, iter);
		} else if (map->fd == fd) {
			ret = true;								//a map with (map->fd == fd) existed/was found and will be deleted now
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
R_API bool r_io_map_priorize (RIO *io, ut32 id)
{
	SdbListIter *iter;
	RIOMap *map;
	if (!io || !io->maps)
		return false;
	ls_foreach (io->maps, iter, map) {
		if (map->id == id) {								//search for iter with the correct map
			if (io->maps->tail == iter)						//check if map is allready at the top
				return true;
			if (iter->p)								//bring iter with correct map to the front
				iter->p->n = iter->n;
			if (iter->n)
				iter->n->p = iter->p;
			if (io->maps->head == iter)
				io->maps->head = iter->n;
			io->maps->tail->n = iter;
			iter->p = io->maps->tail;
			io->maps->tail = iter;
			iter->n = NULL;
			return true;								//TRUE if the map could be priorized
		}
	}
	return false;										//FALSE if not
}

R_API bool r_io_map_priorize_for_fd (RIO *io, int fd)
{
	SdbListIter *iter, *ator;
	SdbList *queue;
	if (!io || !io->maps)
		return false;
	queue = ls_new ();
	r_io_map_cleanup (io);			//we need a clean list for this, or this becomes a segfault-field
	queue->free = io->maps->free = NULL;	//tempory set, to speed up ls_delete a bit
	for (iter = io->maps->head; iter != NULL; iter = ator) {
		ator = iter->n;
		if (((RIOMap *)(iter->data))->fd == fd) {
			ls_prepend (queue, iter->data);
			ls_delete (io->maps, iter);
		}
	}
	while (queue->length)
		ls_append (io->maps, ls_pop (queue));
	ls_free (queue);
	io->maps->free = _map_free;
	return true;
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
		return false;
	if (map->from <= from && from <= map->to)	return true;
	if (map->from <= to && to <= map->to)		return true;
	if (map->from > from && to > map->to)		return true;
	return false;
}

R_API void r_io_map_set_name (RIOMap *map, const char *name)
{
	if (!map || !name)
		return;
	free (map->name);
	map->name = strdup (name);
}

R_API void r_io_map_del_name (RIOMap *map)
{
	if (!map)
		return;
	free (map->name);
	map->name = NULL;
}

//TODO: Kill it with fire
R_API RIOMap *r_io_map_add_next_available(RIO *io, int fd, int flags, ut64 delta, ut64 addr, ut64 size, ut64 load_align)
{
	RIOMap *map;
	SdbListIter *iter;
	ut64 next_addr = addr,
		 end_addr = next_addr + size;
	ls_foreach (io->maps, iter, map) {
		next_addr = R_MAX (next_addr, map->to+(load_align - (map->to % load_align)));
		// XXX - This does not handle when file overflow 0xFFFFFFFF000 -> 0x00000FFF
		// adding the check for the map's fd to see if this removes contention for
		// memory mapping with multiple files.

		if (map->fd == fd && ((map->from <= next_addr && next_addr < map->to) ||
			(map->from <= end_addr  && end_addr < map->to)) ) {
			//return r_io_map_add(io, fd, flags, delta, map->to, size);
			next_addr = map->to + (load_align - (map->to % load_align));
			return r_io_map_add_next_available(io, fd, flags, delta, next_addr, size, load_align);
		} else break;
	}
	return r_io_map_new (io, fd, flags, delta, next_addr, size);
}
