/* radare - LGPL - Copyright 2007-2009 pancake<nopcode.org> */

#include <r_io.h>

#define cons_printf printf
#define cons_newline() printf("\n");

#if 0
* TODO:
* - make path of indirections shortr (io->undo.foo is slow) */
* - Handle changes in write and seeks
* - Per-fd history log
#endif

R_API int r_io_undo_init(struct r_io_t *io)
{
	io->undo.w_init = 0;
	io->undo.w_lock = 0;
	io->undo.idx = 0;
	io->undo.limit = 0;
	io->undo.enable = 0;
	return R_TRUE;
}

R_API void r_io_undo_enable(struct r_io_t *io, int set)
{
	io->undo.enable = set;
}

R_API ut64 r_io_undo_get_last_seek(struct r_io_t *io)
{
	return (io->undo.idx)?
		io->undo.seek[io->undo.idx-2] : io->seek;
}

R_API void r_io_undo_seek(struct r_io_t *io)
{
	if (--io->undo.idx<0)
		io->undo.idx = 0;
	else io->seek = io->undo.seek[io->undo.idx-1];
}

R_API void r_io_undo_redo(struct r_io_t *io)
{
	if (io->undo.idx<io->undo.limit) {
		io->undo.idx += 2;
		r_io_undo_seek(io);
	}
}

R_API void r_io_undo_push(struct r_io_t *io)
{
	int i;

	if (io->undo.seek[io->undo.idx-1] == io->seek)
		return;

	io->undo.seek[io->undo.idx] = io->seek;
	if (io->undo.idx==R_IO_UNDOS-1) {
		for(i=1;i<R_IO_UNDOS;i++)
			io->undo.seek[i-1] = io->undo.seek[i];
	} else io->undo.idx++;

	if (io->undo.limit<io->undo.idx)
		io->undo.limit = io->undo.idx;
}

R_API void r_io_undo_reset(struct r_io_t *io)
{
	io->undo.idx = 0;
}

R_API void r_io_undo_list(struct r_io_t *io)
{
	int i;
	if (io->undo.idx>0) {
		cons_printf("f undo_idx @ %d\n", io->undo.idx);
		for(i=io->undo.idx-1;i!=0;i--)
			cons_printf("f undo_%d @ 0x%llx\n",
				io->undo.idx-1-i, io->undo.seek[i-1]);
	} else eprintf("-no seeks done-\n");
}

R_API void r_io_undo_write_new(struct r_io_t *io, ut64 off, const ut8 *data, int len)
{
	struct r_io_undo_w_t *uw = MALLOC_STRUCT(struct r_io_undo_w_t);

	if (io->undo.w_lock)
		return;

	if (!io->undo.w_init) {
		io->undo.w_init = 1;
		INIT_LIST_HEAD(&(io->undo.w_list));
	}

	/* undo changes */
	uw->set = R_TRUE;
	uw->off = off;
	uw->len = len;
	uw->n = (ut8*) malloc(len);
	memcpy(uw->n, data, len);
	uw->o = (ut8*) malloc(len);
	r_io_read_at(io, off, uw->o, len);
	list_add_tail(&(uw->list), &(io->undo.w_list));
}

R_API void r_io_undo_write_clear(struct r_io_t *io)
{
	// XXX memory leak
	INIT_LIST_HEAD(&(io->undo.w_list));
}

// rename to r_io_undo_length
R_API int r_io_undo_write_size(struct r_io_t *io)
{
	struct list_head *p;
	int i = 0;

	if (io->undo.w_init)
	list_for_each_prev(p, &(io->undo.w_list)) {
		i++;
	}
	return i;
}

// TODO: Deprecate or so? iterators must be language-wide, but helpers are useful
R_API void r_io_undo_write_list(struct r_io_t *io)
{
#define BW 8 /* byte wrap */
	struct list_head *p;
	int i = 0, j, len;

	if (io->undo.w_init)
	list_for_each_prev(p, &(io->undo.w_list)) {
		struct r_io_undo_w_t *u = list_entry(p, struct r_io_undo_w_t, list);
		cons_printf("%02d %c %d %08llx: ", i, u->set?'+':'-', u->len, u->off);
		len = (u->len>BW)?BW:u->len;
		for(j=0;j<len;j++) cons_printf("%02x ", u->o[j]);
		if (len == BW) cons_printf(".. ");
		cons_printf ("=> ");
		for(j=0;j<len;j++) cons_printf("%02x ", u->n[j]);
		if (len == BW) cons_printf(".. ");
		cons_newline();
		i++;
	}
}

R_API int r_io_undo_write_set_t(struct r_io_t *io, struct r_io_undo_w_t *u, int set) 
{
	io->undo.w_lock = 1;
	if (set) {
		r_io_write_at(io, u->off, u->n, u->len);
		u->set = R_TRUE;
	} else {
		r_io_write_at(io, u->off, u->o, u->len);
		u->set = R_FALSE;
	}
	io->undo.w_lock = 0;
	return 0;
}

R_API void r_io_undo_write_set_all(struct r_io_t *io, int set)
{
	struct list_head *p;

	if (io->undo.w_init)
	list_for_each_prev(p, &(io->undo.w_list)) {
		struct r_io_undo_w_t *u = list_entry(p, struct r_io_undo_w_t, list);
		r_io_undo_write_set_t(io, u, set); //UNDO_WRITE_UNSET);
		eprintf("%s 0x%08llx\n", set?"redo":"undo", u->off);
	}
}

/* sets or unsets the writes done */
/* if ( set == 0 ) unset(n) */
R_API int r_io_undo_write_set(struct r_io_t *io, int n, int set) 
{
	struct r_io_undo_w_t *u = NULL;
	struct list_head *p;
	int i = 0;
	if (io->undo.w_init) {
		list_for_each_prev(p, &(io->undo.w_list)) {
			if (i++ == n) {
				u = list_entry(p, struct r_io_undo_w_t, list);
				break;
			}
		}

		if (u) r_io_undo_write_set_t(io, u, set);
		else eprintf("invalid undo-write index\n");
	} else eprintf("no writes done\n");
	return 0;
}
