/* radare - LGPL - Copyright 2009-2013 - pancake */

#include <r_io.h>
// TODO: to be deprecated.. this is slow and boring

R_API void r_io_desc_init(RIO *io) {
	io->desc = r_list_new ();
	io->desc->free = (RListFree)r_io_desc_free;
}

R_API void r_io_desc_fini(RIO *io) {
	r_list_free (io->desc);
}

R_API ut64 r_io_desc_size(RIO *io, RIODesc *desc){
	RIODesc *old = NULL;
    	ut64 sz = -1;
	
	if (desc && io->fd != desc){
		old = io->fd;
		r_io_set_fd(io, desc);
	}
        
	if (desc) sz = r_io_size(io);
	
	if(old){
		r_io_set_fd(io, old);
	}
	return sz;
}


R_API RIODesc *r_io_desc_new(RIOPlugin *plugin, int fd, const char *name, int flags, int mode, void *data) {
	int i;
	RIODesc *desc = R_NEW (RIODesc);
	if (!desc) return NULL;
	if (fd==-1) eprintf ("WARNING: r_io_desc_new with fd = -1\n");
	desc->state = R_IO_DESC_TYPE_OPENED;
	desc->name = strdup (name);
	if (desc->name == NULL) {
		free (desc);
		return NULL;
	}
	desc->plugin = plugin;
	desc->flags = flags;
	if (fd == -2) {
		ut8 *p = (ut8 *)&(desc->fd);
		desc->fd = ((int) ((size_t) desc) & 0xffffff);
		desc->fd = p[0];
		for (i=1; i<sizeof (desc->fd); i++)
			desc->fd ^= p[i]; 
	} else desc->fd = fd;
	desc->data = data;
	return desc;
}

R_API void r_io_desc_free(RIODesc *desc) {
	if (!desc) return;
	if (desc->plugin && desc->plugin->close)
		desc->plugin->close (desc);
	if (desc->name) {
		free (desc->name);
		desc->name = NULL;
	}
//	free (desc); double free orw at
}

R_API int r_io_desc_add(RIO *io, RIODesc *desc) {
	RIODesc *foo = r_io_desc_get (io, desc->fd);
	if (!foo)
		r_list_append (io->desc, desc);
	return foo? 1: 0;
}

R_API int r_io_desc_del(RIO *io, int fd) {
	RListIter *iter;
	RIODesc *d;
	/* No _safe loop necessary because we return immediately after the delete. */
	r_list_foreach (io->desc, iter, d) {
		if (d->fd == fd) {
			r_list_delete (io->desc, iter);
			return R_TRUE;
		}
	}
	return R_FALSE;
}

R_API RIODesc *r_io_desc_get(RIO *io, int fd) {
	RListIter *iter;
	RIODesc *d;
	r_list_foreach (io->desc, iter, d) {
		if (d->fd == fd)
			return d;
	}
	return NULL;
}

#if 0
// XXX: This must be deprecated in order to promote the cast of dataptr to ut32
R_API int r_io_desc_generate(struct r_io_t *io) {
	int fd;
	do fd = 0xf000 + rand ()%0xfff;
	while (r_io_desc_get(io, fd));
	return fd;
}
#endif
