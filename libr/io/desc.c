/* radare - LGPL - Copyright 2009-2011 pancake<nopcode.org> */

#include <r_io.h>
// TODO: to be deprecated.. this is slow and boring

R_API void r_io_desc_init(RIO *io) {
	io->desc = r_list_new ();
	io->desc->free = (RListFree)r_io_desc_free;
}

R_API void r_io_desc_fini(RIO *io) {
	r_list_free (io->desc);
}

R_API RIODesc *r_io_desc_new(RIOPlugin *plugin, int fd, const char *name, int flags, int mode, void *data) {
	RIODesc *desc = R_NEW (RIODesc);
	if (!desc) return NULL;
	desc->state = R_IO_DESC_TYPE_OPENED;
	desc->name = strdup (name);
	if (desc->name == NULL) {
		free (desc);
		return NULL;
	}
	desc->plugin = plugin;
	desc->flags = flags;
	if (fd == -1) {
		ut8 *p = &desc->fd;
		desc->fd = ((int) ((size_t) desc) & 0xffffff);
		desc->fd = p[0]^p[1]^p[2]^p[3];
	} else desc->fd = fd;
	desc->data = data;
	return desc;
}

R_API void r_io_desc_free(RIODesc *desc) {
	if (desc->plugin && desc->plugin->close)
		desc->plugin->close (desc);
	free (desc->name);
	free (desc);
}

R_API void r_io_desc_add(RIO *io, RIODesc *desc) {
	r_list_append (io->desc, desc);
}

R_API int r_io_desc_del(struct r_io_t *io, int fd) {
	RListIter *iter;
	RIODesc *d;
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
