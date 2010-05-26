/* radare - LGPL - Copyright 2009-2010 pancake<nopcode.org> */

#include <r_io.h>

R_API int r_io_desc_init(struct r_io_t *io) {
	INIT_LIST_HEAD (&io->desc);
	return R_TRUE;
}

R_API int r_io_desc_add(struct r_io_t *io, int fd, const char *file, int flags, struct r_io_plugin_t *plugin) {
	RIODesc *desc = R_NEW (RIODesc);
	if (desc == NULL)
		return R_FALSE;
	strncpy (desc->name, file, sizeof (desc->name));
	desc->flags = flags;
	desc->fd = fd;
	desc->plugin = plugin;
	list_add_tail (&(desc->list), &(io->desc));
	return R_TRUE;
}

R_API int r_io_desc_del(struct r_io_t *io, int fd) {
	int ret = R_FALSE;
	struct list_head *pos;
	list_for_each_prev (pos, &io->desc) {
		struct r_io_desc_t *d = list_entry (pos, struct r_io_desc_t, list);
		if (d->fd == fd) {
			list_del ((&d->list));
			ret = R_TRUE;
			break;
		}
	}
	return ret;
}

R_API struct r_io_desc_t *r_io_desc_get(RIO *io, int fd) {
	struct list_head *pos;
	list_for_each_prev (pos, &io->desc) {
		RIODesc *d = list_entry (pos, RIODesc, list);
		if (d->fd == fd)
			return d;
	}
	return NULL;
}

R_API int r_io_desc_generate(struct r_io_t *io) {
	int fd;
	do fd = 0xf000 + rand ()%0xfff;
	while (r_io_desc_get(io, fd));
	return fd;
}
