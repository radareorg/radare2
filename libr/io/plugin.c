/* radare - LGPL - Copyright 2008-2009 pancake<nopcode.org> */

/* TODO: write li->fds setter/getter helpers */

#include "r_io.h"
#include "../config.h"
#include "list.h"
#include <stdio.h>

static struct r_io_plugin_t *io_static_plugins[] = 
	{ R_IO_STATIC_PLUGINS };

R_API int r_io_plugin_add(struct r_io_t *io, struct r_io_plugin_t *plugin) {
	int i;
	struct r_io_list_t *li;
	if (plugin == NULL)
		return R_FALSE;
	li = R_NEW(struct r_io_list_t);
	if (li == NULL)
		return R_FALSE;
	li->plugin = plugin;
	for(i=0;i<R_IO_NFDS;i++)
		li->plugin->fds[i] = -1;
	list_add_tail(&(li->list), &(io->io_list));
	return R_TRUE;
}

R_API int r_io_plugin_init(struct r_io_t *io) {
	RIOPlugin *static_plugin;
	int i;

	INIT_LIST_HEAD(&io->io_list);
	for (i=0;io_static_plugins[i];i++) {
		static_plugin = R_NEW (RIOPlugin);
		memcpy (static_plugin, io_static_plugins[i], sizeof (RIOPlugin));
		r_io_plugin_add (io, static_plugin);
	}
	return R_TRUE;
}

R_API struct r_io_plugin_t *r_io_plugin_resolve(struct r_io_t *io, const char *filename) {
	struct list_head *pos;
	list_for_each_prev(pos, &io->io_list) {
		struct r_io_list_t *il = list_entry(pos, struct r_io_list_t, list);
		if (il->plugin == NULL)
			continue;
		if (il->plugin->plugin_open == NULL)
			continue;
		if (il->plugin->plugin_open(io, filename))
			return il->plugin;
	}
	return NULL;
}

R_API struct r_io_plugin_t *r_io_plugin_resolve_fd(struct r_io_t *io, int fd) {
	int i;
	struct list_head *pos;
	list_for_each_prev(pos, &io->io_list) {
		struct r_io_list_t *il = list_entry(pos, struct r_io_list_t, list);
		for(i=0;i<R_IO_NFDS;i++) {
			if (il->plugin->fds[i] == fd)
				return il->plugin;
		}
	}
	return NULL;
}

R_API int r_io_plugin_open(struct r_io_t *io, int fd, struct r_io_plugin_t *plugin) {
	int i=0;
	struct list_head *pos;
	list_for_each_prev(pos, &io->io_list) {
		struct r_io_list_t *il = list_entry(pos, struct r_io_list_t, list);
		if (plugin == il->plugin) {
			for(i=0;i<R_IO_NFDS;i++) {
				if (il->plugin->fds[i] == -1) {
					il->plugin->fds[i] = fd;
					return 0;
				}
			}
			return -1;
		}
	}
	return -1;
}

R_API int r_io_plugin_close(struct r_io_t *io, int fd, struct r_io_plugin_t *plugin) {
	int i=0;
	struct list_head *pos;
	list_for_each_prev(pos, &io->io_list) {
		struct r_io_list_t *il = list_entry(pos, struct r_io_list_t, list);
		if (plugin == il->plugin) {
			for(i=0;i<R_IO_NFDS;i++) {
				if (il->plugin->fds[i] == fd) {
					il->plugin->fds[i] = -1;
					return 0;
				}
			}
			return -1;
		}
	}
	return -1;
}

// TODO: must return an r_iter ator
R_API int r_io_plugin_list(struct r_io_t *io) {
	int n = 0;
	struct list_head *pos;
	io->printf ("IO plugins:\n");
	list_for_each_prev(pos, &io->io_list) {
		struct r_io_list_t *il = list_entry(pos, struct r_io_list_t, list);
		io->printf(" - %s\n", il->plugin->name);
		n++;
	}
	return n;
}

R_API int r_io_plugin_generate(struct r_io_t *io) {
	//TODO
	return -1;
}
