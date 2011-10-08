/* radare - LGPL - Copyright 2008-2010 pancake<nopcode.org> */

/* TODO: write li->fds setter/getter helpers */
// TODO: return true/false everywhere,, not -1 or 0

#include "r_io.h"
#include "../config.h"
#include "list.h"
#include <stdio.h>

static struct r_io_plugin_t *io_static_plugins[] = 
	{ R_IO_STATIC_PLUGINS };

R_API int r_io_plugin_add(RIO *io, struct r_io_plugin_t *plugin) {
	struct r_io_list_t *li;
	if (!plugin || !plugin->name)
		return R_FALSE;
	li = R_NEW (struct r_io_list_t);
	if (li == NULL)
		return R_FALSE;
	li->plugin = plugin;
	list_add_tail (&(li->list), &(io->io_list));
	return R_TRUE;
}

R_API int r_io_plugin_init(RIO *io) {
	RIOPlugin *static_plugin;
	int i;

	INIT_LIST_HEAD (&io->io_list);
	for (i=0; io_static_plugins[i]; i++) {
		if (!io_static_plugins[i]->name)
			continue;
		static_plugin = R_NEW (RIOPlugin);
		memcpy (static_plugin, io_static_plugins[i], sizeof (RIOPlugin));
		r_io_plugin_add (io, static_plugin);
	}
	return R_TRUE;
}

R_API struct r_io_plugin_t *r_io_plugin_resolve(RIO *io, const char *filename) {
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

/*
DEPRECATED
R_API struct r_io_plugin_t *r_io_plugin_resolve_fd(RIO *io, int fd) {
	int i;
	return NULL;
}
*/

R_API int r_io_plugin_open(RIO *io, int fd, struct r_io_plugin_t *plugin) {
#if 0
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
#endif
	return 0;
}

R_API int r_io_plugin_close(RIO *io, int fd, struct r_io_plugin_t *plugin) {
	return 0;
}

// TODO: must return an r_iter ator
R_API int r_io_plugin_list(RIO *io) {
	int n = 0;
	struct list_head *pos;
	io->printf ("IO plugins:\n");
	list_for_each_prev (pos, &io->io_list) {
		struct r_io_list_t *il = list_entry (pos, struct r_io_list_t, list);
		io->printf (" - %s\n", il->plugin->name);
		n++;
	}
	return n;
}

R_API int r_io_plugin_generate(RIO *io) {
	//TODO
	return -1;
}
