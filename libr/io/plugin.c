/* radare - LGPL - Copyright 2008-2014 - pancake */

/* TODO: write li->fds setter/getter helpers */
// TODO: return true/false everywhere,, not -1 or 0
// TODO: use RList here

#include "r_io.h"
#include "../config.h"
#include "list.h"
#include <stdio.h>

volatile static RIOPlugin *DEFAULT = NULL;
static RIOPlugin *io_static_plugins[] =
	{ R_IO_STATIC_PLUGINS };


R_API int r_io_plugin_add(RIO *io, RIOPlugin *plugin) {
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
		// memory leak here: static_plugin never freed
		memcpy (static_plugin, io_static_plugins[i], sizeof (RIOPlugin));
		if (!strncmp (static_plugin->name, "default", 7)) {
			if (DEFAULT) free ((void*)DEFAULT);
			DEFAULT = static_plugin;
			continue;
		}
		r_io_plugin_add (io, static_plugin);
	}
	return R_TRUE;
}

R_API RIOPlugin *r_io_plugin_get_default(RIO *io, const char *filename, ut8 many) {
	if (!DEFAULT ||
		!DEFAULT->plugin_open ||
		!DEFAULT->plugin_open (io, filename, many) ) return NULL;
	return (RIOPlugin*) DEFAULT;
}

R_API RIOPlugin *r_io_plugin_resolve(RIO *io, const char *filename, ut8 many) {
	struct list_head *pos = NULL;
	list_for_each_prev (pos, &io->io_list) {
		struct r_io_list_t *il = list_entry (pos, struct r_io_list_t, list);
		if (il->plugin == NULL)
			continue;
		if (il->plugin->plugin_open == NULL)
			continue;
		if (il->plugin->plugin_open (io, filename, many))
			return il->plugin;
	}
	return NULL;
}

R_API int r_io_plugin_open(RIO *io, int fd, RIOPlugin *plugin) {
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
	return R_FALSE;
}

R_API int r_io_plugin_close(RIO *io, int fd, RIOPlugin *plugin) {
	return R_FALSE;
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
