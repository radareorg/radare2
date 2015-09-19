/* radare - LGPL - Copyright 2008-2014 - pancake */

/* TODO: write li->fds setter/getter helpers */
// TODO: return true/false everywhere,, not -1 or 0

#include "r_io.h"
#include "../config.h"
#include <stdio.h>
#include <sdb.h>

volatile static RIOPlugin *DEFAULT = NULL;
static RIOPlugin *io_static_plugins[] =
	{ R_IO_STATIC_PLUGINS };


R_API int r_io_plugin_add(RIO *io, RIOPlugin *plugin) {
	if (!io || !io->plugins || !plugin)
		return false;
	ls_append (io->plugins, plugin);
	return true;
}

R_API int r_io_plugin_init(RIO *io) {
	RIOPlugin *static_plugin;
	int i;
	if (!io)
		return false;
	io->plugins = r_list_new ();
	io->plugins->free = free;

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
	return true;
}

R_API RIOPlugin *r_io_plugin_get_default(RIO *io, const char *filename, ut8 many) {
	if (!DEFAULT ||
		!DEFAULT->plugin_open ||
		!DEFAULT->plugin_open (io, filename, many) ) return NULL;
	return (RIOPlugin*) DEFAULT;
}

R_API RIOPlugin *r_io_plugin_resolve(RIO *io, const char *filename, ut8 many) {
	SdbListIter *iter;
	RIOPlugin *ret;
	ls_foreach (io->plugins, iter, ret) {
		if (ret == NULL)
			continue;
		if (ret->plugin_open == NULL)
			continue;
		if (ret->plugin_open (io, filename, many))
			return ret;
	}
	return NULL;
}

R_API int r_io_plugin_open(RIO *io, int fd, RIOPlugin *plugin) {
	return false;
}

R_API int r_io_plugin_close(RIO *io, int fd, RIOPlugin *plugin) {
	return false;
}

R_API int r_io_plugin_list(RIO *io) {
	int n = 0;
	SdbListIter *iter;
	RIOPlugin *plugin;
	if (io) {
		if (io->cb_printf)
			io->cb_printf ("IO plugins:\n");
	} else	return 0;
	if (!io->plugins)
		return 0;
	r_list_foreach (io->plugins, iter, plugin)
		if (plugin) {
			if (plugin->name)
				io->cb_printf (" - %s\n", plugin->name);
			n++;
		}
	}
	return n;
}

R_API int r_io_plugin_generate(RIO *io) {
	//TODO
	return -1;
}
