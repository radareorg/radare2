/* radare - LGPL - Copyright 2008-2016 - pancake */

/* TODO: write li->fds setter/getter helpers */
// TODO: return true/false everywhere,, not -1 or 0

#include "r_io.h"
#include "../config.h"
#include <stdio.h>
#include <r_db.h>

static RIOPlugin *io_static_plugins[] = {
	R_IO_STATIC_PLUGINS
};

R_API int r_io_plugin_add(RIO *io, RIOPlugin *plugin) {
	if (!io || !io->plugins || !plugin)
		return false;
	ls_append (io->plugins, plugin);
	return true;
}

R_API bool r_io_plugin_init(RIO *io) {
	RIOPlugin *static_plugin;
	int i;
	if (!io)
		return false;
	io->plugins = ls_new ();
	io->plugins->free = free;

	for (i=0; io_static_plugins[i]; i++) {
		if (!io_static_plugins[i]->name)
			continue;
		}
		static_plugin = R_NEW (RIOPlugin);
		if (!static_plugin) {
			return false;
		}
		memcpy (static_plugin, io_static_plugins[i], sizeof (RIOPlugin));
		if (!strcmp (static_plugin->name, "default")) {
			io->plugin_default = static_plugin;
		} else {
			r_io_plugin_add (io, static_plugin);
		}
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
	return io->plugin_default;
}

R_API int r_io_plugin_open(RIO *io, int fd, RIOPlugin *plugin) {
	return false;
}

R_API RIOPlugin *r_io_plugin_byname(RIO *io, const char *name) {
	RListIter *iter;
	RIOPlugin *iop;
	r_list_foreach (io->plugins, iter, iop) {
		if (!strcmp (name, iop->name)) {
			return iop;
		}
	}
	return io->plugin_default;
}

R_API int r_io_plugin_list(RIO *io) {
	RIOPlugin *plugin;
	RListIter *iter;
	char str[4];
	int n = 0;
	SdbListIter *iter;
	RIOPlugin *plugin;
	if (io) {
		if (io->cb_printf)
			io->cb_printf ("IO plugins:\n");
	} else	return 0;
	if (!io->plugins)
		return 0;
	ls_foreach (io->plugins, iter, plugin)
		if (plugin) {
			if (plugin->name)
				io->cb_printf (" - %s\n", plugin->name);
			n++;
		}
	}
	return n;
}
