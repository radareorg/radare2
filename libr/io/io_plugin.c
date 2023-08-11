/* radare - LGPL - Copyright 2008-2022 - pancake */

#include <r_io.h>
#include "config.h"

static RIOPlugin *io_static_plugins[] = {
	R_IO_STATIC_PLUGINS
};

R_API bool r_io_plugin_add(RIO *io, RIOPlugin *plugin) {
	r_return_val_if_fail (io && plugin && io->plugins, false);
	if (!plugin->meta.name) {
		return false;
	}
	ls_append (io->plugins, plugin);
	return true;
}

R_API bool r_io_plugin_remove(RIO *io, RIOPlugin *plugin) {
	// XXX TODO
	return true;
}

R_API bool r_io_plugin_init(RIO *io) {
	RIOPlugin *static_plugin;
	int i;
	if (!io) {
		return false;
	}
	io->plugins = ls_newf (free);
	for (i = 0; io_static_plugins[i]; i++) {
		if (!io_static_plugins[i]->meta.name) {
			continue;
		}
		static_plugin = R_NEW0 (RIOPlugin);
		if (!static_plugin) {
			return false;
		}
		memcpy (static_plugin, io_static_plugins[i], sizeof (RIOPlugin));
		if (!r_io_plugin_add (io, static_plugin)) {
			free (static_plugin);
			return false;
		}
	}
	return true;
}

R_API RIOPlugin *r_io_plugin_resolve(RIO *io, const char *filename, bool many) {
	// TODO: optimization
	if (strstr (filename, "://")) {
		RIOPlugin *ret;
		SdbListIter *iter;
		ls_foreach (io->plugins, iter, ret) {
			if (!ret || !ret->check) {
				continue;
			}
			if (ret->check (io, filename, many)) {
				return ret;
			}
		}
	}
	return &r_io_plugin_default;
}

R_API RIOPlugin *r_io_plugin_byname(RIO *io, const char *name) {
	SdbListIter *iter;
	RIOPlugin *iop;
	ls_foreach (io->plugins, iter, iop) {
		if (!strcmp (name, iop->meta.name)) {
			return iop;
		}
	}
	return NULL;
}

R_API int r_io_plugin_list(RIO *io) {
	RIOPlugin *plugin;
	SdbListIter *iter;
	char str[4];
	int n = 0;

	ls_foreach (io->plugins, iter, plugin) {
		str[0] = 'r';
		str[1] = plugin->write ? 'w' : '_';
		str[2] = plugin->isdbg ? 'd' : '_';
		str[3] = 0;
		io->cb_printf ("%s  %-8s %-6s %s.", str,
			r_str_get (plugin->meta.name), r_str_get (plugin->meta.license), r_str_get (plugin->meta.desc));
		if (plugin->uris) {
			io->cb_printf (" %s", plugin->uris);
		}
		io->cb_printf ("\n");
		n++;
	}
	return n;
}

R_API int r_io_plugin_list_json(RIO *io) {
	RIOPlugin *plugin;
	SdbListIter *iter;
	PJ *pj = pj_new ();
	if (!pj) {
		return 0;
	}

	char str[4];
	int n = 0;
	pj_a (pj);
	ls_foreach (io->plugins, iter, plugin) {
		str[0] = 'r';
		str[1] = plugin->write ? 'w' : '_';
		str[2] = plugin->isdbg ? 'd' : '_';
		str[3] = 0;

		pj_o (pj);
		pj_ks (pj, "permissions", str);
		if (plugin->meta.name) {
			pj_ks (pj, "name", plugin->meta.name);
		}
		if (plugin->meta.desc) {
			pj_ks (pj, "description", plugin->meta.desc);
		}
		if (plugin->meta.license) {
			pj_ks (pj, "license", plugin->meta.license);
		}
		if (plugin->uris) {
			char *uri;
			char *uris = strdup (plugin->uris);
			RList *plist = r_str_split_list (uris, ",",  0);
			RListIter *piter;
			pj_k (pj, "uris");
			pj_a (pj);
			r_list_foreach (plist, piter, uri) {
				pj_s (pj, uri);
			}
			pj_end (pj);
			r_list_free (plist);
			free (uris);
		}
		if (plugin->meta.version) {
			pj_ks (pj, "version", plugin->meta.version);
		}
		if (plugin->meta.author) {
			pj_ks (pj, "author", plugin->meta.author);
		}
		pj_end (pj);
		n++;
	}
	pj_end (pj);
	io->cb_printf ("%s", pj_string (pj));
	pj_free (pj);
	return n;
}

R_API int r_io_plugin_read(RIODesc *desc, ut8 *buf, int len) {
	if (!buf || !desc || !desc->plugin || len < 1 || !(desc->perm & R_PERM_R)) {
		return 0;
	}
	if (!desc->plugin->read) {
		return -1;
	}
	return desc->plugin->read (desc->io, desc, buf, len);
}

R_API int r_io_plugin_write(RIODesc *desc, const ut8 *buf, int len) {
	if (!buf || !desc || !desc->plugin || len < 1 || !(desc->perm & R_PERM_W)) {
		return 0;
	}
	if (!desc->plugin->write) {
		return -1;
	}
	const ut64 cur_addr = r_io_desc_seek (desc, 0LL, R_IO_SEEK_CUR);
	int ret = desc->plugin->write (desc->io, desc, buf, len);
	REventIOWrite iow = { cur_addr, buf, len };
	r_event_send (desc->io->event, R_EVENT_IO_WRITE, &iow);
	return ret;
}

R_API int r_io_plugin_read_at(RIODesc *desc, ut64 addr, ut8 *buf, int len) {
	if (r_io_desc_is_chardevice (desc) || (r_io_desc_seek (desc, addr, R_IO_SEEK_SET) == addr)) {
		return r_io_plugin_read (desc, buf, len);
	}
	return 0;
}

R_API int r_io_plugin_write_at(RIODesc *desc, ut64 addr, const ut8 *buf, int len) {
	if (r_io_desc_is_chardevice (desc) || r_io_desc_seek (desc, addr, R_IO_SEEK_SET)  == addr) {
		return r_io_plugin_write (desc, buf, len);
	}
	return 0;
}
