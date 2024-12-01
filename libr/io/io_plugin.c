/* radare - LGPL - Copyright 2008-2024 - pancake */

#include <r_io.h>
#include "config.h"

static RIOPlugin *io_static_plugins[] = {
	R_IO_STATIC_PLUGINS
};

R_API bool r_io_plugin_add(RIO *io, RIOPlugin *plugin) {
	R_RETURN_VAL_IF_FAIL (io && plugin && io->plugins, false);
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
	int i;
	if (!io) {
		return false;
	}
	io->plugins = ls_newf (NULL); // fine to use NULL here?
	for (i = 0; io_static_plugins[i]; i++) {
		if (!io_static_plugins[i]->meta.name) {
			continue;
		}
		r_io_plugin_add (io, io_static_plugins[i]);
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
