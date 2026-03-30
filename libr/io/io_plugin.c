/* radare - LGPL - Copyright 2008-2026 - pancake */

#include <r_io.h>
#include "config.h"

// reset and reload plugins (used by r_io_close_all)
R_IPI bool r_io_plugins_reset(RIO *io) {
	R_RETURN_VAL_IF_FAIL (io && io->libstore, false);
	r_list_free (io->libstore->plugins);
	io->libstore->plugins = r_list_newf (io->libstore->free);
	io->libstore->loaded = false;
	if (r_lib_defaults ()) {
		r_libstore_load (io->libstore);
	}
	return true;
}

R_API RIOPlugin *r_io_plugin_resolve(RIO *io, const char *filename, bool many) {
	// TODO: optimization
	if (strstr (filename, "://")) {
		RIOPlugin *ret;
		RListIter *iter;
		r_list_foreach (io->libstore->plugins, iter, ret) {
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
