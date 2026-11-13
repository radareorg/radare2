/* radare - LGPL - Copyright 2009-2026 - pancake & dso */

#include <r_core.h>

R_API bool r_core_yank_set(RCore *core, ut64 addr, const ut8 *buf, ut32 len) {
	R_RETURN_VAL_IF_FAIL (core && (buf || !len), false);
	if (!len || !r_buf_set_bytes (core->yank_buf, buf, len)) {
		return false;
	}
	core->yank_addr = addr;
	return true;
}

R_API bool r_core_yank(RCore *core, ut64 addr, ut32 len) {
	R_RETURN_VAL_IF_FAIL (core, false);
	ut8 *buf = len? malloc (len): NULL;
	if (buf) {
		r_io_read_at (core->io, addr, buf, len);
	}
	const bool ok = buf && r_core_yank_set (core, addr, buf, len);
	free (buf);
	return ok;
}

// Writes the first len clipboard bytes at addr, or all of them when len is 0
R_API bool r_core_yank_paste(RCore *core, ut64 addr, ut32 len) {
	R_RETURN_VAL_IF_FAIL (core, false);
	const ut64 size = r_buf_size (core->yank_buf);
	if (!len || len > size) {
		len = size;
	}
	ut8 *buf = len? malloc (len): NULL;
	const bool ok = buf && r_buf_read_at (core->yank_buf, 0, buf, len) == len
		&& r_core_write_at (core, addr, buf, len);
	free (buf);
	return ok;
}
