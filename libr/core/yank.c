/* radare - LGPL - Copyright 2009-2026 - pancake & dso */

#include <r_core.h>

R_API bool r_core_yank_file(RCore *core, ut64 offset, ut64 len, const char *filename) {
	R_RETURN_VAL_IF_FAIL (core, false);
	if (R_STR_ISEMPTY (filename)) {
		return false;
	}
	const ut64 io_off = core->io->off;
	RIODesc *desc = r_io_desc_open (core->io, filename, R_PERM_R, 0644);
	if (!desc) {
		core->io->off = io_off;
		return false;
	}
	bool res = false;
	const ut64 size = r_io_desc_size (desc);
	if (len == UT64_MAX) {
		len = size;
	}
	if (!len || len > ST32_MAX || offset > size || len > size - offset) {
		R_LOG_ERROR ("Invalid file yank range");
		goto beach;
	}
	ut8 *buf = malloc (len);
	if (buf) {
		if (r_io_desc_read_at (desc, offset, buf, len) == len) {
			res = r_core_yank_set (core, R_CORE_FOREIGN_ADDR, buf, len);
		} else {
			R_LOG_ERROR ("Cannot read file for yank: %s", filename);
		}
		free (buf);
	}
beach:
	r_io_desc_close (desc);
	core->io->off = io_off;
	return res;
}

R_API bool r_core_yank_set(RCore *core, ut64 addr, const ut8 *buf, ut32 len) {
	// free (core->yank_buf);
	if (buf && len) {
		// FIXME: direct access to base should be avoided (use _sparse
		// when you need buffer that starts at given addr)
		r_buf_set_bytes (core->yank_buf, buf, len);
		core->yank_addr = addr;
		return true;
	}
	return false;
}

// Call set and then null terminate the bytes.
R_API bool r_core_yank_set_str(RCore *core, ut64 addr, const char *str, ut32 len) {
	if (r_core_yank_set (core, addr, (ut8 *)str, len)) {
		ut8 zero = 0;
		return r_buf_write_at (core->yank_buf, len - 1, &zero, sizeof (zero)) != -1;
	}
	return false;
}

R_API bool r_core_yank(RCore *core, ut64 addr, int len) {
	ut64 curseek = core->addr;
	if (len < 0) {
		R_LOG_ERROR ("Cannot yank negative bytes");
		return false;
	}
	if (len == 0) {
		len = core->blocksize;
	}
	ut8 *buf = malloc (len);
	if (!buf) {
		return false;
	}
	if (addr != core->addr) {
		r_core_seek (core, addr, true);
	}
	r_io_read_at (core->io, addr, buf, len);
	r_core_yank_set (core, addr, buf, len);
	if (curseek != addr) {
		r_core_seek (core, curseek, true);
	}
	free (buf);
	return true;
}

/* Copy a zero terminated string to the clipboard. Clamp to maxlen or blocksize. */
R_API bool r_core_yank_string(RCore *core, ut64 addr, int maxlen) {
	ut64 curseek = core->addr;
	if (maxlen < 0) {
		R_LOG_ERROR ("Cannot yank negative bytes");
		return false;
	}
	if (addr != core->addr) {
		r_core_seek (core, addr, true);
	}
	/* Ensure space and safe termination for largest possible string allowed */
	ut8 *buf = calloc (1, core->blocksize + 1);
	if (!buf) {
		return false;
	}
	buf[core->blocksize] = 0;
	r_io_read_at (core->io, addr, buf, core->blocksize);
	if (maxlen == 0) {
		// Don't use strnlen, see: https://sourceforge.net/p/mingw/bugs/1912/
		maxlen = r_str_nlen ((const char *) buf, core->blocksize);
	} else if (maxlen > core->blocksize) {
		maxlen = core->blocksize;
	}
	r_core_yank_set (core, addr, buf, maxlen);
	if (curseek != addr) {
		r_core_seek (core, curseek, true);
	}
	free (buf);
	return true;
}

R_API bool r_core_yank_paste(RCore *core, ut64 addr, int len) {
	if (len < 0) {
		return false;
	}
	if (len == 0 || len >= r_buf_size (core->yank_buf)) {
		len = r_buf_size (core->yank_buf);
	}
	ut8 *buf = R_NEWS (ut8, len);
	if (!buf) {
		return false;
	}
	r_buf_read_at (core->yank_buf, 0, buf, len);
	bool written = r_core_write_at (core, addr, buf, len);
	free (buf);
	return written;
}

R_API bool r_core_yank_hud_file(RCore *core, const char *input) {
	R_RETURN_VAL_IF_FAIL (core, false);
	if (R_STR_ISEMPTY (input)) {
		return false;
	}
	char *buf = r_cons_hud_file (core->cons, r_str_trim_head_ro (input + 1));
	ut32 len = buf? strlen ((const char *) buf) + 1: 0;
	bool res = r_core_yank_set_str (core, R_CORE_FOREIGN_ADDR, buf, len);
	free (buf);
	return res;
}

R_API bool r_core_yank_hud_path(RCore *core, const char *input, int dir) {
	R_RETURN_VAL_IF_FAIL (core, false);
	char *buf = r_cons_hud_path (core->cons, r_str_trim_head_ro (input), dir);
	ut32 len = buf? strlen ((const char *) buf) + 1: 0;
	int res = r_core_yank_set_str (core, R_CORE_FOREIGN_ADDR, buf, len);
	free (buf);
	return res;
}

R_API void r_core_yank_unset(RCore *core) {
	R_RETURN_IF_FAIL (core);
	r_unref (core->yank_buf);
	core->yank_buf = r_buf_new ();
	core->yank_addr = UT64_MAX;
}
