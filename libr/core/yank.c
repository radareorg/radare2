/* radare - LGPL - Copyright 2009-2024 - pancake & dso */

#include <r_core.h>

static ut32 find_next_char(const char *input, char b) {
	ut32 i = 0;
	for (; *input != b; i++, input++) {
		/* nothing */
	}
	return i;
}

static ut32 consume_chars(const char *input, char b) {
	ut32 i = 0;
	for (; *input == b; i++, input++) {
		/* nothing */
	}
	return i;
}

static bool perform_file_yank(RCore *core, ut64 offset, ut64 len, const char *filename) {
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

R_API bool r_core_yank_to(RCore *core, const char *_arg) {
	ut64 len = 0;
	ut64 pos = -1;
	bool res = false;
	char *arg = strdup (r_str_trim_head_ro (_arg));
	char *str = strchr (arg, ' ');
	if (str) {
		str[0] = '\0';
		len = r_num_math (core->num, arg);
		pos = r_num_math (core->num, str + 1);
		str[0] = ' ';
	}
	if (str && pos != -1 && len > 0) {
		if (r_core_yank (core, core->addr, len) == true) {
			res = r_core_yank_paste (core, pos, len);
		}
	}
	free (arg);
	return res;
}

R_API bool r_core_yank_dump(RCore *core, ut64 pos, int format) {
	int i = 0;
	int ybl = core->yank_buf ? r_buf_size (core->yank_buf): 0;
	if (ybl < 1) {
		if (format == 'j') {
			r_cons_println (core->cons, "{}");
		} else {
			R_LOG_ERROR ("No buffer yanked yet");
		}
		return false;
	}
	if (pos >= ybl) {
		R_LOG_ERROR ("Position exceeds buffer length");
		return false;
	}
	switch (format) {
	case '8':
		for (i = pos; i < r_buf_size (core->yank_buf); i++) {
			r_cons_printf (core->cons, "%02x", r_buf_read8_at (core->yank_buf, i));
		}
		r_cons_newline (core->cons);
		break;
	case 'j': {
		PJ *pj = r_core_pj_new (core);
		if (!pj) {
			break;
		}
		pj_o (pj);
		pj_kn (pj, "addr", core->yank_addr);
		RStrBuf *buf = r_strbuf_new ("");
		for (i = pos; i < r_buf_size (core->yank_buf); i++) {
			r_strbuf_appendf (buf, "%02x", r_buf_read8_at (core->yank_buf, i));
		}
		pj_ks (pj, "bytes", r_strbuf_get (buf));
		r_strbuf_free (buf);
		pj_end (pj);
		r_cons_println (core->cons, pj_string (pj));
		pj_free (pj);
		break;
	}
	case '*':
		r_cons_print (core->cons, "'wx ");
		for (i = pos; i < r_buf_size (core->yank_buf); i++) {
			r_cons_printf (core->cons, "%02x", r_buf_read8_at (core->yank_buf, i));
		}
		r_cons_newline (core->cons);
		break;
	default:
		r_cons_printf (core->cons, "0x%08" PFMT64x " %" PFMT64d " ",
				core->yank_addr + pos,
				r_buf_size (core->yank_buf) - pos);
		for (i = pos; i < r_buf_size (core->yank_buf); i++) {
			r_cons_printf (core->cons, "%02x", r_buf_read8_at (core->yank_buf, i));
		}
		r_cons_newline (core->cons);
	}
	return true;
}

R_API bool r_core_yank_hexdump(RCore *core, ut64 pos) {
	const int ybl = r_buf_size (core->yank_buf);
	if (ybl > 0) {
		if (pos < ybl) {
			size_t len = ybl - pos;
			ut8 *buf = R_NEWS (ut8, len);
			if (buf) {
				r_buf_read_at (core->yank_buf, pos, buf, len);
				r_print_hexdump (core->print, pos,
					buf, len, 16, 1, 1);
				free (buf);
				return true;
			}
		} else {
			R_LOG_ERROR ("Position exceeds buffer length");
		}
	} else {
		R_LOG_ERROR ("No buffer yanked yet");
	}
	return false;
}

R_API bool r_core_yank_cat(RCore *core, ut64 pos) {
	int ybl = r_buf_size (core->yank_buf);
	if (ybl > 0) {
		if (pos < ybl) {
			ut64 sz = ybl - pos;
			char *buf = R_NEWS (char, sz);
			if (buf) {
				r_buf_read_at (core->yank_buf, pos, (ut8 *)buf, sz);
				r_cons_write (core->cons, buf, sz);
				r_cons_newline (core->cons);
				free (buf);
				return true;
			}
		}
		R_LOG_ERROR ("Position exceeds buffer length");
	} else {
		r_cons_newline (core->cons);
	}
	return false;
}

R_API bool r_core_yank_cat_string(RCore *core, ut64 pos) {
	R_RETURN_VAL_IF_FAIL (core, false);
	int ybl = r_buf_size (core->yank_buf);
	if (ybl > 0) {
		if (pos < ybl) {
			ut64 sz = ybl - pos;
			char *buf = R_NEWS (char, sz);
			if (!buf) {
				return false;
			}
			r_buf_read_at (core->yank_buf, pos, (ut8 *)buf, sz);
			int len = r_str_nlen (buf, sz);
			r_cons_write (core->cons, buf, len);
			r_cons_newline (core->cons);
			free (buf);
			return true;
		}
	//	R_LOG_ERROR ("Position exceeds buffer length");
	} else {
		r_cons_newline (core->cons);
	}
	return false;
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
	core->yank_buf = NULL;
	core->yank_addr = UT64_MAX;
}

R_API bool r_core_yank_hexpair(RCore *core, const char *input) {
	R_RETURN_VAL_IF_FAIL (core, false);
	if (R_STR_ISEMPTY (input)) {
		return false;
	}
	char *out = strdup (input);
	const int len = r_hex_str2bin (input, (ut8 *)out);
	if (len > 0) {
		r_core_yank_set (core, core->addr, (ut8 *)out, len);
	}
	free (out);
	return true;
}

R_API bool r_core_yank_file_ex(RCore *core, const char *input) {
	R_RETURN_VAL_IF_FAIL (core, false);
	bool res = false;

	if (!input) {
		return res;
	}
	char *inp = strdup (input);
	// get the number of bytes to yank
	ut64 adv = consume_chars (inp, ' ');
	ut64 len = r_num_math (core->num, inp + adv);
	if (len == 0) {
		free (inp);
		R_LOG_ERROR ("Number of bytes read must be > 0");
		return res;
	}
	// get the addr/offset from in the file we want to read
	adv += find_next_char (inp + adv, ' ');
	if (adv == 0) {
		free (inp);
		R_LOG_ERROR ("Address must be specified");
		return res;
	}
	adv++;

	ut64 next = find_next_char (inp + adv, ' ');
	if (next) {
		inp[adv + next] = 0;
	} else {
		R_LOG_ERROR ("File must be specified");
		free (inp);
		return res;
	}
	ut64 addr = r_num_math (core->num, inp + adv);
	adv += next + 1;
	bool b = perform_file_yank (core, addr, len, inp + adv);
	free (inp);
	return b;
}

R_API bool r_core_yank_file_all(RCore *core, const char *input) {
	R_RETURN_VAL_IF_FAIL (core && input, false);
	ut64 adv = consume_chars (input, ' ');
	return perform_file_yank (core, 0, UT64_MAX, input + adv);
}
