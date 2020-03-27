/* radare - LGPL - Copyright 2009-2019 - pancake & dso */

#include "r_core.h"
#include "r_util.h"
#include "r_io.h"

/*
 * perform_mapped_file_yank will map in a file and yank from offset the number of len bytes from
 * filename.  if the len is -1, the all the bytes are mapped into the yank buffer.
 */
static int perform_mapped_file_yank(RCore *core, ut64 offset, ut64 len, const char *filename);
static ut32 find_next_char(const char *input, char b);
static ut32 consume_chars(const char *input, char b);

static ut32 find_next_char(const char *input, char b) {
	ut32 i = 0;
	if (!input) {
		return i;
	}
	for (; *input != b; i++, input++) {
		/* nothing */
	}
	return i;
}

static ut32 consume_chars(const char *input, char b) {
	ut32 i = 0;
	if (!input) {
		return i;
	}
	for (; *input == b; i++, input++) {
		/* nothing */
	}
	return i;
}

static int perform_mapped_file_yank(RCore *core, ut64 offset, ut64 len, const char *filename) {
	// grab the current file descriptor, so we can reset core and io state
	// after our io op is done
	RIODesc *yankdesc = NULL;
	ut64 fd = core->file? core->file->fd: -1, yank_file_sz = 0,
	     loadaddr = 0, addr = offset;
	int res = false;

	if (filename && *filename) {
		ut64 load_align = r_config_get_i (core->config, "file.loadalign");
		RIOMap *map = NULL;
		yankdesc = r_io_open_nomap (core->io, filename, R_PERM_R, 0644);
		// map the file in for IO operations.
		if (yankdesc && load_align) {
			yank_file_sz = r_io_size (core->io);
			ut64 addr = r_io_map_next_available (core->io, 0, yank_file_sz, load_align);
        		map = r_io_map_new (core->io, yankdesc->fd, R_PERM_R, 0, addr, yank_file_sz);
			loadaddr = map? map->itv.addr: -1;
			if (yankdesc && map && loadaddr != -1) {
				// ***NOTE*** this is important, we need to
				// address the file at its physical address!
				addr += loadaddr;
			} else if (yankdesc) {
				eprintf ("Unable to map the opened file: %s", filename);
				r_io_desc_close (yankdesc);
				yankdesc = NULL;
			} else {
				eprintf ("Unable to open the file: %s", filename);
			}
		}
	}

	// if len is -1 then we yank in everything
	if (len == -1) {
		len = yank_file_sz;
	}

	// this wont happen if the file failed to open or the file failed to
	// map into the IO layer
	if (yankdesc) {
		ut64 res = r_io_seek (core->io, addr, R_IO_SEEK_SET);
		ut64 actual_len = len <= yank_file_sz? len: 0;
		ut8 *buf = NULL;
		if (actual_len > 0 && res == addr) {
			buf = malloc (actual_len);
			if (!r_io_read_at (core->io, addr, buf, actual_len)) {
				actual_len = 0;
			}
			r_core_yank_set (core, R_CORE_FOREIGN_ADDR, buf, len);
			res = true;
		} else if (res != addr) {
			eprintf (
				"ERROR: Unable to yank data from file: (loadaddr (0x%"
				PFMT64x ") (addr (0x%"
				PFMT64x ") > file_sz (0x%"PFMT64x ")\n", res, addr,
				yank_file_sz );
		} else if (actual_len == 0) {
			eprintf (
				"ERROR: Unable to yank from file: addr+len (0x%"
				PFMT64x ") > file_sz (0x%"PFMT64x ")\n", addr + len,
				yank_file_sz );
		}
		r_io_desc_close (yankdesc);
		free (buf);
	}
	if (fd != -1) {
		r_io_use_fd (core->io, fd);
		core->switch_file_view = 1;
		r_core_block_read (core);
	}
	return res;
}

R_API int r_core_yank_set(RCore *core, ut64 addr, const ut8 *buf, ut32 len) {
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
R_API int r_core_yank_set_str(RCore *core, ut64 addr, const char *str, ut32 len) {
	// free (core->yank_buf);
	int res = r_core_yank_set (core, addr, (ut8 *)str, len);
	if (res == true) {
		ut8 zero = 0;
		r_buf_write_at (core->yank_buf, len - 1, &zero, sizeof (zero));
	}
	return res;
}

R_API int r_core_yank(struct r_core_t *core, ut64 addr, int len) {
	ut64 curseek = core->offset;
	ut8 *buf = NULL;
	if (len < 0) {
		eprintf ("r_core_yank: cannot yank negative bytes\n");
		return false;
	}
	if (len == 0) {
		len = core->blocksize;
	}
	buf = malloc (len);
	if (!buf) {
		return false;
	}
	if (addr != core->offset) {
		r_core_seek (core, addr, 1);
	}
	r_io_read_at (core->io, addr, buf, len);
	r_core_yank_set (core, addr, buf, len);
	if (curseek != addr) {
		r_core_seek (core, curseek, 1);
	}
	free (buf);
	return true;
}

/* Copy a zero terminated string to the clipboard. Clamp to maxlen or blocksize. */
R_API int r_core_yank_string(RCore *core, ut64 addr, int maxlen) {
	ut64 curseek = core->offset;
	ut8 *buf = NULL;
	if (maxlen < 0) {
		eprintf ("r_core_yank_string: cannot yank negative bytes\n");
		return false;
	}
	if (addr != core->offset) {
		r_core_seek (core, addr, 1);
	}
	/* Ensure space and safe termination for largest possible string allowed */
	buf = calloc (1, core->blocksize + 1);
	if (!buf) {
		return false;
	}
	buf[core->blocksize] = 0;
	r_io_read_at (core->io, addr, buf, core->blocksize);
	if (maxlen == 0) {
		// Don't use strnlen, see: http://sourceforge.net/p/mingw/bugs/1912/
		maxlen = r_str_nlen ((const char *) buf, core->blocksize);
	} else if (maxlen > core->blocksize) {
		maxlen = core->blocksize;
	}
	r_core_yank_set (core, addr, buf, maxlen);
	if (curseek != addr) {
		r_core_seek (core, curseek, 1);
	}
	free (buf);
	return true;
}

R_API int r_core_yank_paste(RCore *core, ut64 addr, int len) {
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
	if (!r_core_write_at (core, addr, buf, len)) {
		return false;
	}
	return true;
}

R_API int r_core_yank_to(RCore *core, const char *_arg) {
	ut64 len = 0;
	ut64 pos = -1;
	char *str, *arg;
	int res = false;

	while (*_arg == ' ') {
		_arg++;
	}
	arg = strdup (_arg);
	str = strchr (arg, ' ');
	if (str) {
		str[0] = '\0';
		len = r_num_math (core->num, arg);
		pos = r_num_math (core->num, str + 1);
		str[0] = ' ';
	}
	if (len < 1) {
		free (arg);
		return res;
	}
	if (!str || pos == -1 || len == 0) {
		eprintf ("Usage: yt [len] [dst-addr]\n");
		free (arg);
		return res;
	}
	if (r_core_yank (core, core->offset, len) == true) {
		res = r_core_yank_paste (core, pos, len);
	}
	free (arg);
	return res;
}

R_API bool r_core_yank_dump(RCore *core, ut64 pos, int format) {
	bool res = false;
	int i = 0;
	int ybl = r_buf_size (core->yank_buf);
	if (ybl > 0) {
		if (pos < ybl) {
			switch (format) {
			case 'q':
				for (i = pos; i < r_buf_size (core->yank_buf); i++) {
					r_cons_printf ("%02x", r_buf_read8_at (core->yank_buf, i));
				}
				r_cons_newline ();
				break;
			case 'j':
				{
					r_cons_printf ("{\"addr\":%"PFMT64u",\"bytes\":\"", core->yank_addr);
					for (i = pos; i < r_buf_size (core->yank_buf); i++) {
						r_cons_printf ("%02x", r_buf_read8_at (core->yank_buf, i));
					}
					r_cons_printf ("\"}\n");
				}
				break;
			case '*':
				//r_cons_printf ("yfx ");
				r_cons_printf ("wx ");
				for (i = pos; i < r_buf_size (core->yank_buf); i++) {
					r_cons_printf ("%02x", r_buf_read8_at (core->yank_buf, i));
				}
				//r_cons_printf (" @ 0x%08"PFMT64x, core->yank_addr);
				r_cons_newline ();
				break;
			default:
				r_cons_printf ("0x%08" PFMT64x " %d ",
						core->yank_addr + pos,
						r_buf_size (core->yank_buf) - pos);
				for (i = pos; i < r_buf_size (core->yank_buf); i++) {
					r_cons_printf ("%02x", r_buf_read8_at (core->yank_buf, i));
				}
				r_cons_newline ();
			}
			res = true;
		} else {
			eprintf ("Position exceeds buffer length.\n");
		}
	} else {
		if (format == 'j') {
			r_cons_printf ("{}\n");
		} else {
			eprintf ("No buffer yanked already\n");
		}
	}
	return res;
}

R_API int r_core_yank_hexdump(RCore *core, ut64 pos) {
	int res = false;
	int ybl = r_buf_size (core->yank_buf);
	if (ybl > 0) {
		if (pos < ybl) {
			ut8 *buf = R_NEWS (ut8, ybl - pos);
			if (!buf) {
				return false;
			}
			r_buf_read_at (core->yank_buf, pos, buf, ybl - pos);
			r_print_hexdump (core->print, pos,
				buf, ybl - pos, 16, 1, 1);
			res = true;
		} else {
			eprintf ("Position exceeds buffer length.\n");
		}
	} else {
		eprintf ("No buffer yanked already\n");
	}
	return res;
}

R_API int r_core_yank_cat(RCore *core, ut64 pos) {
	int ybl = r_buf_size (core->yank_buf);
	if (ybl > 0) {
		if (pos < ybl) {
			ut64 sz = ybl - pos;
			char *buf = R_NEWS (char, sz);
			if (!buf) {
				return false;
			}
			r_buf_read_at (core->yank_buf, pos, (ut8 *)buf, sz);
			r_cons_memcat (buf, sz);
			r_cons_newline ();
			return true;
		}
		eprintf ("Position exceeds buffer length.\n");
	} else {
		r_cons_newline ();
	}
	return false;
}

R_API int r_core_yank_cat_string(RCore *core, ut64 pos) {
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
			r_cons_memcat (buf, len);
			r_cons_newline ();
			return true;
		}
		eprintf ("Position exceeds buffer length.\n");
	} else {
		r_cons_newline ();
	}
	return false;
}

R_API int r_core_yank_hud_file(RCore *core, const char *input) {
	char *buf = NULL;
	bool res = false;
	ut32 len = 0;
	if (!input || !*input) {
		return false;
	}
	for (input++; *input == ' '; input++) {
		/* nothing */
	}
	buf = r_cons_hud_file (input);
	len = buf? strlen ((const char *) buf) + 1: 0;
	res = r_core_yank_set_str (core, R_CORE_FOREIGN_ADDR, buf, len);
	free (buf);
	return res;
}

R_API int r_core_yank_hud_path(RCore *core, const char *input, int dir) {
	char *buf = NULL;
	ut32 len = 0;
	int res;
	for (input++; *input == ' '; input++) {
		/* nothing */
	}
	buf = r_cons_hud_path (input, dir);
	len = buf? strlen ((const char *) buf) + 1: 0;
	res = r_core_yank_set_str (core, R_CORE_FOREIGN_ADDR, buf, len);
	free (buf);
	return res;
}

R_API bool r_core_yank_hexpair(RCore *core, const char *input) {
	if (!input || !*input) {
		return false;
	}
	char *out = strdup (input);
	int len = r_hex_str2bin (input, (ut8 *)out);
	if (len > 0) {
		r_core_yank_set (core, core->offset, (ut8 *)out, len);
	}
	free (out);
	return true;
}

R_API bool r_core_yank_file_ex(RCore *core, const char *input) {
	ut64 len = 0, adv = 0, addr = 0;
	bool res = false;

	if (!input) {
		return res;
	}
	// get the number of bytes to yank
	adv = consume_chars (input, ' ');
	len = r_num_math (core->num, input + adv);
	if (len == 0) {
		eprintf ("ERROR: Number of bytes read must be > 0\n");
		return res;
	}
	// get the addr/offset from in the file we want to read
	adv += find_next_char (input + adv, ' ');
	if (adv == 0) {
		eprintf ("ERROR: Address must be specified\n");
		return res;
	}
	adv++;

	// XXX - bug, will fail if address needs to be computed and has spaces
	addr = r_num_math (core->num, input + adv);

	adv += find_next_char (input + adv, ' ');
	if (adv == 0) {
		eprintf ("ERROR: File must be specified\n");
		return res;
	}
	adv++;

	// grab the current file descriptor, so we can reset core and io state
	// after our io op is done
	return perform_mapped_file_yank (core, addr, len, input + adv);
}

R_API int r_core_yank_file_all(RCore *core, const char *input) {
	ut64 adv = 0;
	if (!input) {
		return false;
	}
	adv = consume_chars (input, ' ');
	return perform_mapped_file_yank (core, 0, -1, input + adv);
}
