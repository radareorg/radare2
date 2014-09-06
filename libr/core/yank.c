/* radare - LGPL - Copyright 2009-2014 - pancake & dso */

#include "r_core.h"
#include "r_print.h"
#include "r_io.h"

#ifdef IFDBG
#undef IFDBG
#endif

#define DO_THE_DBG 0
#define IFDBG if (DO_THE_DBG)

/*
 * perform_mapped_file_yank will map in a file and yank from offset the number of len bytes from
 * filename.  if the len is -1, the all the bytes are mapped into the yank buffer.
 */
static int perform_mapped_file_yank (RCore *core, ut64 offset, ut64 len, const char *filename);
static ut32 find_next_char (const char *input, char b);
static ut32 consume_chars (const char *input, char b);

static ut32 find_next_char (const char *input, char b) {
	ut32 i = 0;
	if (!input) return i;
	for (; *input != b; i++, input++) {}
	return i;
}

static ut32 consume_chars (const char *input, char b) {
	ut32 i = 0;
	if (!input) return i;
	for (; *input == b; i++, input++) {}
	return i;
}

static int perform_mapped_file_yank (RCore *core, ut64 offset, ut64 len, const char *filename) {
	// grab the current file descriptor, so we can reset core and io state
	// after our io op is done
	RIODesc *yankfd = NULL;
	ut64 fd = core->file ? core->file->desc->fd : -1, yank_file_sz = 0,
		 loadaddr = 0, addr = offset;
	int res = R_FALSE;

	if (filename && *filename) {
		ut64 load_align = r_config_get_i (core->config,
			"file.loadalign");
		RIOMap * map = NULL;
		yankfd = r_io_open_nomap (core->io, filename, R_IO_READ, 0644);
		// map the file in for IO operations.
		if (yankfd && load_align) {
			yank_file_sz = r_io_size (core->io);
			map = r_io_map_add_next_available (core->io,
				yankfd->fd,
				R_IO_READ, 0, 0,
				yank_file_sz,
				load_align);
			loadaddr = map ? map->from : -1;
			if (yankfd && map && loadaddr != -1) {
				// ***NOTE*** this is important, we need to
				// address the file at its physical address!
				addr += loadaddr;
			} else if (yankfd) {
				eprintf ("Unable to map the opened file: %s", filename);
				r_io_close (core->io, yankfd);
				yankfd = NULL;
			} else {
				eprintf ("Unable to open the file: %s", filename);
			}
		}
	}

	// if len is -1 then we yank in everything
	if (len == -1) len = yank_file_sz;

	IFDBG eprintf ("yankfd: %p, yank->fd = %d, fd=%d\n", yankfd,
		       (int)(yankfd ? yankfd->fd : -1), (int)fd);
	// this wont happen if the file failed to open or the file failed to
	// map into the IO layer
	if (yankfd) {
		ut64 res = r_io_seek (core->io, addr, R_IO_SEEK_SET),
		     actual_len = len <= yank_file_sz ? len : 0;
		ut8 *buf = NULL;
		IFDBG eprintf (
			"Addr (%"PFMT64d
			") file_sz (%"PFMT64d
			") actual_len (%"PFMT64d
			") len (%"PFMT64d
			") bytes from file: %s\n", addr, yank_file_sz,
			actual_len, len, filename);
		if (actual_len > 0 && res == addr) {
			IFDBG eprintf (
				"Creating buffer and reading %"PFMT64d
				" bytes from file: %s\n", actual_len, filename);
			buf = malloc (actual_len);
			actual_len = r_io_read_at (core->io, addr, buf,
				actual_len);
			IFDBG eprintf (
				"Reading %"PFMT64d " bytes from file: %s\n",
				actual_len, filename);
			/*IFDBG {
				int i = 0;
				eprintf ("Read these bytes from file: \n");
				for (i = 0; i < actual_len; i++)
					eprintf ("%02x", buf[i]);
				eprintf ("\n");
			}*/
			r_core_yank_set (core, R_CORE_FOREIGN_ADDR, buf, len);
			res = R_TRUE;
		} else if (res != addr) {
			eprintf (
				"ERROR: Unable to yank data from file: (loadaddr (0x%"
				PFMT64x ") (addr (0x%"
				PFMT64x ") > file_sz (0x%"PFMT64x ")\n", res, addr,
				yank_file_sz );
		} else if (actual_len == 0) {
			eprintf (
				"ERROR: Unable to yank from file: addr+len (0x%"
				PFMT64x ") > file_sz (0x%"PFMT64x ")\n", addr+len,
				yank_file_sz );
		}
		r_io_close (core->io, yankfd);
		free (buf);
	}
	if (fd != -1) {
		r_io_raise (core->io, fd);
		core->switch_file_view = 1;
		r_core_block_read (core, 0);
	}
	return res;
}

R_API int r_core_yank_set (RCore *core, ut64 addr, const ut8 *buf, ut32 len) {
	//free (core->yank_buf);
	if (buf && len) {
		r_buf_set_bytes (core->yank_buf, buf, len);
		core->yank_buf->base = addr;
		return R_TRUE;
	}
	return R_FALSE;
}

// Call set and then null terminate the bytes.
R_API int r_core_yank_set_str (RCore *core, ut64 addr, const char *str,
			       ut32 len) {
	//free (core->yank_buf);
	int res = r_core_yank_set (core, addr, (ut8*)str, len);
	if (res == R_TRUE)
		core->yank_buf->buf[len-1] = 0;
	return res;
}

R_API int r_core_yank(struct r_core_t *core, ut64 addr, int len) {
	ut64 curseek = core->offset;
	ut8 *buf = NULL;
	if (len<0) {
		eprintf ("r_core_yank: cannot yank negative bytes\n");
		return R_FALSE;
	}
	if (len == 0) len = core->blocksize;
	//free (core->yank_buf);
	buf = malloc (len);
	//core->yank_buf = (ut8 *)malloc (len);
	if (addr != core->offset)
		r_core_seek (core, addr, 1);

	r_core_read_at (core, addr, buf, len);
	r_core_yank_set (core, addr, buf, len);

	if (curseek != addr)
		r_core_seek (core, curseek, 1);
	free (buf);
	return R_TRUE;
}

/* Copy a zero terminated string to the clipboard. Clamp to maxlen or blocksize. */
R_API int r_core_yank_string(RCore *core, ut64 addr, int maxlen) {
	ut64 curseek = core->offset;
	ut8 *buf = NULL;
	if (maxlen<0) {
		eprintf ("r_core_yank_string: cannot yank negative bytes\n");
		return R_FALSE;
	}
	if (addr != core->offset)
		r_core_seek (core, addr, 1);
	/* Ensure space and safe termination for largest possible string allowed */
	buf = malloc (core->blocksize + 1);
	if (!buf)
		return R_FALSE;
	buf[core->blocksize] = 0;
	r_core_read_at (core, addr, buf, core->blocksize);
	if (maxlen == 0) {
		maxlen = r_str_nlen ((const char*)buf, core->blocksize);	//Don't use strnlen, see: http://sourceforge.net/p/mingw/bugs/1912/
	} else if (maxlen > core->blocksize) {
		maxlen = core->blocksize;
	}
	r_core_yank_set (core, addr, buf, maxlen);
	if (curseek != addr)
		r_core_seek (core, curseek, 1);
	free (buf);
	return R_TRUE;
}

R_API int r_core_yank_paste(RCore *core, ut64 addr, int len) {
	if (len<0) return R_FALSE;
	if (len == 0 || len >= core->yank_buf->length) len =
			core->yank_buf->length;
	r_core_write_at (core, addr, core->yank_buf->buf, len);
	return R_TRUE;
}

R_API int r_core_yank_to(RCore *core, const char *_arg) {
	ut64 len = 0;
	ut64 pos = -1;
	char *str, *arg;
	int res = R_FALSE;

	while (*_arg==' ') _arg++;
	arg = strdup (_arg);
	str = strchr (arg, ' ');
	if (str) {
		str[0] = '\0';
		len = r_num_math (core->num, arg);
		pos = r_num_math (core->num, str+1);
		str[0] = ' ';
	}
	if (len < 1) {
		free (arg);
		return res;
	}
	if ((str == NULL) || (pos == -1) || (len == 0)) {
		eprintf ("Usage: yt [len] [dst-addr]\n");
		free (arg);
		return res;
	}

	if (r_core_yank (core, core->offset, len) == R_TRUE)
		res = r_core_yank_paste (core, pos, len);

	free (arg);
	return res;
}

R_API int r_core_yank_dump (RCore *core, ut64 pos) {
	int res = R_FALSE, i = 0;
	int ybl = core->yank_buf->length;
	if (ybl>0) {
		if (pos<ybl) {
			r_cons_printf ("0x%08"PFMT64x " %d ",
				core->yank_buf->base+pos,
				core->yank_buf->length-pos);
			for (i = pos; i < core->yank_buf->length; i++)
				r_cons_printf ("%02x",
					core->yank_buf->buf[i]);
			r_cons_newline ();
			res = R_TRUE;
		} else eprintf ("Position exceeds buffer length.\n");
	} else eprintf ("No buffer yanked already\n");
	return res;
}

R_API int r_core_yank_hexdump (RCore *core, ut64 pos) {
	int res = R_FALSE;
	int ybl = core->yank_buf->length;
	if (ybl>0) {
		if (pos < ybl) {
			r_print_hexdump (core->print, pos,
				core->yank_buf->buf+pos,
				ybl-pos, 16, 4);
			res = R_TRUE;
		} else eprintf ("Position exceeds buffer length.\n");
	} else eprintf ("No buffer yanked already\n");
	return res;
}

R_API int r_core_yank_cat (RCore *core, ut64 pos) {
	int res = R_FALSE;
	int ybl = core->yank_buf->length;
	if (ybl>0) {
		if (pos < ybl) {
			r_cons_memcat ((const char*)core->yank_buf->buf+pos,
				core->yank_buf->length-pos);
			r_cons_newline ();
			res = R_TRUE;
		} else eprintf ("Position exceeds buffer length.\n");
	} else r_cons_newline ();
	return res;
}

R_API int r_core_yank_hud_file (RCore *core, const char *input) {
	char *buf = NULL;
	ut32 len = 0;
	int res = R_FALSE;

	for (input++; *input==' '; input++) ;

	buf = r_cons_hud_file (input);
	len = buf ? strlen ((const char*)buf) + 1 : 0;
	res = r_core_yank_set_str (core, R_CORE_FOREIGN_ADDR, buf, len);
	return res;
}

R_API int r_core_yank_hud_path (RCore *core, const char *input, int dir) {
	char *buf = NULL;
	ut32 len = 0;
	int res = R_FALSE;
	for (input++; *input==' '; input++) ;

	buf = r_cons_hud_path (input, dir);
	len = buf ? strlen ((const char*)buf) + 1 : 0;
	res = r_core_yank_set_str (core, R_CORE_FOREIGN_ADDR, buf, len);
	return res;
}

R_API int r_core_yank_file_ex (RCore *core, const char *input) {
	ut64 len = 0, adv = 0, addr = 0;
	int res = R_FALSE;

	if (!input) return res;

	// get the number of bytes to yank
	adv = consume_chars (input, ' ');
	len = r_num_math (core->num, input+adv);
	if (len == 0) {
		eprintf ("ERROR: Number of bytes read must be > 0\n");
		return res;
	}
	// get the addr/offset from in the file we want to read
	adv += find_next_char (input+adv, ' ');
	if (adv == 0) {
		eprintf ("ERROR: Address must be specified\n");
		return res;
	}
	adv++;

	IFDBG eprintf ("Handling the input: %s\n", input+adv);
	// XXX - bug, will fail if address needs to be computed and has spaces
	addr = r_num_math (core->num, input+adv);

	adv += find_next_char (input+adv, ' ');
	if (adv == 0) {
		eprintf ("ERROR: File must be specified\n");
		return res;
	}
	adv++;

	IFDBG eprintf ("Filename: %s\n", input+adv);
	// grab the current file descriptor, so we can reset core and io state
	// after our io op is done
	return perform_mapped_file_yank (core, addr, len, input+adv);
}

R_API int r_core_yank_file_all (RCore *core, const char *input) {
	ut64 adv = 0;
	if (!input) return R_FALSE;
	adv = consume_chars (input, ' ');
	IFDBG eprintf ("Filename: %s\n", input+adv);
	return perform_mapped_file_yank (core, 0, -1, input+adv);
}
