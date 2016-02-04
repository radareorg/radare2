/* radare2 - LGPL - Copyright 2009-2016 - pancake */

#include "r_core.h"

R_API int r_core_setup_debugger (RCore *r, const char *debugbackend, bool attach) {
	int pid, *p = NULL;
	bool is_gdb = !strcmp (debugbackend, "gdb");
	RIODesc * fd = r->file ? r->file->desc : NULL;
	const char *prompt = NULL;

	p = fd ? fd->data : NULL;
	r_config_set_i (r->config, "cfg.debug", 1);
	if (!p) {
		eprintf ("Invalid debug io\n");
		return false;
	}

	r_config_set (r->config, "io.ff", "true");
	r_core_cmdf (r, "dh %s", debugbackend);
	if (!is_gdb) {
		pid = *p; // 1st element in debugger's struct must be int
		r_core_cmdf (r, "dp=%d", pid);
		if (attach) {
			r_core_cmdf (r, "dpa %d", pid);
		}
	}
	//this makes to attach twice showing warnings in the output
	//we get "resource busy" so it seems isn't an issue
	r_core_cmd (r, ".dr*", 0);
	/* honor dbg.bep */
	{
		const char *bep = r_config_get (r->config, "dbg.bep");
		if (bep) {
			if (!strcmp (bep, "loader")) {
				/* do nothing here */
			} else if (!strcmp (bep, "entry")) {
				r_core_cmd (r, "dcu entry0", 0);
			} else {
				r_core_cmdf (r, "dcu %s", bep);
			}
		}
	}
	r_core_cmd (r, "sr PC", 0);

	/* set the prompt if it's not been set already by the callbacks */
	prompt = r_config_get (r->config, "cmd.prompt");
	if (prompt && !strcmp (prompt, "")) {
		if (r_config_get_i (r->config, "dbg.status")) {
			r_config_set (r->config, "cmd.prompt", ".dr*;drd;sr PC;pi 1;s-");
		} else {
			r_config_set (r->config, "cmd.prompt", ".dr*");
		}
	}
	r_config_set (r->config, "cmd.vprompt", ".dr*");
	return true;
}

R_API int r_core_seek_base (RCore *core, const char *hex) {
	ut64 addr = r_num_tail (core->num, core->offset, hex);
	return r_core_seek (core, addr, 1);
}

R_API int r_core_dump(RCore *core, const char *file, ut64 addr, ut64 size, int append) {
	ut64 i;
	ut8 *buf;
	int bs = core->blocksize;
	FILE *fd;
	if (append) {
		fd = r_sandbox_fopen (file, "ab");
	} else {
		r_sys_truncate (file, 0);
		fd = r_sandbox_fopen (file, "wb");
	}
	if (!fd) {
		eprintf ("Cannot open '%s' for writing\n", file);
		return false;
	}
	/* some io backends seems to be buggy in those cases */
	if (bs > 4096)
		bs = 4096;
	buf = malloc (bs);
	if (!buf) {
		eprintf ("Cannot alloc %d bytes\n", bs);
		fclose (fd);
		return false;
	}
	r_cons_break_push (NULL, NULL);
	for (i = 0; i < size; i += bs) {
		if (r_cons_is_breaked ()) {
			break;
		}
		if ((i + bs) > size) {
			bs = size - i;
		}
		r_io_read_at (core->io, addr + i, buf, bs);
		if (fwrite (buf, bs, 1, fd) < 1) {
			eprintf ("write error\n");
			break;
		}
	}
	eprintf ("dumped 0x%"PFMT64x" bytes\n", i);
	r_cons_break_pop ();
	fclose (fd);
	free (buf);
	return true;
}

R_API int r_core_write_op(RCore *core, const char *arg, char op) {
	int i, j, len, ret = false;
	char *str = NULL;
	ut8 *buf;

	// XXX we can work with config.block instead of dupping it
	buf = (ut8 *)malloc (core->blocksize);
	if (!buf)
		goto beach;
	memcpy (buf, core->block, core->blocksize);

	if (op!='e') {
		// fill key buffer either from arg or from clipboard
		if (arg) {  // parse arg for key
			// r_hex_str2bin() is guaranteed to output maximum half the
			// input size, or 1 byte if there is just a single nibble.
			str = (char *)malloc (strlen (arg) / 2 + 1);
			if (!str)
				goto beach;
			len = r_hex_str2bin (arg, (ut8 *)str);
			// Output is invalid if there was just a single nibble,
			// but in that case, len is negative (-1).
			if (len <= 0) {
				eprintf ("Invalid hexpair string\n");
				goto beach;
			}
		} else {  // use clipboard as key
			len = core->yank_buf->length;
			if (len <= 0) {
				eprintf ("Clipboard is empty and no value argument(s) given\n");
				goto beach;
			}
			str = r_mem_dup (core->yank_buf->buf, len);
			if (!str)
				goto beach;
		}
	} else len = 0;

	// execute the operand
	if (op=='e') {
		int wordsize = 1;
		char *os, *p, *s = strdup (arg);
		int n, from = 0, to = 0, dif = 0, step = 1;
		n = from = to;
		os = s;
		to = UT8_MAX;
		//
		p = strchr (s, ' ');
		if (p) {
			*p = 0;
			from = r_num_math (core->num, s);
			s = p+1;
		}
		p = strchr (s, ' ');
		if (p) {
			*p = 0;
			to = r_num_math (core->num, s);
			s = p+1;
		}
		p = strchr (s, ' ');
		if (p) {
			*p = 0;
			step = r_num_math (core->num, s);
			s = p+1;
			wordsize = r_num_math (core->num, s);
		} else {
			step = r_num_math (core->num, s);
		}
		free (os);
		eprintf ("from %d to %d step %d size %d\n", from, to, step, wordsize);
		dif = (to<=from)? UT8_MAX: (to-from)+1;
		if (wordsize==1) {
			if (to<1 || to>UT8_MAX) to = UT8_MAX;
			from %= (UT8_MAX+1);
		}
		if (dif<1) dif = UT8_MAX+1;
		if (step<1) step = 1;
		if (wordsize<1) wordsize = 1;
		if (wordsize == 1) {
			for (i=n=0; i<core->blocksize; i++, n+= step)
				buf[i] = (ut8)(n % dif) + from;
		} else if (wordsize == 2) {
			ut16 num16 = from;
			for (i = 0; i < core->blocksize; i += wordsize, num16 += step) {
				r_write_le16 (buf + i, num16);
			}
		} else if (wordsize == 4) {
			ut32 num32 = from;
			for (i = 0; i < core->blocksize; i += wordsize, num32 += step) {
				r_write_le32 (buf + i, num32);
			}
		} else if (wordsize == 8) {
			ut64 num64 = from;
			for (i = 0; i < core->blocksize; i += wordsize, num64 += step) {
				r_write_le64 (buf + i, num64);
			}
		} else {
			eprintf ("Invalid word size. Use 1, 2, 4 or 8\n");
		}
	} else
	if (op=='2' || op=='4') {
		op -= '0';
		// if i < core->blocksize would pass the test but buf[i+3] goes beyond the buffer
		if (core->blocksize > 3) {
			for (i=0; i<core->blocksize-3; i+=op) {
				/* endian swap */
				ut8 tmp = buf[i];
				buf[i] = buf[i+3];
				buf[i+3] = tmp;
				if (op==4) {
					tmp = buf[i+1];
					buf[i+1] = buf[i+2];
					buf[i+2] = tmp;
				}
			}
		}
	} else {
		for (i=j=0; i<core->blocksize; i++) {
			switch (op) {
			case 'x': buf[i] ^= str[j]; break;
			case 'a': buf[i] += str[j]; break;
			case 's': buf[i] -= str[j]; break;
			case 'm': buf[i] *= str[j]; break;
			case 'w': buf[i] = str[j]; break;
			case 'd': buf[i] = (str[j])? buf[i] / str[j]: 0; break;
			case 'r': buf[i] >>= str[j]; break;
			case 'l': buf[i] <<= str[j]; break;
			case 'o': buf[i] |= str[j]; break;
			case 'A': buf[i] &= str[j]; break;
			}
			j++; if (j>=len) j=0; /* cyclic key */
		}
	}

	ret = r_core_write_at (core, core->offset, buf, core->blocksize);
beach:
	free (buf);
	free (str);
	return ret;
}


static void _set_bits(RCore *core, ut64 addr, int *bits) {
	RAnalRange *range;
	RListIter *iter;
	r_list_foreach (core->anal->bits_ranges, iter, range) {
		if (addr >= range->from && addr < range->to) {
			*bits = range->bits;
			return;
		}
	}
}


R_API void r_core_seek_archbits(RCore *core, ut64 addr) {
	static char *oldarch = NULL;
	static int oldbits = 0;
	bool flag = false;
	int bits = 0;
	char *arch = (char *)r_io_section_get_archbits (core->io, addr, &bits);
	if (!bits) {
		_set_bits (core, addr, &bits);
	}
	if (!arch) {
		arch = strdup (r_config_get (core->config, "asm.arch"));
		flag = true;
	} else {
		arch = strdup (arch);
	}
	if (arch && bits) {
		if (bits != oldbits) {
			r_config_set_i (core->config, "asm.bits", bits);
			oldbits = bits;
		}
		if (!oldarch) {
			RBinInfo *info = r_bin_get_info (core->bin);
			if (info && info->arch) {
				oldarch = strdup (info->arch);
			} else {
				oldarch = strdup (r_config_get (core->config, "asm.arch"));
				oldbits = r_config_get_i (core->config, "asm.bits");
			}
			if (strcmp (arch, oldarch)) {
				r_config_set (core->config, "asm.arch", arch);
			}
		}
		free (arch);
		return;
	}
	if (oldarch) {
		if (!(flag && arch && oldarch && !strcmp (oldarch, arch))) {
			r_config_set (core->config, "asm.arch", oldarch);
		}
		R_FREE (oldarch);
	}
	if (oldbits) {
		r_config_set_i (core->config, "asm.bits", oldbits);
	}
	free (arch);
}

R_API bool r_core_seek(RCore *core, ut64 addr, bool rb) {
	ut64 old = core->offset;
	ut64 ret;

	core->offset = addr;
	/* XXX unnecesary call */
	//r_io_use_fd (core->io, core->file->desc);
	ret = r_io_seek (core->io, addr, R_IO_SEEK_SET);

	if (ret == UT64_MAX) {
		if (!core->io->va) {
			return false;
		}
	} else {
		core->offset = addr;
	}
	if (rb) {
		ret = r_core_block_read (core, 0);
		if (!ret) {
			core->offset = old;
		}
	}
	r_core_seek_archbits (core, core->offset);
	return (ret==-1)? false: true;
}

R_API int r_core_seek_delta(RCore *core, st64 addr) {
	ut64 tmp = core->offset;
	int ret;
	if (addr == 0)
		return true;
	if (addr>0LL) {
		/* check end of file */
		if (0) addr = 0;
		else addr += tmp;
	} else {
		/* check < 0 */
		if (-addr > tmp) addr = 0;
		else addr += tmp;
	}
	core->offset = addr;
	ret = r_core_seek (core, addr, 1);
	//ret = r_core_block_read (core);
	//if (ret == -1)
	//	memset (core->block, 0xff, core->blocksize);
	//	core->offset = tmp;
	return ret;
}

R_API int r_core_write_at(RCore *core, ut64 addr, const ut8 *buf, int size) {
	int ret;
	if (!core->io || !core->file || !core->file->desc || size<1)
		return false;
	ret = r_io_desc_use (core->io, core->file->desc->fd);
	if (ret != -1) {
		ret = r_io_write_at (core->io, addr, buf, size);
		if (addr >= core->offset && addr <= core->offset + core->blocksize) {
			r_core_block_read (core);
		}
	}
	return (ret == -1)? false: true;
}

R_API int r_core_extend_at(RCore *core, ut64 addr, int size) {
	int ret;
	if (!core->io || !core->file || !core->file->desc || size<1)
		return false;
	ret = r_io_desc_use (core->io, core->file->desc->fd);
	if (ret != -1) {
		ret = r_io_extend_at (core->io, addr, size);
		if (addr >= core->offset && addr <= core->offset+core->blocksize)
			r_core_block_read (core);
	}
	return (ret==-1)? false: true;
}

R_API int r_core_shift_block(RCore *core, ut64 addr, ut64 b_size, st64 dist) {
	// bstart - block start, fstart file start
	ut64 fend = 0, fstart = 0, bstart = 0, file_sz = 0;
	ut8 * shift_buf = NULL;
	int res = false;

	if (!core->io || !core->file || !core->file->desc || b_size<1)
		return false;
	
	if (b_size == 0 || b_size == (ut64) -1) {
		res = r_io_desc_use (core->io, core->file->desc->fd);
		file_sz = r_io_size (core->io);
		bstart = r_io_seek (core->io, addr, R_IO_SEEK_SET);
		fend = r_io_seek (core->io, 0, R_IO_SEEK_END);
		fstart = file_sz - fend;
		b_size = fend > bstart ? fend - bstart: 0;
	}

	if (b_size < 1)
		return false;

	// XXX handling basic cases atm
	shift_buf = malloc (b_size);
	memset (shift_buf, 0, b_size);

	// cases
	// addr + b_size + dist > file_end
	//if ( (addr+b_size) + dist > file_end ) {
	//	res = false;
	//}
	// addr + b_size + dist < file_start (should work since dist is signed)
	//else if ( (addr+b_size) + dist < 0 ) {
	//	res = false;
	//}
	// addr + dist < file_start
	if ( addr + dist < fstart ) {
		res = false;
	}
	// addr + dist > file_end
	else if ( (addr) + dist > fend) {
		res = false;
	} else {
		res = r_io_desc_use (core->io, core->file->desc->fd);
		r_io_read_at (core->io, addr, shift_buf, b_size);
		r_io_write_at (core->io, addr+dist, shift_buf, b_size);
		res = true;
	}

	r_core_seek (core, addr, 1);
	free (shift_buf);
	return res;
}

static RCoreFile * r_core_file_set_first_valid(RCore *core) {
	RListIter *iter;
	RCoreFile *file = NULL;

	r_list_foreach (core->files, iter, file) {
		if (file && file->desc){
			r_io_desc_use (core->io, file->desc->fd);
			core->switch_file_view = 1;
			break;
		}
	}
	return file;
}

R_API int r_core_block_read(RCore *core) {
	if (!core->file && !r_core_file_set_first_valid (core)) {
		memset (core->block, core->io->Oxff, core->blocksize);
		return -1;
	}
	if (core->file && core->switch_file_view) {
		r_io_desc_use (core->io, core->file->desc->fd);
		r_core_bin_set_by_fd (core, core->file->desc->fd); //needed?
		core->switch_file_view = 0;
	}
	return r_io_read_at (core->io, core->offset, core->block, core->blocksize);
}

R_API int r_core_read_at(RCore *core, ut64 addr, ut8 *buf, int size) {
	if (!core || !core->io || !core->file || !core->file->desc || size < 1) {
		if (core && core->io && size > 0) {
			memset (buf, core->io->Oxff, size);
		}
		return false;
	}
	r_io_desc_use (core->io, core->file->desc->fd);
	return r_io_read_at (core->io, addr, buf, size);
}

R_API int r_core_is_valid_offset (RCore *core, ut64 offset) {
	if (!core) {
		eprintf ("r_core_is_valid_offset: core is NULL\n");
		r_sys_backtrace ();
		return R_FAIL;
	}
	return r_io_is_valid_offset (core->io, offset, 0);
}
