/* radare2 - LGPL - Copyright 2009-2021 - pancake */

#include "r_core.h"

R_API int r_core_setup_debugger (RCore *r, const char *debugbackend, bool attach) {
	int pid, *p = NULL;
	bool is_gdb = !strcmp (debugbackend, "gdb");
	RIODesc * fd = r->io->desc;
	const char *prompt = NULL;

	p = fd ? fd->data : NULL;
	r_config_set_b (r->config, "cfg.debug", true);
	if (!p) {
		eprintf ("Invalid debug io\n");
		return false;
	}

	r_config_set (r->config, "io.ff", "true");
	r_core_cmdf (r, "dL %s", debugbackend);
	if (!is_gdb) {
		pid = r_io_desc_get_pid (fd);
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
	r_config_set (r->config, "cmd.gprompt", ".dr*");
	return true;
}

R_API int r_core_seek_base (RCore *core, const char *hex) {
	ut64 addr = r_num_tail (core->num, core->offset, hex);
	return r_core_seek (core, addr, true);
}

R_API bool r_core_dump(RCore *core, const char *file, ut64 addr, ut64 size, int append) {
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
	if (bs > 4096) {
		bs = 4096;
	}
	buf = malloc (bs);
	if (!buf) {
		eprintf ("Cannot alloc %d byte(s)\n", bs);
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
	r_cons_break_pop ();
	fclose (fd);
	free (buf);
	return true;
}

static bool __endian_swap(ut8 *buf, ut32 blocksize, ut8 len) {
	ut32 i;
	ut16 v16;
	ut32 v32;
	ut64 v64;
	if (len != 8 && len != 4 && len != 2 && len != 1) {
		eprintf ("Invalid word size. Use 1, 2, 4 or 8\n");
		return false;
	}
	if (len == 1) {
		return true;
	}
	for (i = 0; i < blocksize; i += len) {
		switch (len) {
		case 8:
			v64 = r_read_at_be64 (buf, i);
			r_write_at_le64 (buf, v64, i);
			break;
		case 4:
			v32 = r_read_at_be32 (buf, i);
			r_write_at_le32 (buf, v32, i);
			break;
		case 2:
			v16 = r_read_at_be16 (buf, i);
			r_write_at_le16 (buf, v16, i);
			break;
		}
	}
	return true;
}

R_API ut8* r_core_transform_op(RCore *core, const char *arg, char op) {
	int i, j;
	ut64 len;
	char *str = NULL;
	ut8 *buf;

	buf = (ut8 *)malloc (core->blocksize);
	if (!buf) {
		return NULL;
	}
	memcpy (buf, core->block, core->blocksize);

	if (op!='e') {
		// fill key buffer either from arg or from clipboard
		if (arg) {  // parse arg for key
			// r_hex_str2bin() is guaranteed to output maximum half the
			// input size, or 1 byte if there is just a single nibble.
			str = (char *)malloc (strlen (arg) / 2 + 1);
			if (!str) {
				goto beach;
			}
			len = r_hex_str2bin (arg, (ut8 *)str);
			// Output is invalid if there was just a single nibble,
			// but in that case, len is negative (-1).
			if (len <= 0) {
				eprintf ("Invalid hexpair string\n");
				goto beach;
			}
		} else {  // use clipboard as key
			const ut8 *tmp = r_buf_data (core->yank_buf, &len);
			str = r_mem_dup (tmp, len);
			if (!str) {
				goto beach;
			}
		}
	} else {
		len = 0;
	}

	// execute the operand
	if (op=='e') {
		int wordsize = 1;
		char *os, *p, *s = strdup (arg);
		int n = 0, from = 0, to = UT8_MAX, dif = 0, step = 1;
		os = s;
		p = strchr (s, ' ');
		if (p) {
			*p = 0;
			from = r_num_math (core->num, s);
			s = p + 1;
		}
		p = strchr (s, ' ');
		if (p) {
			*p = 0;
			to = r_num_math (core->num, s);
			s = p + 1;
		}
		p = strchr (s, ' ');
		if (p) {
			*p = 0;
			step = r_num_math (core->num, s);
			s = p + 1;
			wordsize = r_num_math (core->num, s);
		} else {
			step = r_num_math (core->num, s);
		}
		free (os);
		eprintf ("from %d to %d step %d size %d\n", from, to, step, wordsize);
		dif = (to <= from)? UT8_MAX: to - from + 1;
		if (wordsize == 1) {
			from %= (UT8_MAX + 1);
		}
		if (dif < 1) {
			dif = UT8_MAX + 1;
		}
		if (step < 1) {
			step = 1;
		}
		if (wordsize < 1) {
			wordsize = 1;
		}
		if (wordsize == 1) {
			for (i = n = 0; i < core->blocksize; i++, n += step) {
				buf[i] = (ut8)(n % dif) + from;
			}
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
	} else if (op == '2' || op == '4' || op == '8') { // "wo2" "wo4" "wo8"
		int inc = op - '0';
		ut8 tmp;
		for (i = 0; (i + inc) <= core->blocksize; i += inc) {
			if (inc == 2) {
				tmp = buf[i];
				buf[i] = buf[i+1];
				buf[i+1] = tmp;
			} else if (inc == 4) {
				tmp = buf[i];
				buf[i] = buf[i+3];
				buf[i+3] = tmp;
				tmp = buf[i+1];
				buf[i+1] = buf[i+2];
				buf[i+2] = tmp;
			} else if (inc == 8) {
				tmp = buf[i];
				buf[i] = buf[i+7];
				buf[i+7] = tmp;

				tmp = buf[i+1];
				buf[i+1] = buf[i+6];
				buf[i+6] = tmp;

				tmp = buf[i+2];
				buf[i+2] = buf[i+5];
				buf[i+5] = tmp;

				tmp = buf[i+3];
				buf[i+3] = buf[i+4];
				buf[i+4] = tmp;
			} else {
				eprintf ("Invalid inc, use 2, 4 or 8.\n");
				break;
			}
		}
	} else {
		bool be = r_config_get_i (core->config, "cfg.bigendian");
		if (!be) {
			if (!__endian_swap ((ut8*)str, len, len)) {
				goto beach;
			}
		}
		for (i = j = 0; i < core->blocksize; i++) {
			switch (op) {
			case 'x': buf[i] ^= str[j]; break;
			case 'a': buf[i] += str[j]; break;
			case 's': buf[i] -= str[j]; break;
			case 'm': buf[i] *= str[j]; break;
			case 'w': buf[i] = str[j]; break;
			case 'd': buf[i] = (str[j])? (buf[i] / str[j]): 0; break;
			case 'r': buf[i] >>= str[j]; break;
			case 'l': buf[i] <<= str[j]; break;
			case 'o': buf[i] |= str[j]; break;
			case 'A': buf[i] &= str[j]; break;
			}
			j++;
			if (j >= len) {
				j = 0; /* cyclic key */
			}
		}
	}

	free (str);
	return buf;
beach:
	free (str);
	free (buf);
	return NULL;
}

R_API int r_core_write_op(RCore *core, const char *arg, char op) {
	ut8 *buf = r_core_transform_op(core, arg, op);
	if (!buf) {
		return false;
	}
	int ret = r_core_write_at (core, core->offset, buf, core->blocksize);
	free (buf);
	return ret;
}

// Get address-specific bits and arch at a certain address.
// If there are no specific infos (i.e. asm.bits and asm.arch should apply), the bits and arch will be 0 or NULL respectively!
R_API void r_core_arch_bits_at(RCore *core, ut64 addr, R_OUT R_NULLABLE int *bits, R_OUT R_BORROW R_NULLABLE const char **arch) {
	int bitsval = 0;
	const char *archval = NULL;
	RBinObject *o = r_bin_cur_object (core->bin);
	RBinSection *s = o ? r_bin_get_section_at (o, addr, core->io->va) : NULL;
	if (s) {
		if (!core->fixedarch) {
			archval = s->arch;
		}
		if (!core->fixedbits && s->bits) {
			// only enforce if there's one bits set
			switch (s->bits) {
			case R_SYS_BITS_16:
			case R_SYS_BITS_32:
			case R_SYS_BITS_64:
				bitsval = s->bits * 8;
				break;
			}
		}
	}
	//if we found bits related with anal hints pick it up
	if (bits && !bitsval && !core->fixedbits) {
		bitsval = r_anal_hint_bits_at (core->anal, addr, NULL);
	}
	if (arch && !archval && !core->fixedarch) {
		archval = r_anal_hint_arch_at (core->anal, addr, NULL);
	}
	if (bits && bitsval) {
		*bits = bitsval;
	}
	if (arch && archval) {
		*arch = archval;
	}
}

R_API void r_core_seek_arch_bits(RCore *core, ut64 addr) {
	int bits = 0;
	const char *arch = NULL;
	r_core_arch_bits_at (core, addr, &bits, &arch);
	if (bits) {
		r_config_set_i (core->config, "asm.bits", bits);
	}
	if (arch) {
		r_config_set (core->config, "asm.arch", arch);
	}
}

R_API bool r_core_seek(RCore *core, ut64 addr, bool rb) {
	core->offset = r_io_seek (core->io, addr, R_IO_SEEK_SET);
	if (rb) {
		r_core_block_read (core);
	}
	if (core->binat) {
		RBinFile *bf = r_bin_file_at (core->bin, core->offset);
		if (bf) {
			core->bin->cur = bf;
			r_bin_select_bfid (core->bin, bf->id);
			// XXX r_core_cmdf (core, "obb %d", bf->id);
		} else {
			core->bin->cur = NULL;
		}
	}
	return core->offset == addr;
}

R_API int r_core_seek_delta(RCore *core, st64 addr) {
	ut64 tmp = core->offset;
	if (addr == 0) {
		return true;
	}
	if (addr > 0LL) {
		/* TODO: check end of file */
		addr += tmp;
	} else {
		/* check < 0 */
		if (-addr > tmp) {
			addr = 0;
		} else {
			addr += tmp;
		}
	}
	core->offset = addr;
	return r_core_seek (core, addr, true);
}

// TODO: kill this wrapper
R_API bool r_core_write_at(RCore *core, ut64 addr, const ut8 *buf, int size) {
	r_return_val_if_fail (core && buf && addr != UT64_MAX, false);
	if (size < 1) {
		return false;
	}
	bool ret = r_io_write_at (core->io, addr, buf, size);
	if (addr >= core->offset && addr <= core->offset + core->blocksize - 1) {
		r_core_block_read (core);
	}
	return ret;
}

R_API bool r_core_extend_at(RCore *core, ut64 addr, int size) {
	if (!core->io || !core->io->desc || size < 1) {
		return false;
	}
	int io_va = r_config_get_i (core->config, "io.va");
	if (io_va) {
		RIOMap *map = r_io_map_get_at (core->io, core->offset);
		if (map) {
			addr = addr - r_io_map_begin (map) + map->delta;
		}
		r_config_set_i (core->config, "io.va", false);
	}
	int ret = r_io_extend_at (core->io, addr, size);
	if (addr >= core->offset && addr <= core->offset+core->blocksize) {
		r_core_block_read (core);
	}
	r_config_set_i (core->config, "io.va", io_va);
	return ret;
}

R_API int r_core_shift_block(RCore *core, ut64 addr, ut64 b_size, st64 dist) {
	// bstart - block start, fstart file start
	ut64 fend = 0, fstart = 0, bstart = 0, file_sz = 0;
	ut8 * shift_buf = NULL;
	int res = false;

	if (!core->io || !core->io->desc) {
		return false;
	}

	if (b_size == 0 || b_size == (ut64) -1) {
		r_io_use_fd (core->io, core->io->desc->fd);
		file_sz = r_io_size (core->io);
		if (file_sz == UT64_MAX) {
			file_sz = 0;
		}
#if 0
		bstart = r_io_seek (core->io, addr, R_IO_SEEK_SET);
		fend = r_io_seek (core->io, 0, R_IO_SEEK_END);
		if (fend < 1) {
			fend = 0;
		}
#else
		bstart = 0;
		fend = file_sz;
#endif
		fstart = file_sz - fend;
		b_size = fend > bstart ? fend - bstart: 0;
	}

	if ((st64)b_size < 1) {
		return false;
	}
	shift_buf = calloc (b_size, 1);
	if (!shift_buf) {
		eprintf ("Cannot allocated %d byte(s)\n", (int)b_size);
		return false;
	}

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
	if (addr + dist < fstart) {
		res = false;
	// addr + dist > file_end
	} else if ( (addr) + dist > fend) {
		res = false;
	} else {
		r_io_read_at (core->io, addr, shift_buf, b_size);
		r_io_write_at (core->io, addr + dist, shift_buf, b_size);
		res = true;
	}
	r_core_seek (core, addr, true);
	free (shift_buf);
	return res;
}

R_API int r_core_block_read(RCore *core) {
	if (core && core->block) {
		return r_io_read_at (core->io, core->offset, core->block, core->blocksize);
	}
	return -1;
}
