/* radare2 - LGPL - Copyright 2009-2023 - pancake */

#include "r_core.h"

R_API int r_core_setup_debugger(RCore *r, const char *debugbackend, bool attach) {
	int pid, *p = NULL;
	bool is_gdb = !strcmp (debugbackend, "gdb");
	RIODesc * fd = r->io->desc;
	const char *prompt = NULL;

	p = fd ? fd->data : NULL;
	r_config_set_b (r->config, "cfg.debug", true);
	if (!p) {
		R_LOG_ERROR ("Invalid debug io");
		return false;
	}

	r_config_set_b (r->config, "io.ff", true);
	r_core_cmdf (r, "dL %s", debugbackend);
	if (!is_gdb) {
		pid = r_io_desc_get_pid (fd);
		if (pid >= 0) {
			r_core_cmdf (r, "dp=%d", pid);
			if (attach) {
				r_core_cmdf (r, "dpa %d", pid);
			}
		} else {
			R_LOG_ERROR ("Cannot retrieve pid from io");
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

R_API int r_core_seek_base(RCore *core, const char *hex) {
	ut64 addr = r_num_tail (core->num, core->addr, hex);
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
		R_LOG_ERROR ("Cannot open coredump '%s' for writing", file);
		return false;
	}
	/* some io backends seems to be buggy in those cases */
	if (bs > 4096) {
		bs = 4096;
	}
	buf = malloc (bs);
	if (!buf) {
		R_LOG_ERROR ("Cannot alloc %d byte(s)", bs);
		fclose (fd);
		return false;
	}
	r_cons_break_push (NULL, NULL);
	for (i = 0; i < size; i += bs) {
		if (r_kons_is_breaked (core->cons)) {
			break;
		}
		if ((i + bs) > size) {
			bs = size - i;
		}
		r_io_read_at (core->io, addr + i, buf, bs);
		if (fwrite (buf, bs, 1, fd) < 1) {
			R_LOG_ERROR ("write error");
			break;
		}
	}
	r_cons_break_pop ();
	fclose (fd);
	free (buf);
	return true;
}

R_API ut8* r_core_transform_op(RCore *core, const char *arg, char op) {
	int i, j;
	ut64 len;
	char *str = NULL;
	ut8 *buf = (ut8 *)malloc (core->blocksize);
	if (!buf) {
		return NULL;
	}
	bool isnum = false;
	const char *plus = arg? strchr (arg, '+'): NULL;
	int numsize = 1;
	if (plus) {
		numsize = (*arg == '+')? 1: atoi (arg);
		if (numsize < 1) {
			numsize = 1;
		}
		isnum = true;
		arg = r_str_trim_head_ro (plus + 1);
	}
	if (op == 'i') { // "woi"
		int hbs = core->blocksize / 2;
		int j = core->blocksize - 1;
		for (i = 0; i < hbs; i++, j--) {
			buf[i] = core->block[j];
			buf[j] = core->block[i];
		}
		return buf;
	}
	memcpy (buf, core->block, core->blocksize);

	if (op != 'e') {
		// fill key buffer either from arg or from clipboard
		if (arg && !isnum) {  // parse arg for key
			// r_hex_str2bin() is guaranteed to output maximum half the
			// input size, or 1 byte if there is just a single nibble.
			str = (char *)malloc (((strlen (arg) + 2) / 2) + 1);
			if (!str) {
				goto beach;
			}
			int xlen = r_hex_str2bin (arg, (ut8 *)str);
			// Output is invalid if there was just a single nibble,
			// but in that case, len is negative (-1).
			if (xlen <= 0) {
				R_LOG_ERROR ("Invalid hexpair string");
				goto beach;
			}
			len = xlen;
		} else {  // use clipboard as key
			const ut8 *tmp = r_buf_data (core->yank_buf, &len);
			if (tmp && len > 0) {
				str = r_mem_dup (tmp, len);
				if (!str) {
					goto beach;
				}
			}
		}
	} else {
		len = 0;
	}

	// execute the operand
	if (op == 'e') {
		int wordsize = 1;
		char *os, *p, *s = strdup (arg? arg: "");
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
		R_LOG_INFO ("from %d to %d step %d size %d", from, to, step, wordsize);
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
			R_LOG_ERROR ("Invalid word size. Use 1, 2, 4 or 8");
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
				R_LOG_ERROR ("Invalid inc, use 2, 4 or 8");
				break;
			}
		}
	} else {
		if (isnum) {
			ut64 n = r_num_math (core->num, arg);
			bool be = r_config_get_b (core->config, "cfg.bigendian");
			free (str);
			len = 0;
			str = calloc (8, 1);
			if (R_LIKELY (str)) {
				switch (numsize) {
				case 1:
					if (n > UT8_MAX) {
						R_LOG_ERROR ("%d doesnt fit in ut8.max", n);
						goto beach;
					}
					str[0] = n;
					break;
				case 2:
					if (n > UT16_MAX) {
						R_LOG_ERROR ("%d doesnt fit in ut16.max", n);
						goto beach;
					}
					r_write_ble16 (str, n, be);
					break;
				case 4:
					if (n > UT32_MAX) {
						R_LOG_ERROR ("%d doesnt fit in ut32.max", n);
						goto beach;
					}
					r_write_ble32 (str, n, be);
					break;
				case 8:
					r_write_ble64 (str, n, be);
					break;
				}
				len = numsize;
			}
		}
		if (str) {
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
	}

	free (str);
	return buf;
beach:
	free (str);
	free (buf);
	return NULL;
}

R_API int r_core_write_op(RCore *core, const char *arg, char op) {
	ut8 *buf = r_core_transform_op (core, arg, op);
	if (!buf) {
		return false;
	}
	int ret = r_core_write_at (core, core->addr, buf, core->blocksize);
	free (buf);
	return ret;
}

R_API void r_core_arch_bits_at(RCore *core, ut64 addr, R_OUT int * R_NULLABLE bits, R_OUT R_BORROW const char ** R_NULLABLE arch) {
	int bitsval = 0;
	const char *archval = NULL;
	if (!core->fixedarch || !core->fixedbits) {
		RBinObject *o = r_bin_cur_object (core->bin);
		RBinSection *s = o ? r_bin_get_section_at (o, addr, core->io->va) : NULL;
		if (s) {
			if (!core->fixedarch) {
				archval = s->arch;
			}
			if (!core->fixedbits && s->bits) {
				// only enforce if there's one bits set
				if (R_SYS_BITS_CHECK (s->bits, 16)) {
					bitsval = 16;
				} else if (R_SYS_BITS_CHECK (s->bits, 32)) {
					bitsval = 32;
				} else if (R_SYS_BITS_CHECK (s->bits, 64)) {
					bitsval = 64;
				}
			}
		}
	}
	// if we found bits related with anal hints pick it up
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
		if (bits != core->anal->config->bits) {
			r_config_set_i (core->config, "asm.bits", bits);
		}
	}
	if (arch) {
		if (core->anal->config->arch && strcmp (arch, core->anal->config->arch)) {
			r_config_set (core->config, "asm.arch", arch);
		}
	}
}

R_API bool r_core_seek(RCore *core, ut64 addr, bool rb) {
	if (!rb && addr == core->addr) {
		return false;
	}
	core->addr = r_io_seek (core->io, addr, R_IO_SEEK_SET);
	if (rb) {
		r_core_block_read (core);
	}
	if (core->binat) {
		// XXX wtf is this code doing here
		RBinFile *bf = r_bin_file_at (core->bin, core->addr);
		if (bf) {
			core->bin->cur = bf;
			r_bin_select_bfid (core->bin, bf->id);
			// XXX r_core_cmdf (core, "obb %d", bf->id);
		} else {
			core->bin->cur = NULL;
		}
	}
	return core->addr == addr;
}

R_API int r_core_seek_delta(RCore *core, st64 addr) {
	ut64 tmp = core->addr;
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
	core->addr = addr;
	return r_core_seek (core, addr, true);
}

// TODO: R2_600 deprecate this wrapper
R_API bool r_core_write_at(RCore *core, ut64 addr, const ut8 *buf, int size) {
	R_RETURN_VAL_IF_FAIL (core && buf, false);
	if (size < 1) {
		return false;
	}
	bool ret = false;
	if (core->io->va && !r_config_get_b (core->config, "io.voidwrites")) {
		ut64 vaddr = addr;
		if ((UT64_MAX - (size - 1)) < addr) {
			int len = UT64_MAX - addr + 1;
			if (!r_io_map_locate (core->io, &vaddr, len, 1) || vaddr != addr) {
				ret = r_io_write_at (core->io, addr, buf, size);
				goto beach;
			}
			vaddr = 0;
			if (!r_io_map_locate (core->io, &vaddr, size - len, 1) || vaddr != 0ULL) {
				ret = r_io_write_at (core->io, addr, buf, size);
			} else {
				return false;
			}
		} else if (!r_io_map_locate (core->io, &vaddr, size, 1) || vaddr != addr) {
			ret = r_io_write_at (core->io, addr, buf, size);
		} else {
			return false;
		}
	} else {
		ret = r_io_write_at (core->io, addr, buf, size);
	}
beach:
	if (addr >= core->addr && addr <= core->addr + core->blocksize - 1) {
		r_core_block_read (core);
	}
	return ret;
}

R_API bool r_core_extend_at(RCore *core, ut64 addr, int size) {
	R_RETURN_VAL_IF_FAIL (core && core->io, false);
	if (!core->io->desc || size < 1 || addr == UT64_MAX) {
		return false;
	}
	const bool io_va = r_config_get_b (core->config, "io.va");
	if (io_va) {
		RIOMap *map = r_io_map_get_at (core->io, core->addr);
		if (map) {
			addr = addr - r_io_map_begin (map) + map->delta;
		}
		r_config_set_i (core->config, "io.va", false);
	}
	int ret = r_io_extend_at (core->io, addr, size);
	if (addr >= core->addr && addr <= core->addr + core->blocksize) {
		r_core_block_read (core);
	}
	r_config_set_b (core->config, "io.va", io_va);
	return ret;
}

R_API bool r_core_shift_block(RCore *core, ut64 addr, ut64 b_size, st64 dist) {
	// bstart - block start, fstart file start
	ut64 fend = 0, fstart = 0, bstart = 0, file_sz = 0;
	ut8 * shift_buf = NULL;
	bool res = false;

	if (!core->io || !core->io->desc) {
		return false;
	}

	if (b_size == 0 || b_size == UT64_MAX) {
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
		R_LOG_ERROR ("Cannot allocate %d byte(s)", (int)b_size);
		return false;
	}

	// cases
	// addr + b_size + dist > file_end
	//if ((addr+b_size) + dist > file_end ) {
	//	res = false;
	//}
	// addr + b_size + dist < file_start (should work since dist is signed)
	//else if ((addr+b_size) + dist < 0 ) {
	//	res = false;
	//}
	// addr + dist < file_start
	if (addr + dist < fstart) {
		res = false;
	// addr + dist > file_end
	} else if ((addr) + dist > fend) {
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
	int res = -1;
	R_CRITICAL_ENTER (core);
	if (core && core->block) {
		res = r_io_read_at (core->io, core->addr, core->block, core->blocksize);
	}
	R_CRITICAL_LEAVE (core);
	return res;
}
