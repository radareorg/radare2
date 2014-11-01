/* radare2 - LGPL - Copyright 2009-2014 - pancake */

#include "r_core.h"

R_API int r_core_setup_debugger (RCore *r, const char *debugbackend) {
	int pid, *p = NULL;
	ut8 is_gdb = (strcmp (debugbackend, "gdb") == 0);
	RIODesc * fd = r->file ? r->file->desc : NULL;
	p = fd ? fd->data : NULL;
	r_config_set_i (r->config, "cfg.debug", 1);
	if (!p) {
		eprintf ("Invalid debug io\n");
		return R_FALSE;
	}

	pid = *p; // 1st element in debugger's struct must be int
	r_config_set (r->config, "io.ff", "true");
	if (is_gdb) r_core_cmd (r, "dh gdb", 0);
	else r_core_cmdf (r, "dh %s", debugbackend);
	r_core_cmdf (r, "dpa %d", pid);
	r_core_cmdf (r, "dp=%d", pid);
	r_core_cmd (r, ".dr*", 0);
	/* honor dbg.bep */
	{
		const char *bep = r_config_get (r->config, "dbg.bep");
		if (bep) {
			if (!strcmp (bep, "loader")) {
				/* do nothing here */
			} else if (!strcmp (bep, "entry"))
				r_core_cmd (r, "dcu entry0", 0);
		    else
                r_core_cmdf (r, "dcu %s", bep);
		}
	}
	r_core_cmd (r, "sr pc", 0);
	if (r_config_get_i (r->config, "dbg.status")) {
		r_config_set (r->config, "cmd.prompt", ".dr* ; drd ; sr pc;pi 1;s-");
	} else r_config_set (r->config, "cmd.prompt", ".dr*");
	r_config_set (r->config, "cmd.vprompt", ".dr*");
	return R_TRUE;
}

R_API int r_core_seek_base (RCore *core, const char *hex) {
	int i;
	ut64 n = 0;
	ut64 addr = core->offset;
	ut64 mask = 0LL;
	char * p;

	i = strlen (hex) * 4;
	p = malloc (strlen (hex)+10);
	if (p) {
		strcpy (p, "0x");
		strcpy (p+2, hex);
		n = r_num_math (core->num, p);
		free (p);
	}
	mask = UT64_MAX << i;
	addr = (addr & mask) | n;
	return r_core_seek (core, addr, 1);
}

R_API int r_core_dump(RCore *core, const char *file, ut64 addr, ut64 size) {
	ut64 i;
	ut8 *buf;
	int bs = core->blocksize;
	FILE *fd;
	r_sys_truncate (file, 0);
	fd = r_sandbox_fopen (file, "wb");
	if (!fd) {
		eprintf ("Cannot open '%s' for writing\n", file);
		return R_FALSE;
	}
	buf = malloc (bs);
	r_cons_break (NULL, NULL);
	for (i=0; i<size; i+=bs) {
		if (r_cons_singleton ()->breaked)
			break;
		if ((i+bs)>size)
			bs = size-i;
		r_io_read_at (core->io, addr+i, buf, bs);
		if (fwrite (buf, bs, 1, fd) <1) {
			eprintf ("write error\n");
			break;
		}
	}
	eprintf ("dumped 0x%"PFMT64x" bytes\n", i);
	r_cons_break_end ();
	fclose (fd);
	free (buf);
	return R_TRUE;
}

R_API int r_core_write_op(RCore *core, const char *arg, char op) {
	int i, j, len, ret = R_FALSE;
	char *str;
	ut8 *buf;

	// XXX we can work with config.block instead of dupping it
	buf = (ut8 *)malloc (core->blocksize);
	str = (char *)malloc (strlen (arg)+1);
	if (buf == NULL || str == NULL)
		goto beach;
	memcpy (buf, core->block, core->blocksize);
	if (op!='e') {
		len = r_hex_str2bin (arg, (ut8 *)str);
		if (len==-1) {
			eprintf ("Invalid hexpair string\n");
			goto beach;
		}
	} else len = 0;

	if (op=='e') {
		char *p, *s = strdup (arg);
		int n, from = 0, to = 0, dif = 0, step = 1;
		n = from = to;
		to = UT8_MAX;
		//
		p = strchr (s, ' ');
		if (p) {
			*p = 0;
			step = atoi (p+1);
		}
		p = strchr (s, '-');
		if (p) {
			*p = 0;
			to = atoi (p+1);
		}
		if (to<1 || to>UT8_MAX) to = UT8_MAX;
		from = atoi (s);
		free (s);
		dif = (to<=from)? UT8_MAX: (to-from)+1;
		from %= (UT8_MAX+1);
		if (dif<1) dif = UT8_MAX+1;
		if (step<1) step = 1;
		for (i=n=0; i<core->blocksize; i++, n+= step)
			buf[i] = (ut8)(n%dif)+from;
	} else
	if (op=='2' || op=='4') {
		op -= '0';
		for (i=0; i<core->blocksize; i+=op) {
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

R_API int r_core_seek_archbits (RCore *core, ut64 addr) {
	static char *oldarch = NULL;
	static int oldbits = 32;
	int bits = 0;// = core->io->section->bits;
	const char *arch = r_io_section_get_archbits (core->io, addr, &bits);
	if (arch && bits) {
		if (!oldarch) {
			RBinInfo *info = r_bin_get_info (core->bin);
			if (info) {
				oldarch = strdup (info->arch);
				oldbits = info->bits;
			} else {
				oldarch = strdup (r_config_get (core->config, "asm.arch"));
				oldbits = 32;
			}
		}
		r_config_set (core->config, "asm.arch", arch);
		r_config_set_i (core->config, "asm.bits", bits);
		return 1;
	}
	if (oldarch) {
		r_config_set (core->config, "asm.arch", oldarch);
		r_config_set_i (core->config, "asm.bits", oldbits);
		free (oldarch);
		oldarch = NULL;
	}
	return 0;
}

R_API boolt r_core_seek(RCore *core, ut64 addr, boolt rb) {
	RIOSection *newsection;
	ut64 old = core->offset;
	ut64 ret;

	core->offset = addr;
	/* XXX unnecesary call */
	//r_io_use_fd (core->io, core->file->desc);
	core->io->section = core->section; // HACK
	ret = r_io_seek (core->io, addr, R_IO_SEEK_SET);
	newsection = core->io->section;

	if (ret == UT64_MAX) {
		//eprintf ("RET =%d %llx\n", ret, addr);
		/*
		   XXX handle read errors correctly
		   if (core->io->ff) {
		   core->offset = addr;
		   } else return R_FALSE;
		 */
		//core->offset = addr;
		if (!core->io->va)
			return R_FALSE;
		//memset (core->block, 0xff, core->blocksize);
	} else core->offset = addr;
	if (rb) {
		ret = r_core_block_read (core, 0);
		if (core->io->ff) {
			if (ret<1 || ret > core->blocksize)
				memset (core->block, 0xff, core->blocksize);
			else memset (core->block+ret, 0xff, core->blocksize-ret);
			ret = core->blocksize;
			core->offset = addr;
		} else {
			if (ret<1) {
				core->offset = old;
				//eprintf ("Cannot read block at 0x%08"PFMT64x"\n", addr);
			}
		}
	}
	if (core->section != newsection) {
		r_core_seek_archbits (core, core->offset);
		core->section = newsection;
	}
	return (ret==-1)? R_FALSE: R_TRUE;
}

R_API int r_core_seek_delta(RCore *core, st64 addr) {
	ut64 tmp = core->offset;
	int ret;
	if (addr == 0)
		return R_TRUE;
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
	//ret = r_core_block_read (core, 0);
	//if (ret == -1)
	//	memset (core->block, 0xff, core->blocksize);
	//	core->offset = tmp;
	return ret;
}

R_API int r_core_write_at(RCore *core, ut64 addr, const ut8 *buf, int size) {
	int ret;
	if (!core->io || !core->file || size<1)
		return R_FALSE;
	ret = r_io_use_desc (core->io, core->file->desc);
	if (ret != -1) {
		ret = r_io_write_at (core->io, addr, buf, size);
		if (addr >= core->offset && addr <= core->offset+core->blocksize)
			r_core_block_read (core, 0);
	}
	return (ret==-1)? R_FALSE: R_TRUE;
}

R_API int r_core_extend_at(RCore *core, ut64 addr, int size) {
	int ret;
	if (!core->io || !core->file || size<1)
		return R_FALSE;
	//ret = r_io_use_fd (core->io, core->file->desc->fd);
	ret = r_io_use_desc (core->io, core->file->desc);
	if (ret != -1) {
		ret = r_io_extend_at (core->io, addr, size);
		if (addr >= core->offset && addr <= core->offset+core->blocksize)
			r_core_block_read (core, 0);
	}
	return (ret==-1)? R_FALSE: R_TRUE;
}

R_API int r_core_shift_block(RCore *core, ut64 addr, ut64 b_size, st64 dist) {
	// bstart - block start, fstart file start
	ut64 fend = 0, fstart = 0, bstart = 0, file_sz = 0;
	ut8 * shift_buf = NULL;
	int res = R_FALSE;

	if (b_size == 0 || b_size == (ut64) -1) {
		res = r_io_use_desc (core->io, core->file->desc);
		file_sz = r_io_size (core->io);
		bstart = r_io_seek (core->io, addr, R_IO_SEEK_SET);
		fend = r_io_seek (core->io, 0, R_IO_SEEK_END);
		fstart = file_sz - fend;
		b_size = fend > bstart ? fend - bstart: 0;
	}


	if (!core->io || !core->file || b_size<1)
		return R_FALSE;


	// XXX handling basic cases atm
	shift_buf = malloc (b_size);
	memset (shift_buf, 0, b_size);

	// cases
	// addr + b_size + dist > file_end
	//if ( (addr+b_size) + dist > file_end ) {
	//	res = R_FALSE;
	//}
	// addr + b_size + dist < file_start (should work since dist is signed)
	//else if ( (addr+b_size) + dist < 0 ) {
	//	res = R_FALSE;
	//}
	// addr + dist < file_start
	if ( addr + dist < fstart ) {
		res = R_FALSE;
	}
	// addr + dist > file_end
	else if ( (addr) + dist > fend) {
		res = R_FALSE;
	} else {
		res = r_io_use_desc (core->io, core->file->desc);
		r_io_read_at (core->io, addr, shift_buf, b_size);
		r_io_write_at (core->io, addr+dist, shift_buf, b_size);
		res = R_TRUE;
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
			core->io->raised = file->desc->fd;
			core->switch_file_view = 1;
			break;
		}
	}
	return file;
}

R_API int r_core_block_read(RCore *core, int next) {
	if (core->file == NULL && r_core_file_set_first_valid(core) == NULL) {
		memset (core->block, 0xff, core->blocksize);
		return -1;
	}
	if (core->file && core->switch_file_view) {
		r_io_use_desc (core->io, core->file->desc);
		r_core_bin_set_by_fd (core, core->file->desc->fd);	//needed?
		core->switch_file_view = 0;
	} else	r_io_use_fd (core->io, core->io->raised);		//possibly not needed
	return r_io_read_at (core->io, core->offset+((next)?core->blocksize:0), core->block, core->blocksize);
}

R_API int r_core_read_at(RCore *core, ut64 addr, ut8 *buf, int size) {
	if (!core->io || !core->file || !core->file->desc || size<1) {
		if (size>0)
			memset (buf, 0xff, size);
		return R_FALSE;
	}
	r_io_use_desc (core->io, core->file->desc);
	return r_io_read_at (core->io, addr, buf, size);
}

R_API int r_core_is_valid_offset (RCore *core, ut64 offset) {
	if (!core) {
		eprintf ("r_core_is_valid_offset: core is NULL\n");
		r_sys_backtrace ();
		return R_FAIL;
	}
	return r_io_is_valid_offset (core->io, offset);
}
