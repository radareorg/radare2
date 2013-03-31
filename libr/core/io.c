/* radare2 - LGPL - Copyright 2009-2013 - pancake */

#include "r_core.h"

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
	str = (char *)malloc (strlen (arg));
	if (buf == NULL || str == NULL)
		goto beach;
	memcpy (buf, core->block, core->blocksize);
	len = r_hex_str2bin (arg, (ut8 *)str);
	if (len==-1) {
		eprintf ("Invalid hexpair string\n");
		goto beach;
	}

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
	static int oldbits;
	int bits = 0;// = core->io->section->bits;
	const char *arch = r_io_section_get_archbits (core->io, core->offset, &bits);
	if (arch && bits) {
		oldarch = strdup (r_config_get (core->config, "asm.arch"));
		oldbits = r_config_get_i (core->config, "asm.bits");
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

	/* XXX unnecesary call */
	//r_io_set_fd (core->io, core->file->fd);
	core->io->section = core->section; // HACK
	ret = r_io_seek (core->io, addr, R_IO_SEEK_SET);
	newsection = core->io->section;

	if (ret == UT64_MAX) {
		//eprintf ("RET =%d %llx\n", ret, addr);
		/*
		   XXX handle read errors correctly
		   if (core->ffio) {
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
		if (core->ffio) {
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
	if (core->section != newsection) {//&& core->io->section->arch) {
		r_core_seek_archbits (core, core->offset);
		core->section = core->io->section;
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
	ret = r_io_set_fd (core->io, core->file->fd);
	if (ret != -1) {
		ret = r_io_write_at (core->io, addr, buf, size);
		if (addr >= core->offset && addr <= core->offset+core->blocksize)
			r_core_block_read (core, 0);
	}
	core->file->size = r_io_size (core->io);
	return (ret==-1)? R_FALSE: R_TRUE;
}

R_API int r_core_block_read(RCore *core, int next) {
	ut64 off;
	if (core->file == NULL) {
		memset (core->block, 0xff, core->blocksize);
		return -1;
	}
	r_io_set_fd (core->io, core->file->fd);
	off = r_io_seek (core->io, core->offset+((next)?core->blocksize:0), R_IO_SEEK_SET);
	if (off == UT64_MAX) {
		memset (core->block, 0xff, core->blocksize);
// TODO: do continuation in io
		if (!core->io->va)
			return -1;
	}
	return (int)r_io_read (core->io, core->block, core->blocksize);
}

R_API int r_core_read_at(RCore *core, ut64 addr, ut8 *buf, int size) {
	int ret;
	if (!core->io || !core->file || size<1)
		return R_FALSE;
#if 0
	r_io_set_fd (core->io, core->file->fd); // XXX ignore ret? -- ultra slow method.. inverse resolution of io plugin brbrb
	ret = r_io_read_at (core->io, addr, buf, size);
	if (addr>=core->offset && addr<=core->offset+core->blocksize)
		r_core_block_read (core, 0);
#else
	r_io_set_fd (core->io, core->file->fd); // XXX ignore ret? -- ultra slow method.. inverse resolution of io plugin brbrb
	//ret = r_io_read_at (core->io, addr, buf, size);
	r_io_seek (core->io, addr, R_IO_SEEK_SET);
	ret = r_io_read (core->io, buf, size);
	if (ret != size) {
		if (ret>=size || ret<0) ret = 0;
		memset (buf+ret, 0xff, size-ret);
	}
	if (addr>=core->offset && addr<=core->offset+core->blocksize)
		r_core_block_read (core, 0);
#endif
	return (ret==size); //UT64_MAX);
}
