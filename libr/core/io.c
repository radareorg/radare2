/* radare - LGPL - Copyright 2009-2010 pancake<nopcode.org> */

#include "r_core.h"

R_API int r_core_write_op(RCore *core, const char *arg, char op) {
	char *str;
	ut8 *buf;
	int i,j;
	int ret;
	int len;

	// XXX we can work with config.block instead of dupping it
	buf = (ut8 *)malloc (core->blocksize);
	str = (char *)malloc (strlen(arg));
	if (buf == NULL || str == NULL) {
		free (buf);
		free (str);
		return R_FALSE;
	}
	memcpy (buf, core->block, core->blocksize);
	len = r_hex_str2bin (arg, (ut8 *)str);
	if (len==-1) {
		eprintf ("Invalid hexpair string\n");
		return R_FALSE;
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
			case 'd': if (str[j]) buf[i] /= str[j];
				else buf[i] = 0; break;
			case 'r': buf[i] >>= str[j]; break;
			case 'l': buf[i] <<= str[j]; break;
			case 'o': buf[i] |= str[j]; break;
			case 'A': buf[i] &= str[j]; break;
			}
			j++; if (j>=len) j=0; /* cyclic key */
		}
	}

	ret = r_core_write_at (core, core->offset, buf, core->blocksize);
	free (buf);
	return ret;
}

R_API int r_core_seek(RCore *core, ut64 addr, int rb) {
	ut64 old = core->offset;

	/* XXX unnecesary call */
	r_io_set_fd (&core->io, core->file->fd);
	core->offset = r_io_seek (&core->io, addr, R_IO_SEEK_SET);
	if (rb) {
		int ret = r_core_block_read (core, 0);
		if (ret<1 && !core->ffio) {
			core->offset = old;
			eprintf ("Cannot read block at 0x%08llx\n", addr);
		} else
		if (ret != core->blocksize) {
			if (core->ffio) {
				memset (core->block, 0xff, core->blocksize);
				core->offset = addr;
			} else memset (core->block+ret, 0xff, core->blocksize-ret);
		}
	}
	return core->offset;
}

R_API int r_core_write_at(RCore *core, ut64 addr, const ut8 *buf, int size) {
	int ret = r_io_set_fd (&core->io, core->file->fd);
	if (ret != -1) {
		ret = r_io_write_at (&core->io, addr, buf, size);
		if (addr >= core->offset && addr <= core->offset+core->blocksize)
			r_core_block_read (core, 0);
	}
	return (ret==-1)?R_FALSE:R_TRUE;
}

R_API int r_core_block_read(RCore *core, int next) {
	if (core->file == NULL)
		return -1;
	r_io_set_fd (&core->io, core->file->fd);
	r_io_seek (&core->io, core->offset+((next)?core->blocksize:0), R_IO_SEEK_SET);
	return r_io_read (&core->io, core->block, core->blocksize);
}

R_API int r_core_read_at(RCore *core, ut64 addr, ut8 *buf, int size) {
	int ret = r_io_set_fd (&core->io, core->file->fd);
	ret = r_io_read_at (&core->io, addr, buf, size);
	if (addr>=core->offset && addr<=core->offset+core->blocksize)
		r_core_block_read (core, 0);
	return (ret==-1)?R_FALSE:R_TRUE;
}
