/* radare - LGPL - Copyright 2013 - pancake */

#include "r_io.h"
#include "r_lib.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

#define MEMSIZE 0x10000

typedef struct {
	int fd;
	ut8 *buf;
	ut32 size;
} RIOMalloc;

#define RIOHEX_FD(x) (((RIOMalloc*)x->data)->fd)
#define RIOHEX_SZ(x) (((RIOMalloc*)x->data)->size)
#define RIOHEX_BUF(x) (((RIOMalloc*)x->data)->buf)

static int __write(RIO *io, RIODesc *fd, const ut8 *buf, int count) {
	const char *ffffuuuu = "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
		"\xff\xff\xff\xff\xff\xff";
	const char *pathname;
	const ut8 *b;
	ut8 cksum;
	FILE *out;
	int i, j;
	if (fd == NULL || fd->data == NULL)
		return -1;
	pathname = fd->name + 7;
	out = fopen (pathname, "w");
	if (!out) {
		eprintf ("Cannot open '%s' for writing\n", pathname);
		return -1;
	}
	/* mem write */
	if (io->off+count > RIOHEX_SZ (fd))
		count -= (io->off+count-(RIOHEX_SZ (fd)));
	if (count>0)
		memcpy (RIOHEX_BUF (fd)+io->off, buf, count);
	/* disk write */
	for (i=0; i<MEMSIZE; i+=0x10) {
		b = RIOHEX_BUF (fd)+i;
		if (memcmp (ffffuuuu, b, 0x10)) {
			cksum = 0x10;
			cksum += i>>8;
			cksum += i;
			for (j=0; j<0x10; j++) cksum += b[j];
			cksum = 0-cksum;
			fprintf (out, ":10%04x00%02x%02x%02x%02x%02x%02x%02x"
				"%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",
				i, b[0], b[1], b[2], b[3], b[4], b[5], b[6],
				b[7], b[8], b[9], b[10], b[11], b[12], b[13],
				b[14], b[15], cksum);
		}
	}
	fprintf (out, ":00000001FF\n");
	fclose (out);
	return count;
}

static int __read(RIO *io, RIODesc *fd, ut8 *buf, int count) {
	memset (buf, 0xff, count);
	if (fd == NULL || fd->data == NULL)
		return -1;
	if (io->off>= RIOHEX_SZ (fd))
		return -1;
	if (io->off+count >= RIOHEX_SZ (fd))
		count = RIOHEX_SZ (fd) - io->off;
	memcpy (buf, RIOHEX_BUF (fd)+io->off, count);
	return count;
}

static int __close(RIODesc *fd) {
	RIOMalloc *riom;
	if (fd == NULL || fd->data == NULL)
		return -1;
	riom = fd->data;
	free (riom->buf);
	riom->buf = NULL;
	free (fd->data);
	fd->data = NULL;
	fd->state = R_IO_DESC_TYPE_CLOSED;
	return 0;
}

static ut64 __lseek(struct r_io_t *io, RIODesc *fd, ut64 offset, int whence) {
	switch (whence) {
	case SEEK_SET: return offset;
	case SEEK_CUR: return io->off + offset;
	case SEEK_END: return RIOHEX_SZ (fd);
	}
	return offset;
}

static int __plugin_open(RIO *io, const char *pathname, ut8 many) {
	return (!strncmp (pathname, "ihex://", 7));
}

#if 0
:10010000214601360121470136007EFE09D2190140
:100110002146017EB7C20001FF5F16002148011988
:10012000194E79234623965778239EDA3F01B2CAA7
:100130003F0156702B5E712B722B732146013421C7
:00000001FF

  :  Start code
  1 Byte count
  2 byte Address
  1 byte Record type (00 data 01 eof)
  N bytes Data
  1 byte Checksum (sum 00)
#endif

// TODO: implement bin2ihex function
static int ihex2bin(ut8 *mem, char *str) {
	ut32 addr = 0;
	char *eol, *ptr = str;
	ut8 cksum, *memptr;
	int bc, type, byte, i, l, blen = 0;
	do {
		l = sscanf (ptr, ":%02x%04x%02x", &bc, &addr, &type);
		if (l != 3) {
			eprintf ("Invalid data in ihex file (%s)\n", ptr);
			break;
		}
		l = 1+ (l*2);
		switch (type) {
		case 0: // DATA
			eol = strchr (ptr+1, ':');
			if (eol) *eol = 0;
			cksum = bc;
			cksum += addr>>8;
			cksum += addr&0xff;
			cksum += type;
			memptr = mem + addr;
			if ((addr+bc)>MEMSIZE)
				bc = MEMSIZE-addr;
			for (i=0; i<bc; i++) {
				sscanf (ptr+9+ (i*2), "%02x", &byte);
				memptr[i] = byte;
				cksum += byte;
			}
			if (eol) {
				// checksum
				sscanf (ptr+9+(i*2), "%02x", &byte);
				cksum += byte;
				if (cksum != 0) {
					ut8 fixedcksum = 0-(cksum-byte);
					eprintf ("Checksum failed %02x (got %02x expected %02x)\n",
						cksum, byte, fixedcksum);
				}
				*eol = ':';
			}
			ptr = eol;
			break;
		case 1: // EOF
			ptr = NULL;
			break;
		case 2:
		case 3:
		case 4:
		case 5:
			ptr = strchr(ptr + 1, ':');
			break;
		}
	} while (ptr);

	return blen;
}

static RIODesc *__open(RIO *io, const char *pathname, int rw, int mode) {
	int ret;
	RIOMalloc *mal = NULL;
	char *str = NULL;
	if (__plugin_open (io, pathname, 0)) {
		str = r_file_slurp (pathname+7, NULL);
		if (!str) return NULL;
		mal = R_NEW (RIOMalloc);
		if (!mal) {
			free (str);
			return NULL;
		}
		mal->fd = -1; /* causes r_io_desc_new() to set the correct fd */
		mal->buf = malloc (MEMSIZE);
		if (!mal->buf) {
			free (str);
			free (mal);
			return NULL;
		}
		mal->size = MEMSIZE;
		memset (mal->buf, 0xff, mal->size);
		ret = ihex2bin (mal->buf, str);
		if (ret) eprintf ("ihex: checksum issues?\n");
		free (str);
		return r_io_desc_new (&r_io_plugin_ihex,
			mal->fd, pathname, rw, mode, mal);
	}
	return NULL;
}

RIOPlugin r_io_plugin_ihex = {
	.name = "ihex",
        .desc = "Intel HEX file (ihex://eeproms.hex)",
	.license = "LGPL",
        .open = __open,
        .close = __close,
	.read = __read,
        .plugin_open = __plugin_open,
	.lseek = __lseek,
	.write = __write,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_hex
};
#endif
