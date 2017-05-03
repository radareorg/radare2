/* radare - LGPL - Copyright 2013-2016 - pancake, fenugrec */

/*
*** .hex format description : every line follows this pattern
:SSAAAARR<xx*SS>KK
SS: num of "xx" bytes
AAAA lower 16bits of address for resulting data (==0 for 01, 02, 04 and 05 records)
RR: rec type:
	00 data
	01 EOF (always SS=0, AAAA=0)
	02 extended segment addr reg: (always SS=02, AAAA=0); data = 0x<xxyy> => bits 4..19 of following addresses
	04 extended linear addr reg: (always SS=02, AAAA=0); data = 0x<xxyy> => bits 16..31 of following addresses
	05 non-standard; could be "start linear address" AKA "entry point".
KK = 0 - (sum of all bytes)

//sauce : http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.faqs/ka9903.html

**** example records
:02000002fffffe		#rec 02 : new seg = 0xffff, so next addresses will be (seg<<4)+AAAA
:02000000556643		#rec 00 : load 2 bytes [0x000f fff0]=0x55; [0x000f fff1]=0x66
:020000040800f2		#rec 04 : new linear addr = 0x0800, so next addresses will be (0x0800 <<16) + AAAA
:10000000480F0020F948000811480008134800086C	#rec 00 : load 16 bytes @ 0x0800 0000
:04000005080049099D	#rec 05 : entry point = 0x0800 4909 (ignored)
:00000001FF		#rec 01 : EOF

*/

#include "r_io.h"
#include "r_lib.h"
#include "r_util.h"
#include <limits.h>	//for INT_MAX
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

//struct Rihex : holds sparse buffer + its own fd, for internal management
typedef struct {
	int fd;
	RBuffer *rbuf;
} Rihex;

static int fw04b(FILE *fd, ut16 eaddr);
static int fwblock(FILE *fd, ut8 *b, ut32 start_addr, ut16 size);

static int __write(RIO *io, RIODesc *fd, const ut8 *buf, int count) {
	const char *pathname;
	FILE *out;
	Rihex *rih;
	RBufferSparse *rbs;
	RListIter *iter;

	if (!fd || !fd->data || (fd->flags & R_IO_WRITE) == 0 || count <= 0) {
		return -1;
	}
	rih = fd->data;
	pathname = fd->name + 7;
	out = r_sandbox_fopen (pathname, "w");
	if (!out) {
		eprintf ("Cannot open '%s' for writing\n", pathname);
		return -1;
	}
	/* mem write */
	if (r_buf_write_at (rih->rbuf, io->off, buf, count) != count) {
		eprintf ("ihex:write(): sparse write failed\n");
		fclose (out);
		return -1;
	}

	/* disk write : process each sparse chunk */
	//TODO : sort addresses + check overlap?
	r_list_foreach (rih->rbuf->sparse, iter, rbs) {
		ut16 addl0 = rbs->from & 0xffff;
		ut16 addh0 = rbs->from >> 16;
		ut16 addh1 = rbs->to >> 16;
		ut16 tsiz =0;
		if (rbs->size == 0) {
			continue;
		}

		if (addh0 != addh1) {
			//we cross a 64k boundary, so write in two steps
			//04 record (ext address)
			if (fw04b (out, addh0) < 0) {
				eprintf("ihex:write: file error\n");
				fclose (out);
				return -1;
			}
			//00 records (data)
			tsiz = -addl0;
			addl0 = 0;
			if (fwblock (out, rbs->data, rbs->from, tsiz)) {
				eprintf("ihex:fwblock error\n");
				fclose (out);
				return -1;
			}
		}
		//04 record (ext address)
		if (fw04b (out, addh1) < 0) {
			eprintf ("ihex:write: file error\n");
			fclose (out);
			return -1;
		}
		//00 records (remaining data)
		if (fwblock (out, rbs->data + tsiz, (addh1 << 16) | addl0, rbs->size - tsiz)) {
			eprintf ("ihex:fwblock error\n");
			fclose (out);
			return -1;
		}
	}	//list_foreach

	fprintf (out, ":00000001FF\n");
	fclose (out);
	out = NULL;
	return 0;
}

//write contiguous block of data to file; ret 0 if ok
//max 65535 bytes; assumes a 04 rec was written before
static int fwblock(FILE *fd, ut8 *b, ut32 start_addr, ut16 size) {
	ut8 cks;
	char linebuf[80];
	ut16 last_addr;
	int j;
	ut32 i;	//has to be bigger than size !

	if (size <1 || !fd || !b)
		return -1;

	for (i = 0; (i + 0x10) < size; i += 0x10) {
		cks = 0x10;
		cks += (i + start_addr) >> 8;
		cks += (i + start_addr);
		for (j = 0; j < 0x10; j++) {
			cks += b[j];
		}
		cks = 0 - cks;
		if (fprintf (fd, ":10%04x00%02x%02x%02x%02x%02x%02x%02x"
			"%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",
			(i+start_addr)&0xffff, b[0], b[1], b[2], b[3], b[4], b[5], b[6],
			b[7], b[8], b[9], b[10], b[11], b[12], b[13],
			b[14], b[15], cks) < 0) return -1;
		start_addr += 0x10;
		b += 0x10;
		if ((start_addr & 0xffff) < 0x10) {
			//addr rollover: write ext address record
			if (fw04b (fd, start_addr >> 16) < 0)
				return -1;
		}
	}
	if (i == size) {
		return 0;
	}
	//write crumbs
	last_addr = i+start_addr;
	cks = -last_addr;
	cks -= last_addr>>8;
	for (j=0;i<size; i++, j++) {
		cks -= b[j];
		sprintf(linebuf+(2*j), "%02X", b[j]);
	}
	cks -= j;

	if (fprintf (fd, ":%02X%04X00%.*s%02X\n", j, last_addr, 2*j, linebuf,cks) < 0)
		return -1;
	return 0;
}

//fw04b : write 04 record (extended address); ret <0 if error
static int fw04b(FILE *fd, ut16 eaddr) {
	ut8 cks = 0 - (6 + (eaddr >> 8) + (eaddr & 0xff));
	return fprintf (fd, ":02000004%04X%02X\n", eaddr, cks);

}

static int __read(RIO *io, RIODesc *fd, ut8 *buf, int count) {
	if (!fd || !fd->data || (count <= 0)) {
		return -1;
	}
	Rihex *rih = fd->data;
	if (r_buf_read_at (rih->rbuf, io->off, buf, count) != count) {
		return -1; //should never happen with a sparsebuf..
	}
	return count;
}

static int __close(RIODesc *fd) {
	if (!fd || !fd->data) {
		return -1;
	}
	Rihex *rih = fd->data;
	r_buf_free (rih->rbuf);
	free (rih);
	fd->data = NULL;
	return 0;
}

static ut64 __lseek(struct r_io_t *io, RIODesc *fd, ut64 offset, int whence) {
	Rihex *rih;
	if (!fd || !fd->data) {
		return -1;
	}
	rih = fd->data;
	return r_buf_seek (rih->rbuf, offset, whence);
}

static bool __plugin_open(RIO *io, const char *pathname, bool many) {
	return (!strncmp (pathname, "ihex://", 7));
}

//ihex_parse : parse ihex file loaded at *str, fill sparse buffer "rbuf"
//supported rec types : 00, 01, 02, 04
//ret 0 if ok
static bool ihex_parse(RBuffer *rbuf, char *str) {
	ut8 *sec_tmp;
	ut32 sec_start = 0;	//addr for next section write
	ut32 segreg = 0;	//basis for addr fields
	ut32 addr_tmp = 0;	//addr for record
	ut16 next_addr = 0;	//for checking if records are sequential
	char *eol;
	ut8 cksum;
	int extH, extL;
	int bc = 0, type, byte, i, l;
	//fugly macro to prevent an overflow of r_buf_write_at() len
#define SEC_MAX (sec_size < INT_MAX)? sec_size: INT_MAX
	ut32 sec_size = 0;
	const int sec_count = UT16_MAX;
	sec_tmp = calloc (1, sec_count);
	if (!sec_tmp) {
		goto fail;
	}
	do {
		l = sscanf (str, ":%02x%04x%02x", &bc, &addr_tmp, &type);
		if (l != 3) {
			eprintf ("Invalid data in ihex file (%.*s)\n", 80, str);
			goto fail;
		}
		bc &= 0xff;
		addr_tmp &= 0xffff;
		type &= 0xff;

		switch (type) {
		case 0: // DATA
			eol = strchr (str + 1, ':');
			if (eol) {
				*eol = 0;
			}
			cksum = bc;
			cksum += addr_tmp>>8;
			cksum += addr_tmp;
			cksum += type;

			if ((next_addr != addr_tmp) || ((sec_size + bc) > SEC_MAX)) {
				//previous block is not contiguous, or
				//section buffer is full => write a sparse chunk
				if (sec_size && sec_size < UT16_MAX) {
					if (r_buf_write_at (rbuf, sec_start, sec_tmp, (int) sec_size) != sec_size) {
						eprintf ("sparse buffer problem, giving up\n");
						goto fail;
					}
				}
				//advance cursor, reset section
				sec_start = segreg + addr_tmp;
				next_addr = addr_tmp;
				sec_size = 0;
			}

			for (i = 0; i < bc; i++) {
				if (sscanf (str + 9+ (i*2), "%02x", &byte) !=1) {
					eprintf ("unparsable data !\n");
					goto fail;
				}
				if (sec_size + i < sec_count) {
					sec_tmp[sec_size + i] = (ut8) byte & 0xff;
				}
				cksum += byte;
			}
			sec_size += bc;
			next_addr += bc;
			if (eol) {
				// checksum
				if (sscanf(str+9+(i*2), "%02x", &byte) !=1) {
					eprintf("unparsable data !\n");
					goto fail;
				}
				cksum += byte;
				if (cksum != 0) {
					ut8 fixedcksum = 0-(cksum-byte);
					eprintf ("Checksum failed %02x (got %02x expected %02x)\n",
						cksum, byte, fixedcksum);
					goto fail;
				}
				*eol = ':';
			}
			str = eol;
			break;
		case 1: // EOF. we don't validate checksum here
			if (sec_size) {
				if (r_buf_write_at(rbuf, sec_start, sec_tmp, sec_size) != sec_size) {
					eprintf ("sparse buffer problem, giving up. ssiz=%X, sstart=%X\n", sec_size, sec_start);
					goto fail;
				}
			}
			str = NULL;
			break;
		case 2:	//extended segment record
		case 4:	//extended linear address rec
			//both rec types are handled the same except :
			//	new address = seg_reg <<4 for type 02; new address = lin_addr <<16 for type 04.
			//write current section
			if (sec_size) {
				if (r_buf_write_at(rbuf, sec_start, sec_tmp, sec_size) != sec_size) {
					eprintf("sparse buffer problem, giving up\n");
					goto fail;
				}
			}
			sec_size = 0;

			eol = strchr (str+1, ':');
			if (eol) *eol = 0;
			cksum = bc;
			cksum += addr_tmp>>8;
			cksum += addr_tmp;
			cksum += type;
			if ((bc !=2) || (addr_tmp != 0)) {
				eprintf ("invalid type 02/04 record!\n");
				goto fail;
			}

			if ((sscanf (str + 9 + 0, "%02x", &extH) !=1) ||
				(sscanf (str + 9 + 2, "%02x", &extL) !=1)) {
				eprintf ("unparsable data !\n");
				goto fail;
			}
			extH &= 0xff;
			extL &= 0xff;
			cksum += extH + extL;

			segreg = extH <<8 | extL;

			//segment rec(02) gives bits 4..19; linear rec(04) is bits 16..31
			segreg = segreg << ((type==2)? 4: 16);
			next_addr = 0;
			sec_start = segreg;

			if (eol) {
				// checksum
				byte=0;	//break checksum if sscanf failed
				if (sscanf (str+9+ 4, "%02x", &byte) !=1) cksum=1;
				cksum += byte;
				if (cksum != 0) {
					ut8 fixedcksum = 0-(cksum-byte);
					eprintf ("Checksum failed %02x (got %02x expected %02x)\n",
						cksum, byte, fixedcksum);
					goto fail;
				}
				*eol = ':';
			}
			str = eol;
			break;
		case 3:	//undefined rec. Just skip.
		case 5:	//non-standard, sometimes "start linear adddress"
			str = strchr (str + 1, ':');
			break;
		}
	} while (str);
	free (sec_tmp);
	return true;
fail:
	free (sec_tmp);
	return false;
}

static RIODesc *__open(RIO *io, const char *pathname, int rw, int mode) {
	Rihex *mal = NULL;
	char *str = NULL;
	if (__plugin_open (io, pathname, 0)) {
		str = r_file_slurp (pathname + 7, NULL);
		if (!str) return NULL;
		mal= R_NEW0 (Rihex);
		if (!mal) {
			free (str);
			return NULL;
		}
		mal->rbuf = r_buf_new_sparse();
		if (!mal->rbuf) {
			free (str);
			free (mal);
			return NULL;
		}
		if (!ihex_parse (mal->rbuf, str)) {
			eprintf ("ihex: failed to parse file\n");
			free (str);
			r_buf_free (mal->rbuf);
			free (mal);
			return NULL;
		}
		free (str);
		return r_io_desc_new (io, &r_io_plugin_ihex,
			pathname, rw, mode, mal);
	}
	return NULL;
}

static bool __resize(RIO *io, RIODesc *fd, ut64 size) {
	Rihex *rih = fd->data;
	return r_buf_resize (rih->rbuf, size);
}

RIOPlugin r_io_plugin_ihex = {
	.name = "ihex",
        .desc = "Intel HEX file (ihex://eeproms.hex)",
	.license = "LGPL",
        .open = __open,
        .close = __close,
	.read = __read,
        .check = __plugin_open,
	.lseek = __lseek,
	.write = __write,
	.resize = __resize
};

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_hex,
	.version = R2_VERSION
};
#endif
