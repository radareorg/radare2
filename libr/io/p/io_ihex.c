/* radare - LGPL - Copyright 2013-2015 - pancake, fenugrec */

//TODO : fix r_buf_copy return values so we can check r_buf_write_at() and r_buf_read_at() succeed !
#include "r_io.h"
#include "r_lib.h"
#include "r_util.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

#define MEMSIZE 0x10000

//struct Rihex : holds sparse buffer + its own fd, for internal management
typedef struct {
	int fd;
	RBuffer *rbuf;
} Rihex;

static int fw04b(FILE *fd, ut16 eaddr);
static int fwblock(FILE *fd, ut8 *b, ut32 start_addr, int size);

static int __write(RIO *io, RIODesc *fd, const ut8 *buf, int count) {
	const char *pathname;
	FILE *out;
	Rihex *rih;
	RBufferSparse *rbs;
	RListIter *iter;
	
	if (fd == NULL || fd->data == NULL || (count<=0))
		return -1;
	rih = fd->data;
	pathname = fd->name + 7;
	out = fopen (pathname, "w");
	if (!out) {
		eprintf ("Cannot open '%s' for writing\n", pathname);
		return -1;
	}
	/* mem write */
	if (r_buf_write_at(rih->rbuf, io->off, buf, count) <0) {
		eprintf("ihex:write(): sparse write failed\n");
		fclose(out);
	}

	/* disk write : process each sparse chunk */
	//TODO : sort addresses; not sure if the r_list is already sorted?
	r_list_foreach(rih->rbuf->sparse, iter, rbs) {
		if ((rbs->from >65535) || (rbs->to >65535)) {
			eprintf("ihex:write: skipping chunk with address out of range\n");
			continue;
		}
		//04 record (ext address)
		if (fw04b(out, rbs->from >> 16) < 0) {
			eprintf("ihex:write: file error\n");
			return -1;
		}
		//00 records (data)
		if (fwblock(out, rbs->data, rbs->from, rbs->size)) {
			eprintf("ihex:fwblock error\n");
			return -1;
		}
		
	}
	
	fprintf (out, ":00000001FF\n");
	fclose (out);
	return 0;
}

//write contiguous block of data to file; ret 0 if ok
static int fwblock(FILE *fd, ut8 *b, ut32 start_addr, int size) {
	ut8 cks;
	char linebuf[80];	//":xxAAAA00...\n"
	int i,j;
	
	if (size <=0 || !fd || !b)
		return -1;
		
	for (i=0; i<size; i+=0x10) {
		cks = 0x10;
		cks += (i+start_addr)>>8;
		cks += (i+start_addr);
		for (j=0; j<0x10; j++) cks += b[j];
		cks = 0-cks;
		if (fprintf (fd, ":10%04x00%02x%02x%02x%02x%02x%02x%02x"
			"%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",
			(i+start_addr)&0xffff, b[0], b[1], b[2], b[3], b[4], b[5], b[6],
			b[7], b[8], b[9], b[10], b[11], b[12], b[13],
			b[14], b[15], cks) < 0) return -1;
		start_addr += 0x10;
		b += 0x10;
		if ((start_addr & 0xffff) < 0x10) {
			//addr rollover: write ext address record
			if (fw04b(fd, start_addr >> 16) < 0)
				return -1;
		}
	}
	if (i==size) return 0;
	//write crumbs
	cks = 0x10;
	cks = 0x10;
	cks += (i+start_addr)>>8;
	cks += (i+start_addr);
	for (j=0;i<size; i++, j++) {
		cks += b[j];
		sprintf(linebuf+3+(2*j), "%02X", b[j]);		
	}
	if (fprintf(fd, ":%02X%.*s\n", j, 2*j, linebuf) < 0)
		return -1;
	return 0;
}

//fw04b : write 04 record (extended address); ret <0 if error
static int fw04b(FILE *fd, ut16 eaddr) {
	ut8 cks = 0-(6+ (eaddr>>8) + (eaddr&0xff));
	return fprintf(fd, ":02000004%04X%02X\n", eaddr, cks);

}

static int __read(RIO *io, RIODesc *fd, ut8 *buf, int count) {
	Rihex *rih;
	if (fd == NULL || fd->data == NULL || (count<=0))
		return -1;
	rih=fd->data;
	if (r_buf_read_at(rih->rbuf, io->off, buf, count) != count)
		return -1;	//should never happen with a sparsebuf..

	return count;
}

static int __close(RIODesc *fd) {
	Rihex *rih;
	if (fd == NULL || fd->data == NULL)
		return -1;
	rih = fd->data;
	r_buf_free(rih->rbuf);
	free(rih);
	fd->data = NULL;
	fd->state = R_IO_DESC_TYPE_CLOSED;
	return 0;
}

static ut64 __lseek(struct r_io_t *io, RIODesc *fd, ut64 offset, int whence) {
	Rihex *rih;
	if (fd == NULL || fd->data == NULL)
		return -1;	//not sure if this is ok..
	rih = fd->data;
	return r_buf_seek(rih->rbuf, offset, whence);
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
  1 byte Record type (00 data, 01 eof, 02 extended seg addr, 04 extended linear addr)
  N bytes Data
  1 byte Checksum (sum 00)
#endif

//ihex_parsparse : parse ihex file loaded at *str, fill sparse buffer "rbuf"
//supported rec types : 00, 01, 02, 04
//ret 0 if ok
static int ihex_parsparse(RBuffer *rbuf, char *str){
	ut32 sec_start = 0;	//addr for next section write
	ut32 segreg = 0;	//basis for addr fields
	int addr_tmp = 0;	//addr for record
	ut16 next_addr = 0;	//for checking if records are sequential
	char *eol;
	ut8 cksum;
	int extH, extL;
	int bc=0, type, byte, i, l;
	ut8 sec_tmp[65536];	//buffer section beffore calling r_buf_write_at
	ut16 sec_size=0;
	do {
		l = sscanf (str, ":%02x%04x%02x", &bc, &addr_tmp, &type);
		if (l != 3) {
			eprintf ("Invalid data in ihex file (%s)\n", str);
			return -1;
		}
		bc &= 0xff;
		addr_tmp &= 0xffff;
		type &= 0xff;
		
		switch (type) {
		case 0: // DATA
			eol = strchr (str+1, ':');
			if (eol) *eol = 0;
			cksum = bc;
			cksum += addr_tmp>>8;
			cksum += addr_tmp&0xff;
			cksum += type;

			if ((next_addr != addr_tmp) ||
				((sec_size + bc) > sizeof(sec_tmp))) {
				//previous block is not contiguous ||
				//section buffer is full => write a sparse chunk
				if (sec_size) {
						eprintf("rec 00: loading 0x%04x-bytes @ 0x%08x\n",sec_size, sec_start);	//TODO : remove dbg msg
					if (r_buf_write_at(rbuf, sec_start, sec_tmp, sec_size) <0) {
						eprintf("sparse buffer problem, giving up\n");
						return -1;
					}
				}
				//advance cursor, reset section
				sec_start = segreg + addr_tmp;
				next_addr = addr_tmp;
				sec_size = 0;
			}

			for (i=0; i<bc; i++) {
				if (sscanf(str+9+ (i*2), "%02x", &byte) !=1) {
					eprintf("unparsable data !\n");
					return -1;
				}
				sec_tmp[sec_size+i] = (uint8_t) byte & 0xff;
				cksum += byte;
			}
			sec_size += bc;
			next_addr += bc;
			if (eol) {
				// checksum
				if (sscanf(str+9+(i*2), "%02x", &byte) !=1) {
					eprintf("unparsable data !\n");
					return -1;
				}
				cksum += byte;
				if (cksum != 0) {
					ut8 fixedcksum = 0-(cksum-byte);
					eprintf ("Checksum failed %02x (got %02x expected %02x)\n",
						cksum, byte, fixedcksum);
					return -1;
				}
				*eol = ':';
			}
			str = eol;
			eprintf("rec 00: sec_size=0x%x, next_addr=0x%x\n", sec_size, next_addr);	//TODO : remove dbg msg
			break;
		case 1: // EOF. we don't validate checksum here
			if (sec_size) {
					eprintf("rec 01: loading last 0x%04x bytes @ 0x%08x\n",sec_size, sec_start);	//TODO : remove dbg msg
				if (r_buf_write_at(rbuf, sec_start, sec_tmp, sec_size) < 0) {
					eprintf("sparse buffer problem, giving up. ssiz=%X, sstart=%X\n", sec_size, sec_start);
					return -1;
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
				eprintf("rec 02/04: writing 0x%04x-bytes @ 0x%08x\n",sec_size, sec_start);	//TODO : remove dbg msg
				if (r_buf_write_at(rbuf, sec_start, sec_tmp, sec_size) <0) {
					eprintf("sparse buffer problem, giving up\n");
					return -1;
				}
			}
			sec_size=0;
			
			eol = strchr (str+1, ':');
			if (eol) *eol = 0;
			cksum = bc;
			cksum += addr_tmp>>8;
			cksum += addr_tmp&0xff;
			cksum += type;
			if ((bc !=2) || (addr_tmp != 0)) {
				eprintf("corrupt type 02/04 record!\n");
				return -1;
			}
			
			if ((sscanf(str+9+ 0, "%02x", &extH) !=1) ||
				(sscanf(str+9+ 2, "%02x", &extL) !=1)) {
				eprintf("unparsable data !\n");
				return -1;
			}
			extH &= 0xff;
			extL &= 0xff;
			cksum += extH + extL;
			
			segreg = extH <<8 | extL;
			
			//segment rec(02) gives bits 4..19; linear rec(04) is bits 16..31 
			segreg = segreg << ((type==02)? 4:16);
			next_addr = 0;
			sec_start = segreg;
			eprintf("rec %02d: new addr=%x\n", type, sec_start);	//TODO : remove dbg message
		
			if (eol) {
				// checksum
				sscanf (str+9+ 4, "%02x", &byte);
				cksum += byte;
				if (cksum != 0) {
					ut8 fixedcksum = 0-(cksum-byte);
					eprintf ("Checksum failed %02x (got %02x expected %02x)\n",
						cksum, byte, fixedcksum);
					return -1;
				}
				*eol = ':';
			}
			str = eol;
			break;			
		case 3:	//undefined rec. Just skip.
		case 5:	//non-standard, sometimes "start linear adddress"
			str = strchr(str + 1, ':');
			break;
		}
	} while (str);

	return 0;
}

static RIODesc *__open(RIO *io, const char *pathname, int rw, int mode) {
	int ret;
	Rihex *mal = NULL;
	char *str = NULL;
	
	if (__plugin_open (io, pathname, 0)) {
		str = r_file_slurp (pathname+7, NULL);
		if (!str) return NULL;
		mal= R_NEW (Rihex);
		if (!mal) {
			free (str);
			return NULL;
		}
		mal->fd = -1; /* causes r_io_desc_new() to set the correct fd */
		mal->rbuf = r_buf_new_sparse();
		if (!mal->rbuf) {
			free (str);
			free (mal);
			return NULL;
		}
		ret = ihex_parsparse(mal->rbuf, str);
		if (ret) {
			eprintf("ihex: failed to parse file\n");
			free(str);
			r_buf_free(mal->rbuf);
			free(mal);
			return NULL;
		}
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
