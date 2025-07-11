/* radare - LGPL - Copyright 2013-2024 - pancake, fenugrec */

/*
*** .hex format description : every line follows this pattern
:SSAAAARR<xx*SS>KK
SS: num of "xx" bytes
AAAA lower 16bits of address for resulting data (== 0 for 01, 02, 04 and 05 records)
RR: rec type:
	00 data
	01 EOF (always SS= 0, AAAA = 0)
	02 extended segment addr reg: (always SS = 02, AAAA = 0); data = 0x<xxyy> => bits 4..19 of following addresses
	04 extended linear addr reg: (always SS = 02, AAAA = 0); data = 0x<xxyy> => bits 16..31 of following addresses
	05 non-standard; could be "start linear address" AKA "entry point".
KK = 0 - (sum of all bytes)

//sauce : https://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.faqs/ka9903.html

**** example records
:02000002fffffe		#rec 02 : new seg = 0xffff, so next addresses will be (seg<<4)+AAAA
:02000000556643		#rec 00 : load 2 bytes [0x000f fff0] = 0x55; [0x000f fff1] = 0x66
:020000040800f2		#rec 04 : new linear addr = 0x0800, so next addresses will be (0x0800 <<16) + AAAA
:10000000480F0020F948000811480008134800086C	#rec 00 : load 16 bytes @ 0x0800 0000
:04000005080049099D	#rec 05 : entry point = 0x0800 4909 (ignored)
:00000001FF		#rec 01 : EOF

*/

#include <r_io.h>

//struct Rihex : holds sparse buffer + its own fd, for internal management
typedef struct {
	int fd;
	RBuffer *rbuf;
	ut64 min;
	ut64 max;
	RRange *range;
} Rihex;

static void update_bounds(Rihex *rih, ut64 min, ut64 max, const ut8 *buf) {
	size_t i, len = max - min;
	bool isff = true;
	for (i = 0; i < len; i++) {
		if (buf[i] != 0xff) {
			isff = false;
			break;
		}
	}
	if (isff) {
		return;
	}
	r_range_add (rih->range, min, max, 1);
	if (min < rih->min) {
		rih->min = min;
	}
	if (max > rih->max) {
		rih->max = max;
	}
}

// fw04b : write 04 record (extended address); ret <0 if error
static int fw04b(FILE *fd, ut16 eaddr) {
	ut8 cks = 0 - (6 + (eaddr >> 8) + (eaddr & 0xff));
	return fprintf (fd, ":02000004%04X%02X\n", eaddr, cks);
}

// write contiguous block of data to file; ret 0 if ok
// max 65535 bytes; assumes a 04 rec was written before
static int fwblock(FILE *fd, ut8 *b, ut32 start_addr, ut16 size) {
	ut8 cks;
	char linebuf[80];
	ut16 last_addr;
	int j;
	ut32 i;	// has to be larger than size!

	if (size < 1 || !fd || !b) {
		return -1;
	}

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
			    (i + start_addr) & 0xffff, b[0], b[1], b[2], b[3], b[4], b[5], b[6],
			    b[7], b[8], b[9], b[10], b[11], b[12], b[13],
			    b[14], b[15], cks) < 0) {
			return -1;
		}
		start_addr += 0x10;
		b += 0x10;
		if ((start_addr & 0xffff) < 0x10) {
			// addr rollover: write ext address record
			if (fw04b (fd, start_addr >> 16) < 0) {
				return -1;
			}
		}
	}
	if (i == size) {
		return 0;
	}
	//  write crumbs
	last_addr = i+start_addr;
	cks = -last_addr;
	cks -= last_addr >> 8;
	for (j = 0; i < size; i++, j++) {
		const size_t delta = 2 * j;
		cks -= b[j];
		snprintf (linebuf + delta, sizeof (linebuf) - delta, "%02X", b[j]);
	}
	cks -= j;

	if (fprintf (fd, ":%02X%04X00%.*s%02X\n", j, last_addr, 2 * j, linebuf, cks) < 0) {
		return -1;
	}
	return 0;
}

static int __write(RIO *io, RIODesc *fd, const ut8 *buf, int count) {
	RBufferSparseItem *rbsi;
	RListIter *iter;

	if (!fd || !fd->data || (fd->perm & R_PERM_W) == 0 || count <= 0) {
		return -1;
	}
	Rihex *rih = fd->data;
	const char *pathname = fd->name + 7;
	FILE *out = r_sandbox_fopen (pathname, "w");
	if (!out) {
		R_LOG_ERROR ("Cannot open '%s' for writing", pathname);
		return -1;
	}
	/* mem write */
	update_bounds (rih, io->off, io->off + count, buf);
	if (r_buf_write_at (rih->rbuf, io->off, buf, count) != count) {
		R_LOG_ERROR ("ihex:write(): sparse write failed");
		fclose (out);
		return -1;
	}
	r_buf_seek (rih->rbuf, count, R_BUF_CUR);

	/* disk write : process each sparse chunk */
	// TODO: sort addresses + check overlap?
	RList *nonempty = r_buf_nonempty_list (rih->rbuf);
	r_list_foreach (nonempty, iter, rbsi) {
		ut16 addl0 = rbsi->from & 0xffff;
		ut16 addh0 = rbsi->from >> 16;
		ut16 addh1 = rbsi->to >> 16;
		ut16 tsiz = 0;
		if (rbsi->size == 0) {
			continue;
		}

		if (addh0 != addh1) {
			// we cross a 64k boundary, so write in two steps
			// 04 record (ext address)
			if (fw04b (out, addh0) < 0) {
				R_LOG_ERROR ("ihex:write:file error");
				r_list_free (nonempty);
				fclose (out);
				return -1;
			}
			// 00 records (data)
			tsiz = -addl0;
			addl0 = 0;
			if (fwblock (out, rbsi->data, rbsi->from, tsiz)) {
				R_LOG_ERROR ("ihex:fwblock error");
				r_list_free (nonempty);
				fclose (out);
				return -1;
			}
		}
		// 04 record (ext address)
		if (fw04b (out, addh1) < 0) {
			R_LOG_ERROR ("ihex:write: file error");
			r_list_free (nonempty);
			fclose (out);
			return -1;
		}
		// 00 records (remaining data)
		if (fwblock (out, rbsi->data + tsiz, (addh1 << 16) | addl0, rbsi->size - tsiz)) {
			R_LOG_ERROR ("ihex:fwblock error");
			r_list_free (nonempty);
			fclose (out);
			return -1;
		}
	}

	r_list_free (nonempty);
	fprintf (out, ":00000001FF\n");
	fclose (out);
	out = NULL;
	return 0;
}

static int __read(RIO *io, RIODesc *fd, ut8 *buf, int count) {
	if (!fd || !fd->data || (count <= 0)) {
		return -1;
	}
	Rihex *rih = fd->data;
	memset (buf, io->Oxff, count);
	int r = r_buf_read_at (rih->rbuf, io->off, buf, count);
	if (r >= 0) {
		r_buf_seek (rih->rbuf, r, R_BUF_CUR);
	}
	return r;
}

static bool __close(RIODesc *fd) {
	if (!fd || !fd->data) {
		return false;
	}
	Rihex *rih = fd->data;
	r_buf_free (rih->rbuf);
	r_range_free (rih->range);
	free (rih);
	fd->data = NULL;
	return true;
}

static ut64 __lseek(RIO *io, RIODesc *fd, ut64 offset, int whence) {
	if (!fd || !fd->data) {
		return UT64_MAX;
	}
	Rihex *rih = fd->data;
	io->off = r_buf_seek (rih->rbuf, offset, whence);
	return io->off;
}

static bool __plugin_open(RIO *io, const char *pathname, bool many) {
	return r_str_startswith (pathname, "ihex://");
}

// ihex_parse : parse ihex file loaded at *str, fill sparse buffer "rbuf"
// supported rec types : 00, 01, 02, 04
// ret 0 if ok
static bool ihex_parse(Rihex *rih, char *str) {
	RBuffer *rbuf = rih->rbuf;
	ut32 sec_start = 0;	// addr for next section write
	ut32 segreg = 0;	// basis for addr fields
	ut32 addr_tmp = 0;	// addr for record
	// ut16 next_addr = 0;	// for checking if records are sequential
	char *eol;
	ut8 cksum;
	int extH, extL;
	int bc = 0, type, byte, i, l;
	// fugly macro to prevent an overflow of r_buf_write_at() len
#define SEC_MAX (sec_size < INT_MAX)? sec_size: INT_MAX
	ut32 sec_size = 0;
	const int sec_count = UT16_MAX;
	ut8 *sec_tmp = calloc (1, sec_count);
	if (!sec_tmp) {
		goto fail;
	}
	const char *ostr = str;
	const bool ignore_cksum = r_sys_getenv_asbool ("R2_IHEX_IGNORE_CKSUM");
	do {
		l = sscanf (str, ":%02x%04x%02x", &bc, &addr_tmp, &type);
		if (l != 3) {
			R_LOG_ERROR ("Invalid data in ihex file (%.*s)", 80, str);
			goto fail;
		}
		bc &= 0xff;
		addr_tmp &= 0xffff;
		type &= 0xff;
		ut64 at = (!sec_start && sec_start == addr_tmp)? addr_tmp? addr_tmp: sec_start: sec_start + addr_tmp;

		switch (type) {
		case 0: // DATA
			eol = strchr (str + 1, ':');
			if (eol) {
				*eol = 0;
			}
			cksum = bc;
			cksum += addr_tmp >> 8;
			cksum += addr_tmp;
			cksum += type;

			for (i = 0; i < bc; i++) {
				if (sscanf (str + 9 + (i * 2), "%02x", &byte) != 1) {
					R_LOG_ERROR ("unparsable data (%s)", str);
					goto fail;
				}
				if (sec_size + i < sec_count) {
					sec_tmp[i] = (ut8) byte & 0xff;
				}
				cksum += byte;
			}
			sec_size = bc;
			ut32 tmp = 0;
			r_buf_read_at (rbuf, at, (ut8*)&tmp, 4);
			if (tmp && tmp != UT32_MAX) {
				R_LOG_ERROR ("Cannot write");
				return true;
			}
			update_bounds (rih, at, at + sec_size, sec_tmp);
			if (r_buf_write_at (rbuf, at, sec_tmp, sec_size) != sec_size) {
				R_LOG_ERROR ("sparse buffer problem, giving up");
				goto fail;
			}
			sec_size = 0;

			sec_size += bc;
			//next_addr += bc;
			if (eol) {
				// checksum
				if (sscanf (str + 9 + (i * 2), "%02x", &byte) !=1) {
					R_LOG_ERROR ("unparsable data!");
					goto fail;
				}
				cksum += byte;
				if (cksum != 0) {
					ut8 fixedcksum = 0 - cksum - byte;
					if (ignore_cksum) {
						R_LOG_ERROR ("Ignored checksum failed %02x (got %02x expected %02x)",
							cksum, byte, fixedcksum);
					} else {
						R_LOG_ERROR ("Checksum failed %02x (got %02x expected %02x)",
							cksum, byte, fixedcksum);
						goto fail;
					}
				}
				*eol = ':';
			}
			str = eol;
			break;
		case 1: // EOF. we don't validate checksum here
			if (at && sec_size) {
				update_bounds (rih, at, at + sec_size, sec_tmp);
				if (r_buf_write_at (rbuf, at, sec_tmp, sec_size) != sec_size) {
					R_LOG_ERROR ("sparse buffer problem, giving up. ssiz=%X, sstart=%X", sec_size, sec_start);
					goto fail;
				}
			}
			str = NULL;
			break;
		case 2:	// extended segment record
		case 4:	// extended linear address rec
			// both rec types are handled the same except:
			// new address = seg_reg <<4 for type 02; new address = lin_addr <<16 for type 04.
			sec_size = 0;

			eol = strchr (str + 1, ':');
			if (eol) {
				*eol = 0;
			}
			cksum = bc;
			cksum += (addr_tmp >> 8);
			cksum += addr_tmp;
			cksum += type;
			if ((bc != 2) || (addr_tmp != 0)) {
				R_LOG_ERROR ("invalid type 02/04 record!");
				goto fail;
			}
			if ((sscanf (str + 9 + 0, "%02x", &extH) !=1) ||
				(sscanf (str + 9 + 2, "%02x", &extL) !=1)) {
				R_LOG_ERROR ("unparsable data!");
				goto fail;
			}
			extH &= 0xff;
			extL &= 0xff;
			cksum += extH + extL;

			segreg = (extH << 8) | extL;

			//segment rec(02) gives bits 4..19; linear rec(04) is bits 16..31
			segreg = segreg << ((type == 2)? 4: 16);
			// next_addr = 0;
			sec_start = segreg;

			if (eol) {
				byte = 0; //break checksum if sscanf failed
				if (sscanf (str + 9 + 4, "%02x", &byte) != 1) {
					cksum = 1;
				}
				cksum += byte;
				if (cksum != 0) {
					ut8 fixedcksum = 0 - cksum - byte;
					R_LOG_ERROR ("Checksum failed %02x (got %02x expected %02x)",
						cksum, byte, fixedcksum);
					goto fail;
				}
				*eol = ':';
			}
			str = eol;
			break;
		case 3:	// undefined rec. Just skip.
		case 5:	// non-standard, sometimes "start linear address"
			str = strchr (str + 1, ':');
			break;
		}
		if (str == ostr) {
			R_LOG_DEBUG ("Optimized infinite loop");
			break;
		}
		ostr = str;
	} while (str);
	free (sec_tmp);
	return true;
fail:
	free (sec_tmp);
	return false;
}

static RIODesc *__open(RIO *io, const char *pathname, int rw, int mode) {
	if (!__plugin_open (io, pathname, 0)) {
		return NULL;
	}
	char *str = r_file_slurp (pathname + 7, NULL);
	if (!str) {
		return NULL;
	}
	Rihex *rih = R_NEW0 (Rihex);
	if (!rih) {
		free (str);
		return NULL;
	}
	rih->range = r_range_new ();
	rih->min = UT64_MAX;
	rih->rbuf = r_buf_new_sparse (io->Oxff);
	if (!rih->rbuf) {
		free (str);
		free (rih);
		return NULL;
	}
	if (!ihex_parse (rih, str)) {
		R_LOG_ERROR ("ihex: failed to parse file");
		free (str);
		r_buf_free (rih->rbuf);
		free (rih);
		return NULL;
	}
	free (str);
	return r_io_desc_new (io, &r_io_plugin_ihex, pathname, rw, mode, rih);
}

static bool __resize(RIO *io, RIODesc *fd, ut64 size) {
	if (!fd) {
		return false;
	}
	Rihex *rih = fd->data;
	if (rih) {
		return r_buf_resize (rih->rbuf, size);
	}
	return false;
}

static char *__system(RIO *io, RIODesc *fd, const char *cmd) {
	if (R_STR_ISEMPTY (cmd)) {
		return NULL;
	}
	Rihex *rih = fd->data;
	RStrBuf *sb = r_strbuf_new ("");
	switch (*cmd) {
	case '?':
		r_strbuf_append (sb, "Usage: [:][arg]\n");
		r_strbuf_append (sb, ":b     show minimum and maximum addresses written\n");
		r_strbuf_append (sb, ":r     show written ranges\n");
		r_strbuf_append (sb, ":i     create new ihex with current contents\n");
		break;
	case 'i':
		{
			RRangeItem *r;
			RListIter *iter;
			r_list_foreach_prev (rih->range->ranges, iter, r) {
				ut8 buf[0x20];
				// use r_io instead?
				int i, j;
				ut32 len = r->to - r->fr;
				for (i = 0; i < len; i++) {
					int type = 0x20;
					ut32 at = r->fr + i;
					r_strbuf_appendf (sb, ":%02x%04x00", type, at);
					int max = R_MIN (0x20, len);
					// r_buf_read_at (rih->rbuf, r->fr + i, buf, sizeof (buf));
					r_io_read_at (io, r->fr + i, buf, sizeof (buf));
					ut8 cksum = 0;
					cksum += at >> 8;
					cksum += at;
					cksum += max;
					for (j = 0; j < max; j++) {
						cksum += buf[j];
						r_strbuf_appendf (sb, "%02x", buf[j]);
					}
					r_strbuf_appendf (sb, "%02x\n", (ut8)(0-cksum));
					i += max - 1;
				}
			}
		}
		break;
	case 'r':
		{
			char *s = r_range_tostring (rih->range);
			r_str_replace_char (s, ',', '\n');
			r_strbuf_append (sb, s);
			free (s);
		}
		break;
	case 'j':
		{
			PJ *pj = pj_new ();
			pj_o (pj);
			pj_kn (pj, "min", rih->min);
			pj_kn (pj, "max", rih->max);
			pj_kn (pj, "size", rih->max - rih->min);
			pj_ka (pj, "ranges");
			RRangeItem *r;
			RListIter *iter;
			r_list_foreach_prev (rih->range->ranges, iter, r) {
				pj_o (pj);
				pj_kn (pj, "from", r->fr);
				pj_kn (pj, "to", r->to);
				pj_end (pj);
			}
			pj_end (pj);
			pj_end (pj);
			char *s = pj_drain (pj);
			r_strbuf_append (sb, s);
			free (s);
		}
		break;
	default:
		r_strbuf_appendf (sb, "min 0x%08"PFMT64x"\n", rih->min);
		r_strbuf_appendf (sb, "max 0x%08"PFMT64x"\n", rih->max);
		r_strbuf_appendf (sb, "siz 0x%08"PFMT64x"\n", rih->max - rih->min);
		break;
	}
	r_strbuf_trim (sb);
	return r_strbuf_drain (sb);
}

RIOPlugin r_io_plugin_ihex = {
	.meta = {
		.name = "ihex",
		.desc = "Open intel HEX file (R2_IHEX_IGNORE_CKSUM=1)",
		.author = "pancake,fenugrec",
		.license = "LGPL-3.0-only",
	},
	.uris = "ihex://",
	.open = __open,
	.close = __close,
	.read = __read,
	.check = __plugin_open,
	.seek = __lseek,
	.write = __write,
	.resize = __resize,
	.system = __system,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_ihex,
	.version = R2_VERSION
};
#endif
