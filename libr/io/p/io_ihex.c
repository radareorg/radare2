/* radare - LGPL - Copyright 2013-2026 - pancake, fenugrec */

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

typedef struct {
	RBuffer *rbuf;
	ut64 min;
	ut64 max;
} Rihex;

static bool is_all_ff(const ut8 *buf, size_t len) {
	size_t i;
	for (i = 0; i < len; i++) {
		if (buf[i] != 0xff) {
			return false;
		}
	}
	return true;
}

static void update_bounds(Rihex *rih, ut64 min, ut64 max, const ut8 *buf) {
	if (is_all_ff (buf, max - min)) {
		return;
	}
	if (min < rih->min) {
		rih->min = min;
	}
	if (max > rih->max) {
		rih->max = max;
	}
}

// written chunks that are not all 0xff, adjacent ones merged
static RRange *written_ranges(RBuffer *rbuf) {
	RRange *rgs = r_range_new ();
	RList *chunks = r_buf_nonempty_list (rbuf);
	RListIter *iter;
	RBufferSparseItem *si;
	r_list_foreach (chunks, iter, si) {
		if (!is_all_ff (si->data, si->size)) {
			r_range_add (rgs, si->from, si->to, 1);
		}
	}
	r_list_free (chunks);
	return rgs;
}

static void ihex_record(RStrBuf *sb, ut8 type, ut16 addr, const ut8 *data, int len) {
	ut8 cksum = len + (addr >> 8) + addr + type;
	int i;
	r_strbuf_appendf (sb, ":%02X%04X%02X", len, addr, type);
	for (i = 0; i < len; i++) {
		cksum += data[i];
		r_strbuf_appendf (sb, "%02X", data[i]);
	}
	r_strbuf_appendf (sb, "%02X\n", (ut8)-cksum);
}

// every written chunk as 16-byte data records, with an 04 record when the upper address changes
static char *ihex_dump(RBuffer *rbuf) {
	RStrBuf *sb = r_strbuf_new ("");
	RList *chunks = r_buf_nonempty_list (rbuf);
	RListIter *iter;
	RBufferSparseItem *si;
	ut32 upper = 0;
	r_list_foreach (chunks, iter, si) {
		int off = 0;
		while (off < si->size) {
			const ut32 at = si->from + off;
			if (at >> 16 != upper) {
				upper = at >> 16;
				const ut8 ext[2] = { upper >> 8, upper };
				ihex_record (sb, 4, 0, ext, sizeof (ext));
			}
			const int n = R_MIN (R_MIN (16, si->size - off), 0x10000 - (at & 0xffff));
			ihex_record (sb, 0, at, si->data + off, n);
			off += n;
		}
	}
	r_list_free (chunks);
	r_strbuf_append (sb, ":00000001FF\n");
	return r_strbuf_drain (sb);
}

static int __write(RIO *io, RIODesc *fd, const ut8 *buf, int count) {
	if (!fd || !fd->data || (fd->perm & R_PERM_W) == 0 || count <= 0) {
		return -1;
	}
	Rihex *rih = fd->data;
	update_bounds (rih, io->off, io->off + count, buf);
	if (r_buf_write_at (rih->rbuf, io->off, buf, count) != count) {
		R_LOG_ERROR ("ihex:write(): sparse write failed");
		return -1;
	}
	r_buf_seek (rih->rbuf, count, R_BUF_CUR);
	char *text = ihex_dump (rih->rbuf);
	const bool ok = r_file_dump (fd->name + 7, (const ut8 *)text, -1, false);
	free (text);
	return ok? count: -1;
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
	r_unref (rih->rbuf);
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

static bool ihex_bytes(const char *s, ut8 *out, int n) {
	int i;
	for (i = 0; i < n; i++, s += 2) {
		out[i] = 0;
		if (!r_hex_to_byte (&out[i], s[0]) || !r_hex_to_byte (&out[i], s[1])) {
			return false;
		}
	}
	return true;
}

// fill the sparse buffer with the data records; later records overwrite earlier ones
static bool ihex_parse(Rihex *rih, const char *str) {
	const bool ignore_cksum = r_sys_getenv_asbool ("R2_IHEX_IGNCSUM");
	ut32 base = 0;
	// count, address, type, up to 255 data bytes and the checksum
	ut8 rec[4 + 255 + 1];
	if (*str != ':') {
		R_LOG_ERROR ("Invalid data in ihex file (%.*s)", 80, str);
		return false;
	}
	for (; str; str = strchr (str + 1, ':')) {
		if (!ihex_bytes (str + 1, rec, 4) || !ihex_bytes (str + 9, rec + 4, rec[0] + 1)) {
			R_LOG_ERROR ("Invalid record in ihex file (%.*s)", 80, str);
			return false;
		}
		const int len = rec[0];
		const ut8 *data = rec + 4;
		ut8 cksum = 0;
		int i;
		for (i = 0; i < len + 5; i++) {
			cksum += rec[i];
		}
		// empty records carry nothing, some files end with a broken one instead of the EOF record
		if (cksum && len > 0) {
			R_LOG_ERROR ("Checksum failed in ihex record (%.*s)", 2 * len + 11, str);
			if (!ignore_cksum) {
				return false;
			}
		}
		switch (rec[3]) {
		case 0: // data
			{
				const ut64 at = base + ((rec[1] << 8) | rec[2]);
				update_bounds (rih, at, at + len, data);
				if (r_buf_write_at (rih->rbuf, at, data, len) != len) {
					return false;
				}
			}
			break;
		case 1: // end of file
			return true;
		case 2: // extended segment address, bits 4..19
		case 4: // extended linear address, bits 16..31
			if (len != 2) {
				R_LOG_ERROR ("Invalid type %02x ihex record", rec[3]);
				return false;
			}
			base = (ut32)((data[0] << 8) | data[1]) << ((rec[3] == 2)? 4: 16);
			break;
		case 3: // start segment address
		case 5: // start linear address
			break;
		default:
			R_LOG_ERROR ("Unknown ihex record type %02x", rec[3]);
			return false;
		}
	}
	return true;
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
		r_unref (rih->rbuf);
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
		r_strbuf_append (sb, ":j     show bounds and ranges in json\n");
		r_strbuf_append (sb, ":i     print the current contents as ihex\n");
		break;
	case 'i':
		{
			char *text = ihex_dump (rih->rbuf);
			r_strbuf_append (sb, text);
			free (text);
		}
		break;
	case 'r':
		{
			RRange *rgs = written_ranges (rih->rbuf);
			char *s = r_range_tostring (rgs);
			r_range_free (rgs);
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
			RRange *rgs = written_ranges (rih->rbuf);
			RRangeItem *r;
			RListIter *iter;
			r_list_foreach_prev (rgs->ranges, iter, r) {
				pj_o (pj);
				pj_kn (pj, "from", r->fr);
				pj_kn (pj, "to", r->to);
				pj_end (pj);
			}
			r_range_free (rgs);
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
		.desc = "Open intel HEX file (R2_IHEX_IGNCSUM=1)",
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
