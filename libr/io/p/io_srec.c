/* radare - LGPL - Copyright 2026 - seifreed */

/*
*** Motorola SREC format description
S<type><count><address><data><checksum>
count: number of bytes in address+data+checksum
checksum: ones complement of sum of count+address+data

Supported record types:
  S0 header (ignored)
  S1 data, 16-bit address
  S2 data, 24-bit address
  S3 data, 32-bit address
  S5/S6 count (ignored)
  S7/S8/S9 entry (ignored)
*/

#include <r_io.h>

typedef struct {
	int fd;
	RBuffer *rbuf;
	ut64 min;
	ut64 max;
	RRange *range;
} Rsrec;

static void update_bounds(Rsrec *rs, ut64 min, ut64 max, const ut8 *buf) {
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
	r_range_add (rs->range, min, max, 1);
	if (min < rs->min) {
		rs->min = min;
	}
	if (max > rs->max) {
		rs->max = max;
	}
}

static bool srec_parse_byte(const char *s, ut8 *out) {
	int v = r_hex_pair2bin (s);
	if (v < 0) {
		return false;
	}
	*out = (ut8)v;
	return true;
}

static int srec_addr_len(char type) {
	switch (type) {
	case '0':
	case '1':
	case '5':
	case '9':
		return 2;
	case '2':
	case '6':
	case '8':
		return 3;
	case '3':
	case '7':
		return 4;
	default:
		return -1;
	}
}

static bool srec_parse(Rsrec *rs, char *str) {
	RBuffer *rbuf = rs->rbuf;
	const bool ignore_cksum = r_sys_getenv_asbool ("R2_SREC_IGNORE_CKSUM");
	char *line = str;
	while (line && *line) {
		char *eol = strchr (line, '\n');
		if (eol) {
			if (eol > line && eol[-1] == '\r') {
				eol[-1] = 0;
			}
			*eol = 0;
		} else {
			size_t len = strlen (line);
			if (len && line[len - 1] == '\r') {
				line[len - 1] = 0;
			}
		}
		char *cur = r_str_trim_head (line);
		if (*cur == 0) {
			line = eol? eol + 1: NULL;
			continue;
		}
		if (cur[0] != 'S' || !cur[1]) {
			R_LOG_ERROR ("Invalid SREC record (%.*s)", 80, cur);
			return false;
		}
		const char type = cur[1];
		int addr_len = srec_addr_len (type);
		if (addr_len < 0) {
			R_LOG_ERROR ("Unknown SREC record type '%c'", type);
			return false;
		}
		ut8 count = 0;
		if (!srec_parse_byte (cur + 2, &count)) {
			R_LOG_ERROR ("Invalid SREC count (%.*s)", 80, cur);
			return false;
		}
		size_t pos = 4;
		ut64 addr = 0;
		ut8 cksum = count;
		int i;
		for (i = 0; i < addr_len; i++) {
			ut8 b = 0;
			if (!srec_parse_byte (cur + pos, &b)) {
				R_LOG_ERROR ("Invalid SREC address (%.*s)", 80, cur);
				return false;
			}
			addr = (addr << 8) | b;
			cksum += b;
			pos += 2;
		}
		int data_len = (int)count - addr_len - 1;
		if (data_len < 0 || data_len > 255) {
			R_LOG_ERROR ("Invalid SREC data length (%.*s)", 80, cur);
			return false;
		}
		ut8 data[255];
		for (i = 0; i < data_len; i++) {
			ut8 b = 0;
			if (!srec_parse_byte (cur + pos, &b)) {
				R_LOG_ERROR ("Invalid SREC data (%.*s)", 80, cur);
				return false;
			}
			data[i] = b;
			cksum += b;
			pos += 2;
		}
		ut8 cks = 0;
		if (!srec_parse_byte (cur + pos, &cks)) {
			R_LOG_ERROR ("Invalid SREC checksum (%.*s)", 80, cur);
			return false;
		}
		cksum += cks;
		if ((cksum & 0xff) != 0xff) {
			if (!ignore_cksum) {
				ut8 fixed = 0xff - (cksum - cks);
				R_LOG_ERROR ("Checksum failed %02x (got %02x expected %02x)", cksum, cks, fixed);
				return false;
			}
			R_LOG_ERROR ("Ignored checksum failed %02x", cksum);
		}

		switch (type) {
		case '1':
		case '2':
		case '3':
			if (data_len > 0) {
				update_bounds (rs, addr, addr + data_len, data);
				if (r_buf_write_at (rbuf, addr, data, data_len) != data_len) {
					R_LOG_ERROR ("srec: sparse buffer problem, giving up");
					return false;
				}
			}
			break;
		default:
			break;
		}
		line = eol? eol + 1: NULL;
	}
	return true;
}

static int __read(RIO *io, RIODesc *fd, ut8 *buf, int count) {
	if (!fd || !fd->data || count <= 0) {
		return -1;
	}
	Rsrec *rs = fd->data;
	memset (buf, io->Oxff, count);
	int r = r_buf_read_at (rs->rbuf, io->off, buf, count);
	if (r >= 0) {
		r_buf_seek (rs->rbuf, r, R_BUF_CUR);
	}
	return r;
}

static bool __close(RIODesc *fd) {
	if (!fd || !fd->data) {
		return false;
	}
	Rsrec *rs = fd->data;
	r_unref (rs->rbuf);
	r_range_free (rs->range);
	free (rs);
	fd->data = NULL;
	return true;
}

static ut64 __lseek(RIO *io, RIODesc *fd, ut64 offset, int whence) {
	if (!fd || !fd->data) {
		return UT64_MAX;
	}
	Rsrec *rs = fd->data;
	io->off = r_buf_seek (rs->rbuf, offset, whence);
	return io->off;
}

static bool __plugin_open(RIO *io, const char *pathname, bool many) {
	return r_str_startswith (pathname, "srec://");
}

static RIODesc *__open(RIO *io, const char *pathname, int rw, int mode) {
	if (!__plugin_open (io, pathname, 0)) {
		return NULL;
	}
	char *str = r_file_slurp (pathname + 7, NULL);
	if (!str) {
		return NULL;
	}
	Rsrec *rs = R_NEW0 (Rsrec);
	if (!rs) {
		free (str);
		return NULL;
	}
	rs->range = r_range_new ();
	rs->min = UT64_MAX;
	rs->rbuf = r_buf_new_sparse (io->Oxff);
	if (!rs->rbuf) {
		free (str);
		free (rs);
		return NULL;
	}
	if (!srec_parse (rs, str)) {
		R_LOG_ERROR ("srec: failed to parse file");
		free (str);
		r_unref (rs->rbuf);
		free (rs);
		return NULL;
	}
	free (str);
	return r_io_desc_new (io, &r_io_plugin_srec, pathname, rw, mode, rs);
}

static bool __resize(RIO *io, RIODesc *fd, ut64 size) {
	if (!fd) {
		return false;
	}
	Rsrec *rs = fd->data;
	if (rs) {
		return r_buf_resize (rs->rbuf, size);
	}
	return false;
}

static char *__system(RIO *io, RIODesc *fd, const char *cmd) {
	if (R_STR_ISEMPTY (cmd)) {
		return NULL;
	}
	Rsrec *rs = fd->data;
	RStrBuf *sb = r_strbuf_new ("");
	switch (*cmd) {
	case '?':
		r_strbuf_append (sb, "Usage: [:][arg]\n");
		r_strbuf_append (sb, ":b     show minimum and maximum addresses written\n");
		r_strbuf_append (sb, ":r     show written ranges\n");
		break;
	case 'r':
		{
			char *s = r_range_tostring (rs->range);
			r_str_replace_char (s, ',', '\n');
			r_strbuf_append (sb, s);
			free (s);
		}
		break;
	case 'b':
		{
			ut64 size = rs->max - rs->min;
			r_strbuf_appendf (sb, "0x%"PFMT64x" - 0x%"PFMT64x" (size 0x%"PFMT64x")\n",
				rs->min, rs->max, size);
		}
		break;
	}
	return r_strbuf_drain (sb);
}

RIOPlugin r_io_plugin_srec = {
	.meta = {
		.name = "srec",
		.desc = "Open Motorola SREC file (R2_SREC_IGNORE_CKSUM=1)",
		.author = "seifreed",
		.license = "LGPL-3.0-only",
	},
	.uris = "srec://",
	.open = __open,
	.close = __close,
	.read = __read,
	.seek = __lseek,
	.resize = __resize,
	.system = __system,
	.check = __plugin_open,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_srec,
	.version = R2_VERSION
};
#endif
