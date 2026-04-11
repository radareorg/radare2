/* radare - LGPL - Copyright 2015-2025 - pancake */

#include <r_io.h>
#include <r_socket.h>

#define R2P(x) ((R2Pipe*)(x)->data)

static int __write(RIO *io, RIODesc *fd, const ut8 *buf, int count) {
	if (!fd || !fd->data) {
		return -1;
	}
	RStrBuf *sb = r_strbuf_new ("");
	int i;
	for (i = 0; i < count; i++) {
		r_strbuf_appendf (sb, "%s%d", i ? "," : "", buf[i]);
	}
	char *nums = r_strbuf_drain (sb);
	//TODO PJ (?)
	char *fmt = r_str_newf ("{\"op\":\"write\",\"address\":%" PFMT64d ",\"data\":[%s]}",
		io->off, nums);
	free (nums);
	int rv = r2pipe_write (R2P (fd), fmt);
	free (fmt);
	if (rv < 1) {
		R_LOG_ERROR ("r2pipe_write failed");
		return -1;
	}
	char *res = r2pipe_read (R2P (fd));
	if (!res) {
		return -1;
	}
	int rescount = -1;
	/* TODO: parse json back */
	char *r = strstr (res, "result");
	if (r && r[6]) {
		rescount = atoi (r + 6 + 1);
	}
	free (res);
	return rescount;
}

static int __read(RIO *io, RIODesc *fd, ut8 *buf, int count) {
	if (!fd || !fd->data) {
		return -1;
	}
	if (count > 1024) {
		count = 1024;
	}
	//TODO PJ (?)
	char *fmt = r_str_newf ("{\"op\":\"read\",\"address\":%" PFMT64d ",\"count\":%d}",
		io->off, count);
	int rv = r2pipe_write (R2P (fd), fmt);
	free (fmt);
	if (rv < 1) {
		R_LOG_ERROR ("r2pipe_write failed");
		return -1;
	}
	char *res = r2pipe_read (R2P (fd));
	if (!res) {
		return -1;
	}

	int rescount = -1;
	/* TODO: parse json back */
	char *r = strstr (res, "result");
	if (r) {
		rescount = atoi (r + 6 + 2);
	}
	r = strstr (res, "data");
	if (r) {
		char *arr = strchr (r, ':');
		if (!arr || arr[1] != '[') {
			goto beach;
		}
		char num[128];
		int bufi = 0, numi = 0;
		num[0] = 0;
		for (arr += 2; bufi < count && *arr; arr++) {
			const char c = *arr;
			if (IS_DIGIT (c)) {
				if (numi < (int)sizeof (num) - 1) {
					num[numi++] = c;
					num[numi] = 0;
				}
			} else if (c == ' ' || c == ',' || c == ']') {
				if (num[0]) {
					buf[bufi++] = atoi (num);
					num[0] = 0;
					numi = 0;
				}
			} else if (c != 'n' && c != 'u' && c != 'l') {
				goto beach;
			}
		}
	}
beach:
	free (res);
	return rescount;
}

static bool __close(RIODesc *fd) {
	if (!fd || !fd->data) {
		return false;
	}
	r2pipe_close (fd->data);
	fd->data = NULL;
	return true;
}

static ut64 __lseek(RIO *io, RIODesc *fd, ut64 offset, int whence) {
	switch (whence) {
	case R_IO_SEEK_SET: return offset;
	case R_IO_SEEK_CUR: return io->off + offset;
	case R_IO_SEEK_END: return UT64_MAX - 1;
	}
	return offset;
}

static bool __check(RIO *io, const char *pathname, bool many) {
	return r_str_startswith (pathname, "r2pipe://");
}

static RIODesc *__open(RIO *io, const char *pathname, int rw, int mode) {
	if (!__check (io, pathname, false)) {
		return NULL;
	}
	R2Pipe *r2p = r2pipe_open (pathname + 9);
	if (!r2p) {
		return NULL;
	}
	return r_io_desc_new (io, &r_io_plugin_r2pipe, pathname, rw, mode, r2p);
}

static char *__system(RIO *io, RIODesc *fd, const char *msg) {
	R_RETURN_VAL_IF_FAIL (io && fd && msg, NULL);
	PJ *pj = pj_new ();
	pj_o (pj);
	pj_ks (pj, "op", "system");
	pj_ks (pj, "cmd", msg);
	pj_end (pj);
	const char *fmt = pj_string (pj);
	int rv = r2pipe_write (R2P (fd), fmt);
	pj_free (pj);
	if (rv < 1) {
		R_LOG_ERROR ("r2pipe_write failed");
		return NULL;
	}
	char *res = r2pipe_read (R2P (fd));
	if (R_LIKELY (res)) {
		/* TODO: parse json back */
		char *r = strstr (res, "result");
		if (r) {
			int rescount = atoi (r + 6 + 1);
			R_LOG_INFO ("RESULT %d", rescount);
		}
		free (res);
	}
	return NULL;
}

RIOPlugin r_io_plugin_r2pipe = {
	.meta = {
		.name = "r2pipe",
		.author = "pancake",
		.desc = "r2pipe io plugin",
		.license = "MIT",
	},
	.uris = "r2pipe://",
	.open = __open,
	.close = __close,
	.read = __read,
	.check = __check,
	.seek = __lseek,
	.write = __write,
	.system = __system
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_r2pipe,
	.version = R2_VERSION
};
#endif
