/* radare - LGPL - Copyright 2015-2019 - pancake */

#include "r_io.h"
#include "r_lib.h"
#include "r_socket.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

/* --------------------------------------------------------- */
#define R2P(x) ((R2Pipe*)(x)->data)

// TODO: add r2pipe_assert

static int __write(RIO *io, RIODesc *fd, const ut8 *buf, int count) {
	char fmt[4096];
	char *bufn, bufnum[4096];
	int i, rv, rescount = -1;
	char *res, *r;
	if (!fd || !fd->data) {
		return -1;
	}
	bufn = bufnum;
	*bufn = 0;
	for (i = 0; i < count; i++) {
		int bufn_sz = sizeof (bufnum) - (bufn - bufnum);
		snprintf (bufn, bufn_sz, "%s%d", i ? "," : "", buf[i]);
		bufn += strlen (bufn);
	}
	//TODO PJ (?)
	int len = snprintf (fmt, sizeof (fmt),
		"{\"op\":\"write\",\"address\":%" PFMT64d ",\"data\":[%s]}",
		io->off, bufnum);
	if (len >= sizeof (fmt)) {
		eprintf ("r2pipe_write: error, fmt string has been truncated\n");
		return -1;
	}
	rv = r2pipe_write (R2P (fd), fmt);
	if (rv < 1) {
		eprintf ("r2pipe_write: error\n");
		return -1;
	}
	res = r2pipe_read (R2P (fd));
	/* TODO: parse json back */
	r = strstr (res, "result");
	if (r && r[6]) {
		count = atoi (r + 6 + 1);
	}
	free (res);
	return rescount;
}

static int __read(RIO *io, RIODesc *fd, ut8 *buf, int count) {
	char fmt[4096], num[128];
	int rv, rescount = -1;
	int bufi, numi;
	char *res, *r;
	if (!fd || !fd->data) {
		return -1;
	}
	if (count > 1024) {
		count = 1024;
	}
	//TODO PJ (?)
	snprintf (fmt, sizeof (fmt),
		"{\"op\":\"read\",\"address\":%"PFMT64d",\"count\":%d}",
		io->off, count);
	rv = r2pipe_write (R2P (fd), fmt);
	if (rv < 1) {
		eprintf ("r2pipe_write: error\n");
		return -1;
	}
	res = r2pipe_read (R2P (fd));

	/* TODO: parse json back */
	r = strstr (res, "result");
	if (r) {
		rescount = atoi (r + 6 + 2);
	}
	r = strstr (res, "data");
	if (r) {
		char *arr = strchr (r, ':');
		if (!arr || arr[1]!='[') {
			goto beach;
		}
		arr += 2;
		for (num[0] = numi = bufi = 0; bufi < count && *arr; arr++) {
			switch (*arr) {
			case '0':
			case '1':
			case '2':
			case '3':
			case '4':
			case '5':
			case '6':
			case '7':
			case '8':
			case '9':
				num[numi++] = *arr;
				num[numi] = 0;
				break;
			case ' ':
			case ',':
			case ']':
				if (num[0]) {
					buf[bufi++] = atoi (num);
					num[numi = 0] = 0;
				}
				break;
			case 'n':
			case 'u':
			case 'l':
				break;
			default:
				goto beach;
				break;
			}
		}
	}
beach:
	free (res);
	return rescount;
}

static int __close(RIODesc *fd) {
	if (!fd || !fd->data) {
		return -1;
	}
	r2pipe_close (fd->data);
	fd->data = NULL;
	return 0;
}

static ut64 __lseek(RIO *io, RIODesc *fd, ut64 offset, int whence) {
	switch (whence) {
	case SEEK_SET: return offset;
	case SEEK_CUR: return io->off + offset;
	case SEEK_END: return UT64_MAX;
	}
	return offset;
}

static bool __check(RIO *io, const char *pathname, bool many) {
	return (!strncmp (pathname, "r2pipe://", 9));
}

static RIODesc *__open(RIO *io, const char *pathname, int rw, int mode) {
	R2Pipe *r2p = NULL;
	if (__check (io, pathname, 0)) {
		r2p = r2pipe_open (pathname + 9);
	}
	return r2p? r_io_desc_new (io, &r_io_plugin_r2pipe,
		pathname, rw, mode, r2p): NULL;
}

static char *__system(RIO *io, RIODesc *fd, const char *msg) {
	r_return_val_if_fail (io && fd && msg, NULL);
	PJ *pj = pj_new ();
	pj_o (pj);
	pj_ks (pj, "op", "system");
	pj_ks (pj, "cmd", msg);
	pj_end (pj);
	const char *fmt = pj_string (pj);
	int rv = r2pipe_write (R2P (fd), fmt);
	pj_free (pj);
	if (rv < 1) {
		eprintf ("r2pipe_write: error\n");
		return NULL;
	}
	char *res = r2pipe_read (R2P (fd));
	//eprintf ("%s\n", res);
	/* TODO: parse json back */
	char *r = strstr (res, "result");
	if (r) {
		int rescount = atoi (r + 6 + 1);
		eprintf ("RESULT %d\n", rescount);
	}
	free (res);
	return NULL;
}

RIOPlugin r_io_plugin_r2pipe = {
	.name = "r2pipe",
	.desc = "r2pipe io plugin",
	.license = "MIT",
	.uris = "r2pipe://",
	.open = __open,
	.close = __close,
	.read = __read,
	.check = __check,
	.lseek = __lseek,
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
