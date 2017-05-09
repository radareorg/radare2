/* radare - LGPL - Copyright 2015-2016 - pancake */

#include "r_io.h"
#include "r_lib.h"
#include "r_socket.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

/* --------------------------------------------------------- */
#define R2P(x) ((R2Pipe*)x->data)

// TODO: add r2p_assert

static int __write(RIO *io, RIODesc *fd, const ut8 *buf, int count) {
	char fmt[4096];
	char *bufn, bufnum[4096];
	int i, rv, rescount = -1;
	char *res, *r;
	if (!fd || !fd->data)
		return -1;
	bufn = bufnum;
	*bufn = 0;
	for (i=0; i<count; i++) {
		int bufn_sz = sizeof (bufnum) - (bufn-bufnum);
		snprintf (bufn, bufn_sz, "%s%d", i?",":"", buf[i]);
		bufn += strlen (bufn);
	}
	snprintf (fmt, sizeof (fmt),
		"{\"op\":\"write\",\"address\":%"PFMT64d",\"data\":[%s]}",
		io->off, bufnum);
	rv = r2p_write (R2P (fd), fmt);
	if (rv <1) {
		eprintf ("r2p_write: error\n");
		return -1;
	}
	res = r2p_read (R2P (fd));
	/* TODO: parse json back */
	r = strstr (res, "result");
	if (r) {
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
	snprintf (fmt, sizeof (fmt),
		"{\"op\":\"read\",\"address\":%"PFMT64d",\"count\":%d}",
		io->off, count);
	rv = r2p_write (R2P (fd), fmt);
	if (rv < 1) {
		eprintf ("r2p_write: error\n");
		return -1;
	}
	res = r2p_read (R2P (fd));

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
			case '0'...'9':
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
	if (!fd || !fd->data)
		return -1;
	r2p_free (fd->data);
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
		r2p = r2p_open (pathname + 9);
	}
	return r2p? r_io_desc_new (io, &r_io_plugin_r2pipe,
		pathname, rw, mode, r2p): NULL;
}

static int __system(RIO *io, RIODesc *fd, const char *msg) {
	char fmt[4096];
	int rv, rescount = -1;
	char *res, *r;
	if (!fd || !fd->data)
		return -1;
	snprintf (fmt, sizeof (fmt),
		"{\"op\":\"system\",\"cmd\":\"%s\"}", msg);
	rv = r2p_write (R2P (fd), fmt);
	if (rv <1) {
		eprintf ("r2p_write: error\n");
		return -1;
	}
	res = r2p_read (R2P (fd));
	//eprintf ("%s\n", res);
	/* TODO: parse json back */
	r = strstr (res, "result");
	if (r) { rescount = atoi (r+6+1); }
	free (res);
	return rescount;
}

RIOPlugin r_io_plugin_r2pipe = {
	.name = "r2pipe",
        .desc = "r2pipe io plugin",
	.license = "MIT",
        .open = __open,
        .close = __close,
	.read = __read,
        .check = __check,
	.lseek = __lseek,
	.write = __write,
	.system = __system
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_r2pipe,
	.version = R2_VERSION
};
#endif
