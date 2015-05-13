/* radare - LGPL - Copyright 2015 - pancake */

#include "r_io.h"
#include "r_lib.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

typedef struct {
	int magic;
	int child;
	int input[2];
	int output[2];
} R2Pipe;

#define R2P_MAGIC 0x329193
#define R2P_PID(x) (((R2Pipe*)x->data)->pid)
#define R2P_INPUT(x) (((R2Pipe*)x->data)->input[0])
#define R2P_OUTPUT(x) (((R2Pipe*)x->data)->output[1])

static void env(const char *s, int f) {
        char *a = r_str_newf ("%d", f);
        r_sys_setenv (s, a);
        free (a);
}

static int r2p_close(R2Pipe *r2p) {
	if (r2p->input[0] != -1) {
		close (r2p->input[0]);
		close (r2p->input[1]);
		r2p->input[0] = -1;
		r2p->input[1] = -1;
	}
	if (r2p->output[0] != -1) {
		close (r2p->output[0]);
		close (r2p->output[1]);
		r2p->output[0] = -1;
		r2p->output[1] = -1;
	}
	if (r2p->child != -1) {
		kill (r2p->child, SIGINT);
		r2p->child = -1;
	}
	return 0;
}

static R2Pipe *r2p_open(const char *cmd) {
	R2Pipe *r2p = R_NEW0 (R2Pipe);
	r2p->magic = R2P_MAGIC;
	pipe (r2p->input);
	pipe (r2p->output);
	r2p->child = fork ();
	if (r2p->child == -1) {
		return NULL;
	}
	env ("R2PIPE_IN", r2p->input[0]);
	env ("R2PIPE_OUT", r2p->output[1]);

	if (r2p->child) {
		eprintf ("Child is %d\n", r2p->child);
	} else {
		int rc;
		rc = r_sandbox_system (cmd, 1);
		eprintf ("Child was %d with %d\n", r2p->child, rc);
		r2p_close (r2p);
		exit (0);
	}
	return r2p;
}

static int r2p_write(R2Pipe *r2p, const char *str) {
	int len = strlen (str)+1; /* include \x00 */
	return write (r2p->input[1], str, len);
}

/* TODO: add timeout here ? */
static char *r2p_read(R2Pipe *r2p) {
	char buf[1024];
	int i, rv;
	for (i=0; i<sizeof (buf)-1; i++) {
		rv = read (r2p->output[0], buf+i, 1);
		if (rv != 1 || !buf[i]) break;
	}
	buf[i] = 0;
	return strdup (buf);
}

static void r2p_free (R2Pipe *r2p) {
	r2p->magic = 0;
	free (r2p);
}

/* --------------------------------------------------------- */
#define R2P(x) ((R2Pipe*)x->data)

// TODO: add r2p_assert

static int __write(RIO *io, RIODesc *fd, const ut8 *buf, int count) {
	char fmt[4096];
	int rv, rescount = -1;
	char *res, *r;
	if (fd == NULL || fd->data == NULL)
		return -1;
	snprintf (fmt, sizeof (fmt),
		"{\"op\":\"write\",\"address\":%"PFMT64d",\"data\":%s}",
		io->off, "[]");
	rv = r2p_write (R2P(fd), fmt);
	if (rv <1) {
		eprintf ("r2p_write: error\n");
		return -1;
	}
	res = r2p_read (R2P(fd));
	/* TODO: parse json back */
	r = strstr (res, "result");
	if (r) { count = atoi (r+6+1); }
	free (res);
	return rescount;
}

static int __read(RIO *io, RIODesc *fd, ut8 *buf, const int count) {
	char fmt[4096], num[128];
	int rv, rescount = -1;
	int bufi, numi;
	char *res, *r;
	if (fd == NULL || fd->data == NULL)
		return -1;
	snprintf (fmt, sizeof (fmt),
		"{\"op\":\"read\",\"address\":%"PFMT64d",\"count\":%d}",
		io->off, count);
	rv = r2p_write (R2P(fd), fmt);
	if (rv <1) {
		eprintf ("r2p_write: error\n");
		return -1;
	}
	res = r2p_read (R2P(fd));
	/* TODO: parse json back */
	r = strstr (res, "result");
	if (r) { rescount = atoi (r+6+2); }
	r = strstr (res, "data");
	if (r) {
		char *arr = strchr (r, ':');
		if (!arr) goto beach;
		if (arr[1]!='[') goto beach;
		arr += 2;
		for (numi=bufi=0; *arr; arr++) {
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
	r2p_close (fd->data);
	r2p_free (fd->data);
	fd->data = NULL;
	fd->state = R_IO_DESC_TYPE_CLOSED;
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

static int __plugin_open(RIO *io, const char *pathname, ut8 many) {
	return (!strncmp (pathname, "r2pipe://", 9));
}

static RIODesc *__open(RIO *io, const char *pathname, int rw, int mode) {
	R2Pipe *r2p = NULL;
	if (__plugin_open (io, pathname, 0)) {
		r2p = r2p_open (pathname+9);
	}
	return r2p? r_io_desc_new (&r_io_plugin_r2pipe,
		r2p->child, pathname, rw, mode, r2p): NULL;
}

static int __system(RIO *io, RIODesc *fd, const char *msg) {
	char fmt[4096];
	int rv, rescount = -1;
	char *res, *r;
	if (fd == NULL || fd->data == NULL)
		return -1;
	snprintf (fmt, sizeof (fmt),
		"{\"op\":\"system\",\"cmd\":\"%s\"}", msg);
	rv = r2p_write (R2P (fd), fmt);
	if (rv <1) {
		eprintf ("r2p_write: error\n");
		return -1;
	}
	res = r2p_read (R2P (fd));
	eprintf ("%s\n", res);
	/* TODO: parse json back */
	r = strstr (res, "result");
	if (r) { rescount = atoi (r+6+1); }
	free (res);
	return rescount;
}

RIOPlugin r_io_plugin_r2pipe = {
	.name = "r2pipe",
        .desc = "r2pipe exec",
	.license = "MIT",
        .open = __open,
        .close = __close,
	.read = __read,
        .plugin_open = __plugin_open,
	.lseek = __lseek,
	.write = __write,
	.system = __system
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_r2pipe
};
#endif
