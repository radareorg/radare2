/* radare - GPL - Copyright 2010-2026 pancake */

#include <r_io.h>
#include <r_lib.h>

#if WITH_GPL
#include <r_socket.h>
#include <r_util.h>
#define IRAPI static inline
#include <libqnxr.h>

typedef struct {
	libqnxr_t desc;
	ut64 c_addr;
	ut32 c_size;
	ut8 *c_buff;
} RIOQnx;

static bool __plugin_open(RIO *io, const char *file, bool many) {
	return r_str_startswith (file, "qnx://");
}

/* reading in a different place clears the previous cache */

static int debug_qnx_read_at(RIOQnx *rioq, ut8 *buf, int sz, ut64 addr) {
	ut32 size_max = 500;
	ut32 packets = sz / size_max;
	ut32 last = sz % size_max;
	ut32 x;
	if (rioq->c_buff && addr != UT64_MAX && addr == rioq->c_addr) {
		memcpy (buf, rioq->c_buff, sz);
		return sz;
	}
	if (sz < 1 || addr >= UT64_MAX) {
		return -1;
	}
	for (x = 0; x < packets; x++) {
		qnxr_read_memory (&rioq->desc, addr + x * size_max, (buf + x * size_max), size_max);
	}
	if (last) {
		qnxr_read_memory (&rioq->desc, addr + x * size_max, (buf + x * size_max), last);
	}
	rioq->c_addr = addr;
	rioq->c_size = sz;
	return sz;
}

static int debug_qnx_write_at(RIOQnx *rioq, const ut8 *buf, int sz, ut64 addr) {
	ut32 x, size_max = 500;
	ut32 packets = sz / size_max;
	ut32 last = sz % size_max;

	if (sz < 1 || addr >= UT64_MAX) {
		return -1;
	}
	if (rioq->c_addr != UT64_MAX && addr >= rioq->c_addr && rioq->c_addr + sz < (rioq->c_addr + rioq->c_size)) {
		R_FREE (rioq->c_buff);
		rioq->c_addr = UT64_MAX;
	}
	for (x = 0; x < packets; x++) {
		qnxr_write_memory (&rioq->desc, addr + x * size_max,
				   (const uint8_t *)(buf + x * size_max), size_max);
	}
	if (last) {
		qnxr_write_memory (&rioq->desc, addr + x * size_max,
				   (buf + x * size_max), last);
	}
	return sz;
}

static RIODesc *__open(RIO *io, const char *file, int rw, int mode) {
	char host[128], *port, *p;

	if (!__plugin_open (io, file, 0)) {
		return NULL;
	}
	strncpy (host, file + 6, sizeof (host) - 1);
	host[sizeof (host) - 1] = '\0';
	port = strchr (host, ':');
	if (!port) {
		R_LOG_ERROR ("Port not specified. Please use qnx://[host]:[port]");
		return NULL;
	}
	*port = '\0';
	port++;
	p = strchr (port, '/');
	if (p) {
		*p = 0;
	}

	if (r_sandbox_enable (0)) {
		R_LOG_ERROR ("sandbox: Cannot use network");
		return NULL;
	}
	RIOQnx *rioq = R_NEW0 (RIOQnx);
	rioq->c_addr = UT64_MAX;
	rioq->c_size = UT32_MAX;
	qnxr_init (&rioq->desc);
	int i_port = atoi (port);
	if (qnxr_connect (&rioq->desc, host, i_port) == 0) {
		return r_io_desc_new (io, &r_io_plugin_qnx, file, rw, mode, rioq);
	}
	R_LOG_ERROR ("qnx.io.open: Cannot connect to host");
	free (rioq);
	return NULL;
}

static int __write(RIO *io, RIODesc *fd, const ut8 *buf, int count) {
	ut64 addr = io->off;
	RIOQnx *rioq = fd->data;
	return rioq? debug_qnx_write_at (rioq, buf, count, addr): -1;
}

static ut64 __lseek(RIO *io, RIODesc *fd, ut64 offset, int whence) {
	return offset;
}

static int __read(RIO *io, RIODesc *fd, ut8 *buf, int count) {
	memset (buf, io->Oxff, count);
	ut64 addr = io->off;
	RIOQnx *rioq = fd->data;
	return rioq? debug_qnx_read_at (rioq, buf, count, addr): -1;
}

static bool __close(RIODesc *fd) {
	RIOQnx *rioq = fd ? fd->data : NULL;
	if (rioq) {
		R_FREE (rioq->c_buff);
	}
	return true;
}

static char *__system(RIO *io, RIODesc *fd, const char *cmd) {
	return NULL;
}

RIOPlugin r_io_plugin_qnx = {
	.meta = {
		.name = "qnx",
		.desc = "Attach to QNX pdebug instance",
		.author = "Sergey Anufrienko",
		.license = "GPL-3.0-only",
	},
	.uris = "qnx://",
	.open = __open,
	.close = __close,
	.read = __read,
	.write = __write,
	.check = __plugin_open,
	.seek = __lseek,
	.system = __system,
	.isdbg = true
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_qnx,
	.version = R2_VERSION
};
#endif

#else

RIOPlugin r_io_plugin_qnx = {
	.meta = {
		.name = "qnx",
		.license = "GPL-3.0-only",
		.desc = "Attach to QNX pdebug instance (compiled without GPL)",
	},
};
#endif

