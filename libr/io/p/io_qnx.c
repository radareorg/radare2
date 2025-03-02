/* radare - GPL - Copyright 2010-2024 pancake */

#include <r_io.h>
#include <r_lib.h>

#if WITH_GPL
#include <r_socket.h>
#include <r_util.h>
#define IRAPI static inline
#include <libqnxr.h>

typedef struct {
	libqnxr_t desc;
} RIOQnx;

static libqnxr_t *desc = NULL;
static RIODesc *rioqnx = NULL;

static bool __plugin_open(RIO *io, const char *file, bool many) {
	return r_str_startswith (file, "qnx://");
}

/* hacky cache to speedup io a bit */
/* reading in a different place clears the previous cache */
static R_TH_LOCAL ut64 c_addr = UT64_MAX;
static R_TH_LOCAL ut32 c_size = UT32_MAX;
static R_TH_LOCAL ut8 *c_buff = NULL;
#define SILLY_CACHE 0

static int debug_qnx_read_at(ut8 *buf, int sz, ut64 addr) {
	ut32 size_max = 500;
	ut32 packets = sz / size_max;
	ut32 last = sz % size_max;
	ut32 x;
	if (c_buff && addr != UT64_MAX && addr == c_addr) {
		memcpy (buf, c_buff, sz);
		return sz;
	}
	if (sz < 1 || addr >= UT64_MAX) {
		return -1;
	}
	for (x = 0; x < packets; x++) {
		qnxr_read_memory (desc, addr + x * size_max, (buf + x * size_max), size_max);
	}
	if (last) {
		qnxr_read_memory (desc, addr + x * size_max, (buf + x * size_max), last);
	}
	c_addr = addr;
	c_size = sz;
#if SILLY_CACHE
	free (c_buff);
	c_buff = r_mem_dup (buf, sz);
#endif
	return sz;
}

static int debug_qnx_write_at(const ut8 *buf, int sz, ut64 addr) {
	ut32 x, size_max = 500;
	ut32 packets = sz / size_max;
	ut32 last = sz % size_max;

	if (sz < 1 || addr >= UT64_MAX) {
		return -1;
	}
	if (c_addr != UT64_MAX && addr >= c_addr && c_addr + sz < (c_addr + c_size)) {
		R_FREE (c_buff);
		c_addr = UT64_MAX;
	}
	for (x = 0; x < packets; x++) {
		qnxr_write_memory (desc, addr + x * size_max,
				   (const uint8_t *)(buf + x * size_max), size_max);
	}
	if (last) {
		qnxr_write_memory (desc, addr + x * size_max,
				   (buf + x * size_max), last);
	}
	return sz;
}

static RIODesc *__open(RIO *io, const char *file, int rw, int mode) {
	char host[128], *port, *p;

	if (!__plugin_open (io, file, 0)) {
		return NULL;
	}
	if (rioqnx) {
		// FIX: Don't allocate more than one RIODesc
		return rioqnx;
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
	qnxr_init (&rioq->desc);
	int i_port = atoi (port);
	if (qnxr_connect (&rioq->desc, host, i_port) == 0) {
		desc = &rioq->desc;
		rioqnx = r_io_desc_new (io, &r_io_plugin_qnx, file, rw, mode, rioq);
		return rioqnx;
	}
	R_LOG_ERROR ("qnx.io.open: Cannot connect to host");
	free (rioq);
	return NULL;
}

static int __write(RIO *io, RIODesc *fd, const ut8 *buf, int count) {
	ut64 addr = io->off;
	if (!desc) {
		return -1;
	}
	return debug_qnx_write_at (buf, count, addr);
}

static ut64 __lseek(RIO *io, RIODesc *fd, ut64 offset, int whence) {
	return offset;
}

static int __read(RIO *io, RIODesc *fd, ut8 *buf, int count) {
	memset (buf, io->Oxff, count);
	ut64 addr = io->off;
	if (!desc) {
		return -1;
	}
	return debug_qnx_read_at (buf, count, addr);
}

static bool __close(RIODesc *fd) {
	// TODO
	return true;
}

static char *__system(RIO *io, RIODesc *fd, const char *cmd) {
	return NULL;
}

RIOPlugin r_io_plugin_qnx = {
	.meta = {
		.name = "qnx",
		.desc = "Attach to QNX pdebug instance",
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

