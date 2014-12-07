/* radare - LGPL - Copyright 2010-2014 pancake */

#include <r_io.h>
#include <r_lib.h>
#include <r_socket.h>
#include <r_util.h>
#define IRAPI static inline
#include <libgdbr.h>

typedef struct {
	libgdbr_t desc;
} RIOGdb;

static libgdbr_t *desc = NULL;

static int __plugin_open(RIO *io, const char *file, ut8 many) {
	return (!strncmp (file, "gdb://", 6));
}

static int debug_gdb_read_at(ut8 *buf, int sz, ut64 addr) {
	ut32 size_max = 500;
	ut32 packets = sz / size_max;
	ut32 last = sz % size_max;
	ut32 x;
	if (sz < 1 || addr >= UT64_MAX) return -1;
	for (x = 0; x < packets; x++) {
		gdbr_read_memory(desc, addr + x * size_max, size_max);
		memcpy((buf + x * size_max), desc->data + x * size_max, size_max);
	}
	if (last) {
		gdbr_read_memory(desc, addr + x * size_max, last);
		memcpy((buf + x * size_max), desc->data + x * size_max, last);
	}
	return sz;
}

static int debug_gdb_write_at(const ut8 *buf, int sz, ut64 addr) {
	ut32 size_max = 500;
	ut32 packets = sz / size_max;
	ut32 last = sz % size_max;
	ut32 x;
	if (sz < 1 || addr >= UT64_MAX) return -1;
	for (x = 0; x < packets; x++) {
		gdbr_write_memory (desc, addr + x * size_max,
			(const uint8_t*)(buf + x * size_max), size_max);
	}
	if (last) {
		gdbr_write_memory (desc, addr + x * size_max,
			(buf + x * size_max), last);
	}

	return sz;
}

static RIODesc *__open(RIO *io, const char *file, int rw, int mode) {
	char host[128], *port, *p;
	if (!__plugin_open (io, file, 0))
		return NULL;
	RIOGdb *riog;
	strncpy (host, file+6, sizeof (host)-1);
	host [sizeof(host)-1] = '\0';
	port = strchr (host , ':');
	if (!port) {
		eprintf ("Port not specified. Please use gdb://[host]:[port]\n");
		return NULL;
	}
	*port = '\0';
	port++;
	p = strchr (port, '/');
	if (p) *p=0;

	if (r_sandbox_enable (0)) {
		eprintf ("sandbox: Cannot use network\n");
		return NULL;
	}
	riog = R_NEW (RIOGdb);
	gdbr_init(&riog->desc);
	int i_port = atoi(port);
	if (gdbr_connect(&riog->desc, host, i_port) == 0) {
		desc = &riog->desc;
		return r_io_desc_new (&r_io_plugin_gdb, riog->desc.sock->fd, file, rw, mode, riog);
	}
	eprintf ("gdb.io.open: Cannot connect to host.\n");
	free (riog);
	return NULL;
}

static int __write(RIO *io, RIODesc *fd, const ut8 *buf, int count) {
	ut64 addr = io->off;
	if (!desc || !desc->data) return -1;
	return debug_gdb_write_at(buf, count, addr);
}

static ut64 __lseek(RIO *io, RIODesc *fd, ut64 offset, int whence) {
	return offset;
}

static int __read(RIO *io, RIODesc *fd, ut8 *buf, int count) {
	memset (buf, 0xff, count);
	ut64 addr = io->off;
	if (!desc || !desc->data) return -1;
	return debug_gdb_read_at(buf, count, addr);
}

static int __close(RIODesc *fd) {
	// TODO
	return -1;
}

static int __system(RIO *io, RIODesc *fd, const char *cmd) {
	return -1;
}

RIOPlugin r_io_plugin_gdb = {
	//void *plugin;
	.name = "gdb",
	.license = "LGPL3",
	.desc = "Attach to gdbserver, 'qemu -s', gdb://localhost:1234",
	.open = __open,
	.close = __close,
	.read = __read,
	.write = __write,
	.plugin_open = __plugin_open,
	.lseek = __lseek,
	.system = __system,
	.isdbg = R_TRUE
};

