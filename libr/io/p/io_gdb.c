/* radare - LGPL - Copyright 2010-2016 pancake */

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
static RIODesc *riogdb = NULL;

static bool __plugin_open(RIO *io, const char *file, bool many) {
	return (!strncmp (file, "gdb://", 6));
}

/* hacky cache to speedup gdb io a bit */
/* reading in a different place clears the previous cache */
static ut64 c_addr = UT64_MAX;
static ut32 c_size = UT32_MAX;
static ut8 *c_buff = NULL;
#define SILLY_CACHE 0

static int debug_gdb_read_at(ut8 *buf, int sz, ut64 addr) {
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
		gdbr_read_memory (desc, addr + (x * size_max), size_max);
		memcpy ((buf + (x * size_max)), desc->data + (x * size_max), R_MIN (sz, size_max));
	}
	if (last) {
		gdbr_read_memory (desc, addr + x * size_max, last);
		memcpy ((buf + x * size_max), desc->data + (x * size_max), last);
	}
	c_addr = addr;
	c_size = sz;
#if SILLY_CACHE
	free (c_buff);
	c_buff = r_mem_dup (buf, sz);
#endif
	return sz;
}

static int debug_gdb_write_at(const ut8 *buf, int sz, ut64 addr) {
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
	RIOGdb *riog;
	char host[128], *port, *p;

	if (!__plugin_open (io, file, 0))
		return NULL;
	if (riogdb) {
		// FIX: Don't allocate more than one gdb RIODesc
		return riogdb;
	}
	strncpy (host, file+6, sizeof (host)-1);
	host [sizeof (host)-1] = '\0';
	port = strchr (host , ':');
	if (!port) {
		eprintf ("Port not specified. Please use gdb://[host]:[port]\n");
		return NULL;
	}
	*port = '\0';
	port++;
	p = strchr (port, '/');
	if (p) *p = 0;

	if (r_sandbox_enable (0)) {
		eprintf ("sandbox: Cannot use network\n");
		return NULL;
	}
	riog = R_NEW0 (RIOGdb);
	gdbr_init (&riog->desc);
	int i_port = atoi(port);
	if (gdbr_connect (&riog->desc, host, i_port) == 0) {
		desc = &riog->desc;
		riogdb = r_io_desc_new (io, &r_io_plugin_gdb, file, rw, mode, riog);
		return riogdb;
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

int send_command(libgdbr_t* g, const char* command);
int read_packet(libgdbr_t* instance);

static int __system(RIO *io, RIODesc *fd, const char *cmd) {
        //printf("ptrace io command (%s)\n", cmd);
        /* XXX ugly hack for testing purposes */
        if (!cmd[0] || cmd[0] == '?' || !strcmp (cmd, "help")) {
                eprintf ("Usage: =!cmd args\n"
                        " =!pid      - show targeted pid\n"
                        " =!pkt s    - send packet 's'\n");
	} else if (!strncmp (cmd, "pkt ", 4)) {
		send_command (desc, cmd + 4);
		int r = read_packet (desc);
		eprintf ("r = %d\n", r);
	} else if (!strncmp (cmd, "pid", 3)) {
		int pid = 1234;
		if (!cmd[3]) {
			io->cb_printf ("%d\n", pid);
		}
		return pid;
	} else {
		eprintf ("Try: '=!?'\n");
	}
        return true;
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
	.check = __plugin_open,
	.lseek = __lseek,
	.system = __system,
	.isdbg = true
};

