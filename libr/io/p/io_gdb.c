/* radare - LGPL - Copyright 2010-2017 pancake */

#include <r_io.h>
#include <r_lib.h>
#include <r_socket.h>
#include <r_util.h>
#define IRAPI static inline
#include <libgdbr.h>
#include <gdbclient/commands.h>

typedef struct {
	libgdbr_t desc;
} RIOGdb;

static libgdbr_t *desc = NULL;
static RIODesc *riogdb = NULL;

static bool __plugin_open(RIO *io, const char *file, bool many) {
	return (!strncmp (file, "gdb://", 6));
}

static int debug_gdb_read_at(ut8 *buf, int sz, ut64 addr) {
	ut32 size_max;
	ut32 packets;
	ut32 last;
	ut32 x;
	int ret = 0;
	if (sz < 1 || addr >= UT64_MAX || !desc) {
		return -1;
	}
	size_max = desc->data_max / 2;
	packets = sz / size_max;
	last = sz % size_max;
	for (x = 0; x < packets; x++) {
		if (gdbr_read_memory (desc, addr + (x * size_max), size_max) < 0) {
			eprintf ("%s: Error reading gdbserver memory (%d bytes at 0x%"PFMT64x")\n",
				 __func__, size_max, addr + (x * size_max));
			return ret;
		}
		memcpy ((buf + (x * size_max)), desc->data + (x * size_max), R_MIN (sz, size_max));
		ret += desc->data_len;
	}
	if (last) {
		if (gdbr_read_memory (desc, addr + x * size_max, last) < 0) {
			eprintf ("%s: Error reading gdbserver memory (%d bytes at 0x%"PFMT64x")\n",
				 __func__, last, addr + (x * size_max));
			return ret;
		}
		memcpy ((buf + x * size_max), desc->data + (x * size_max), last);
		ret += desc->data_len;
	}
	return ret;
}

static int debug_gdb_write_at(const ut8 *buf, int sz, ut64 addr) {
	ut32 x, size_max;
	ut32 packets;
	ut32 last;
	if (sz < 1 || addr >= UT64_MAX || !desc) {
		return -1;
	}
	size_max = desc->read_max;
	packets = sz / size_max;
	last = sz % size_max;
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
	char host[128], *port, *pid;

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
		eprintf ("Port not specified. Please use gdb://host:port[/port]\n");
		return NULL;
	}
	*port = '\0';
	port++;

	pid = strchr (port, '/');
	if (pid) {
		*pid = 0;
		pid++;
	}

	if (r_sandbox_enable (0)) {
		eprintf ("sandbox: Cannot use network\n");
		return NULL;
	}
	riog = R_NEW0 (RIOGdb);
	gdbr_init (&riog->desc, false);
	int i_port = atoi(port);
	int i_pid = -1;
	if (pid) {
		i_pid = atoi (pid);
	}

	if (gdbr_connect (&riog->desc, host, i_port) == 0) {
		desc = &riog->desc;
		if (pid) { // FIXME this is here for now because RDebug's pid and libgdbr's aren't properly synced.
			desc->pid = i_pid;
			int ret = gdbr_attach (desc, i_pid);
			if (ret < 0) {
				eprintf ("gdbr: Failed to attach to PID %i\n", i_pid);
				return NULL;
			}
		}
		riogdb = r_io_desc_new (&r_io_plugin_gdb, riog->desc.sock->fd, file, rw, mode, riog);
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
	switch (whence) {
	case R_IO_SEEK_SET:
		return offset;
	case R_IO_SEEK_CUR:
		return io->off + offset;
	case R_IO_SEEK_END:
		return UT64_MAX;
	default:
		return offset;
	}
}

static int __read(RIO *io, RIODesc *fd, ut8 *buf, int count) {
	memset (buf, 0xff, count);
	ut64 addr = io->off;
	if (!desc || !desc->data) {
		return -1;
	}
	return debug_gdb_read_at(buf, count, addr);
}

static int __close(RIODesc *fd) {
	// TODO
	return -1;
}

int send_msg(libgdbr_t* g, const char* command);
int read_packet(libgdbr_t* instance);

static int __system(RIO *io, RIODesc *fd, const char *cmd) {
        //printf("ptrace io command (%s)\n", cmd);
        /* XXX ugly hack for testing purposes */
        if (!cmd[0] || cmd[0] == '?' || !strcmp (cmd, "help")) {
                eprintf ("Usage: =!cmd args\n"
                        " =!pid      - show targeted pid\n"
                        " =!pkt s    - send packet 's'\n");
	} else if (!strncmp (cmd, "pkt ", 4)) {
		if (send_msg (desc, cmd + 4) == -1) {
			return false;
		}
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

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_gdb,
	.version = R2_VERSION
};
#endif
