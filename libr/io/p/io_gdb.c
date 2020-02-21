/* radare - LGPL - Copyright 2010-2020 pancake */

#include <r_io.h>
#include <r_lib.h>
#include <r_socket.h>
#include <r_util.h>
#include <ctype.h>
#define IRAPI static inline
#include <libgdbr.h>
#include <gdbclient/commands.h>
#include <gdbclient/responses.h>

typedef struct {
	libgdbr_t desc;
} RIOGdb;

#define R_GDB_MAGIC r_str_hash ("gdb")

static int __close(RIODesc *fd);
static libgdbr_t *desc = NULL;

static bool __plugin_open(RIO *io, const char *file, bool many) {
	return (!strncmp (file, "gdb://", 6));
}

static int debug_gdb_read_at(ut8 *buf, int sz, ut64 addr) {
	if (sz < 1 || addr >= UT64_MAX || !desc) {
		return -1;
	}
	return gdbr_read_memory (desc, addr, buf, sz);
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
	RIODesc *riogdb = NULL;
	RIOGdb *riog;
	char host[128], *port, *pid;
	int i_port = -1;
	bool isdev = false;

	if (!__plugin_open (io, file, 0)) {
		return NULL;
	}
	strncpy (host, file + 6, sizeof (host) - 1);
	host [sizeof (host) - 1] = '\0';
	if (host[0] == '/') {
		isdev = true;
	}

	rw |= R_PERM_W;
	if (isdev) {
		port = strchr (host, '@');
		if (port) {
			*port = '\0';
			port++;
			pid = strchr (port, ':');
		} else {
			pid = strchr (host, ':');
		}
	} else {
		if (r_sandbox_enable (0)) {
			eprintf ("sandbox: Cannot use network\n");
			return NULL;
		}

		port = strchr (host , ':');
		if (!port) {
			eprintf ("Invalid debugger URI. Port missing?\nPlease use either\n"
				" - gdb://host:port[/pid] for a network gdbserver.\n"
				" - gdb:///dev/DEVICENAME[@speed][:pid] for a serial gdbserver.\n");
			return NULL;
		}
		*port = '\0';
		port++;
		pid = strchr (port, '/');
	}

	int i_pid = -1;
	if (pid) {
		*pid = 0;
		pid++;
		i_pid = atoi (pid);
	}

	if (port) {
		i_port = atoi (port);
	}

	if (!(riog = R_NEW0 (RIOGdb))) {
		return NULL;
	}
	gdbr_init (&riog->desc, false);

	if (gdbr_connect (&riog->desc, host, i_port) == 0) {
		__close (NULL);
		// R_FREE (desc);
		desc = &riog->desc;
		if (pid > 0) { // FIXME this is here for now because RDebug's pid and libgdbr's aren't properly synced.
			desc->pid = i_pid;
			if (gdbr_attach (desc, i_pid) < 0) {
				eprintf ("gdbr: Failed to attach to PID %i\n", i_pid);
				return NULL;
			}
		} else if ((i_pid = desc->pid) < 0) {
			i_pid = -1;
		}
		riogdb = r_io_desc_new (io, &r_io_plugin_gdb, file, R_PERM_RWX, mode, riog);
	}
	// Get name
	if (riogdb) {
		riogdb->name = gdbr_exec_file_read (desc, i_pid);
	} else {
		eprintf ("gdb.io.open: Cannot connect to host.\n");
		free (riog);
	}
	return riogdb;
}

static int __write(RIO *io, RIODesc *fd, const ut8 *buf, int count) {
	ut64 addr = io->off;
	if (!desc || !desc->data) {
		return -1;
	}
	return debug_gdb_write_at (buf, count, addr);
}

static ut64 __lseek(RIO *io, RIODesc *fd, ut64 offset, int whence) {
	switch (whence) {
	case R_IO_SEEK_SET:
		io->off = offset;
		break;
	case R_IO_SEEK_CUR:
		io->off += offset;
		break;
	case R_IO_SEEK_END:
		io->off = ST64_MAX;
	}
	return io->off;
}

static int __read(RIO *io, RIODesc *fd, ut8 *buf, int count) {
	if (!io || !fd || !buf || count < 1) {
		return -1;
	}
	memset (buf, 0xff, count);
	ut64 addr = io->off;
	if (!desc || !desc->data) {
		return -1;
	}
	return debug_gdb_read_at (buf, count, addr);
}

static int __close(RIODesc *fd) {
	if (fd) {
		R_FREE (fd->name);
	}
	gdbr_disconnect (desc);
	gdbr_cleanup (desc);
	R_FREE (desc);
	return -1;
}

static int __getpid(RIODesc *fd) {
	// XXX don't use globals
	return desc ? desc->pid : -1;
#if 0
	// dupe for ? r_io_desc_get_pid (desc);
	if (!desc || !desc->data) {
		return -1;
	}
	RIODescData *iodd = desc->data;
	if (iodd) {
		if (iodd->magic != R_GDB_MAGIC) {
			return -1;
		}
		return iodd->pid;
	}
	return -1;
#endif
}

static int __gettid(RIODesc *fd) {
	return desc ? desc->tid : -1;
}

extern int send_msg(libgdbr_t *g, const char *command);
extern int read_packet(libgdbr_t *instance);

static char *__system(RIO *io, RIODesc *fd, const char *cmd) {
	if (!desc) {
		return NULL;
	}
	if (!*cmd) {
		return NULL;
	}
	if (cmd[0] == '?' || !strcmp (cmd, "help")) {
		eprintf ("Usage: =!cmd args\n"
			 " =!pid             - show targeted pid\n"
			 " =!pkt s           - send packet 's'\n"
			 " =!rd              - show reverse debugging availability\n"
			 " =!dsb             - step backwards\n"
			 " =!dcb             - continue backwards\n"
			 " =!monitor cmd     - hex-encode monitor command and pass"
			                     " to target interpreter\n"
			 " =!detach [pid]    - detach from remote/detach specific pid\n"
			 " =!inv.reg         - invalidate reg cache\n"
			 " =!pktsz           - get max packet size used\n"
			 " =!pktsz bytes     - set max. packet size as 'bytes' bytes\n"
			 " =!exec_file [pid] - get file which was executed for"
			                     " current/specified pid\n");
		return NULL;
	}
	if (r_str_startswith (cmd, "pktsz")) {
		const char *ptr = r_str_trim_head_ro (cmd + 5);
		if (!isdigit ((ut8)*ptr)) {
			io->cb_printf ("packet size: %u bytes\n",
				       desc->stub_features.pkt_sz);
			return NULL;
		}
		ut32 pktsz;
		if (!(pktsz = (ut32) strtoul (ptr, NULL, 10))) {
			// pktsz = 0 doesn't make sense
			return NULL;
		}
		desc->stub_features.pkt_sz = R_MAX (pktsz, 8); // min = 64
		return NULL;
	}
	if (r_str_startswith (cmd, "detach")) {
		int res;
		if (!isspace ((ut8)cmd[6]) || !desc->stub_features.multiprocess) {
			res = gdbr_detach (desc) >= 0;
		} else {
			int pid = 0;
			cmd = r_str_trim_head_ro (cmd + 6);
			if (!*cmd || !(pid = strtoul (cmd, NULL, 10))) {
				res = gdbr_detach (desc) >= 0;
			} else {
				res = gdbr_detach_pid (desc, pid) >= 0;
			}
		}
		eprintf ("%d\n", res);
		return NULL;
	}
	if (r_str_startswith (cmd, "pkt ")) {
		gdbr_lock_enter (desc);
		if (send_msg (desc, cmd + 4) >= 0) {
			(void)read_packet (desc);
			desc->data[desc->data_len] = '\0';
			io->cb_printf ("reply:\n%s\n", desc->data);
			if (!desc->no_ack) {
				eprintf ("[waiting for ack]\n");
			}
		}
		gdbr_lock_leave (desc);
		return NULL;
	}
	if (r_str_startswith (cmd, "rd")) {
		PJ *pj = pj_new ();
		pj_o (pj);
		pj_kb (pj, "reverse-continue", desc->stub_features.ReverseStep);
		pj_kb (pj, "reverse-step", desc->stub_features.ReverseContinue);
		pj_end (pj);
		io->cb_printf ("%s\n", pj_string (pj));
		pj_free (pj);
		return NULL;
	}
	if (r_str_startswith (cmd, "dsb")) {
		if (!desc->stub_features.ReverseStep) {
			eprintf ("Stepping backwards is not supported in this gdbserver implementation\n");
			return NULL;
		}
		gdbr_lock_enter (desc);
		if (send_msg (desc, "bs") >= 0) {
			(void)read_packet (desc);
			desc->data[desc->data_len] = '\0';
			if (!desc->no_ack) {
				eprintf ("[waiting for ack]\n");
			} else {
				handle_stop_reason (desc);
				if (desc->stop_reason.is_valid == false) {
					eprintf("Thread (%d) stopped for an invalid reason: %d\n",
						desc->stop_reason.thread.tid, desc->stop_reason.reason);
				}
			}
			gdbr_invalidate_reg_cache ();
		}
		gdbr_lock_leave (desc);
		return NULL;
	}
	if (r_str_startswith (cmd, "dcb")) {
		if (!desc->stub_features.ReverseContinue) {
			eprintf ("Continue backwards is not supported in this gdbserver implementation\n");
			return NULL;
		}
		gdbr_lock_enter (desc);
		if (send_msg (desc, "bc") >= 0) {
			(void)read_packet (desc);
			desc->data[desc->data_len] = '\0';
			if (!desc->no_ack) {
				eprintf ("[waiting for ack]\n");
			} else {
				handle_stop_reason (desc);
				if (desc->stop_reason.is_valid == false) {
					eprintf("Thread (%d) stopped for an invalid reason: %d\n",
						desc->stop_reason.thread.tid, desc->stop_reason.reason);
				}
			}
			gdbr_invalidate_reg_cache ();
		}
		gdbr_lock_leave (desc);
		return NULL;
	}
	if (r_str_startswith (cmd, "pid")) {
		int pid = desc ? desc->pid : -1;
		if (!cmd[3]) {
			io->cb_printf ("%d\n", pid);
		}
		return r_str_newf ("%d", pid);
	}
	if (r_str_startswith (cmd, "monitor")) {
		const char *qrcmd = cmd + 8;
		if (!isspace ((ut8)cmd[7])) {
			qrcmd = "help";
		}
		if (gdbr_send_qRcmd (desc, qrcmd, io->cb_printf) < 0) {
			eprintf ("remote error\n");
			return NULL;
		}
		return NULL;
	}
	if (r_str_startswith (cmd, "inv.reg")) {
		gdbr_invalidate_reg_cache ();
		return NULL;
	}
	if (r_str_startswith (cmd, "exec_file")) {
		const char *ptr = cmd + strlen ("exec_file");
		char *file;
		if (!isspace ((ut8)*ptr)) {
			file = gdbr_exec_file_read (desc, 0);
		} else {
			while (isspace ((ut8)*ptr)) {
				ptr++;
			}
			if (isdigit ((ut8)*ptr)) {
				int pid = atoi (ptr);
				file = gdbr_exec_file_read (desc, pid);
			} else {
				file = gdbr_exec_file_read (desc, 0);
			}
		}
		if (!file) {
			return NULL;
		}
		io->cb_printf ("%s\n", file);
		return file;
	}
	// These are internal, not available to user directly
	if (r_str_startswith (cmd, "retries")) {
		int num_retries;
		if (isspace ((ut8)cmd[7]) && isdigit ((ut8)cmd[8])) {
			if ((num_retries = atoi (cmd + 8)) >= 1) {
				desc->num_retries = num_retries;
			}
			return NULL;
		}
		io->cb_printf ("num_retries: %d byte(s)\n", desc->page_size);
		return NULL;
	}
	if (r_str_startswith (cmd, "page_size")) {
		int page_size;
		if (isspace ((ut8)cmd[9]) && isdigit ((ut8)cmd[10])) {
			if ((page_size = atoi (cmd + 10)) >= 64) {
				desc->page_size = page_size;
			}
			return NULL;
		}
		io->cb_printf ("page size: %d byte(s)\n", desc->page_size);
		return NULL;
	}
	// Sets a flag that next call to get memmap will be for getting baddr
	if (!strcmp (cmd, "baddr")) {
		desc->get_baddr = true;
		return NULL;
	}
	eprintf ("Try: '=!?'\n");
	return NULL;
}

RIOPlugin r_io_plugin_gdb = {
	//void *plugin;
	.name = "gdb",
	.license = "LGPL3",
	.desc = "Attach to gdbserver instance",
	.uris = "gdb://",
	.open = __open,
	.close = __close,
	.read = __read,
	.write = __write,
	.check = __plugin_open,
	.lseek = __lseek,
	.system = __system,
	.getpid = __getpid,
	.gettid = __gettid,
	.isdbg = true
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_gdb,
	.version = R2_VERSION
};
#endif
