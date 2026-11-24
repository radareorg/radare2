/* radare - LGPL - Copyright 2010-2026 - pancake, defragger */

#include <r_io.h>
#include <r_lib.h>
#define IRAPI static inline
#include <libgdbr.h>
#include <gdbclient/commands.h>
#include <gdbclient/core.h>

typedef struct {
	libgdbr_t desc;
} RIOGdb;

#define R_GDB_MAGIC r_str_hash ("gdb")

static libgdbr_t *get_desc_from_fd(RIODesc *fd) {
	if (!fd || !fd->data) {
		return NULL;
	}
	RIOGdb *riog = fd->data;
	return &riog->desc;
}

static bool __close(RIODesc *fd) {
	libgdbr_t *desc = get_desc_from_fd (fd);
	if (desc) {
		gdbr_disconnect (desc);
		gdbr_cleanup (desc);
	}
	if (fd) {
		R_FREE (fd->name);
		R_FREE (fd->data);
	}
	return true;
}

static bool __plugin_open(RIO *io, const char *file, bool many) {
	return r_str_startswith (file, "gdb://");
}

static int debug_gdb_read_at(libgdbr_t *desc, ut8 *buf, int sz, ut64 addr) {
	if (sz < 1 || addr >= UT64_MAX || !desc) {
		return -1;
	}
	return gdbr_read_memory (desc, addr, buf, sz);
}

static int debug_gdb_write_at(libgdbr_t *desc, const ut8 *buf, int sz, ut64 addr) {
	ut32 x, size_max;
	ut32 packets;
	ut32 last;
	if (sz < 1 || addr >= UT64_MAX || !desc) {
		return -1;
	}
	size_max = desc->read_max;
	packets = sz / size_max;
	last = sz % size_max;
	ut64 offset = 0;
	for (x = 0; x < packets; x++, offset += size_max) {
		if (gdbr_write_memory (desc, addr + offset, buf + offset, size_max) < 0) {
			return -1;
		}
	}
	if (last) {
		if (gdbr_write_memory (desc, addr + offset, buf + offset, last) < 0) {
			return -1;
		}
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
	r_str_ncpy (host, file + 6, sizeof (host));
	if (host[0] == '/') {
		isdev = true;
	}

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
			R_LOG_ERROR ("sandbox: Cannot use network");
			return NULL;
		}

		port = strchr (host , ':');
		if (!port) {
			R_LOG_ERROR ("Invalid debugger URI. Missing port number?");
			R_LOG_INFO ("Use gdb://host:port[/pid] for a network gdbserver");
			R_LOG_INFO ("Or gdb:///dev/DEVICENAME[@speed][:pid] for a serial gdbserver");
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

	riog = R_NEW0 (RIOGdb);
	gdbr_init (&riog->desc, false);

	if (gdbr_connect (&riog->desc, host, i_port) == 0) {
		__close (NULL);
		if (pid > 0) { // FIXME this is here for now because RDebug's pid and libgdbr's aren't properly synced.
			riog->desc.pid = i_pid;
			if (gdbr_attach (&riog->desc, i_pid) < 0) {
				R_LOG_ERROR ("gdbr: Failed to attach to PID %i", i_pid);
				R_FREE (riog);
				return NULL;
			}
		} else if ((i_pid = riog->desc.pid) < 0) {
			i_pid = -1;
		}
		riogdb = r_io_desc_new (io, &r_io_plugin_gdb, file, R_PERM_RWX, mode, riog);
	}
	// Get name
	if (riogdb) {
		riogdb->name = gdbr_exec_file_read (&riog->desc, i_pid);
	} else {
		R_LOG_ERROR ("gdb.io.open: Cannot connect to host");
		free (riog);
	}
	return riogdb;
}

static int __write(RIO *io, RIODesc *fd, const ut8 *buf, int count) {
	const ut64 addr = io->off;
	libgdbr_t *desc = get_desc_from_fd (fd);
	if (!desc) {
		return -1;
	}
	return debug_gdb_write_at (desc, buf, count, addr);
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
		io->off = UT64_MAX;
		break;
	}
	return io->off;
}

static int __read(RIO *io, RIODesc *fd, ut8 *buf, int count) {
	if (!io || !fd || !buf || count < 1) {
		return -1;
	}
	libgdbr_t *desc = get_desc_from_fd (fd);
	if (!desc) {
		return -1;
	}
	memset (buf, io->Oxff, count);
	ut64 addr = io->off;
	return debug_gdb_read_at (desc, buf, count, addr);
}

static int __getpid(RIODesc *fd) {
	libgdbr_t *desc = get_desc_from_fd (fd);
	return desc ? desc->pid : -1;
}

static int __gettid(RIODesc *fd) {
	libgdbr_t *desc = get_desc_from_fd (fd);
	return desc ? desc->tid : -1;
}

extern int send_msg(libgdbr_t *g, const char *command);
extern int read_packet(libgdbr_t *instance, bool vcont);

static bool set_syscall_catchpoints(libgdbr_t *desc, const char *args) {
	int argc = 0;
	char **argv = r_str_argv (args, &argc);
	if (!argv || argc < 1 || (ut32)argc > desc->stub_features.pkt_sz / 2) {
		r_str_argv_free (argv);
		return false;
	}
	bool ok = false;
	if (argc == 1 && (!strcmp (argv[0], "all") || !strcmp (argv[0], "off"))) {
		ok = gdbr_catch_syscalls (desc, !strcmp (argv[0], "all"), NULL, 0);
	} else {
		ut32 *numbers = R_NEWS (ut32, argc);
		if (numbers) {
			int i;
			for (i = 0; i < argc; i++) {
				const char *error = NULL;
				ut64 value = r_num_math_err (NULL, argv[i], &error);
				if (error || value > UT32_MAX) {
					break;
				}
				numbers[i] = value;
			}
			ok = i == argc && gdbr_catch_syscalls (desc, true, numbers, argc);
			free (numbers);
		}
	}
	r_str_argv_free (argv);
	return ok;
}

static char *__system(RIO *io, RIODesc *fd, const char *cmd) {
	libgdbr_t *desc = get_desc_from_fd (fd);
	if (!desc || !*cmd) {
		return NULL;
	}
	if (cmd[0] == '?' || !strcmp (cmd, "help")) {
		eprintf ("Usage: :cmd args\n"
			 " :pid             - show targeted pid\n"
			 " :osabi           - show the target XML OS ABI\n"
			 " :tls lm offset   - resolve TLS for the selected thread and load module\n"
			 " :tib             - resolve the selected Windows thread's TIB address\n"
			 " :catch-syscalls <all|off|number ...> - configure remote syscall stops\n"
			 " :nonstop [on|off|wait] - inspect, change, or wait in non-stop mode\n"
			 " :pkt s           - send packet 's'\n"
			 " :rd              - show reverse debugging availability\n"
			 " :dsb             - step backwards\n"
			 " :dcb             - continue backwards\n"
			 " :monitor cmd     - hex-encode monitor command and pass"
			                     " to target interpreter\n"
			 " :detach [pid]    - detach from remote/detach specific pid\n"
			 " :inv.reg         - invalidate reg cache\n"
			 " :pktsz           - get max packet size used\n"
			 " :pktsz bytes     - lower max. packet size to 'bytes' bytes\n"
			 " :exec_file [pid] - get file which was executed for"
			                     " current/specified pid\n");
		return NULL;
	}
	if (r_str_startswith (cmd, "pktsz")) {
		const char *ptr = r_str_trim_head_ro (cmd + 5);
		if (!isdigit ((ut8)*ptr)) {
			return r_str_newf ("packet size: %u bytes\n", desc->stub_features.pkt_sz);
		}
		ut64 pktsz = r_num_get (NULL, ptr);
		if (pktsz) {
			desc->stub_features.pkt_sz = R_MIN (pktsz, desc->stub_features.pkt_sz);
		}
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
		char *res = NULL;
		if (gdbr_lock_enter (desc) && send_msg (desc, cmd + 4) >= 0 && read_packet (desc, false) >= 0) {
			res = r_str_newf ("reply:\n%s\n", desc->data);
		}
		gdbr_lock_leave (desc);
		return res;
	}
	if (r_str_startswith (cmd, "rd")) {
		PJ *pj = pj_new ();
		pj_o (pj);
		pj_kb (pj, "reverse-continue", desc->stub_features.ReverseContinue);
		pj_kb (pj, "reverse-step", desc->stub_features.ReverseStep);
		pj_end (pj);
		return pj_drain (pj);
	}
	const bool reverse_step = !strcmp (cmd, "dsb");
	if (reverse_step || !strcmp (cmd, "dcb")) {
		bool supported = reverse_step? desc->stub_features.ReverseStep: desc->stub_features.ReverseContinue;
		if (!supported) {
			R_LOG_ERROR ("Reverse %s is not supported by the GDB stub", reverse_step? "step": "continue");
		} else if (send_vcont (desc, reverse_step? "bs": "bc", NULL) < 0) {
			R_LOG_ERROR ("Reverse %s failed", reverse_step? "step": "continue");
		}
		return NULL;
	}
	if (r_str_startswith (cmd, "pid")) {
		return r_str_newf ("%d\n", desc->pid);
	}
	if (!strcmp (cmd, "osabi")) {
		return r_str_newf ("%s\n", r_str_get_fail (desc->target.osabi, "unknown"));
	}
	if (!strcmp (cmd, "nonstop") || r_str_startswith (cmd, "nonstop ")) {
		const char *action = r_str_trim_head_ro (cmd + strlen ("nonstop"));
		if (!*action) {
			return strdup (desc->non_stop? "on\n": "off\n");
		}
		if (!strcmp (action, "wait")) {
			if (gdbr_wait_nonstop (desc) >= 0) {
				return r_str_newf ("thread %d: %d\n", desc->stop_reason.thread.tid, desc->stop_reason.reason);
			}
		} else if ((!strcmp (action, "on") || !strcmp (action, "off"))
		    && gdbr_set_nonstop (desc, !strcmp (action, "on"))) {
			return strdup ("OK\n");
		}
		R_LOG_ERROR ("Cannot complete GDB non-stop operation");
		return NULL;
	}
	if (!strcmp (cmd, "catch-syscalls") || r_str_startswith (cmd, "catch-syscalls ")) {
		if (!set_syscall_catchpoints (desc, r_str_trim_head_ro (cmd + strlen ("catch-syscalls")))) {
			R_LOG_ERROR ("Cannot configure syscall stops. Usage: :catch-syscalls <all|off|number ...>");
			return NULL;
		}
		return strdup ("OK\n");
	}
	if (!strcmp (cmd, "tib")) {
		ut64 address;
		if (gdbr_get_tib_addr (desc, &address)) {
			return r_str_newf ("0x%"PFMT64x"\n", address);
		}
		R_LOG_ERROR ("The GDB stub did not provide a TIB address");
		return NULL;
	}
	if (!strcmp (cmd, "tls") || r_str_startswith (cmd, "tls ")) {
		int argc;
		char **argv = r_str_argv (cmd, &argc);
		const char *module_error = NULL, *offset_error = NULL;
		ut64 module = 0, offset = 0;
		if (argv && argc == 3) {
			module = r_num_math_err (NULL, argv[1], &module_error);
			offset = r_num_math_err (NULL, argv[2], &offset_error);
		}
		bool valid = argv && argc == 3 && !module_error && !offset_error;
		r_str_argv_free (argv);
		if (!valid) {
			R_LOG_ERROR ("Usage: :tls lm offset");
			return NULL;
		}
		ut64 address;
		if (gdbr_get_tls_addr (desc, module, offset, &address)) {
			return r_str_newf ("0x%"PFMT64x"\n", address);
		}
		R_LOG_ERROR ("The GDB stub did not resolve the TLS address");
		return NULL;
	}
	if (r_str_startswith (cmd, "monitor")) {
		const char *qrcmd = cmd + 8;
		if (!isspace ((ut8)cmd[7])) {
			qrcmd = "help";
		}
		RStrBuf output;
		r_strbuf_init (&output);
		if (gdbr_send_qRcmd (desc, qrcmd, &output) < 0) {
			R_LOG_ERROR ("remote command error");
		}
		if (r_strbuf_is_empty (&output)) {
			r_strbuf_fini (&output);
			return NULL;
		}
		return r_strbuf_drain_nofree (&output);
	}
	if (r_str_startswith (cmd, "inv.reg")) {
		gdbr_invalidate_reg_cache (desc);
		return NULL;
	}
	if (r_str_startswith (cmd, "exec_file")) {
		const char *ptr = cmd + strlen ("exec_file");
		char *file;
		if (!isspace ((ut8)*ptr)) {
			file = gdbr_exec_file_read (desc, 0);
		} else {
			ptr = r_str_trim_head_ro (ptr);
			if (isdigit ((ut8)*ptr)) {
				file = gdbr_exec_file_read (desc, atoi (ptr));
			} else {
				file = gdbr_exec_file_read (desc, 0);
			}
		}
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
		return r_str_newf ("num_retries: %d byte(s)\n", desc->page_size);
	}
	if (r_str_startswith (cmd, "page_size")) {
		int page_size;
		if (isspace ((ut8)cmd[9]) && isdigit ((ut8)cmd[10])) {
			if ((page_size = atoi (cmd + 10)) >= 64) {
				desc->page_size = page_size;
			}
			return NULL;
		}
		return r_str_newf ("page size: %d byte(s)\n", desc->page_size);
	}
	// Sets a flag that next call to get memmap will be for getting baddr
	if (!strcmp (cmd, "baddr")) {
		desc->get_baddr = true;
		return NULL;
	}
	eprintf ("Try: ':?'\n");
	return NULL;
}

RIOPlugin r_io_plugin_gdb = {
	.meta = {
		.name = "gdb",
		.author = "defragger",
		.license = "LGPL-3.0-only",
		.desc = "Attach to gdbserver instance",
	},
	//void *plugin;
	.uris = "gdb://",
	.open = __open,
	.close = __close,
	.read = __read,
	.write = __write,
	.check = __plugin_open,
	.seek = __lseek,
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
