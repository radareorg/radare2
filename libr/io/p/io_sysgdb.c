/* radare - LGPL - Copyright 2023 - pancake */

#include <r_io.h>
#include <r_lib.h>

static R_TH_LOCAL RSocket *gs = NULL;
#if __APPLE__
static R_TH_LOCAL bool use_lldb = true;
#else
static R_TH_LOCAL bool use_lldb = false;
#endif

// TODO: make it vargarg...
static char *runcmd(const char *cmd) {
	char buf[4096] = {0};
	if (cmd) {
		r_socket_printf (gs, "%s\n", cmd);
	}
	int timeout = 1000;
	char *str = NULL;
	r_socket_block_time (gs, 1, timeout, 0);
	while (true) {
		eprintf ("LOOP\n");
		memset (buf, 0, sizeof (buf));
		int rc = r_socket_read (gs, (ut8*)buf, sizeof (buf) - 1); // NULL-terminate the string always
		if (rc == -1) {
			eprintf ("socket-read-break\n");
			break;
		}
		buf[sizeof (buf) - 1] = 0;
		// DEBUG
		write (1, "READ: (", 7);
		write (1, buf, strlen (buf));
		write (1, ")\n", 2);
		char *promptFound = use_lldb
			? strstr (buf, "(lldb) ")
			: strstr (buf, "(gdb) ");
		if (promptFound) {
			// check if there's anything after the prompt, then skip and continue
			if (use_lldb) {
				if (buf[7]) {
					promptFound = NULL;
				}
			} else {
				if (buf[6]) {
					promptFound = NULL;
				}
			}
			if (promptFound) {
				*promptFound = 0;
				return r_str_append (str, buf);
			}
		}
		str = r_str_append (str, buf);
	}
	free (str);
	return NULL;
}

static int __write(RIO *io, RIODesc *fd, const ut8 *buf, int count) {
	if (!fd || !fd->data) {
		return -1;
	}
	int wordSize = 4;
	ut32 *w = (ut32*)buf;
	int i;
	int words = count / wordSize; // XXX must pad align to 4
	for (i = 0; i < words ; i++) {
		ut64 addr = io->off + (i * wordSize);
		char *cmd = r_str_newf ("set *0x%"PFMT64x" = 0x%x", addr, w[i]);
		free (runcmd (cmd));
		free (cmd);
	}

	int left = count % wordSize;
	if (left > 0) {
		ut32 leftW = -1;
		memcpy (&leftW, w + words, left);
		ut64 addr = io->off + (words * wordSize);
		char *cmd = r_str_newf ("set *0x%"PFMT64x" = 0x%x", addr, leftW);
		free (runcmd (cmd));
		free (cmd);
	}
	return count;
}

static int __read(RIO *io, RIODesc *fd, ut8 *buf, int count) {
	if (!fd || !fd->data) {
		return -1;
	}
#if 0
	if (count > (1024*128)) {
		// cannot read that much
		return -1;
	}
	int wordSize = 4;
	ut32 *w = (ut32*)buf;
	int i;
	memset (buf, 0xff, count);
	int words = count / wordSize; // XXX must pad align to 4
	for (i = 0; i < words ; i++) {
		ut64 addr = io->off + (i * wordSize);
		char *cmd = r_str_newf ("x 0x%"PFMT64x, addr);
		char *res = runcmd (cmd);
		if (res) {
			sscanf (res, "%x", &w[i]);
			free (res);
		}
		free (cmd);
	}

	int left = count % wordSize;
	if (left > 0) {
		ut32 n = 0xff;
		ut8 *wn = (ut8*)&n;
		ut64 addr = io->off + (i * wordSize);
		char *cmd = r_str_newf ("x 0x%"PFMT64x, addr);
		char *res = runcmd (cmd);
		sscanf (res, "%x", &n);
		free (res);
		free (cmd);
		memcpy (buf + (words * wordSize), wn, left);
	}
#endif
	buf[0] = 1;
	buf[1] = 2;
	buf[2] = 3;
	return count;
}

static bool __close(RIODesc *fd) {
	if (!fd || !fd->data) {
		return false;
	}
#if R2__UNIX__
	r_sys_cmdf ("pkill rarun2 2>/dev/null");
#endif
	return true;
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
	io->off = offset;
	return offset;
}

static bool __plugin_open(RIO *io, const char *pathname, bool many) {
	return r_str_startswith (pathname, "sysgdb://");
}

static RIODesc *__open(RIO *io, const char *pathname, int rw, int mode) {
	if (__plugin_open (io, pathname, 0)) {
		if (gs) {
			return NULL;
		}
		gs = r_socket_new (0);
		char *cmd = use_lldb
			? r_str_newf ("lldb -- %s", pathname + 9)
			: r_str_newf ("gdb --args %s", pathname + 10);
		int res = r_socket_spawn (gs, cmd, 1000);
		free (cmd);
		if (!res) {
			return NULL;
		}
		char *reply = runcmd (NULL);
		eprintf ("REPLY (%s)\n", reply);
		if (reply) {
			int rw = 7;
			free (reply);
			R_LOG_INFO ("sysgdb is ready to go");
			return r_io_desc_new (io, &r_io_plugin_sysgdb, pathname, rw, mode, gs);
		}
		R_LOG_ERROR ("Can't find the gdb prompt");
	}
	return NULL;
}

static void printcmd(RIO *io, const char *cmd) {
	char *res = runcmd (cmd);
	io->cb_printf ("%s\n", res);
	free (res);
}

#if 0
static struct sysgdb_x86_32 regState(void) {
	struct sysgdb_x86_32 r = {0};
	char *res = runcmd ("info reg");
	if (res) {
		char *line = strstr (res, "EIP:");
		if (line) {
			ut32 eip, esp, ebp, eflags;
			(void)sscanf (line, "EIP:%08x ESP:%08x EBP:%08x EFLAGS:%08x",
				&eip, &esp, &ebp, &eflags);
			r.eip = eip;
			r.esp = esp;
			r.ebp = ebp;
			r.eflags = eflags;
			line = strstr (line, "EAX:");
			if (line) {
				ut32 eax, ebx, ecx, edx;
				(void)sscanf (line, "EAX:%08x EBX:%08x ECX:%08x EDX:%08x",
					&eax, &ebx, &ecx, &edx);
				r.eax = eax;
				r.ebx = ebx;
				r.ecx = ecx;
				r.edx = edx;
				line = strstr (line, "ESI:");
				if (line) {
					ut32 esi, edi;
					(void)sscanf (line, "ESI:%08x EDI:%08x", &esi, &edi);
					r.esi = esi;
					r.edi = edi;
				}
			}
		}
		free (res);
	}
	return r;
}
#endif

static char *__system(RIO *io, RIODesc *fd, const char *cmd) {
	if (R_STR_ISEMPTY (cmd)) {
		return NULL;
	}
	if (*cmd == '?') {
		eprintf ("dr  : show registers\n");
		eprintf ("dr* : show registers as flags\n");
		eprintf ("drp : show reg profile\n");
		eprintf ("dr8 : show hexpairs with regstate\n");
		eprintf ("ds  : step into\n");
		eprintf ("dp  : show process info\n");
		eprintf ("dc  : continue\n");
		eprintf ("dm  : show maps\n");
		eprintf ("pid : show current process id\n");
	} else {
		printcmd (io, cmd);
	}
	return NULL;
}

RIOPlugin r_io_plugin_sysgdb = {
	.meta = {
		.name = "sysgdb",
		.desc = "spawn gdb/lldb and use the program instead of the protocol",
		.license = "MIT",
	},
	.uris = "sysgdb://",
	.open = __open,
	.close = __close,
	.read = __read,
	.check = __plugin_open,
	.seek = __lseek,
	.write = __write,
	.system = __system,
	.isdbg = true
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_sysgdb,
	.version = R2_VERSION
};
#endif
