/* radare - LGPL - Copyright 2017-2019 - pancake */

#include "r_types_base.h"
#include "r_io.h"
#include "r_lib.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

static RSocket *gs = NULL;

R_PACKED (struct winedbg_x86_32 {
	ut16 cs;
	ut16 ss;
	ut16 ds;
	ut16 es;
	ut16 fs;
	ut16 gs;
	ut32 eip;
	ut32 esp;
	ut32 ebp;
	ut32 eflags;
	ut32 eax;
	ut32 ebx;
	ut32 ecx;
	ut32 edx;
	ut32 esi;
	ut32 edi;
});

// TODO: make it vargarg...
static char *runcmd (const char *cmd) {
	char buf[4096] = {0};
	if (cmd) {
		r_socket_printf (gs, "%s\n", cmd);
	}
	int timeout = 1000000;
	char *str = NULL;
	r_socket_block_time (gs, 1, timeout, 0);
	while (true) {
		memset (buf, 0, sizeof (buf));
		r_socket_read (gs, (ut8*)buf, sizeof (buf) - 1); // NULL-terminate the string always
		char *promptFound = strstr (buf, "Wine-dbg>");
		if (promptFound) {
			*promptFound = 0;
			return r_str_append (str, buf);
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
	if (count > (1024*128)) {
		// cannot read that much
		return -1;
	}
#if 0
// TODO: use x/${count}b for performance and solve alignment issues
Wine-dbg>x/128b 0x7b444730
0x7b444730 _start_process+0x10a:  cc 83 ec 08 57 56 e8 b5 fe ff ff 83 c4 04 50 e8
0x7b444740 _start_process+0x11a:  24 2f 01 00 83 c4 0c 8b 44 24 68 83 ec 08 ff 70
0x7b444750 _start_process+0x12a:  5c 6a fe e8 27 2f 01 00 83 c4 08 e8 34 de 01 00
0x7b444760 _debugstr_w:  55 89 e5 83 ec 08 83 ec 08 6a ff 51 e8 45 e0 01
0x7b444770 _debugstr_w+0x10:  00 83 c4 18 5d c3 55 89 e5 53 57 56 83 e4 f0 81
0x7b444780 ___wine_kernel_init+0xa:  ec e0 0e 00 00 e8 00 00 00 00 5e 64 a1 18 00 00
0x7b444790 ___wine_kernel_init+0x1a:  00 89 44 24 40 8b 40 30 89 44 24 44 8b 78 10 8b
0x7b4447a0 ___wine_kernel_init+0x2a:  86 ca 48 1b 00 83 ec 08 31 db 53 ff 30 e8 e4 de
Wine-dbg>
#endif
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
	return count;
}

static int __close(RIODesc *fd) {
	if (!fd || !fd->data) {
		return -1;
	}
	// XXX
	r_sys_cmdf ("pkill rarun2");
	return 0;
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
	return (!strncmp (pathname, "winedbg://", 10));
}

static RIODesc *__open(RIO *io, const char *pathname, int rw, int mode) {
	if (__plugin_open (io, pathname, 0)) {
		if (gs) {
			return NULL;
		}
		gs = r_socket_new (0);
		char *cmd = r_str_newf ("winedbg '%s'", pathname + 10);
		int res = r_socket_spawn (gs, cmd, 1000);
		free (cmd);
		if (!res) {
			return NULL;
		}
		char *reply = runcmd (NULL);
		if (reply) {
			int rw = 7;
			free (reply);
			eprintf ("Wine-dbg is ready to go!\n");
			return r_io_desc_new (io, &r_io_plugin_winedbg, pathname, rw, mode, gs);
		}
		eprintf ("Can't find the Wine-dbg prompt\n");
	}
	return NULL;
}

static void printcmd (RIO *io, const char *cmd) {
	char *res = runcmd (cmd);
	io->cb_printf ("%s\n", res);
	free (res);
}

static struct winedbg_x86_32 regState() {
	struct winedbg_x86_32 r = {0};
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

static char *__system(RIO *io, RIODesc *fd, const char *cmd) {
	if (!strcmp (cmd, "")) {
		return NULL;
	}
	if (!strncmp (cmd, "?", 1)) {
		eprintf ("dr  : show registers\n");
		eprintf ("dr* : show registers as flags\n");
		eprintf ("drp : show reg profile\n");
		eprintf ("dr8 : show hexpairs with regstate\n");
		eprintf ("ds  : step into\n");
		eprintf ("dp  : show process info\n");
		eprintf ("dc  : continue\n");
		eprintf ("dm  : show maps\n");
		eprintf ("pid : show current process id\n");
	} else if (!strncmp (cmd, "dr8", 3)) {
		struct winedbg_x86_32 r = regState ();
		ut8 *arena = (ut8*)calloc (3, sizeof (struct winedbg_x86_32));
		if (arena) {
			r_hex_bin2str ((ut8*)&r, sizeof (r), (char *)arena);
			return (char *)arena;
		}
	} else if (!strncmp (cmd, "drp", 3)) {
const char *msg =
"=PC	eip\n"\
"=SP	esp\n"\
"=BP	ebp\n"\
"=A0	eax\n"\
"=A1	ebx\n"\
"=A2	ecx\n"\
"=A3	edx\n"\
"=A4	esi\n"\
"=A5	edi\n"\
"=SN	eax\n"\

"seg	cs	.16	0	0\n"\
"seg	ss	.16	2	0\n"\
"seg	ds	.16	4	0\n"\
"seg	es	.16	6	0\n"\
"seg	fs	.16	8	0\n"\
"seg	gs	.16	10	0\n"\

"gpr	eip	.32	12	0\n"\
"gpr	esp	.32	16	0\n"\
"gpr	ebp	.32	20	0\n"\
"gpr	eflags	.32	24	0\n"\

"gpr	eax	.32	28	0\n"\
"gpr	ebx	.32	32	0\n"\
"gpr	ecx	.32	36	0\n"\
"gpr	edx	.32	40	0\n"\
"gpr	esi	.32	44	0\n"\
"gpr	edi	.32	48	0\n"\

"flg	flags	.16	24	0\n"\
"flg	cf	.1	.192	0\n"\
"flg	pf	.1	.193	0\n"\
"flg	af	.1	.194	0\n"\
"flg	zf	.1	.195	0\n"\
"flg	sf	.1	.196	0\n"\
"flg	tf	.1	.197	0\n"\
"flg	if	.1	.198	0\n"\
"flg	df	.1	.199	0\n"\
"flg	of	.1	.200	0\n"\
"flg	nt	.1	.201	0\n"\
"flg	rf	.1	.202	0\n"\
"flg	vm	.1	.203	0\n";
		return strdup (msg);
	} else if (!strncmp (cmd, "dr*", 2)) {
		struct winedbg_x86_32 r = regState ();
		io->cb_printf ("f eip = 0x%08x\n", r.eip);
		io->cb_printf ("f esp = 0x%08x\n", r.esp);
		io->cb_printf ("f ebp = 0x%08x\n", r.ebp);
		io->cb_printf ("f eax = 0x%08x\n", r.eax);
		io->cb_printf ("f ebx = 0x%08x\n", r.ebx);
		io->cb_printf ("f ecx = 0x%08x\n", r.ecx);
		io->cb_printf ("f edx = 0x%08x\n", r.edx);
		io->cb_printf ("f esi = 0x%08x\n", r.esi);
		io->cb_printf ("f edi = 0x%08x\n", r.edi);
		io->cb_printf ("f eflags = 0x%08x\n", r.eflags);
		io->cb_printf ("f cs = 0x%08x\n", r.cs);
		io->cb_printf ("f ss = 0x%08x\n", r.ss);
		io->cb_printf ("f ds = 0x%08x\n", r.ds);
		io->cb_printf ("f es = 0x%08x\n", r.es);
		io->cb_printf ("f fs = 0x%08x\n", r.fs);
		io->cb_printf ("f gs = 0x%08x\n", r.gs);
	} else if (!strncmp (cmd, "dr", 2)) {
		printcmd (io, "info reg");
	} else if (!strncmp (cmd, "db ", 3)) {
		free (runcmd (sdb_fmt ("break *%x", r_num_get (NULL, cmd + 3) || io->off)));
	} else if (!strncmp (cmd, "ds", 2)) {
		free (runcmd ("stepi"));
	} else if (!strncmp (cmd, "dc", 2)) {
		free (runcmd ("cont"));
	} else if (!strncmp (cmd, "dso", 3)) {
		eprintf ("TODO: dso\n");
	} else if (!strncmp (cmd, "dp", 3)) {
		printcmd (io, "info thread");
	} else if (!strncmp (cmd, "dm", 3)) {
		char *wineDbgMaps = runcmd ("info maps");
		char *res = NULL;
		if (wineDbgMaps) {
			const char *perm;
			char *ptr = wineDbgMaps;
			for (;;) {
				char *nl = strchr (ptr, '\n');
				if (!nl) {
					break;
				}
				*nl++ = 0;
				perm = "r-x";
				ut64 from = 0, to = 0;
				if (strstr (ptr, " commit ")) {
					if (strstr (ptr, "RW")) {
						perm = "rw-";
					}
					sscanf (ptr, "%08"PFMT64x" %08"PFMT64x, &from, &to);
				}
				char *row = r_str_newf ("0x%08"PFMT64x" - 0x%08" PFMT64x" %s %s\n", from, to, perm, "");
				ptr = nl;
				if (row) {
					res = r_str_append (res, row);
					free (row);
				}
			}
			free (wineDbgMaps);
			return res;
		}
	} else if (!strncmp (cmd, "pid", 3)) {
		return r_str_newf ("%d", fd->fd);
	} else {
		printcmd (io, cmd);
	}
	return NULL;
}

RIOPlugin r_io_plugin_winedbg = {
	.name = "winedbg",
	.desc = "Wine-dbg io and debug.io plugin",
	.uris = "winedbg://",
	.license = "MIT",
	.open = __open,
	.close = __close,
	.read = __read,
	.check = __plugin_open,
	.lseek = __lseek,
	.write = __write,
	.system = __system,
	.isdbg = true
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_winedbg,
	.version = R2_VERSION
};
#endif
