/* radare - LGPL - Copyright 2023 - pancake */

#include <r_io.h>
#include <r_lib.h>

#define DEBUG 0

static R_TH_LOCAL RSocket *gs = NULL;
#if __APPLE__
static R_TH_LOCAL bool use_lldb = true;
static bool usefirst = true;
#else
static R_TH_LOCAL bool use_lldb = false;
static bool usefirst = false;
#endif
static bool lastbroken = false;
static bool use_pwndbg = false;

// TODO: make it vargarg...
static char *runcmd(const char *cmd) {
	char buf[4096] = {0};
	if (cmd) {
		if (usefirst) {
			usefirst = false;
			free (runcmd ("starti"));
		}
		r_socket_printf (gs, "%s\n", cmd);
	} else {
		if (use_lldb) {
			cmd = "process launch --stop-at-entry\n";
		} else {
			usefirst = true;
		}
	}
	if (lastbroken) {
		r_socket_read (gs, (ut8*)buf, sizeof (buf) - 1);
		lastbroken = false;
	}
	int timeout = 10000;
	char *str = NULL;
	r_socket_block_time (gs, 1, timeout, 0);
	while (true) {
#if DEBUG
		eprintf ("LOOP\n");
#endif
		memset (buf, 0, sizeof (buf));
		if (use_lldb && !r_socket_ready (gs, 0, 250)) {
			return str;
		}
		int rc = r_socket_read (gs, (ut8*)buf, sizeof (buf) - 1); // always NULL-terminate the string
		if (rc < 0) {
#if DEBUG
			eprintf ("socket-read-break\n");
#endif
			r_socket_read (gs, (ut8*)buf, sizeof (buf) - 1);
			lastbroken = true;
			free (str);
			return NULL;
		}
		if (rc == 0) {
			break;
		}
		buf[sizeof (buf) - 1] = 0;
		r_str_ansi_strip (buf);
#if DEBUG
		write (1, "READ: (", 7);
		write (1, buf, strlen (buf));
		write (1, ")\n", 2);
#endif
		if (use_lldb) {
			if (!cmd) {
				usefirst = true;
				return r_str_append (str, buf);
			}
			if (0 && usefirst) {
				str = r_str_append (str, buf);
				int rc = r_socket_read (gs, (ut8*)buf, sizeof (buf) - 1); // always NULL-terminate the string
				usefirst = false;
				if (rc < 1) {
					return str;
				}
			}
			// (lldb ) goes first, so we skip it
			str = r_str_append (str, buf);
			if (strstr (buf, "(lldb")) {
				//return str;
			}
		} else {
			char *promptFound;
			if (!use_pwndbg && usefirst) {
				use_pwndbg = strstr (buf, "pwndbg>");
			}
			if (use_pwndbg) {
				promptFound = strstr (buf, "pwndbg>");
				if (promptFound) {
					return r_str_append (str, buf);
				}
			} else {
				promptFound = strstr (buf, "(gdb) ");
				if (promptFound) {
					if (promptFound[6]) {
						promptFound = NULL;
					}
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
	int i;
	for (i = 0; i < count ; i++) {
		ut64 addr = io->off + i;
		char *cmd = r_str_newf ("set *((unsigned char *)0x%"PFMT64x") = 0x%x", addr, buf[i]);
		free (runcmd (cmd));
		free (cmd);
	}

	return count;
}

static int __read(RIO *io, RIODesc *fd, ut8 *buf, int count) {
	if (!fd || !fd->data) {
		return -1;
	}
	const ut64 addr = io->off;
	if (count > (1024*128)) {
		// cannot read that much
		return -1;
	}
	if (addr == 0 || addr == UT64_MAX) {
		return -1;
	}
	int bufi = 0;
	int left = 0;
repeat:
	if (count > 1024) {
		left = count - 1024;
		count = 1024;
	}
	memset (buf, 0xff, count);
	if (count > 0) {
		char *cmd = r_str_newf ("x/%db 0x%"PFMT64x, count, addr);
		char *ores = runcmd (cmd);
		char *nextline = NULL;
		char *res = ores;
		do {
			nextline = r_str_after (res, '\n');
			char *colon = r_str_after (res, ':');
			while (colon && bufi < count) {
				colon = (char *)r_str_trim_head_ro (colon);
				if (!*colon) {
					break;
				}
				ut64 b = atoi (colon);
				buf[bufi++] = b;
				while (colon && (isdigit (*colon) || *colon == '-')) {
					colon++;
				}
			}
			res = nextline + 1;
		} while (nextline);
		free (ores);
		free (cmd);
	}
	if (left > 0) {
		count = left;
		goto repeat;
	}
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
		io->off = UT64_MAX;
	}
	return io->off;
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
			? r_str_newf ("lldb --no-use-colors -- %s", pathname + 9)
			: r_str_newf ("gdb --args %s", pathname + 9);
		int res = r_socket_spawn (gs, cmd, 1000);
		free (cmd);
		if (!res) {
			return NULL;
		}
		if (use_lldb) {
			R_LOG_WARN ("lldb support is broken and experimental");
		}
		char *reply = runcmd (NULL);
#if DEBUG
		eprintf ("REPLY (%s)\n", reply);
#endif
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

static const char x86r_32[] = "\n"
"=PC	eip\n"
"=SP	esp\n"
"=BP	ebp\n"
"=R0	eax\n"
"=A0	eax\n"
"=A1	ebx\n"
"=A2	ecx\n"
"=A3	edx\n"
"=A4	esi\n"
"=A5	edi\n"
"=SN	eax\n"
"gpr	eiz	.32	?	0\n"
"gpr	oeax	.32	44	0\n"
"gpr	eax	.32	24	0\n"
"gpr	ax	.16	24	0\n"
"gpr	ah	.8	25	0\n"
"gpr	al	.8	24	0\n"
"gpr	ebx	.32	0	0\n"
"gpr	bx	.16	0	0\n"
"gpr	bh	.8	1	0\n"
"gpr	bl	.8	0	0\n"
"gpr	ecx	.32	4	0\n"
"gpr	cx	.16	4	0\n"
"gpr	ch	.8	5	0\n"
"gpr	cl	.8	4	0\n"
"gpr	edx	.32	8	0\n"
"gpr	dx	.16	8	0\n"
"gpr	dh	.8	9	0\n"
"gpr	dl	.8	8	0\n"
"gpr	esi	.32	12	0\n"
"gpr	si	.16	12	0\n"
"gpr	edi	.32	16	0\n"
"gpr	di	.16	16	0\n"
"gpr	esp	.32	60	0\n"
"gpr	sp	.16	60	0\n"
"gpr	ebp	.32	20	0\n"
"gpr	bp	.16	20	0\n"
"gpr	eip	.32	48	0\n"
"gpr	ip	.16	48	0\n"
"seg	xfs	.32	36	0\n"
"seg	xgs	.32	40	0\n"
"seg	xcs	.32	52	0\n"
"seg	cs	.16	52	0\n"
"seg	xss	.32	52	0\n"
"flg	eflags	.32	.448	0	c1p.a.zstido.n.rv\n"
"flg	flags	.16	.448	0\n"
"flg	cf	.1	.448	0\n"
"flg	pf	.1	.450	0\n"
"flg	af	.1	.452	0\n"
"flg	zf	.1	.454	0\n"
"flg	sf	.1	.455	0\n"
"flg	tf	.1	.456	0\n"
"flg	if	.1	.457	0\n"
"flg	df	.1	.458	0\n"
"flg	of	.1	.459	0\n"
"flg	nt	.1	.462	0\n"
"flg	rf	.1	.464	0\n"
"flg	vm	.1	.465	0\n"
"drx	dr0	.32	0	0\n"
"drx	dr1	.32	4	0\n"
"drx	dr2	.32	8	0\n"
"drx	dr3	.32	12	0\n"
"drx	dr6	.32	24	0\n"
"drx	dr7	.32	28	0\n";

static char *printprofile(RIO *io, RIODesc *fd) {
	if (io->bits == 32) {
		return strdup (x86r_32);
	}
	const char *x86r = "\n"
"=PC	rip\n"
"=SP	rsp\n"
"=BP	rbp\n"
"=R0	rax\n"
"=A0	rdi\n"
"=A1	rsi\n"
"=A2	rdx\n"
"=A3	rcx\n"
"=A4	r8\n"
"=A5	r9\n"
"=A6	r10\n"
"=A7	r11\n"
"=SN	rax\n"
"gpr	rax	.64	80	0\n"
"gpr	eax	.32	80	0\n"
"gpr	ax	.16	80	0\n"
"gpr	al	.8	80	0\n"
"gpr	ah	.8	81	0\n"
"gpr	rbx	.64	40	0\n"
"gpr	ebx	.32	40	0\n"
"gpr	bx	.16	40	0\n"
"gpr	bl	.8	40	0\n"
"gpr	bh	.8	41	0\n"
"gpr	rcx	.64	88	0\n"
"gpr	ecx	.32	88	0\n"
"gpr	cx	.16	88	0\n"
"gpr	cl	.8	88	0\n"
"gpr	ch	.8	89	0\n"
"gpr	rdx	.64	96	0\n"
"gpr	edx	.32	96	0\n"
"gpr	dx	.16	96	0\n"
"gpr	dl	.8	96	0\n"
"gpr	dh	.8	97	0\n"
"gpr	rsi	.64	104	0\n"
"gpr	esi	.32	104	0\n"
"gpr	si	.16	104	0\n"
"gpr	sil	.8	104	0\n"
"gpr	rdi	.64	112	0\n"
"gpr	edi	.32	112	0\n"
"gpr	di	.16	112	0\n"
"gpr	dil	.8	112	0\n"
"gpr	r8	.64	72	0\n"
"gpr	r8d	.32	72	0\n"
"gpr	r8w	.16	72	0\n"
"gpr	r8b	.8	72	0\n"
"gpr	r9	.64	64	0\n"
"gpr	r9d	.32	64	0\n"
"gpr	r9w	.16	64	0\n"
"gpr	r9b	.8	64	0\n"
"gpr	r10	.64	56	0\n"
"gpr	r10d	.32	56	0\n"
"gpr	r10w	.16	56	0\n"
"gpr	r10b	.8	56	0\n"
"gpr	r11	.64	48	0\n"
"gpr	r11d	.32	48	0\n"
"gpr	r11w	.16	48	0\n"
"gpr	r11b	.8	48	0\n"
"gpr	r12	.64	24	0\n"
"gpr	r12d	.32	24	0\n"
"gpr	r12w	.16	24	0\n"
"gpr	r12b	.8	24	0\n"
"gpr	r13	.64	16	0\n"
"gpr	r13d	.32	16	0\n"
"gpr	r13w	.16	16	0\n"
"gpr	r13b	.8	16	0\n"
"gpr	r14	.64	8	0\n"
"gpr	r14d	.32	8	0\n"
"gpr	r14w	.16	8	0\n"
"gpr	r14b	.8	8	0\n"
"gpr	r15	.64	0	0\n"
"gpr	r15d	.32	0	0\n"
"gpr	r15w	.16	0	0\n"
"gpr	r15b	.8	0	0\n"
"gpr	rip	.64	128	0\n"
"gpr	rbp	.64	32	0\n"
"gpr	ebp	.32	32	0\n"
"gpr	bp	.16	32	0\n"
"gpr	bpl	.8	32	0\n"
"seg	cs	.64	136	0\n"
"flg	rflags	.64	144	0	c1p.a.zstido.n.rv\n"
"flg	eflags	.32	144	0	c1p.a.zstido.n.rv\n"
"flg	cf	.1	144.0	0	carry\n"
"flg	pf	.1	144.2	0	parity\n"
"flg	af	.1	144.4	0	adjust\n"
"flg	zf	.1	144.6	0	zero\n"
"flg	sf	.1	144.7	0	sign\n"
"flg	tf	.1	.1160	0	trap\n"
"flg	if	.1	.1161	0	interrupt\n"
"flg	df	.1	.1162	0	direction\n"
"flg	of	.1	.1163	0	overflow\n"
"gpr	riz	.64	?	0\n"
"gpr	rsp	.64	152	0\n"
"gpr	esp	.32	152	0\n"
"gpr	sp	.16	152	0\n"
"gpr	spl	.8	152	0\n"
"seg	ss	.64	160	0\n"
"seg	fs_base	.64	168	0\n"
"seg	gs_base	.64	176	0\n"
"seg	ds	.64	184	0\n"
"seg	es	.64	192	0\n"
"seg	fs	.64	200	0\n"
"seg	gs	.64	208	0\n"
"drx	dr0	.64	0	0\n"
"drx	dr1	.64	8	0\n"
"drx	dr2	.64	16	0\n"
"drx	dr3	.64	24	0\n"
"drx	dr6	.64	48	0\n"
"drx	dr7	.64	56	0\n"
;
	return strdup (x86r);
}

static int sysgdb_getpid(void) {
	char *res = runcmd ("info proc");
	char *sp = strchr (res, ' ');
	int pid = sp? atoi (sp + 1): 0;
	free (res);
	return pid;
}

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
	} else if (!strcmp (cmd, "drp")) {
		return printprofile (io, fd);
	} else if (!strcmp (cmd, "dbt")) {
		printcmd (io, "backtrace");
	} else if (!strcmp (cmd, "dc")) {
		printcmd (io, "cont");
	} else if (!strcmp (cmd, "dr8")) {
		char *regs = runcmd ("i r");
		int arenacount = 23;
		int arenasize = 64 * arenacount;
		ut64 *arena = (ut64*)calloc (arenacount, sizeof (ut64));
		RList *list = r_str_split_list (regs, "\n", 0);
		RListIter *iter;
		char *line;
#define IFREG(rn, pos) if (r_str_startswith (line, rn)) { arena[pos/8] = r_num_get (NULL, line + strlen (rn)); } else
		r_list_foreach (list, iter, line) {
			IFREG ("rax", 80)
			IFREG ("rbx", 40)
			IFREG ("rcx", 88)
			IFREG ("rdx", 96)
			IFREG ("r8", 72)
			IFREG ("r10", 56)
			IFREG ("rsi", 104)
			IFREG ("rdi", 112)
			IFREG ("rbp", 32)
			IFREG ("rsp", 152)
			IFREG ("rip", 128)
			{}
		}
		r_list_free (list);
		free (regs);
		return r_hex_bin2strdup ((const ut8*)arena, arenasize);
	} else if (!strcmp (cmd, "di")) {
		printcmd (io, "info proc all");
	} else if (r_str_startswith (cmd, "dk")) {
		// do nothing. but we should send a signal here
	} else if (!strcmp (cmd, "ds")) {
		printcmd (io, "stepi");
	} else if (!strcmp (cmd, "dr")) {
		printcmd (io, "i r");
	} else if (!strcmp (cmd, "dm")) {
		RStrBuf *sb = r_strbuf_new ("");
		// TODO: construct new string with standard pat
		char *res = runcmd ("info proc mappings");
		RList *list = r_str_split_list (res, "\n", 0);
		RListIter *iter;
		char *line;
		r_list_foreach (list, iter, line) {
			line = (char *)r_str_trim_head_ro (line);
			if (!r_str_startswith (line, "0x")) {
				continue;
			}
			// 0x555555558000     0x55555556c000    0x14000     0x4000  r-xp   /usr/bin/ls
			line = r_str_replace_all (line, "  ", " ");
			// ut64 min, max; size offset perms name
			RList *args = r_str_split_list (line, " ", 0);
			ut64 min = r_num_get (NULL, r_list_get_n (args, 0));
			ut64 max = r_num_get (NULL, r_list_get_n (args, 1));
			char *perm = r_list_get_n (args, 4);
			char *name = r_list_get_n (args, 5);
			// 0x00007ffdc1e90000 - 0x00007ffdc1e94000 - usr    16K s r-- [vvar] [vvar] ; map._vvar_.r__
			r_strbuf_appendf (sb, "0x%08"PFMT64x" - 0x%08"PFMT64x" %s %s\n", min, max, perm, name);
		}
		r_list_free (list);
		return r_strbuf_drain (sb);
		// printcmd (io, "info proc mappings");
	} else if (r_str_startswith (cmd, "pid")) { // should be using `dp` imho
		int pid = sysgdb_getpid ();
		// io->cb_printf ("%d\n", pid);
		return r_str_newf ("%d\n", pid);
	} else {
		printcmd (io, cmd);
	}
	return NULL;
}

static int __getpid(RIODesc *fd) {
	return sysgdb_getpid ();
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
	.getpid = __getpid,
	.isdbg = true
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_sysgdb,
	.version = R2_VERSION
};
#endif
