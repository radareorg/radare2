/* radare - Copyright 2009-2019 - pancake, nibble */

#include "r_core.h"
#include "r_socket.h"
#include "gdb/include/libgdbr.h"
#include "gdb/include/gdbserver/core.h"

#if HAVE_LIBUV
#include <uv.h>
#endif

#if 0
SECURITY IMPLICATIONS
=====================
- no ssl
- no auth
- commands can be executed by anyone
- default is to listen on localhost
- can access full filesystem
- follow symlinks
#endif

#define rtr_n core->rtr_n
#define rtr_host core->rtr_host

static RSocket *s = NULL;
static RThread *httpthread = NULL;
static RThread *rapthread = NULL;
static const char *listenport = NULL;

typedef struct {
	const char *host;
	const char *port;
	const char *file;
} TextLog;

typedef struct {
	RCore *core;
	int launch;
	int browse;
	char *path;
} HttpThread;

typedef struct {
	RCore *core;
	char* input;
} RapThread;

R_API void r_core_wait(RCore *core) {
	r_cons_singleton ()->context->breaked = true;
	r_th_kill (httpthread, true);
	r_th_kill (rapthread, true);
	r_th_wait (httpthread);
	r_th_wait (rapthread);
}

static void http_logf(RCore *core, const char *fmt, ...) {
	bool http_log_enabled = r_config_get_i (core->config, "http.log");
	va_list ap;
	va_start (ap, fmt);
	if (http_log_enabled) {
		const char *http_log_file = r_config_get (core->config, "http.logfile");
		if (http_log_file && *http_log_file) {
			char * msg = calloc (4096, 1);
			if (msg) {
				vsnprintf (msg, 4095, fmt, ap);
				r_file_dump (http_log_file, (const ut8*)msg, -1, true);
				free (msg);
			}
		} else {
			vfprintf (stderr, fmt, ap);
		}
	}
	va_end (ap);
}

static char *rtrcmd (TextLog T, const char *str) {
	char *res, *ptr2;
	char *ptr = r_str_uri_encode (str);
	char *uri = r_str_newf ("http://%s:%s/%s%s", T.host, T.port, T.file, ptr? ptr: str);
	int len;
	free (ptr);
	ptr2 = r_socket_http_get (uri, NULL, &len);
	free (uri);
	if (ptr2) {
		ptr2[len] = 0;
		res = strstr (ptr2, "\n\n");
		if (res) {
			res = strstr (res + 1, "\n\n");
		}
		return res? res + 2: ptr2;
	}
	return NULL;
}

static void showcursor(RCore *core, int x) {
	if (core && core->vmode) {
		r_cons_show_cursor (x);
		r_cons_enable_mouse (x? r_config_get_i (core->config, "scr.wheel"): false);
	} else {
		r_cons_enable_mouse (false);
	}
	r_cons_flush ();
}

// TODO: rename /name to /nick or /so?
// clone of textlog_chat () using rtrcmd()
static void rtr_textlog_chat (RCore *core, TextLog T) {
	char prompt[64];
	char buf[1024];
	int lastmsg = 0;
	const char *me = r_config_get (core->config, "cfg.user");
	char *ret, msg[1024];

	eprintf ("Type '/help' for commands and ^D to quit:\n");
	char *oldprompt = strdup (r_line_singleton ()->prompt);
	snprintf (prompt, sizeof (prompt) - 1, "[%s]> ", me);
	r_line_set_prompt (prompt);
	ret = rtrcmd (T, msg);
	for (;;) {
		if (lastmsg >= 0) {
			snprintf (msg, sizeof (msg) - 1, "T %d", lastmsg);
		} else {
			strcpy (msg, "T");
		}
		ret = rtrcmd (T, msg);
		r_cons_println (ret);
		free (ret);
		ret = rtrcmd (T, "Tl");
		lastmsg = atoi (ret)-1;
		free (ret);
		if (r_cons_fgets (buf, sizeof (buf) - 1, 0, NULL) < 0) {
			goto beach;
		}
		if (!*buf) {
			continue;
		}
		if (!strcmp (buf, "/help")) {
			eprintf ("/quit           quit the chat (same as ^D)\n");
			eprintf ("/nick <nick>    set cfg.user nick name\n");
			eprintf ("/log            show full log\n");
			eprintf ("/clear          clear text log messages\n");
		} else if (!strncmp (buf, "/nick ", 6)) {
			snprintf (msg, sizeof (msg) - 1, "* '%s' is now known as '%s'", me, buf+6);
			r_cons_println (msg);
			r_core_log_add (core, msg);
			r_config_set (core->config, "cfg.user", buf+6);
			me = r_config_get (core->config, "cfg.user");
			snprintf (prompt, sizeof (prompt) - 1, "[%s]> ", me);
			r_line_set_prompt (prompt);
		} else if (!strcmp (buf, "/log")) {
			char *ret = rtrcmd (T, "T");
			if (ret) {
				r_cons_println (ret);
				free (ret);
			}
		} else if (!strcmp (buf, "/clear")) {
			//r_core_log_del (core, 0);
			free (rtrcmd (T, "T-"));
		} else if (!strcmp (buf, "/quit")) {
			goto beach;
		} else if (*buf=='/') {
			eprintf ("Unknown command: %s\n", buf);
		} else {
			char *cmd = r_str_newf ("T [%s] %s", me, buf);
			free (rtrcmd (T, cmd));
			free (cmd);
		}
	}
beach:
	r_line_set_prompt (oldprompt);
	free (oldprompt);
}

R_API int r_core_rtr_http_stop(RCore *u) {
	RCore *core = (RCore*)u;
	const int timeout = 1; // 1 second
	const char *port;
	RSocket* sock;

#if __WINDOWS__
	r_socket_http_server_set_breaked (&r_cons_singleton ()->context->breaked);
#endif
	if (((size_t)u) > 0xff) {
		port = listenport? listenport: r_config_get (
			core->config, "http.port");
		sock = r_socket_new (0);
		(void)r_socket_connect (sock, "localhost",
			port, R_SOCKET_PROTO_TCP, timeout);
		r_socket_free (sock);
	}
	r_socket_free (s);
	s = NULL;
	return 0;
}

static char *rtr_dir_files (const char *path) {
	char *ptr = strdup ("<html><body>\n");
	const char *file;
	RListIter *iter;
	// list files
	RList *files = r_sys_dir (path);
	eprintf ("Listing directory %s\n", path);
	r_list_foreach (files, iter, file) {
		if (file[0] == '.') {
			continue;
		}
		ptr = r_str_appendf (ptr, "<a href=\"%s%s\">%s</a><br />\n",
			path, file, file);
	}
	r_list_free (files);
	return r_str_append (ptr, "</body></html>\n");
}

#if __UNIX__
static void dietime (int sig) {
	eprintf ("It's Die Time!\n");
	exit (0);
}
#endif

static void activateDieTime (RCore *core) {
	int dt = r_config_get_i (core->config, "http.dietime");
	if (dt > 0) {
#if __UNIX__
		r_sys_signal (SIGALRM, dietime);
		alarm (dt);
#else
		eprintf ("http.dietime only works on *nix systems\n");
#endif
	}
}

#include "rtr_http.c"
#include "rtr_shell.c"

static int write_reg_val(char *buf, ut64 sz, ut64 reg, int regsize, bool bigendian) {
	if (!bigendian) {
		switch (regsize) {
		case 2:
			reg = r_swap_ut16 (reg);
			break;
		case 4:
			reg = r_swap_ut32 (reg);
			break;
		case 8:
			reg = r_swap_ut64 (reg);
			break;
		default:
			eprintf ("%s: Unsupported reg size: %d\n",
				 __func__, regsize);
			return -1;
		}
	}
	return snprintf (buf, sz, regsize == 2 ? "%04"PFMT64x
			 : regsize == 4 ? "%08"PFMT64x : "%016"PFMT64x, reg);
}

static int write_big_reg(char *buf, ut64 sz, const utX *val, int regsize, bool bigendian) {
	switch (regsize) {
	case 10:
		if (bigendian) {
			return snprintf (buf, sz,
					 "%04x%016"PFMT64x, val->v80.High,
					 val->v80.Low);
		}
		return snprintf (buf, sz,
				 "%016"PFMT64x"%04x", r_swap_ut64 (val->v80.Low),
				 r_swap_ut16 (val->v80.High));
	case 12:
		if (bigendian) {
			return snprintf (buf, sz,
					 "%08"PFMT32x"%016"PFMT64x, val->v96.High,
					 val->v96.Low);
		}
		return snprintf (buf, sz,
				 "%016"PFMT64x"%08"PFMT32x, r_swap_ut64 (val->v96.Low),
				 r_swap_ut32 (val->v96.High));
	case 16:
		if (bigendian) {
			return snprintf (buf, sz,
					 "%016"PFMT64x"%016"PFMT64x, val->v128.High,
					 val->v128.Low);
		}
		return snprintf (buf, sz,
				 "%016"PFMT64x"%016"PFMT64x,
				 r_swap_ut64 (val->v128.Low),
				 r_swap_ut64 (val->v128.High));
	default:
		eprintf ("%s: big registers (%d byte(s)) not yet supported\n",
			 __func__, regsize);
		return -1;
	}
}

static int swap_big_regs (char *dest, ut64 sz, const char *src, int regsz) {
	utX val;
	char sdup[128] = {0};
	if (!src || !src[0] || !src[1]) {
		return -1;
	}
	strncpy (sdup, src + 2, sizeof (sdup) - 1);
	int len = strlen (sdup);
	memset (&val, 0, sizeof (val));
	switch (regsz) {
	case 10:
		if (len <= 4) {
			val.v80.High = (ut16) strtoul (sdup, NULL, 16);
		} else {
			val.v80.High = (ut16) strtoul (sdup + (len - 4), NULL, 16);
			sdup[len - 4] = '\0';
			val.v80.Low = (ut64) strtoull (sdup, NULL, 16);
		}
		return snprintf (dest, sz, "0x%04x%016"PFMT64x,
				 val.v80.High, val.v80.Low);
	case 12:
		if (len <= 8) {
			val.v96.High = (ut32) strtoul (sdup, NULL, 16);
		} else {
			val.v96.High = (ut32) strtoul (sdup + (len - 8), NULL, 16);
			sdup[len - 8] = '\0';
			val.v96.Low = (ut64) strtoull (sdup, NULL, 16);
		}
		return snprintf (dest, sz, "0x%08x%016"PFMT64x,
				 val.v96.High, val.v96.Low);
	case 16:
		if (len <= 16) {
			val.v128.High = (ut64) strtoul (sdup, NULL, 16);
		} else {
			val.v128.High = (ut64) strtoul (sdup + (len - 16), NULL, 16);
			sdup[len - 16] = '\0';
			val.v128.Low = (ut64) strtoull (sdup, NULL, 16);
		}
		return snprintf (dest, sz, "0x%016"PFMT64x"%016"PFMT64x,
				 val.v128.High, val.v128.Low);
	default:
		eprintf ("%s: big registers (%d byte(s)) not yet supported\n",
			 __func__, regsz);
		return -1;
	}
}

static int r_core_rtr_gdb_cb(libgdbr_t *g, void *core_ptr, const char *cmd,
			     char *out_buf, size_t max_len) {
	int ret;
	RList *list;
	RListIter *iter;
	gdb_reg_t *gdb_reg;
	RRegItem *r;
	utX val_big;
	ut64 m_off, reg_val;
	bool be;
	RDebugPid *dbgpid;
	if (!core_ptr || ! cmd) {
		return -1;
	}
	RCore *core = (RCore*) core_ptr;
	switch (cmd[0]) {
	case '?': // Stop reason
		if (!out_buf) {
			return -1;
		}
		// dbg->reason.signum and dbg->reason.tid are not correct for native
		// debugger. This is a hack
		switch (core->dbg->reason.type) {
		case R_DEBUG_REASON_BREAKPOINT:
		case R_DEBUG_REASON_STEP:
		case R_DEBUG_REASON_TRAP:
		default: // remove when possible
			return snprintf (out_buf, max_len - 1, "T05thread:%x;",
					 core->dbg->tid);
		}
		// Fallback for when it's fixed
		/*
		return snprintf (out_buf, max_len - 1, "T%02xthread:%x;",
				 core->dbg->reason.type, core->dbg->reason.tid);
		*/
	case 'd':
		switch (cmd[1]) {
		case 'm': // dm
			if (snprintf (out_buf, max_len - 1, "%"PFMT64x, r_debug_get_baddr (core->dbg, NULL)) < 0) {
				return -1;
			}
			return 0;
		case 'p': // dp
			switch (cmd[2]) {
			case '\0': // dp
				// TODO support multiprocess
				snprintf (out_buf, max_len - 1, "QC%x", core->dbg->tid);
				return 0;
			case 't':
				switch (cmd[3]) {
				case '\0': // dpt
					if (!core->dbg->h->threads) {
						return -1;
					}
					if (!(list = core->dbg->h->threads(core->dbg, core->dbg->pid))) {
						return -1;
					}
					memset (out_buf, 0, max_len);
					out_buf[0] = 'm';
					ret = 1;
					r_list_foreach (list, iter, dbgpid) {
						// Max length of a hex pid = 8?
						if (ret >= max_len - 9) {
							break;
						}
						snprintf (out_buf + ret, max_len - ret - 1, "%x,", dbgpid->pid);
						ret = strlen (out_buf);
					}
					if (ret > 1) {
						ret--;
						out_buf[ret] = '\0';
					}
					return 0;
				case 'r': // dptr -> return current tid as int
					return core->dbg->tid;
				default:
					return r_core_cmd (core, cmd, 0);
				}
			}
			break;
		case 'r': // dr
			r_debug_reg_sync (core->dbg, R_REG_TYPE_ALL, false);
			be = r_config_get_i (core->config, "cfg.bigendian");
			if (isspace ((ut8)cmd[2])) { // dr reg
				const char *name, *val_ptr;
				char new_cmd[128] = { 0 };
				int off = 0;
				name = cmd + 3;
				// Temporarily using new_cmd to store reg name
				if ((val_ptr = strchr (name, '='))) {
					strncpy (new_cmd, name, R_MIN (val_ptr - name, sizeof (new_cmd) - 1));
				} else {
					strncpy (new_cmd, name, sizeof (new_cmd) - 1);
				}
				if (!(r = r_reg_get (core->dbg->reg, new_cmd, -1))) {
					return -1;
				}
				if (val_ptr) { // dr reg=val
					val_ptr++;
					off = val_ptr - cmd;
					if (be) {
						// We don't need to swap
						r_core_cmd (core, cmd, 0);
					}
					// Previous contents are overwritten, since len(name) < off
					strncpy (new_cmd, cmd, off);
					if (r->size <= 64) {
						reg_val = strtoll (val_ptr, NULL, 16);
						if (write_reg_val (new_cmd + off, sizeof (new_cmd) - off - 1,
								   reg_val, r->size / 8, be) < 0) {
							return -1;
						}
						return r_core_cmd (core, new_cmd, 0);
					}
					// Big registers
					if (swap_big_regs (new_cmd + off, sizeof (new_cmd) - off - 1,
							   val_ptr, r->size / 8) < 0) {
						return -1;
					}
					return r_core_cmd (core, new_cmd, 0);
				}
				if (r->size <= 64) {
					reg_val = r_reg_get_value (core->dbg->reg, r);
					return write_reg_val (out_buf, max_len - 1,
							      reg_val, r->size / 8, be);
				}
				r_reg_get_value_big (core->dbg->reg,
						     r, &val_big);
				return write_big_reg (out_buf, max_len - 1,
						      &val_big, r->size / 8, be);
			}
			// dr - Print all registers
			ret = 0;
			if (!(gdb_reg = g->registers)) {
				return -1;
			}
			while (*gdb_reg->name) {
				if (ret + gdb_reg->size * 2 >= max_len - 1) {
					return -1;
				}
				if (gdb_reg->size <= 8) {
					reg_val = r_reg_getv (core->dbg->reg, gdb_reg->name);
					if (write_reg_val (out_buf + ret,
							   gdb_reg->size * 2 + 1,
							   reg_val, gdb_reg->size, be) < 0) {
						return -1;
					}
				} else {
					r_reg_get_value_big (core->dbg->reg,
							     r_reg_get (core->dbg->reg, gdb_reg->name, -1),
							     &val_big);
					if (write_big_reg (out_buf + ret, gdb_reg->size * 2 + 1,
							   &val_big, gdb_reg->size, be) < 0) {
						return -1;
					}
				}
				ret += gdb_reg->size * 2;
				gdb_reg++;
			}
			out_buf[ret] = '\0';
			return ret;
		default:
			return r_core_cmd (core, cmd, 0);
		}
		break;
	case 'i':
		switch (cmd[1]) {
		case 'f':
		{
			ut64 off, len, sz, namelen;
			RIODesc *desc = core && core->file ? r_io_desc_get (core->io, core->file->fd) : NULL;
			if (sscanf (cmd + 2, "%"PFMT64x",%"PFMT64x, &off, &len) != 2) {
				strcpy (out_buf, "E00");
				return 0;
			}
			namelen = desc ? strlen (desc->name) : 0;
			if (off >= namelen) {
				out_buf[0] = 'l';
				return 0;
			}
			sz = R_MIN (max_len, len + 2);
			len = snprintf (out_buf, sz, "l%s", desc ? (desc->name + off) : "");
			if (len >= sz) {
				// There's more left
				out_buf[0] = 'm';
			}
			return 0;
		}
		}
		break;
	case 'm':
		sscanf (cmd + 1, "%"PFMT64x",%x", &m_off, &ret);
		if (r_io_read_at (core->io, m_off, (ut8*) out_buf, ret)) {
			return ret;
		}
		return -1;
	default:
		return r_core_cmd (core, cmd, 0);
	}
	return -1;
}

// path = "<port> <file_name>"
static int r_core_rtr_gdb_run(RCore *core, int launch, const char *path) {
	RSocket *sock;
	int p, ret;
	bool debug_msg = false;
	char port[10];
	char *file = NULL, *args = NULL;
	libgdbr_t *g;

	if (!core || !path) {
		return -1;
	}
	if (*path == '!') {
		debug_msg = true;
		path++;
	}
	if (!(path = r_str_trim_head_ro (path)) || !*path) {
		eprintf ("gdbserver: Port not specified\n");
		return -1;
	}
	if (!(p = atoi (path)) || p < 0 || p > 65535) {
		eprintf ("gdbserver: Invalid port: %s\n", port);
		return -1;
	}
	snprintf (port, sizeof (port) - 1, "%d", p);
	if (!(file = strchr (path, ' '))) {
		eprintf ("gdbserver: File not specified\n");
		return -1;
	}
	if (!(file = (char *)r_str_trim_head_ro (file)) || !*file) {
		eprintf ("gdbserver: File not specified\n");
		return -1;
	}
	args = strchr (file, ' ');
	if (args) {
		*args++ = '\0';
		if (!(args = (char *)r_str_trim_head_ro (args))) {
			args = "";
		}
	} else {
		args = "";
	}

	if (!r_core_file_open (core, file, R_PERM_R, 0)) {
		eprintf ("Cannot open file (%s)\n", file);
		return -1;
	}
	r_core_file_reopen_debug (core, args);

	if (!(sock = r_socket_new (false))) {
		eprintf ("gdbserver: Could not open socket for listening\n");
		return -1;
	}
	if (!r_socket_listen (sock, port, NULL)) {
		r_socket_free (sock);
		eprintf ("gdbserver: Cannot listen on port: %s\n", port);
		return -1;
	}
	if (!(g = R_NEW0 (libgdbr_t))) {
		r_socket_free (sock);
		eprintf ("gdbserver: Cannot alloc libgdbr instance\n");
		return -1;
	}
	gdbr_init (g, true);
	g->server_debug = debug_msg;
	gdbr_set_architecture (g, r_config_get (core->config, "asm.arch"), r_config_get_i (core->config, "asm.bits"));
	core->gdbserver_up = 1;
	eprintf ("gdbserver started on port: %s, file: %s\n", port, file);

	for (;;) {
		if (!(g->sock = r_socket_accept (sock))) {
			break;
		}
		g->connected = 1;
		ret = gdbr_server_serve (g, r_core_rtr_gdb_cb, (void*) core);
		r_socket_close (g->sock);
		g->connected = 0;
		if (ret < 0) {
			break;
		}
	}
	core->gdbserver_up = 0;
	gdbr_cleanup (g);
	free (g);
	r_socket_free (sock);
	return 0;
}

R_API int r_core_rtr_gdb(RCore *core, int launch, const char *path) {
	int ret;
	if (r_sandbox_enable (0)) {
		eprintf ("sandbox: connect disabled\n");
		return -1;
	}
	// TODO: do stuff with launch
	if (core->gdbserver_up) {
		eprintf ("gdbserver is already running\n");
		return -1;
	}
	ret = r_core_rtr_gdb_run (core, launch, path);
	return ret;
}

R_API void r_core_rtr_pushout(RCore *core, const char *input) {
	int fd = atoi (input);
	const char *cmd = NULL;
	char *str = NULL;
	if (fd) {
		for (rtr_n = 0; rtr_host[rtr_n].fd && rtr_n < RTR_MAX_HOSTS - 1; rtr_n++) {
			if (rtr_host[rtr_n].fd->fd != fd) {
				continue;
			}
		}
		if (!(cmd = strchr (input, ' '))) {
			eprintf ("Error\n");
			return;
		}
	} else {
		cmd = input;
	}

	if (!rtr_host[rtr_n].fd || !rtr_host[rtr_n].fd->fd) {
		eprintf ("Error: Unknown host\n");
		return;
	}

	if (!(str = r_core_cmd_str (core, cmd))) {
		eprintf ("Error: radare_cmd_str returned NULL\n");
		return;
	}

	switch (rtr_host[rtr_n].proto) {
	case RTR_PROTOCOL_RAP:
		eprintf ("Error: Cannot use '=<' to a rap connection.\n");
		break;
	case RTR_PROTOCOL_UNIX:
		r_socket_write (rtr_host[rtr_n].fd, str, strlen (str));
		break;
	case RTR_PROTOCOL_HTTP:
		eprintf ("TODO\n");
		break;
	case RTR_PROTOCOL_TCP:
	case RTR_PROTOCOL_UDP:
		r_socket_write (rtr_host[rtr_n].fd, str, strlen (str));
		break;
	default:
		eprintf ("Unknown protocol\n");
		break;
	}
	free (str);
}

R_API void r_core_rtr_list(RCore *core) {
	int i;
	for (i = 0; i < RTR_MAX_HOSTS; i++) {
		if (!rtr_host[i].fd) {
			continue;
		}
		const char *proto = "rap";
		switch (rtr_host[i].proto) {
		case RTR_PROTOCOL_HTTP: proto = "http"; break;
		case RTR_PROTOCOL_TCP: proto = "tcp"; break;
		case RTR_PROTOCOL_UDP: proto = "udp"; break;
		case RTR_PROTOCOL_RAP: proto = "r2p"; break;
		case RTR_PROTOCOL_UNIX: proto = "unix"; break;
		}
		r_cons_printf ("%d fd:%i %s://%s:%i/%s\n", 
			i, rtr_host[i].fd->fd, proto, rtr_host[i].host,
			rtr_host[i].port, rtr_host[i].file);
	}
}

R_API void r_core_rtr_add(RCore *core, const char *_input) {
	char *port, input[1024], *file = NULL, *ptr = NULL, buf[1024];
	int i, timeout, ret;
	RSocket *fd;

	timeout = r_config_get_i (core->config, "http.timeout");
	strncpy (input, _input, sizeof (input) - 4);
	input[sizeof (input) - 4] = '\0';

	int proto = RTR_PROTOCOL_RAP;
	char *host = (char *)r_str_trim_head_ro (input);
	char *pikaboo = strstr (host, "://");
	if (pikaboo) {
		struct {
			const char *name;
			int protocol;
		} uris[7] = {
			{"tcp", RTR_PROTOCOL_TCP},
			{"udp", RTR_PROTOCOL_UDP},
			{"rap", RTR_PROTOCOL_RAP},
			{"r2p", RTR_PROTOCOL_RAP},
			{"http", RTR_PROTOCOL_HTTP},
			{"unix", RTR_PROTOCOL_UNIX},
			{NULL, 0}
		};
		char *s = r_str_ndup (input, pikaboo - input);
		//int nlen = pikaboo - input;
		for (i = 0; uris[i].name; i++) {
			if (r_str_endswith (s, uris[i].name)) {
				proto = uris[i].protocol;
				host = pikaboo + 3;
				break;
			}
		}
		free (s);
	}
	if (host) {
		if (!(ptr = strchr (host, ':'))) {
			ptr = host;
			port = "80";
		} else {
			*ptr++ = '\0';
			port = ptr;
		}
	} else {
		port = NULL;
	}
	file = strchr (ptr, '/');
	if (file) {	
		*file = 0;
		file = (char *)r_str_trim_head_ro (file + 1);
	} else {
		if (*host == ':' || strstr (host, "://:")) { // listen
			// it's fine to listen without serving a file
		} else {
			file = "cmd/";
			eprintf ("Error: Missing '/'\n");
			//c:wreturn;
		}
	}

	r_str_trim (port);
	if (r_sandbox_enable (0)) {
		eprintf ("sandbox: connect disabled\n");
		return;
	}

	fd = r_socket_new (false);
	if (!fd) {
		eprintf ("Error: Cannot create new socket\n");
		return;
	}
	switch (proto) {
	case RTR_PROTOCOL_HTTP:
		{
			int len;
			char *uri = r_str_newf ("http://%s:%s/%s", host, port, file);
			char *str = r_socket_http_get (uri, NULL, &len);
			if (!str) {
				eprintf ("Cannot find peer\n");
				return;
			}
			core->num->value = 0;
			eprintf ("Connected to: 'http://%s'\n", host);
		}
		break;
	case RTR_PROTOCOL_RAP:
		if (!r_socket_connect_tcp (fd, host, port, timeout)) { //TODO: Use rap.ssl
			eprintf ("Error: Cannot connect to '%s' (%s)\n", host, port);
			r_socket_free (fd);
			return;
		}
		eprintf ("Connected to %s at port %s\n", host, port);
		/* send */
		buf[0] = RTR_RAP_OPEN;
		buf[1] = 0;
		buf[2] = (ut8)(strlen (file) + 1);
		memcpy (buf + 3, file, buf[2]);
		r_socket_write (fd, buf, 3 + buf[2]);
		/* read */
		eprintf ("waiting... ");
		fflush (stdout);
		r_socket_read (fd, (ut8*)buf, 5);
		i = r_read_at_be32 (buf, 1);
		if (buf[0] != (char)(RTR_RAP_OPEN | RTR_RAP_REPLY) || i <= 0) {
			eprintf ("Error: Wrong reply\n");
			r_socket_free (fd);
			return;
		}
		eprintf ("ok\n");
		break;
	case RTR_PROTOCOL_UNIX:
		if (!r_socket_connect_unix (fd, host)) {
			core->num->value = 1;
			eprintf ("Error: Cannot connect to 'unix://%s'\n", host);
			r_socket_free (fd);
			return;
		}
		core->num->value = 0;
		eprintf ("Connected to: 'unix://%s'\n", host);
		break;
	case RTR_PROTOCOL_TCP:
		if (!r_socket_connect_tcp (fd, host, port, timeout)) { //TODO: Use rap.ssl
			core->num->value = 1;
			eprintf ("Error: Cannot connect to '%s' (%s)\n", host, port);
			r_socket_free (fd);
			return;
		}
		core->num->value = 0;
		eprintf ("Connected to: %s at port %s\n", host, port);
		break;
	case RTR_PROTOCOL_UDP:
		if (!r_socket_connect_udp (fd, host, port, timeout)) { //TODO: Use rap.ssl
			core->num->value = 1;
			eprintf ("Error: Cannot connect to '%s' (%s)\n", host, port);
			r_socket_free (fd);
			return;
		}
		core->num->value = 0;
		eprintf ("Connected to: %s at port %s\n", host, port);
		break;
	}
	ret = core->num->value;
	for (i = 0; i < RTR_MAX_HOSTS; i++) {
		if (rtr_host[i].fd) {
			continue;
		}
		rtr_host[i].proto = proto;
		strncpy (rtr_host[i].host, host, sizeof (rtr_host[i].host)-1);
		rtr_host[i].port = r_num_get (core->num, port);
		if (!file) {
			file = "";
		}
		strncpy (rtr_host[i].file, file, sizeof (rtr_host[i].file)-1);
		rtr_host[i].fd = fd;
		rtr_n = i;
		break;
	}
	core->num->value = ret;
	// double free wtf is freed this here? r_socket_free(fd);
	//r_core_rtr_list (core);
}

R_API void r_core_rtr_remove(RCore *core, const char *input) {
	int i;

	if (IS_DIGIT (input[0])) {
		i = r_num_math (core->num, input);
		if (i >= 0 && i < RTR_MAX_HOSTS) {
			r_socket_free (rtr_host[i].fd);
			rtr_host[i].fd = NULL;
		}
	} else {
		for (i = 0; i < RTR_MAX_HOSTS; i++) {
			if (rtr_host[i].fd) {
				r_socket_free (rtr_host[i].fd);
				rtr_host[i].fd = NULL;
			}
		}
		memset (rtr_host, '\0', RTR_MAX_HOSTS * sizeof (RCoreRtrHost));
		rtr_n = 0;
	}
}

R_API void r_core_rtr_session(RCore *core, const char *input) {
	__rtr_shell (core, atoi (input));
	return;

	char prompt[64], buf[1024];
	int fd;

	prompt[0] = 0;
	if (IS_DIGIT (input[0])) {
		fd = r_num_math (core->num, input);
		for (rtr_n = 0; rtr_host[rtr_n].fd && rtr_host[rtr_n].fd->fd != fd && rtr_n < RTR_MAX_HOSTS - 1; rtr_n++) {
			;
		}
	}

	while (!r_cons_is_breaked ()) {
		if (rtr_host[rtr_n].fd) {
			snprintf (prompt, sizeof (prompt),
				"fd:%d> ", (int)(size_t)rtr_host[rtr_n].fd->fd);
		}
		free (r_line_singleton ()->prompt);
		r_line_singleton ()->prompt = strdup (prompt);
		if (r_cons_fgets (buf, sizeof (buf), 0, NULL) < 1) {
			break;
		}
		if (!*buf || *buf == 'q') {
			break;
		}
		if (*buf == 'V') {
			eprintf ("Visual mode not supported\n");
			continue;
		}
		r_core_rtr_cmd (core, buf);
		r_cons_flush ();
	}
}

static ut8 *r_rap_packet(ut8 type, ut32 len) {
	ut8 *buf = malloc (len + 5);
	if (buf) {
		buf[0] = type;
		r_write_be32 (buf + 1, len);
	}
	return buf;
}

static void r_rap_packet_fill(ut8 *buf, const ut8* src, int len) {
	if (buf && src && len > 0) {
		ut32 curlen = r_read_be32 (buf + 1);
		memcpy (buf + 5, src, R_MIN (curlen, len));
	}
}

static bool r_core_rtr_rap_run(RCore *core, const char *input) {
	char *file = r_str_newf ("rap://%s", input);
	int flags = R_PERM_RW;
	RIODesc *fd = r_io_open_nomap (core->io, file, flags, 0644);
	if (fd) {
		if (r_io_is_listener (core->io)) {
			if (!r_core_serve (core, fd)) {
				r_cons_singleton ()->context->breaked = true;
			}
			r_io_desc_close (fd);
			// avoid double free, we are not the owners of this fd so we can't destroy it
			//r_io_desc_free (fd);
		}
	} else {
		r_cons_singleton ()->context->breaked = true;
	}
	return !r_cons_singleton ()->context->breaked;
	// r_core_cmdf (core, "o rap://%s", input);
}

static RThreadFunctionRet r_core_rtr_rap_thread (RThread *th) {
	if (!th) {
		return false;
	}
	RapThread *rt = th->user;
	if (!rt || !rt->core) {
		return false;
	}
	return r_core_rtr_rap_run (rt->core, rt->input) ? R_TH_REPEAT : R_TH_STOP;
}

R_API void r_core_rtr_cmd(RCore *core, const char *input) {
	char bufw[1024], bufr[8], *cmd_output = NULL;
	//const char *cmd = NULL;
	unsigned int cmd_len = 0;
	int i, fd = atoi (input);
	if (!fd && *input != '0') {
		fd = -1;
	}
	const char *cmd = strchr (r_str_trim_head_ro (input), ' ');
	if (cmd) {
		cmd ++;
		cmd_len = strlen (cmd);
	}
	// "=:"
	if (*input == ':' && !strchr (input + 1, ':')) {
		void *bed = r_cons_sleep_begin ();
		r_core_rtr_rap_run (core, input);
		r_cons_sleep_end (bed);
		return;
	}

	if (*input == '&') { // "=h&" "=&:9090"
		if (rapthread) {
			eprintf ("RAP Thread is already running\n");
			eprintf ("This is experimental and probably buggy. Use at your own risk\n");
		} else {
			// TODO: use tasks
			RapThread *RT = R_NEW0 (RapThread);
			if (RT) {
				RT->core = core;
				RT->input = strdup (input + 1);
				//RapThread rt = { core, strdup (input + 1) };
				rapthread = r_th_new (r_core_rtr_rap_thread, RT, false);
				int cpuaff = (int)r_config_get_i (core->config, "cfg.cpuaffinity");
				r_th_setaffinity (rapthread, cpuaff);
				r_th_setname (rapthread, "rapthread");
				r_th_start (rapthread, true);
				eprintf ("Background rap server started.\n");
			}
		}
		return;
	}

	if (fd != -1) {
		if (fd >= 0 && fd < RTR_MAX_HOSTS) {
			rtr_n = fd;
		} else {
			fd = -1;
		}
	} else {
		// XXX
		cmd = input;
	}

	if (!rtr_host[rtr_n].fd){
		eprintf ("Error: Unknown host\n");
		core->num->value = 1; // fail
		return;
	}

	if (rtr_host[rtr_n].proto == RTR_PROTOCOL_TCP) {
		RCoreRtrHost *rh = &rtr_host[rtr_n];
		RSocket *s = rh->fd;
		if (cmd_len < 1 || cmd_len > 16384) {
			return;
		}
		r_socket_close (s);
		if (!r_socket_connect (s, rh->host, sdb_fmt ("%d", rh->port), R_SOCKET_PROTO_TCP, 0)) {
			eprintf ("Error: Cannot connect to '%s' (%d)\n", rh->host, rh->port);
			r_socket_free (s);
			return;
		}
		r_socket_write (s, (ut8*)cmd, cmd_len);
		r_socket_write (s, "\n", 2);
		int maxlen = 4096; // r_read_le32 (blen);
		cmd_output = calloc (1, maxlen + 1);
		if (!cmd_output) {
			eprintf ("Error: Allocating cmd output\n");
			return;
		}
		(void)r_socket_read_block (s, (ut8*)cmd_output, maxlen);
		//ensure the termination
		r_socket_close (s);
		cmd_output[maxlen] = 0;
		r_cons_println (cmd_output);
		free ((void *)cmd_output);
		return;
	}

	if (rtr_host[rtr_n].proto == RTR_PROTOCOL_HTTP) {
		RCoreRtrHost *rh = &rtr_host[rtr_n];
		if (cmd_len < 1 || cmd_len > 16384) {
			return;
		}
		int len;
		char *uri = r_str_newf ("http://%s:%d/cmd/%s", rh->host, rh->port, cmd);
		char *str = r_socket_http_get (uri, NULL, &len);
		if (!str) {
			eprintf ("Cannot find '%s'\n", uri);
			return;
		}
		core->num->value = 0;
		str[len] = 0;
		r_cons_println (str);
		free ((void *)str);
		free ((void *)uri);
		return;
	}

	if (rtr_host[rtr_n].proto != RTR_PROTOCOL_RAP) {
		eprintf ("Error: Not a rap:// host\n");
		return;
	}

	core->num->value = 0; // that's fine
	cmd = r_str_trim_head_ro (cmd);
	RSocket *fh = rtr_host[rtr_n].fd;
	if (!strlen (cmd)) {
		// just check if we can connect
		r_socket_close (fh);
		return;
	}
	/* send request */
	bufw[0] = RAP_RMT_CMD;
	i = strlen (cmd) + 1;
	r_write_be32 (bufw + 1, i);
	memcpy (bufw + 5, cmd, i);
	r_socket_write (fh, bufw, 5 + i);
	/* read response */
	r_socket_read (fh, (ut8*)bufr, 5);
	if (bufr[0] == (char)(RAP_RMT_CMD)) {
		cmd_len = r_read_at_be32 (bufr, 1);
		char *rcmd = calloc (1, cmd_len + 1);
		if (rcmd) {
			r_socket_read (fh, (ut8*)rcmd, cmd_len);
			char *res = r_core_cmd_str (core, rcmd);
			if (res) {
				int res_len = strlen (res) + 1;
				ut8 *pkt = r_rap_packet ((RAP_RMT_CMD | RAP_RMT_REPLY), res_len);
				r_rap_packet_fill (pkt, (const ut8*)res, res_len);
				r_socket_write (fh, pkt, 5 + res_len);
				free (res);
				free (pkt);
			}
			free (rcmd);
		}
		/* read response */
		r_socket_read (fh, (ut8*)bufr, 5);
	}

	if (bufr[0] != (char)(RAP_RMT_CMD | RTR_RAP_REPLY)) {
		eprintf ("Error: Wrong reply\n");
		return;
	}
	cmd_len = r_read_at_be32 (bufr, 1);
	if (cmd_len < 1 || cmd_len > 16384) {
		eprintf ("Error: cmd_len is wrong\n");
		return;
	}
	cmd_output = calloc (1, cmd_len + 1);
	if (!cmd_output) {
		eprintf ("Error: Allocating cmd output\n");
		return;
	}
	r_socket_read_block (fh, (ut8*)cmd_output, cmd_len);
	//ensure the termination
	cmd_output[cmd_len] = 0;
	r_cons_println (cmd_output);
	free ((void *)cmd_output);
}

// TODO: support len for binary data?
R_API char *r_core_rtr_cmds_query (RCore *core, const char *host, const char *port, const char *cmd) {
	RSocket *s = r_socket_new (0);
	const int timeout = 0;
	char *rbuf = NULL;
	int retries = 6;
	ut8 buf[1024];

	for (; retries > 0; r_sys_usleep (10 * 1000)) {
		if (r_socket_connect (s, host, port, R_SOCKET_PROTO_TCP, timeout)) {
			break;
		}
		retries--;
	}
	if (retries > 0) {
		rbuf = strdup ("");
		r_socket_write (s, (void*)cmd, strlen (cmd));
		//r_socket_write (s, "px\n", 3);
		for (;;) {
			int ret = r_socket_read (s, buf, sizeof (buf));
			if (ret < 1) {
				break;
			}
			buf[ret] = 0;
			rbuf = r_str_append (rbuf, (const char *)buf);
		}
	} else {
		eprintf ("Cannot connect\n");
	}
	r_socket_free (s);
	return rbuf;
}

#if HAVE_LIBUV

typedef struct rtr_cmds_context_t {
	uv_tcp_t server;
	RPVector clients;
	void *bed;
} rtr_cmds_context;

typedef struct rtr_cmds_client_context_t {
	RCore *core;
	char buf[4096];
	char *res;
	size_t len;
	uv_tcp_t *client;
} rtr_cmds_client_context;

static void rtr_cmds_client_close(uv_tcp_t *client, bool remove) {
	uv_loop_t *loop = client->loop;
	rtr_cmds_context *context = loop->data;
	if (remove) {
		size_t i;
		for (i = 0; i < r_pvector_len (&context->clients); i++) {
			if (r_pvector_at (&context->clients, i) == client) {
				r_pvector_remove_at (&context->clients, i);
				break;
			}
		}
	}
	rtr_cmds_client_context *client_context = client->data;
	uv_close ((uv_handle_t *) client, (uv_close_cb) free);
	free (client_context->res);
	free (client_context);
}

static void rtr_cmds_alloc_buffer(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
	rtr_cmds_client_context *context = handle->data;
	buf->base = context->buf + context->len;
	buf->len = sizeof (context->buf) - context->len - 1;
}

static void rtr_cmds_write(uv_write_t *req, int status) {
	rtr_cmds_client_context *context = req->data;

	if (status) {
		eprintf ("Write error: %s\n", uv_strerror (status));
	}

	free (req);
	rtr_cmds_client_close (context->client, true);
}

static void rtr_cmds_read(uv_stream_t *client, ssize_t nread, const uv_buf_t *buf) {
	rtr_cmds_context *context = client->loop->data;
	rtr_cmds_client_context *client_context = client->data;

	if (nread < 0) {
		if (nread != UV_EOF) {
			eprintf ("Failed to read: %s\n", uv_err_name ((int) nread));
		}
		rtr_cmds_client_close ((uv_tcp_t *) client, true);
		return;
	} else if (nread == 0) {
		return;
	}

	buf->base[nread] = '\0';
	char *end = strchr (buf->base, '\n');
	if (!end) {
		return;
	}
	*end = '\0';

	r_cons_sleep_end (context->bed);
	client_context->res = r_core_cmd_str (client_context->core, (const char *)client_context->buf);
	context->bed = r_cons_sleep_begin ();

	if (!client_context->res || !*client_context->res) {
		free (client_context->res);
		client_context->res = strdup ("\n");
	}

	if (!client_context->res || (!r_config_get_i (client_context->core->config, "scr.prompt") &&
				 !strcmp ((char *)buf, "q!")) ||
				 !strcmp ((char *)buf, ".--")) {
		rtr_cmds_client_close ((uv_tcp_t *) client, true);
		return;
	}

	uv_write_t *req = R_NEW (uv_write_t);
	if (req) {
		req->data = client_context;
		uv_buf_t wrbuf = uv_buf_init (client_context->res, (unsigned int) strlen (client_context->res));
		uv_write (req, client, &wrbuf, 1, rtr_cmds_write);
	}
	uv_read_stop (client);
}

static void rtr_cmds_new_connection(uv_stream_t *server, int status) {
	if (status < 0) {
		eprintf ("New connection error: %s\n", uv_strerror (status));
		return;
	}

	rtr_cmds_context *context = server->loop->data;

	uv_tcp_t *client = R_NEW (uv_tcp_t);
	if (!client) {
		return;
	}

	uv_tcp_init (server->loop, client);
	if (uv_accept (server, (uv_stream_t *)client) == 0) {
		rtr_cmds_client_context *client_context = R_NEW (rtr_cmds_client_context);
		if (!client_context) {
			uv_close ((uv_handle_t *)client, NULL);
			return;
		}

		client_context->core = server->data;
		client_context->len = 0;
		client_context->buf[0] = '\0';
		client_context->res = NULL;
		client_context->client = client;
		client->data = client_context;

		uv_read_start ((uv_stream_t *)client, rtr_cmds_alloc_buffer, rtr_cmds_read);

		r_pvector_push (&context->clients, client);
	} else {
		uv_close ((uv_handle_t *)client, NULL);
	}
}

static void rtr_cmds_stop(uv_async_t *handle) {
	uv_close ((uv_handle_t *) handle, NULL);

	rtr_cmds_context *context = handle->loop->data;

	uv_close ((uv_handle_t *) &context->server, NULL);

	void **it;
	r_pvector_foreach (&context->clients, it) {
		uv_tcp_t *client = *it;
		rtr_cmds_client_close (client, false);
	}
}

static void rtr_cmds_break(uv_async_t *async) {
	uv_async_send (async);
}

R_API int r_core_rtr_cmds(RCore *core, const char *port) {
	if (!port || port[0] == '?') {
		r_cons_printf ("Usage: .:[tcp-port]    run r2 commands for clients\n");
		return 0;
	}

	uv_loop_t *loop = R_NEW (uv_loop_t);
	if (!loop) {
		return 0;
	}
	uv_loop_init (loop);

	rtr_cmds_context context;
	r_pvector_init (&context.clients, NULL);
	loop->data = &context;

	context.server.data = core;
	uv_tcp_init (loop, &context.server);

	struct sockaddr_in addr;
	bool local = (bool) r_config_get_i(core->config, "tcp.islocal");
	int porti = r_socket_port_by_name (port);
	uv_ip4_addr (local ? "127.0.0.1" : "0.0.0.0", porti, &addr);

	uv_tcp_bind (&context.server, (const struct sockaddr *) &addr, 0);
	int r = uv_listen ((uv_stream_t *)&context.server, 32, rtr_cmds_new_connection);
	if (r) {
		eprintf ("Failed to listen: %s\n", uv_strerror (r));
		goto beach;
	}

	uv_async_t stop_async;
	uv_async_init (loop, &stop_async, rtr_cmds_stop);

	r_cons_break_push ((RConsBreak) rtr_cmds_break, &stop_async);
	context.bed = r_cons_sleep_begin ();
	uv_run (loop, UV_RUN_DEFAULT);
	r_cons_sleep_end (context.bed);
	r_cons_break_pop ();

beach:
	uv_loop_close (loop);
	free (loop);
	r_pvector_clear (&context.clients);
	return 0;
}

#else

R_API int r_core_rtr_cmds (RCore *core, const char *port) {
	unsigned char buf[4097];
	RSocket *ch = NULL;
	int i, ret;
	char *str;

	if (!port || port[0] == '?') {
		r_cons_printf ("Usage: .:[tcp-port]    run r2 commands for clients\n");
		return false;
	}

	RSocket *s = r_socket_new (0);
	s->local = r_config_get_i (core->config, "tcp.islocal");

	if (!r_socket_listen (s, port, NULL)) {
		eprintf ("Error listening on port %s\n", port);
		r_socket_free (s);
		return false;
	}

	eprintf ("Listening for commands on port %s\n", port);
	listenport = port;
	r_cons_break_push ((RConsBreak)r_core_rtr_http_stop, core);
	for (;;) {
		if (r_cons_is_breaked ()) {
			break;
		}
		void *bed = r_cons_sleep_begin ();
		ch = r_socket_accept (s);
		buf[0] = 0;
		ret = r_socket_read (ch, buf, sizeof (buf) - 1);
		r_cons_sleep_end (bed);
		if (ret > 0) {
			buf[ret] = 0;
			for (i = 0; buf[i]; i++) {
				if (buf[i] == '\n') {
					buf[i] = buf[i + 1]? ';': '\0';
				}
			}
			if ((!r_config_get_i (core->config, "scr.prompt") &&
			     !strcmp ((char *)buf, "q!")) ||
			    !strcmp ((char *)buf, ".--")) {
				r_socket_close (ch);
				break;
			}
			str = r_core_cmd_str (core, (const char *)buf);
			bed = r_cons_sleep_begin ();
			if (str && *str)  {
				r_socket_write (ch, str, strlen (str));
			} else {
				r_socket_write (ch, "\n", 1);
			}
			r_cons_sleep_end (bed);
			free (str);
		}
		r_socket_close (ch);
		r_socket_free (ch);
		ch = NULL;
	}
	r_cons_break_pop ();
	r_socket_free (s);
	r_socket_free (ch);
	return 0;
}

#endif
