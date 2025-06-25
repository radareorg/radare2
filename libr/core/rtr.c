/* radare - Copyright 2009-2025 - pancake, nibble */

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

static R_TH_LOCAL RSocket *s = NULL;
static R_TH_LOCAL RThread *httpthread = NULL;
static R_TH_LOCAL RThread *rapthread = NULL;
static R_TH_LOCAL const char *listenport = NULL;

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
	// we need a global console break
	// r_cons_context_break (core->cons->context);
	// core->cons->context->breaked = true;
#if R2__UNIX__
	if (core->http_up) {
		r_core_rtr_http_stop (core);
	}
#endif
	r_th_kill (httpthread, true);
	r_th_kill (rapthread, true);
	r_th_wait (httpthread);
	r_th_wait (rapthread);
}

static void http_logf(RCore *core, const char *fmt, ...) {
	bool http_log_enabled = r_config_get_b (core->config, "http.log");
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

static char *rtrcmd(TextLog T, const char *str) {
	char *res, *ptr2;
	char *ptr = r_str_uri_encode (str);
	char *uri = r_str_newf ("http://%s:%s/%s%s", T.host, T.port, T.file, ptr? ptr: str);
	int len;
	free (ptr);
	ptr2 = r_socket_http_get (uri, NULL, NULL, &len);
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
	RCons *cons = core->cons;
	if (core->vmode) {
		r_kons_show_cursor (cons, x);
		r_kons_enable_mouse (cons, x? r_config_get_b (core->config, "scr.wheel"): false);
	} else {
		r_kons_enable_mouse (cons, false);
	}
	r_cons_flush (cons);
}

// TODO: rename /name to /nick or /so?
// clone of textlog_chat () using rtrcmd()
static void rtr_textlog_chat(RCore *core, TextLog T) {
	char prompt[64];
	char buf[1024];
	int lastmsg = 0;
	const char *me = r_config_get (core->config, "cfg.user");
	char *ret, msg[1024] = {0};

	R_LOG_INFO ("Type '/help' for commands and ^D to quit:");
	char *oldprompt = strdup (core->cons->line->prompt);
	snprintf (prompt, sizeof (prompt) - 1, "[%s]> ", me);
	r_line_set_prompt (core->cons->line, prompt);
	ret = rtrcmd (T, msg);
	for (;;) {
		if (lastmsg >= 0) {
			snprintf (msg, sizeof (msg) - 1, "T %d", lastmsg);
		} else {
			strcpy (msg, "T");
		}
		ret = rtrcmd (T, msg);
		r_cons_println (core->cons, ret);
		free (ret);
		ret = rtrcmd (T, "Tl");
		lastmsg = atoi (ret)-1;
		free (ret);
		if (r_cons_fgets (core->cons, buf, sizeof (buf), 0, NULL) < 0) {
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
			char *m = r_str_newf ("* '%s' is now known as '%s'", me, buf+6);
			r_cons_println (core->cons, m);
			r_core_log_add (core, m);
			r_config_set (core->config, "cfg.user", buf+6);
			me = r_config_get (core->config, "cfg.user");
			snprintf (prompt, sizeof (prompt) - 1, "[%s]> ", me);
			r_line_set_prompt (core->cons->line, prompt);
			free (m);
		} else if (!strcmp (buf, "/log")) {
			char *ret = rtrcmd (T, "T");
			if (ret) {
				r_cons_println (core->cons, ret);
				free (ret);
			}
		} else if (!strcmp (buf, "/clear")) {
			//r_core_log_del (core, 0);
			free (rtrcmd (T, "T-"));
		} else if (!strcmp (buf, "/quit")) {
			goto beach;
		} else if (*buf == '/') {
			R_LOG_ERROR ("Unknown command: %s", buf);
		} else {
			char *cmd = r_str_newf ("T [%s] %s", me, buf);
			free (rtrcmd (T, cmd));
			free (cmd);
		}
	}
beach:
	r_line_set_prompt (core->cons->line, oldprompt);
	free (oldprompt);
}

R_API int r_core_rtr_http_stop(RCore *u) {
	RCore *core = (RCore*)u;
	const int timeout = 1; // 1 second

#if R2__WINDOWS__
	r_socket_http_server_set_breaked (&core->cons->context->breaked);
#endif
	core->http_up = false;
	if (((size_t)u) > 0xff) {
		char *port = strdup (listenport? listenport: r_config_get (core->config, "http.port"));
		char *sport = r_str_startswith (port, "0x")
			? r_str_newf ("%d", (int)r_num_get (NULL, port))
			: strdup (port);
		RSocket* sock = r_socket_new (0);
		(void)r_socket_connect (sock, "127.0.0.1", sport, R_SOCKET_PROTO_TCP, timeout);
		free (sport);
		r_socket_free (sock);
		free (port);
	}
	r_socket_free (s);
	s = NULL;
	return 0;
}

static char *rtr_dir_files(const char *path) {
	char *ptr = strdup ("<html><body>\n");
	const char *file;
	RListIter *iter;
	// list files
	RList *files = r_sys_dir (path);
	R_LOG_INFO ("Listing directory %s", path);
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

#if R2__UNIX__ && !__wasi__
static void dietime(int sig) {
	eprintf ("It's Time To Die!\n");
	exit (0);
}
#endif

static void activateDieTime(RCore *core) {
	int dt = r_config_get_i (core->config, "http.dietime");
	if (dt > 0) {
#if R2__UNIX__ && !__wasi__
		r_sys_signal (SIGALRM, dietime);
		alarm (dt);
#else
		R_LOG_ERROR ("http.dietime only works on *nix systems");
#endif
	}
}

static const char *rtr_proto_tostring(int proto) {
	switch (proto) {
	case RTR_PROTOCOL_HTTP: return "http"; break;
	case RTR_PROTOCOL_TCP: return "tcp"; break;
	case RTR_PROTOCOL_UDP: return "udp"; break;
	case RTR_PROTOCOL_RAP: return "rap"; break;
	case RTR_PROTOCOL_UNIX: return "unix"; break;
	default: return NULL;
	}
}

#include "rtr_http.inc.c"
#include "rtr_shell.inc.c"

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
			R_LOG_ERROR ("Unsupported reg size: %d", regsize);
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
		R_LOG_ERROR ("big registers (%d byte(s)) not yet supported", regsize);
		return -1;
	}
}

static int swap_big_regs(char *dest, ut64 sz, const char *src, int regsz) {
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
		R_LOG_ERROR ("big registers (%d byte(s)) not yet supported", regsz);
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
	if (!core_ptr || !cmd) {
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
					{
						RDebugPlugin *plugin = R_UNWRAP3 (core->dbg, current, plugin);
						if (!plugin || !plugin->threads) {
							return -1;
						}
						if (!(list = plugin->threads (core->dbg, core->dbg->pid))) {
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
			be = r_config_get_b (core->config, "cfg.bigendian");
			if (isspace ((ut8)cmd[2])) { // dr reg
				const char *name, *val_ptr;
				char new_cmd[128] = {0};
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
			RIODesc *desc = core->io->desc;
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
	char port[10];
	char *file = NULL, *args = NULL;
	libgdbr_t *g;

	if (!core || !path) {
		return -1;
	}
	if (!(path = r_str_trim_head_ro (path)) || !*path) {
		R_LOG_ERROR ("gdbserver: Port not specified");
		return -1;
	}
	if (!(p = atoi (path)) || p < 0 || p > 65535) {
		R_LOG_ERROR ("gdbserver: Invalid port: %d", p);
		return -1;
	}
	snprintf (port, sizeof (port) - 1, "%d", p);
	if (!(file = strchr (path, ' '))) {
		R_LOG_ERROR ("gdbserver: File not specified");
		return -1;
	}
	if (!(file = (char *)r_str_trim_head_ro (file)) || !*file) {
		R_LOG_ERROR ("gdbserver: File not specified");
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

	if (!r_core_file_open (core, file, R_PERM_RX, 0)) {
		R_LOG_ERROR ("Cannot open file (%s)", file);
		return -1;
	}
	r_core_file_reopen_debug (core, args);

	if (!(sock = r_socket_new (false))) {
		R_LOG_ERROR ("gdbserver: Could not open socket for listening");
		return -1;
	}
	if (!r_socket_listen (sock, port, NULL)) {
		r_socket_free (sock);
		R_LOG_ERROR ("gdbserver: Cannot listen on port: %s", port);
		return -1;
	}
	if (!(g = R_NEW0 (libgdbr_t))) {
		r_socket_free (sock);
		R_LOG_ERROR ("gdbserver: Cannot alloc libgdbr instance");
		return -1;
	}
	gdbr_init (g, true);
	int arch = r_sys_arch_id (r_config_get (core->config, "asm.arch"));
	int bits = r_config_get_i (core->config, "asm.bits");
	gdbr_set_architecture (g, arch, bits);
	core->gdbserver_up = 1;
	R_LOG_INFO ("gdbserver started on port: %s, file: %s", port, file);

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
		R_LOG_ERROR ("connect disable the sandbox");
		return -1;
	}
	// TODO: do stuff with launch
	if (core->gdbserver_up) {
		R_LOG_INFO ("the gdbserver is already running");
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
			R_LOG_ERROR ("Missing space");
			return;
		}
	} else {
		cmd = input;
	}

	if (!rtr_host[rtr_n].fd || !rtr_host[rtr_n].fd->fd) {
		R_LOG_ERROR ("Unknown host");
		return;
	}

	if (!(str = r_core_cmd_str (core, cmd))) {
		R_LOG_ERROR ("radare_cmd_str returned NULL");
		return;
	}

	switch (rtr_host[rtr_n].proto) {
	case RTR_PROTOCOL_RAP:
		R_LOG_ERROR ("Cannot use '=<' to a rap connection");
		break;
	case RTR_PROTOCOL_UNIX:
		r_socket_write (rtr_host[rtr_n].fd, str, strlen (str));
		break;
	case RTR_PROTOCOL_HTTP:
		R_LOG_TODO ("RTR_PROTOCOL_HTTP");
		break;
	case RTR_PROTOCOL_TCP:
	case RTR_PROTOCOL_UDP:
		r_socket_write (rtr_host[rtr_n].fd, str, strlen (str));
		break;
	default:
		R_LOG_ERROR ("Unknown protocol");
		break;
	}
	free (str);
}

R_API void r_core_rtr_list(RCore *core, int mode) {
	int i;
	PJ *pj = NULL;
	if (mode == 'j') {
		pj = r_core_pj_new (core);
		pj_a (pj);
	}
	for (i = 0; i < RTR_MAX_HOSTS; i++) {
		if (!rtr_host[i].fd) {
			continue;
		}
		const char *proto = rtr_proto_tostring (rtr_host[i].proto);
		if (pj) {
			pj_o (pj);
			pj_ks (pj, "protocol", proto);
			pj_kn (pj, "fd", rtr_host[i].fd->fd);
			pj_ks (pj, "host", rtr_host[i].host);
			pj_kn (pj, "port", rtr_host[i].port);
			pj_ks (pj, "file", rtr_host[i].file);
			pj_end (pj);
		} else if (mode == '*') {
			r_kons_printf (core->cons, "# %d fd:%i %s://%s:%i/%s\n",
				i, rtr_host[i].fd->fd, proto, rtr_host[i].host,
				rtr_host[i].port, rtr_host[i].file);
		} else {
			r_kons_printf (core->cons, "%d fd:%i %s://%s:%i/%s\n",
				i, rtr_host[i].fd->fd, proto, rtr_host[i].host,
				rtr_host[i].port, rtr_host[i].file);
		}
	}
	if (pj) {
		pj_end (pj);
		char *s = pj_drain (pj);
		r_cons_println (core->cons, s);
		free (s);
	}
}

R_API void r_core_rtr_add(RCore *core, const char *_input) {
	char *port, input[1024], *file = NULL, *ptr = NULL;
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
			{ "tcp", RTR_PROTOCOL_TCP},
			{ "udp", RTR_PROTOCOL_UDP},
			{ "rap", RTR_PROTOCOL_RAP},
			{ "r2p", RTR_PROTOCOL_RAP},
			{ "http", RTR_PROTOCOL_HTTP},
			{ "unix", RTR_PROTOCOL_UNIX},
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
			r_str_trim (port);
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
			R_LOG_ERROR ("Missing '/'");
			//c:wreturn;
		}
	}

	if (r_sandbox_enable (0)) {
		R_LOG_ERROR ("sandbox: connect disabled");
		return;
	}

	fd = r_socket_new (false);
	if (!fd) {
		R_LOG_ERROR ("Cannot create new socket");
		return;
	}
	switch (proto) {
	case RTR_PROTOCOL_HTTP:
		{
			int len;
			char *uri = r_str_newf ("http://%s:%s/%s", host, port, file);
			char *str = r_socket_http_get (uri, NULL, NULL, &len);
			if (!str) {
				R_LOG_ERROR ("Cannot find peer");
				r_socket_free (fd);
				return;
			}
			// eprintf ("Connected to: 'http://%s:%s'\n", host, port);
			r_core_return_value (core, R_CMD_RC_SUCCESS);
			free (str);
		}
		break;
	case RTR_PROTOCOL_RAP:
		if (!r_socket_connect_tcp (fd, host, port, timeout)) { //TODO: Use rap.ssl
			R_LOG_ERROR ("Cannot connect to '%s' (%s)", host, port);
			r_socket_free (fd);
			return;
		} else {
			int n = r_socket_rap_client_open (fd, file, 0);
			R_LOG_INFO ("opened as fd = %d", n);
		}
		break;
	case RTR_PROTOCOL_UNIX:
		if (!r_socket_connect_unix (fd, host)) {
			r_core_return_value (core, R_CMD_RC_FAILURE);
			R_LOG_ERROR ("Cannot connect to 'unix://%s'", host);
			r_socket_free (fd);
			return;
		}
		r_core_return_value (core, R_CMD_RC_SUCCESS);
		R_LOG_INFO ("Connected to: 'unix://%s'", host);
		break;
	case RTR_PROTOCOL_TCP:
		if (!r_socket_connect_tcp (fd, host, port, timeout)) { //TODO: Use rap.ssl
			r_core_return_value (core, R_CMD_RC_FAILURE);
			R_LOG_ERROR ("Cannot connect to '%s' (%s)", host, port);
			r_socket_free (fd);
			return;
		}
		r_core_return_value (core, R_CMD_RC_SUCCESS);
		R_LOG_INFO ("Connected to: %s at port %s", host, port);
		break;
	case RTR_PROTOCOL_UDP:
		if (!r_socket_connect_udp (fd, host, port, timeout)) { //TODO: Use rap.ssl
			r_core_return_value (core, R_CMD_RC_FAILURE);
			R_LOG_ERROR ("Cannot connect to '%s' (%s)", host, port);
			r_socket_free (fd);
			return;
		}
		r_core_return_value (core, R_CMD_RC_SUCCESS);
		R_LOG_INFO ("Connected to: %s at port %s", host, port);
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
	r_core_return_value (core, ret);
	// double free wtf is freed this here? r_socket_free (fd);
	//r_core_rtr_list (core);
}

R_API void r_core_rtr_remove(RCore *core, const char *input) {
	int i;

	if (isdigit (input[0])) {
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

static char *errmsg_tmpfile = NULL;
static int errmsg_fd = -1;

R_API void r_core_rtr_event(RCore *core, const char *input) {
	if (*input == '-') {
		input++;
		if (!strcmp (input, "errmsg")) {
			if (errmsg_tmpfile) {
				r_file_rm (errmsg_tmpfile);
				errmsg_tmpfile = NULL;
				if (errmsg_fd != -1) {
					close (errmsg_fd);
				}
			}
		}
		return;
	}
	if (!strcmp (input, "errmsg")) {
		// TODO: support udp, tcp, rap, ...
#if R2__UNIX__ && !__wasi__
		char *f = r_file_temp ("errmsg");
		r_cons_println (core->cons, f);
		r_file_rm (f);
		errmsg_tmpfile = strdup (f);
		int e = mkfifo (f, 0644);
		if (e == -1) {
			r_sys_perror ("mkfifo");
		} else {
			int ff = open (f, O_RDWR);
			if (ff != -1) {
				dup2 (ff, 2);
				errmsg_fd = ff;
			} else {
				R_LOG_ERROR ("Cannot open fifo: %s", f);
			}
		}
		// r_core_event (core, );
		free (s);
		free (f);
		// TODO: those files are leaked when closing r_core_free () should be deleted
#else
		R_LOG_ERROR ("Not supported for your platform");
#endif
	} else {
		R_LOG_INFO ("Input (%s)", input);
		R_LOG_INFO ("Event types: errmsg, stdin, stdout, stderr, #fdn");
	}
}

R_API void r_core_rtr_session(RCore *core, const char *input) {
	__rtr_shell (core, atoi (input));
}

static bool r_core_rtr_rap_run(RCore *core, const char *input) {
	char *file = r_str_newf ("rap://%s", input);
	int flags = R_PERM_RW;
	RIODesc *fd = r_io_open_nomap (core->io, file, flags, 0644);
	RConsContext *c = core->cons->context;
	if (fd) {
		if (r_io_is_listener (core->io)) {
			if (!r_core_serve (core, fd)) {
				c->breaked = true;
			}
			r_io_desc_close (fd);
			// avoid double free, we are not the owners of this fd so we can't destroy it
			//r_io_desc_free (fd);
		}
	} else {
		c->breaked = true;
	}
	return !c->breaked;
}

static RThreadFunctionRet r_core_rtr_rap_thread(RThread *th) {
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
	unsigned int cmd_len = 0;
	int fd = atoi (input);
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
		void *bed = r_cons_sleep_begin (core->cons);
		r_core_rtr_rap_run (core, input);
		r_cons_sleep_end (core->cons, bed);
		return;
	}

	if (*input == '&') { // "=h&" "=&:9090"
		if (rapthread) {
			R_LOG_INFO ("RAP Thread is already running");
			R_LOG_INFO ("This is experimental and probably buggy. Use at your own risk");
		} else {
			// TODO: use tasks
			RapThread *RT = R_NEW0 (RapThread);
			if (RT) {
				RT->core = core;
				RT->input = strdup (input + 1);
				//RapThread rt = { core, strdup (input + 1) };
				rapthread = r_th_new (r_core_rtr_rap_thread, RT, false);
#if 0
				int cpuaff = (int)r_config_get_i (core->config, "cfg.cpuaffinity");
				r_th_setaffinity (rapthread, cpuaff);
#endif
				r_th_setname (rapthread, "rapthread");
				r_th_start (rapthread);
				R_LOG_INFO ("Background rap server started");
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

	if (!rtr_host[rtr_n].fd) {
		R_LOG_ERROR ("Unknown host");
		r_core_return_value (core, R_CMD_RC_FAILURE);
		return;
	}

	if (rtr_host[rtr_n].proto == RTR_PROTOCOL_TCP) {
		RCoreRtrHost *rh = &rtr_host[rtr_n];
		RSocket *s = rh->fd;
		if (cmd_len < 1 || cmd_len > 16384) {
			return;
		}
		r_socket_close (s);
		r_strf_var (portstr, 32, "%d", rh->port);
		if (!r_socket_connect (s, rh->host, portstr, R_SOCKET_PROTO_TCP, 0)) {
			R_LOG_ERROR ("Cannot connect to '%s' (%d)", rh->host, rh->port);
			r_socket_free (s);
			return;
		}
		r_socket_write (s, (ut8*)cmd, cmd_len);
		r_socket_write (s, "\n", 2);
		int maxlen = 4096; // r_read_le32 (blen);
		char *cmd_output = calloc (1, maxlen + 1);
		if (!cmd_output) {
			R_LOG_ERROR ("Allocating cmd output");
			return;
		}
		(void)r_socket_read_block (s, (ut8*)cmd_output, maxlen);
		//ensure the termination
		r_socket_close (s);
		cmd_output[maxlen] = 0;
		r_cons_println (core->cons, cmd_output);
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
		char *str = r_socket_http_get (uri, NULL, NULL, &len);
		if (!str) {
			R_LOG_ERROR ("Cannot find '%s'", uri);
			return;
		}
		r_core_return_value (core, R_CMD_RC_SUCCESS);
		str[len] = 0;
		r_kons_print (core->cons, str);
		free ((void *)str);
		free ((void *)uri);
		return;
	}

	if (rtr_host[rtr_n].proto == RTR_PROTOCOL_RAP) {
		r_core_return_value (core, R_CMD_RC_SUCCESS);
		cmd = r_str_trim_head_ro (cmd);
		RSocket *fh = rtr_host[rtr_n].fd;
		if (!strlen (cmd)) {
			// just check if we can connect
			r_socket_close (fh);
			return;
		}
		char *cmd_output = r_socket_rap_client_command (fh, cmd, &core->anal->coreb);
		r_cons_println (core->cons, cmd_output);
		free (cmd_output);
		return;
	}
	R_LOG_ERROR ("Unknown protocol");
}

// TODO: support len for binary data?
R_API char *r_core_rtr_cmds_query(RCore *core, const char *host, const char *port, const char *cmd) {
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
		R_LOG_ERROR ("Cannot connect");
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
		for (i = 0; i < r_pvector_length (&context->clients); i++) {
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
		R_LOG_ERROR ("Cannot write %s", uv_strerror (status));
	}
	free (req);
	rtr_cmds_client_close (context->client, true);
}

static void rtr_cmds_read(uv_stream_t *client, ssize_t nread, const uv_buf_t *buf) {
	rtr_cmds_context *context = client->loop->data;
	rtr_cmds_client_context *client_context = client->data;

	if (nread < 0) {
		if (nread != UV_EOF) {
			R_LOG_ERROR ("Failed to read: %s", uv_err_name ((int) nread));
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

	r_cons_sleep_end (core->cons, context->bed);
	client_context->res = r_core_cmd_str (client_context->core, (const char *)client_context->buf);
	context->bed = r_cons_sleep_begin (core->cons);

	if (!client_context->res || !*client_context->res) {
		free (client_context->res);
		client_context->res = strdup ("\n");
	}

	if (!client_context->res || (!r_config_get_b (client_context->core->config, "scr.prompt") &&
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
		R_LOG_ERROR ("New connection failed: %s", uv_strerror (status));
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
		r_kons_printf (core->cons, "Usage: .:[tcp-port]    run r2 commands for clients\n");
		return 0;
	}

	uv_loop_t *loop = R_NEW (uv_loop_t);
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
		R_LOG_ERROR ("Failed to listen: %s", uv_strerror (r));
		goto beach;
	}

	uv_async_t stop_async;
	uv_async_init (loop, &stop_async, rtr_cmds_stop);

	r_cons_break_push (core->cons, (RConsBreak) rtr_cmds_break, &stop_async);
	context.bed = r_cons_sleep_begin (core->cons);
	uv_run (loop, UV_RUN_DEFAULT);
	r_cons_sleep_end (core->cons, context.bed);
	r_cons_break_pop (core->cons);

beach:
	uv_loop_close (loop);
	free (loop);
	r_pvector_clear (&context.clients);
	return 0;
}

#else

R_API int r_core_rtr_cmds(RCore *core, const char *port) {
	ut8 buf[4097];
	RSocket *ch = NULL;
	int i, ret;
	char *str;

	if (!port || port[0] == '?') {
		r_kons_printf (core->cons, "Usage: .:[tcp-port]    run r2 commands for clients\n");
		return false;
	}

	RSocket *s = r_socket_new (0);
	s->local = r_config_get_i (core->config, "tcp.islocal");

	if (!r_socket_listen (s, port, NULL)) {
		R_LOG_ERROR ("listening on port %s", port);
		r_socket_free (s);
		return false;
	}

	R_LOG_INFO ("Listening for commands on port %s", port);
	listenport = port;
	r_cons_break_push (core->cons, (RConsBreak)r_core_rtr_http_stop, core);
	for (;;) {
		if (r_cons_is_breaked (core->cons)) {
			break;
		}
		void *bed = r_cons_sleep_begin (core->cons);
		ch = r_socket_accept (s);
		buf[0] = 0;
		ret = r_socket_read (ch, buf, sizeof (buf) - 1);
		r_cons_sleep_end (core->cons, bed);
		if (ret > 0) {
			buf[ret] = 0;
			for (i = 0; buf[i]; i++) {
				if (buf[i] == '\n') {
					buf[i] = buf[i + 1]? ';': '\0';
				}
			}
			if ((!r_config_get_b (core->config, "scr.prompt") && !strcmp ((char *)buf, "q!")) || !strcmp ((char *)buf, ".--")) {
				r_socket_close (ch);
				break;
			}
			str = r_core_cmd_str (core, (const char *)buf);
			bed = r_cons_sleep_begin (core->cons);
			if (str && *str)  {
				r_socket_write (ch, str, strlen (str));
			} else {
				r_socket_write (ch, "\n", 1);
			}
			r_cons_sleep_end (core->cons, bed);
			free (str);
		}
		r_socket_close (ch);
		r_socket_free (ch);
		ch = NULL;
	}
	r_cons_break_pop (core->cons);
	r_socket_free (s);
	r_socket_free (ch);
	return 0;
}

#endif
