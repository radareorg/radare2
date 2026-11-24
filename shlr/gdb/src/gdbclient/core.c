/* libgdbr - LGPL - Copyright 2014-2018 - defragger */

#include "gdbclient/responses.h"
#include "gdbclient/commands.h"
#include "gdbclient/core.h"
#include "gdbclient/xml.h"
#include "arch.h"
#include "libgdbr.h"
#include "gdbr_common.h"
#include "packet.h"
#include <r_util/r_strbuf.h>
#include <r_util/r_log.h>
#include <r_cons.h>
#include <r_debug.h>
#include <r_types_overflow.h>

#if R2__UNIX__
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#ifndef __wasi__
#include <termios.h>
#endif
#endif

#if R2__UNIX__
#include <signal.h>
#endif

#define QSUPPORTED_MAX_RETRIES 5

extern char hex2char (char *hex);

#if 0
static int set_interface_attribs(int fd, int speed, int parity) {
#if defined(_MSC_VER) || defined(__MINGW32__)
#pragma message("gdbclient/core.c: set_interface_attribs not implemented")
#else
	struct termios tty;
	memset (&tty, 0, sizeof tty);
	if (tcgetattr (fd, &tty) != 0) {
		return -1;
	}

	cfsetospeed (&tty, speed);
	cfsetispeed (&tty, speed);

	tty.c_cflag = (tty.c_cflag & ~CSIZE) | CS8;     // 8-bit chars
	// disable IGNBRK for mismatched speed tests; otherwise receive break
	// as \000 chars
	tty.c_iflag &= ~IGNBRK;         // disable break processing
	tty.c_lflag = 0;                // no signaling chars, no echo,
	// no canonical processing
	tty.c_oflag = 0;                // no remapping, no delays
	tty.c_cc[VMIN]  = 0;            // read doesn't block
	tty.c_cc[VTIME] = 5;            // 0.5 seconds read timeout

	tty.c_iflag &= ~(IXON | IXOFF | IXANY); // shut off xon/xoff ctrl

	tty.c_cflag |= (CLOCAL | CREAD);// ignore modem controls,
	// enable reading
	tty.c_cflag &= ~(PARENB | PARODD);      // shut off parity
	tty.c_cflag |= parity;
	tty.c_cflag &= ~CSTOPB;
	tty.c_cflag &= ~CRTSCTS;

	if (tcsetattr (fd, TCSANOW, &tty) != 0) {
		return -1;
	}
#endif
	return 0;
}
#endif

static bool regs_reserve(libgdbr_t *g, size_t len) {
	if (len <= g->regs.cap) {
		return true;
	}
	size_t cap;
	if (!gdbr_grow_size (len, &cap)) {
		return false;
	}
	ut8 *buf = realloc (g->regs.buf, cap);
	if (!buf) {
		return false;
	}
	g->regs.buf = buf;
	ut8 *known = realloc (g->regs.known, cap);
	if (!known) {
		return false;
	}
	g->regs.known = known;
	g->regs.cap = cap;
	return true;
}

// Lay the block out by the register profile, unless this stop already did.
// A profile placing a register beyond GDBR_REGS_MAX is refused, so every register lies in the block.
static bool regs_prepare(libgdbr_t *g) {
	if (g->regs.len) {
		return true;
	}
	if (!g->registers) {
		return false;
	}
	size_t count, end, len = 0;
	for (count = 0; *g->registers[count].name; count++) {
		if (!gdbr_reg_byte_end (&g->registers[count], &end)) {
			R_LOG_DEBUG ("%s: register %s lies beyond the register block", __func__, g->registers[count].name);
			return false;
		}
		len = R_MAX (len, end);
	}
	if (!len || !regs_reserve (g, len)) {
		return false;
	}
	memset (g->regs.buf, 0, len);
	memset (g->regs.known, 0, len);
	g->regs.len = len;
	g->regs.count = count;
	g->regs.valid = false;
	return true;
}

// The bytes of the block a register occupies; false when they do not all lie in it
static bool regs_span(libgdbr_t *g, const gdb_reg_t *reg, size_t *off, size_t *size) {
	size_t end;
	if (!gdbr_reg_byte_end (reg, &end) || end > g->regs.len) {
		return false;
	}
	// offset / 8 + (size + 7) / 8 never exceeds (offset + size + 7) / 8
	*off = gdbr_reg_byte_offset (reg);
	*size = gdbr_reg_byte_size (reg);
	return true;
}

static bool unavailable_byte(const char *pair) {
	return pair[0] == 'x' && pair[1] == 'x';
}

static bool regs_store_at(libgdbr_t *g, size_t index, const char *hex, size_t hexlen, bool allow_unavailable) {
	size_t off, size, i;
	if (!regs_span (g, &g->registers[index], &off, &size)) {
		return false;
	}
	const size_t n = hexlen / 2;
	if (!n || (hexlen & 1) || n > size) {
		return false;
	}
	for (i = 0; i < hexlen; i += 2) {
		if ((hex2int (hex[i]) < 0 || hex2int (hex[i + 1]) < 0)
		    && !(allow_unavailable && unavailable_byte (hex + i))) {
			return false;
		}
	}
	for (i = 0; i < n; i++) {
		const char *pair = hex + 2 * i;
		const bool known = !unavailable_byte (pair);
		g->regs.buf[off + i] = known? (hex2int (pair[0]) << 4) | hex2int (pair[1]): 0;
		g->regs.known[off + i] = known;
	}
	memset (g->regs.buf + off + n, 0, size - n);
	memset (g->regs.known + off + n, 0, size - n);
	return true;
}

// The index of the register the stub numbers regnum. The profile lists the registers in
// the stub's order and may skip numbers, never repeat them, so the index is at most regnum
static bool regs_index(libgdbr_t *g, ut64 regnum, size_t *index) {
	size_t i = regnum < g->regs.count? (size_t)regnum + 1: g->regs.count;
	while (i-- > 0) {
		if (g->registers[i].regnum <= regnum) {
			*index = i;
			return g->registers[i].regnum == regnum;
		}
	}
	return false;
}

bool gdbr_regs_store(libgdbr_t *g, ut64 regnum, const char *hex, size_t hexlen) {
	size_t i;
	return regs_prepare (g) && regs_index (g, regnum, &i) && regs_store_at (g, i, hex, hexlen, false);
}

static bool regs_known(libgdbr_t *g, const gdb_reg_t *reg) {
	size_t off, size, i;
	if (!regs_span (g, reg, &off, &size)) {
		return false;
	}
	for (i = 0; i < size; i++) {
		if (!g->regs.known[off + i]) {
			return false;
		}
	}
	return true;
}

static bool regs_load(libgdbr_t *g) {
	if (!g->regs.valid || !gdbr_data_reserve (g, g->regs.len)) {
		return false;
	}
	memcpy (g->data, g->regs.buf, g->regs.len);
	g->data_len = g->regs.len;
	g->data[g->data_len] = '\0';
	return true;
}

// Send a register packet, naming its thread when the stub asked for that
static int send_reg_msg(libgdbr_t *g, const char *cmd) {
	const int tid = g->tid > 0? g->tid: g->stop_reason.thread.tid;
	char thread[64];
	if (!g->caps.thread_suffix || tid <= 0
	    || write_thread_id (thread, sizeof (thread), g->pid, tid, g->stub_features.multiprocess) < 0) {
		return send_msg (g, cmd);
	}
	char *msg = r_str_newf ("%s;thread:%s;", cmd, thread);
	int ret = msg? send_msg (g, msg): -1;
	free (msg);
	return ret;
}

// An empty reply means the packet is unsupported; an odd-length one starting with E is an error
static bool reply_refused(libgdbr_t *g) {
	return !g->data_len || (g->data[0] == 'E' && (g->data_len & 1));
}

static void gdbr_break_process(void *arg) {
	libgdbr_t *g = (libgdbr_t *)arg;
	(void)g;
	g->isbreaked = true;
}

bool gdbr_lock_tryenter(libgdbr_t *g) {
	R_RETURN_VAL_IF_FAIL (g, false);
	if (!r_th_lock_tryenter (g->gdbr_lock)) {
		return false;
	}
	RCons *cons = r_cons_singleton ();
	g->gdbr_lock_depth++;
	r_cons_break_push (cons, gdbr_break_process, g);
	return true;
}

bool gdbr_lock_enter(libgdbr_t *g) {
	R_RETURN_VAL_IF_FAIL (g, false);
	RCons *cons = r_cons_singleton ();
	r_cons_break_push (cons, gdbr_break_process, g);
	void *bed = r_cons_sleep_begin (cons);
	r_th_lock_enter (g->gdbr_lock);
	g->gdbr_lock_depth++;
	r_cons_sleep_end (cons, bed);
	return !g->isbreaked;
}

void gdbr_lock_leave(libgdbr_t *g) {
	R_RETURN_IF_FAIL (g);
	RCons *cons = r_cons_singleton ();
	r_cons_break_pop (cons);
	if (g->gdbr_lock_depth < 1) {
		return;
	}
	bool last_leave = g->gdbr_lock_depth == 1;
	g->gdbr_lock_depth--;
	r_th_lock_leave (g->gdbr_lock);
	// if this is the last lock this thread holds make sure that we disable the break
	if (last_leave) {
		g->isbreaked = false;
	}
}

int gdbr_connect(libgdbr_t *g, const char *host, int port) {
	const char *message = "qSupported:multiprocess+;xmlRegisters=i386";
	int i;
	int ret = -1;
	void *bed = NULL;

	if (!g || !host) {
		return -1;
	}
	if (!gdbr_lock_enter (g)) {
		goto end;
	}
	g->connected = 0;
	g->no_ack = false;
	g->ack_retries = -1;
	g->read_len = 0;
	g->stub_features = (libgdbr_stub_features_t){ .pkt_sz = 64, .P = true, .extended_mode = -1 };
	g->remote_type = GDB_REMOTE_TYPE_GDB;
	g->caps.thread_suffix = false;
	R_FREE (g->target.osabi);
	char *env_pktsz_str;
	ut32 env_pktsz = 0;
	if ((env_pktsz_str = r_sys_getenv ("R2_GDB_PKTSZ"))) {
		char *end;
		ut64 size = strtoull (env_pktsz_str, &end, 10);
		if (isdigit ((ut8)*env_pktsz_str) && !*end && size <= UT32_MAX) {
			env_pktsz = size;
		}
		free (env_pktsz_str);
	}
	// Use the default break handler for r_socket_connect to send a signal
	RCons *cons = r_cons_singleton ();
	r_cons_break_pop (cons);
	bed = r_cons_sleep_begin (cons);
	if (*host == '/') {
		ret = r_socket_connect_serial (g->sock, host, port, 1);
	} else {
		r_strf_var (portstr, 32, "%d", port);
		ret = r_socket_connect_tcp (g->sock, host, portstr, 1);
	}
	r_cons_sleep_end (cons, bed);
	r_cons_break_push (cons, gdbr_break_process, g);
	if (!ret) {
		ret = -1;
		goto end;
	}
	if ((ret = send_ack (g)) < 0) {
		goto end;
	}
	read_packet (g, true); // vcont=true lets us skip if we get no reply
	g->connected = 1;
	bed = r_cons_sleep_begin (cons);
	// TODO add config possibility here
	for (i = 0; i < QSUPPORTED_MAX_RETRIES && !g->isbreaked; i++) {
		ret = send_msg (g, message);
		if (ret < 0) {
			continue;
		}
		ret = read_packet (g, false);
		if (ret < 0) {
			continue;
		}
		ret = handle_qSupported (g);
		if (ret < 0) {
			continue;
		}
		break;
	}
	r_cons_sleep_end (cons, bed);
	if (g->isbreaked) {
		g->isbreaked = false;
		ret = -1;
		goto end;
	}
	if (ret < 0) {
		goto end;
	}
	if (env_pktsz > 0) {
		g->stub_features.pkt_sz = R_MIN (env_pktsz, g->stub_features.pkt_sz);
	}
	// If no-ack supported, enable no-ack mode (should speed up things)
	if (g->stub_features.QStartNoAckMode) {
		if (send_msg (g, "QStartNoAckMode") < 0 || read_packet (g, false) < 0) {
			ret = -1;
			goto end;
		}
		g->no_ack = g->data_len == 2 && !memcmp (g->data, "OK", 2);
	}
	// A stub advertising lldb's extensions takes the thread of a register packet in
	// the packet once asked to, and from then on refuses a register packet without it
	if (g->remote_type == GDB_REMOTE_TYPE_LLDB && send_msg (g, "QThreadSuffixSupported") >= 0
	    && read_packet (g, false) >= 0) {
		g->caps.thread_suffix = !strcmp (g->data, "OK");
	}
	// Query the thread / process id
	g->stub_features.qC = true;
	g->pid = g->tid = 0;
	if ((ret = send_msg (g, "qC")) < 0) {
		goto end;
	}
	read_packet (g, false);
	if ((ret = handle_qC (g)) < 0) {
		g->stub_features.qC = false;
	}
	// Check if vCont is supported
	gdbr_check_vcont (g);
	// Set pid/thread for operations other than "step" and "continue"
	if (gdbr_select (g, g->pid, g->tid) < 0) {
		// return -1;
	}
	// Set thread for "step" and "continue" operations
	if ((ret = send_msg (g, "Hc-1")) < 0) {
		goto end;
	}
	ret = read_packet (g, false);
	if (ret < 0) {
		goto end;
	}
	if (strcmp (g->data, "OK")) {
		// return -1;
	}
	gdbr_read_target_xml (g);
	gdbr_regs_invalidate (g);

	ret = 0;
end:
	if (ret != 0) {
		r_socket_close (g->sock);
		g->connected = 0;
	}
	gdbr_lock_leave (g);
	return ret;
}

int gdbr_disconnect(libgdbr_t *g) {
	// TODO Disconnect maybe send something to gdbserver
	if (!g || !g->sock) {
		return -1;
	}
	// r_socket_close returns the close status despite its bool return type.
	const int ret = r_socket_close (g->sock)? -1: 0;
	if (!gdbr_lock_enter (g)) {
		goto end;
	}
	gdbr_regs_invalidate (g);
	gdbr_stop_reason_fini (&g->stop_reason);
	g->stop_reason.is_valid = false;
	if (g->target.valid) {
		R_FREE (g->target.regprofile);
		R_FREE (g->registers);
		g->target.valid = false;
	}
	g->connected = 0;
end:
	gdbr_lock_leave (g);
	return ret;
}

int gdbr_select(libgdbr_t *g, int pid, int tid) {
	char cmd[64] = {0};
	int ret = -1;

	if (!gdbr_lock_enter (g)) {
		goto end;
	}
	if (g->pid != pid || g->tid != tid) {
		gdbr_regs_invalidate (g);
	}
	g->pid = pid;
	g->tid = tid;
	strcpy (cmd, "Hg");
	if ((ret = write_thread_id (cmd + 2, sizeof (cmd) - 3, pid, tid,
		    g->stub_features.multiprocess)) < 0) {
		goto end;
	}
	g->stop_reason.is_valid = false;
	if (send_msg (g, cmd) < 0 || read_packet (g, false) < 0) {
		ret = -1;
		goto end;
	}
	if (strcmp (g->data, "OK")) {
		ret = -1;
		goto end;
	}

	ret = 0;
end:
	gdbr_lock_leave (g);
	return ret;
}

int gdbr_check_vcont(libgdbr_t *g) {
	int ret = -1;
	char *ptr = NULL;
	char *save_ptr = NULL;

	if (!g) {
		return -1;
	}

	if (!gdbr_lock_enter (g)) {
		goto end;
	}
	if (send_msg (g, "vCont?") < 0 || read_packet (g, false) < 0) {
		ret = -1;
		goto end;
	}
	if (g->data_len == 0) {
		g->stub_features.vContSupported = false;
		ret = 0;
		goto end;
	}
	g->data[g->data_len] = '\0';
	if (!(ptr = r_str_tok_r (g->data + strlen ("vCont;"), ";", &save_ptr))) {
		ret = 0;
		goto end;
	}
	while (ptr) {
		switch (*ptr) {
		case 's':
			g->stub_features.vcont.s = true;
			break;
		case 'S':
			g->stub_features.vcont.S = true;
			break;
		case 'c':
			g->stub_features.vcont.c = true;
			break;
		case 'C':
			g->stub_features.vcont.C = true;
			break;
		case 't':
			g->stub_features.vcont.t = true;
			break;
		case 'r':
			g->stub_features.vcont.r = true;
			break;
		}
		g->stub_features.vContSupported = true;
		ptr = r_str_tok_r (NULL, ";", &save_ptr);
	}

	ret = 0;
end:
	gdbr_lock_leave (g);
	return ret;
}

static bool decode_console_output(libgdbr_t *g, size_t *length) {
	if (g->data_len < 1 || g->data[0] != 'O' || !(g->data_len % 2)) {
		return false;
	}
	const size_t bytes = (g->data_len - 1) / 2;
	size_t i;
	for (i = 0; i < bytes; i++) {
		const int high = hex2int ((ut8)g->data[1 + i * 2]);
		const int low = hex2int ((ut8)g->data[2 + i * 2]);
		if (high < 0 || low < 0) {
			return false;
		}
		g->data[1 + i] = high * 16 + low;
	}
	g->data[1 + bytes] = '\0';
	*length = bytes;
	return true;
}

static int read_stop_reply(libgdbr_t *g, bool attaching, bool running) {
	g->stop_reason.is_valid = false;
	for (;;) {
		int ret = read_packet (g, running);
		if (ret == GDBR_READ_TIMEOUT && running) {
			continue;
		}
		if (ret < 0) {
			return -1;
		}
		const bool attach_ok = attaching && g->data_len == 2 && !memcmp (g->data, "OK", 2);
		if (g->data_len && g->data[0] == 'O' && !attach_ok) {
			size_t length;
			if (!decode_console_output (g, &length)) {
				return -1;
			}
			if (length) {
				RCons *cons = r_cons_singleton ();
				if (!r_cons_write (cons, g->data + 1, length)) {
					if (!running || !g->isbreaked || !cons->context->breaked) {
						return -1;
					}
					// Keep the run interrupt pending while retrying output rejected by Ctrl-C.
					r_cons_break_clear (cons);
					if (!r_cons_write (cons, g->data + 1, length)) {
						if (!g->isbreaked || !cons->context->breaked) {
							return -1;
						}
						continue;
					}
				}
				r_cons_flush (cons);
			}
			continue;
		}
		if (attach_ok) {
			return handle_attach (g);
		}
		if (attaching && !g->data_len) {
			return -2;
		}
		return handle_stop_reason (g);
	}
}

int gdbr_stop_reason(libgdbr_t *g) {
	int ret = -1;
	if (!gdbr_lock_enter (g)) {
		goto end;
	}
	if (!g || send_msg (g, "?") < 0) {
		ret = -1;
		goto end;
	}
	ret = read_stop_reply (g, false, false);
end:
	gdbr_lock_leave (g);
	return ret;
}

int gdbr_check_extended_mode(libgdbr_t *g) {
	int ret = -1;

	if (!gdbr_lock_enter (g)) {
		goto end;
	}
	g->stop_reason.is_valid = false;
	gdbr_regs_invalidate (g);
	// Activate extended mode if possible.
	ret = send_msg (g, "!");
	if (ret < 0) {
		g->stub_features.extended_mode = 0;
		goto end;
	}
	ret = read_packet (g, false);
	if (ret < 0) {
		g->stub_features.extended_mode = 0;
		goto end;
	}
	if (strncmp (g->data, "OK", 2)) {
		g->stub_features.extended_mode = 0;
		ret = -1;
		goto end;
	}
	g->stub_features.extended_mode = 1;

	ret = 0;
end:
	gdbr_lock_leave (g);
	return ret;
}

int gdbr_attach(libgdbr_t *g, int pid) {
	int ret = -1;
	char *cmd = NULL;
	size_t buffer_size;

	if (!g || !g->sock) {
		return -1;
	}

	if (!gdbr_lock_enter (g)) {
		goto end;
	}
	g->stop_reason.is_valid = false;
	gdbr_regs_invalidate (g);

	// vAttach is specified for extended mode, but lldb's stubs answer it without '!':
	// its own reply says whether attaching is supported
	if (g->stub_features.extended_mode == -1) {
		gdbr_check_extended_mode (g);
	}

	buffer_size = strlen (CMD_ATTACH) + (sizeof (int) * 2) + 1;
	cmd = calloc (buffer_size, sizeof (char));
	if (!cmd) {
		ret = -1;
		goto end;
	}

	ret = snprintf (cmd, buffer_size, "%s%x", CMD_ATTACH, pid);
	if (ret < 0) {
		goto end;
	}

	ret = send_msg (g, cmd);
	if (ret < 0) {
		goto end;
	}

	ret = read_stop_reply (g, true, false);
	if (!ret) {
		g->pid = pid;
		if (g->stop_reason.thread.present) {
			g->tid = g->stop_reason.thread.tid;
		}
		// The attached process decides the register layout
		gdbr_read_target_xml (g);
	}
end:
	free (cmd);
	gdbr_lock_leave (g);
	return ret;
}

int gdbr_detach(libgdbr_t *g) {
	int ret = -1;

	if (!g || !g->sock) {
		return -1;
	}

	if (!gdbr_lock_enter (g)) {
		goto end;
	}

	gdbr_regs_invalidate (g);
	g->stop_reason.is_valid = false;
	ret = send_msg (g, "D");
	if (ret < 0) {
		ret = -1;
		goto end;
	}
	// Disconnect
	ret = gdbr_disconnect (g);
end:
	gdbr_lock_leave (g);
	return ret;
}

int gdbr_detach_pid(libgdbr_t *g, int pid) {
	char *cmd = NULL;
	int ret = -1;
	size_t buffer_size;

	if (!g || !g->sock || !g->stub_features.multiprocess) {
		return -1;
	}

	if (!gdbr_lock_enter (g)) {
		goto end;
	}

	gdbr_regs_invalidate (g);
	g->stop_reason.is_valid = false;

	buffer_size = strlen (CMD_DETACH_MP) + (sizeof (pid) * 2) + 1;
	cmd = calloc (buffer_size, sizeof (char));
	if (!cmd) {
		ret = -1;
		goto end;
	}

	if ((snprintf (cmd, buffer_size, "%s%x", CMD_DETACH_MP, g->pid)) < 0) {
		ret = -1;
		goto end;
	}

	ret = send_msg (g, cmd);
	if (ret < 0) {
		goto end;
	}

	if ((ret = read_packet (g, false)) < 0) {
		goto end;
	}

	if (strncmp (g->data, "OK", 2)) {
		ret = -1;
		goto end;
	}

	ret = 0;
end:
	free (cmd);
	gdbr_lock_leave (g);
	return ret;
}

int gdbr_kill(libgdbr_t *g) {
	int ret = -1;

	if (!g || !g->sock) {
		return -1;
	}

	if (!gdbr_lock_enter (g)) {
		goto end;
	}

	gdbr_regs_invalidate (g);
	g->stop_reason.is_valid = false;

	if (g->stub_features.multiprocess) {
		if (g->pid <= 0) {
			ret = -1;
			goto end;
		}
		ret = gdbr_kill_pid (g, g->pid);
		goto end;
	}

	if ((ret = send_msg (g, "k")) < 0) {
		goto end;
	}

	ret = 0;
end:
	gdbr_lock_leave (g);
	return ret;
}

int gdbr_kill_pid(libgdbr_t *g, int pid) {
	char *cmd = NULL;
	int ret = -1;
	size_t buffer_size;

	if (!g || !g->sock || !g->stub_features.multiprocess) {
		return -1;
	}

	if (!gdbr_lock_enter (g)) {
		goto end;
	}

	gdbr_regs_invalidate (g);
	g->stop_reason.is_valid = false;

	buffer_size = strlen (CMD_KILL_MP) + (sizeof (pid) * 2) + 1;
	cmd = calloc (buffer_size, sizeof (char));
	if (!cmd) {
		ret = -1;
		goto end;
	}

	if ((snprintf (cmd, buffer_size, "%s%x", CMD_KILL_MP, g->pid)) < 0) {
		ret = -1;
		goto end;
	}
	if ((ret = send_msg (g, cmd)) < 0) {
		goto end;
	}

	if ((ret = read_packet (g, false)) < 0) {
		goto end;
	}
	if (strncmp (g->data, "OK", 2)) {
		ret = -1;
		goto end;
	}

end:
	free (cmd);
	gdbr_lock_leave (g);
	return ret;
}

// 1 when the stub refused 'g', 0 once its block is cached
static int read_registers_g(libgdbr_t *g) {
	if (send_reg_msg (g, CMD_READREGS) < 0 || read_packet (g, false) < 0) {
		return -1;
	}
	if (reply_refused (g)) {
		return 1;
	}
	const size_t len = g->data_len / 2;
	if (!len || (g->data_len & 1) || len > GDBR_REGS_MAX || !regs_reserve (g, len)) {
		return -1;
	}
	size_t i;
	for (i = 0; i < len; i++) {
		const char *pair = g->data + 2 * i;
		const int high = hex2int (pair[0]);
		const int low = hex2int (pair[1]);
		bool known = high >= 0 && low >= 0;
		if (!known && !unavailable_byte (pair)) {
			gdbr_regs_invalidate (g);
			return -1;
		}
		g->regs.buf[i] = known? (high << 4) | low: 0;
		g->regs.known[i] = known;
	}
	g->regs.len = len;
	g->regs.valid = true;
	return 0;
}

// One 'p' per register the stub has not stated since the thread last ran.
// 1 when the stub refused a register, 0 once every register is cached
static int read_registers_p(libgdbr_t *g) {
	if (!regs_prepare (g)) {
		return -1;
	}
	size_t i;
	for (i = 0; i < g->regs.count; i++) {
		if (regs_known (g, &g->registers[i])) {
			continue;
		}
		r_strf_var (cmd, 32, "%s%x", CMD_READREG, (unsigned int)g->registers[i].regnum);
		if (send_reg_msg (g, cmd) < 0 || read_packet (g, false) < 0) {
			return -1;
		}
		if (!g->data_len) {
			g->caps.p = 0;
			return 1;
		}
		if (reply_refused (g) || !regs_store_at (g, i, g->data, g->data_len, true)) {
			R_LOG_DEBUG ("%s: register %s: %s", __func__, g->registers[i].name, g->data);
			return 1;
		}
	}
	g->caps.p = 1;
	g->regs.valid = true;
	return 0;
}

int gdbr_read_registers(libgdbr_t *g) {
	if (!g || !g->data) {
		return -1;
	}
	if (regs_load (g)) {
		return 0;
	}
	if (g->regs.refused) {
		return -1;
	}
	// Don't wait on the lock in read_registers since it's frequently called, including
	// each time "enter" is pressed. Otherwise the user will be forced to interrupt exit
	// read_registers constantly while another task is in progress
	if (!gdbr_lock_tryenter (g)) {
		return -1;
	}
	int ret = g->caps.g? read_registers_g (g): 1;
	if (!ret) {
		g->caps.g = 1;
	} else if (ret > 0 && g->caps.g != 1 && g->caps.p) {
		// one register at a time, unless 'g' worked before: then its refusal is not a missing packet
		ret = read_registers_p (g);
		if (!ret) {
			// the stub refused 'g' and answered 'p'
			g->caps.g = 0;
		}
	}
	if (ret > 0) {
		R_LOG_WARN ("The stub refused to read the registers");
		g->regs.refused = true;
		ret = -1;
	}
	if (!ret && !regs_load (g)) {
		ret = -1;
	}
	gdbr_lock_leave (g);
	return ret;
}

int gdbr_read_memory(libgdbr_t *g, ut64 address, ut8 *buf, int len) {
	if (!g || (!buf && len) || len < 0) {
		return -1;
	}
	if (!len) {
		return 0;
	}
	if (UT64_MAX - address < (ut64)len - 1) {
		return -1;
	}
	if (!gdbr_lock_enter (g)) {
		gdbr_lock_leave (g);
		return -1;
	}
	int total = 0;
	const int limit = R_MIN (g->stub_features.pkt_sz, (ut32)(g->data_max - 1)) / 2;
	const int page = g->page_size;
	while (total < len && limit > 0 && page > 0) {
		ut64 offset = address + total;
		int chunk = R_MIN (len - total, page - (int)(offset % page));
		chunk = R_MIN (chunk, limit);
		r_strf_var (command, 64, "%s%"PFMT64x",%x", CMD_READMEM, offset, chunk);
		if (send_msg (g, command) < 0 || read_packet (g, false) < 0 || handle_m (g, chunk) < 0) {
			break;
		}
		memcpy (buf + total, g->data, g->data_len);
		total += g->data_len;
		if (g->data_len < chunk) {
			break;
		}
	}
	gdbr_lock_leave (g);
	return total? total: -1;
}

int gdbr_write_memory(libgdbr_t *g, ut64 address, const uint8_t *data, ut64 len) {
	if (!g || (!data && len)) {
		return -1;
	}
	if (!len) {
		return 0;
	}
	ut64 last_address;
	if (len > SIZE_MAX || r_add_overflow_ut64 (address, len - 1, &last_address)) {
		return -1;
	}
	if (!gdbr_lock_enter (g)) {
		return -1;
	}
	int ret = -1;
	char *command = NULL;
	char header[64];
	if (g->send_max <= 5) {
		goto end;
	}
	const size_t payload_max = R_MIN ((size_t)g->send_max - 5, g->stub_features.pkt_sz);
	// Even the final address must fit a one-byte write before any data is changed.
	int header_len = snprintf (header, sizeof (header), "M%"PFMT64x",1:", last_address);
	if (header_len < 0 || (size_t)header_len + 2 > payload_max) {
		goto end;
	}
	size_t command_size;
	if (r_add_overflow_size_t (payload_max, 1, &command_size)
	    || !(command = malloc (command_size))) {
		goto end;
	}
	ut64 offset = 0;
	while (offset < len) {
		ut64 chunk = R_MIN (len - offset, payload_max / 2);
		while (chunk) {
			header_len = snprintf (header, sizeof (header), "M%"PFMT64x",%"PFMT64x":", address + offset, chunk);
			if (header_len < 0 || (size_t)header_len >= sizeof (header)) {
				goto end;
			}
			if (header_len + chunk * 2 <= payload_max) {
				break;
			}
			chunk--;
		}
		if (!chunk) {
			goto end;
		}
		memcpy (command, header, header_len);
		pack_hex ((const char *)data + offset, chunk, command + header_len);
		if (send_msg (g, command) < 0 || read_packet (g, false) < 0 || handle_M (g) < 0) {
			goto end;
		}
		offset += chunk;
	}
	ret = 0;
end:
	gdbr_lock_leave (g);
	free (command);
	return ret;
}

int gdbr_step(libgdbr_t *g, int tid) {
	int ret = -1;
	char thread_id[64] = {0};

	if (!gdbr_lock_enter (g)) {
		goto end;
	}

	if (tid <= 0 || write_thread_id (thread_id, sizeof (thread_id) - 1, g->pid, tid,
		    g->stub_features.multiprocess) < 0) {
		send_vcont (g, "vCont?", NULL);
		r_strf_var (hcd, 32, "Hc%d", tid);
		send_vcont (g, hcd, NULL);
		ret = send_vcont (g, CMD_C_STEP, NULL);
		goto end;
	}

	ret = send_vcont (g, CMD_C_STEP, thread_id);
end:
	gdbr_lock_leave (g);
	return ret;
}

int gdbr_continue(libgdbr_t *g, int pid, int tid, int sig) {
	char thread_id[64] = {0};
	char command[16] = {0};
	int ret = -1;

	if (!gdbr_lock_enter (g)) {
		goto end;
	}

	if (sig <= 0) {
		r_str_ncpy (command, CMD_C_CONT, sizeof (command));
	} else {
		snprintf (command, sizeof (command) - 1, "%s%02x", CMD_C_CONT_SIG, sig);
	}
	if (tid <= 0 || write_thread_id (thread_id, sizeof (thread_id) - 1, g->pid, tid,
		    g->stub_features.multiprocess) < 0) {
		ret = send_vcont (g, command, NULL);
		goto end;
	}

	ret = send_vcont (g, command, thread_id);
end:
	gdbr_lock_leave (g);
	return ret;
}

int gdbr_write_bin_registers(libgdbr_t *g, const char *regs, int len) {
	int ret = -1;
	uint64_t buffer_size = 0;
	char *command = NULL;

	if (!g) {
		return -1;
	}

	if (!gdbr_lock_enter (g)) {
		goto end;
	}

	buffer_size = len * 2 + 8;
	gdbr_regs_invalidate (g);

	command = calloc (buffer_size, sizeof (char));
	if (!command) {
		ret = -1;
		goto end;
	}
	snprintf (command, buffer_size, "%s", CMD_WRITEREGS);
	pack_hex (regs, len, command + 1);
	if (send_reg_msg (g, command) < 0) {
		ret = -1;
		goto end;
	}
	if (read_packet (g, false) >= 0) {
		ret = handle_G (g);
	} else {
		ret = -1;
	}
end:
	gdbr_lock_leave (g);
	free (command);
	return ret;
}

int gdbr_write_register(libgdbr_t *g, int regnum, char *value, int len) {
	int ret = -1;
	char *command = NULL;
	if (!g || !g->stub_features.P || len < 0) {
		return -1;
	}
	if (!gdbr_lock_enter (g)) {
		goto end;
	}

	gdbr_regs_invalidate (g);
	// "P<regnum>=" plus two hex digits per byte and the terminator
	command = malloc ((size_t)len * 2 + 16);
	if (!command) {
		goto end;
	}
	ret = sprintf (command, "%s%x=", CMD_WRITEREG, regnum);
	pack_hex (value, len, command + ret);
	if (send_reg_msg (g, command) < 0) {
		ret = -1;
		goto end;
	}
	if (read_packet (g, false) < 0 || handle_P (g) < 0) {
		ret = -1;
		goto end;
	}
	if (g->last_code == MSG_NOT_SUPPORTED) {
		g->stub_features.P = false;
		ret = -1;
		goto end;
	}

	ret = 0;
end:
	gdbr_lock_leave (g);
	free (command);
	return ret;
}

int gdbr_write_reg(libgdbr_t *g, const char *name, char *value, int len) {
	int i = 0;
	int ret = -1;
	if (!g) {
		return -1;
	}

	if (!gdbr_lock_enter (g)) {
		goto end;
	}

	gdbr_regs_invalidate (g);
	while (g->registers[i].size > 0) {
		if (!strcmp (g->registers[i].name, name)) {
			break;
		}
		i++;
	}
	if (g->registers[i].size == 0) {
		R_LOG_ERROR ("%s: registername <%s> not found in profile", __func__, name);
		ret = -1;
		goto end;
	}
	if (g->stub_features.P) {
		ret = gdbr_write_register (g, g->registers[i].regnum, value, len);
		// gdbr_write_register clears stub_features.P only when the stub lacks it
		if (g->stub_features.P) {
			goto end;
		}
	}
	if (gdbr_read_registers (g) < 0 || memchr (g->regs.known, 0, g->regs.len)) {
		ret = -1;
		goto end;
	}
	const ut64 roff = g->registers[i].offset / 8;
	if (len < 0 || roff >= (ut64)g->data_len || (ut64)len > (ut64)g->data_len - roff) {
		R_LOG_ERROR ("%s: register %s lies outside the register block", __func__, name);
		ret = -1;
		goto end;
	}
	memcpy (g->data + roff, value, len);
	ret = gdbr_write_bin_registers (g, g->data, g->data_len) < 0? -1: 0;
end:
	gdbr_lock_leave (g);
	return ret;
}

int gdbr_write_registers(libgdbr_t *g, char *registers) {
	uint64_t buffer_size;
	int i = 0;
	int ret = -1;
	unsigned int x, len;
	char *command, *reg, *buff, *value;
	char *save_ptr = NULL;
	// read current register set
	command = buff = value = NULL;

	if (!g) {
		return -1;
	}

	if (!gdbr_lock_enter (g)) {
		goto end;
	}

	if (gdbr_read_registers (g) < 0 || memchr (g->regs.known, 0, g->regs.len)) {
		goto end;
	}
	gdbr_regs_invalidate (g);
	len = strlen (registers);
	buff = calloc (len + 1, sizeof (char));
	if (!buff) {
		ret = -1;
		goto end;
	}
	memcpy (buff, registers, len);
	reg = r_str_tok_r (buff, ",", &save_ptr);
	while (reg) {
		char *name_end = strchr (reg, '=');
		if (name_end == NULL) {
			R_LOG_ERROR ("%s: Malformed argument: %s", __func__, reg);
			ret = -1;
			goto end;
		}
		*name_end = '\0'; // change '=' to '\0'

		// time to find the current register
		i = 0;
		while (g->registers[i].size > 0) {
			if (strcmp (g->registers[i].name, reg) == 0) {
				const ut64 register_size = g->registers[i].size / 8;
				const ut64 offset = g->registers[i].offset / 8;
				if (!register_size || g->data_max < 1 || g->data_len < 1
				    || offset >= (ut64)g->data_max || register_size > (ut64)g->data_max - offset
				    || offset >= (ut64)g->data_len || register_size > (ut64)g->data_len - offset) {
					R_LOG_ERROR ("%s: register %s exceeds data buffer", __func__, reg);
					ret = -1;
					goto end;
				}
				value = calloc (register_size + 1, 2);
				if (!value) {
					ret = -1;
					goto end;
				}

				memset (value, '0', register_size * 2);
				name_end++;
				// be able to take hex with and without 0x
				if (name_end[0] == '0' && (name_end[1] == 'x' || name_end[1] == 'X')) {
					name_end += 2;
				}
				const size_t val_len = strlen (name_end); // size of the rest
				if (val_len > register_size * 2) {
					R_LOG_ERROR ("%s: value for register %s is too large", __func__, reg);
					ret = -1;
					goto end;
				}
				memcpy (value + (register_size * 2 - val_len), name_end, val_len);

				for (x = 0; x < register_size; x++) {
					g->data[offset + register_size - x - 1] = hex2char (&value[x * 2]);
				}
				R_FREE (value);
			}
			i++;
		}
		reg = r_str_tok_r (NULL, " ,", &save_ptr);
	}

	buffer_size = g->data_len * 2 + 8;
	command = calloc (buffer_size, sizeof (char));
	if (!command) {
		ret = -1;
		goto end;
	}
	snprintf (command, buffer_size, "%s", CMD_WRITEREGS);
	pack_hex (g->data, g->data_len, command + 1);
	ret = send_reg_msg (g, command);
	if (ret < 0) {
		goto end;
	}
	ret = read_packet (g, false) < 0? -1: handle_G (g);
end:
	free (command);
	free (buff);
	free (value);
	gdbr_lock_leave (g);
	return ret;
}

int send_vcont(libgdbr_t *g, const char *command, const char *thread_id) {
	char tmp[255] = {0};
	int ret = -1;
	void *bed = NULL;

	if (!g) {
		return -1;
	}

	RCons *cons = r_cons_singleton ();
	if (!g->stub_features.vContSupported) {
		ret = snprintf (tmp, sizeof (tmp) - 1, "%s", command);
	} else {
		bool supported = false;
		switch (*command) {
		case 's':
			if (g->stub_features.vcont.s) {
				supported = true;
			}
			break;
		case 'S':
			if (g->stub_features.vcont.S) {
				supported = true;
			}
			break;
		case 'c':
			if (g->stub_features.vcont.c) {
				supported = true;
			}
			break;
		case 'C':
			if (g->stub_features.vcont.C) {
				supported = true;
			}
			break;
		case 't':
			if (g->stub_features.vcont.t) {
				supported = true;
			}
			break;
		case 'r':
			if (g->stub_features.vcont.r) {
				supported = true;
			}
			break;
		}
		if (supported) {
			if (!thread_id) {
				ret = snprintf (tmp, sizeof (tmp) - 1, "%s;%s", CMD_C, command);
			} else {
				ret = snprintf (tmp, sizeof (tmp) - 1, "%s;%s:%s", CMD_C, command, thread_id);
			}
		} else {
			ret = snprintf (tmp, sizeof (tmp) - 1, "%s", command);
		}
	}
	if (ret < 0) {
		return ret;
	}

	if (!gdbr_lock_enter (g)) {
		goto end;
	}
	gdbr_regs_invalidate (g);
	g->stop_reason.is_valid = false;
	ret = send_msg (g, tmp);
	if (ret < 0) {
		goto end;
	}

	bed = r_cons_sleep_begin (cons);
	ret = read_stop_reply (g, false, true);
end:
	r_cons_sleep_end (cons, bed);
	gdbr_lock_leave (g);
	return ret;
}

static int change_breakpoint(libgdbr_t *g, bool set, ut64 address, enum Breakpoint type, int size) {
	if (!g || type < BREAKPOINT || type > ACCESS_WATCHPOINT || size < 1) {
		return -1;
	}
	int ret = -1;
	if (gdbr_lock_enter (g)) {
		r_strf_var (packet, 64, "%c%d,%"PFMT64x",%x", set? 'Z': 'z', type, address, (unsigned int)size);
		if (send_msg (g, packet) >= 0 && read_packet (g, false) >= 0) {
			ret = handle_setbp (g);
		}
	}
	gdbr_lock_leave (g);
	return ret;
}

int gdbr_set_bp(libgdbr_t *g, ut64 address, const char *conditions, int sizebp) {
	return change_breakpoint (g, true, address, BREAKPOINT, sizebp);
}

int gdbr_set_hwbp(libgdbr_t *g, ut64 address, const char *conditions, int sizebp) {
	return change_breakpoint (g, true, address, HARDWARE_BREAKPOINT, sizebp);
}

int gdbr_set_hww(libgdbr_t *g, ut64 address, const char *conditions, int sizebp) {
	return change_breakpoint (g, true, address, WRITE_WATCHPOINT, sizebp);
}

int gdbr_set_hwr(libgdbr_t *g, ut64 address, const char *conditions, int sizebp) {
	return change_breakpoint (g, true, address, READ_WATCHPOINT, sizebp);
}

int gdbr_set_hwa(libgdbr_t *g, ut64 address, const char *conditions, int sizebp) {
	return change_breakpoint (g, true, address, ACCESS_WATCHPOINT, sizebp);
}

int gdbr_remove_bp(libgdbr_t *g, ut64 address, int sizebp) {
	return change_breakpoint (g, false, address, BREAKPOINT, sizebp);
}
int gdbr_remove_hwbp(libgdbr_t *g, ut64 address, int sizebp) {
	return change_breakpoint (g, false, address, HARDWARE_BREAKPOINT, sizebp);
}

int gdbr_remove_hww(libgdbr_t *g, ut64 address, int sizebp) {
	return change_breakpoint (g, false, address, WRITE_WATCHPOINT, sizebp);
}

int gdbr_remove_hwr(libgdbr_t *g, ut64 address, int sizebp) {
	return change_breakpoint (g, false, address, READ_WATCHPOINT, sizebp);
}

int gdbr_remove_hwa(libgdbr_t *g, ut64 address, int sizebp) {
	return change_breakpoint (g, false, address, ACCESS_WATCHPOINT, sizebp);
}


int gdbr_open_file(libgdbr_t *g, const char *filename, int flags, int mode) {
	int ret = -1;

	if (!g || R_STR_ISEMPTY (filename)) {
		return -1;
	}
	if (g->remote_file_fd >= 0) {
		R_LOG_ERROR ("%s: Remote file already open", __func__);
		return -1;
	}
	size_t buf_len = (strlen (filename) * 2) + strlen ("vFile:open:") + 30;
	char *buf = calloc (buf_len, sizeof (char));
	if (!buf) {
		return -1;
	}

	if (!gdbr_lock_enter (g)) {
		goto end;
	}
	r_str_ncpy (buf, "vFile:open:", buf_len);
	pack_hex (filename, strlen (filename), buf + strlen (buf));
	snprintf (buf + strlen (buf), buf_len - strlen (buf) - 1, ",%x,%x", flags, mode);
	if ((ret = send_msg (g, buf)) < 0) {
		goto end;
	}
	read_packet (g, false);
	if ((ret = handle_vFile_open (g)) < 0) {
		goto end;
	}

	ret = 0;
end:
	free (buf);
	gdbr_lock_leave (g);
	return ret;
}

int gdbr_read_file(libgdbr_t *g, ut8 *buf, ut64 max_len) {
	R_RETURN_VAL_IF_FAIL (g && buf && max_len, -1);
	int ret, ret1;
	char command[64];
	ut64 data_sz;
	ret = 0;
	if (max_len >= INT32_MAX) {
		R_LOG_ERROR ("%s: Too big a file read requested: %"PFMT64d, __func__, max_len);
		return -1;
	}
	if (g->remote_file_fd < 0) {
		R_LOG_ERROR ("%s: No remote file opened", __func__);
		return -1;
	}

	if (!gdbr_lock_enter (g)) {
		goto end;
	}
	data_sz = g->stub_features.pkt_sz / 2;
	if (!data_sz) {
		ret = -1;
		goto end;
	}
	ret = 0;
	while (ret < max_len) {
		if ((ret1 = snprintf (command, sizeof (command) - 1,
			    "vFile:pread:%x,%"PFMT64x",%"PFMT64x,
			    (int)g->remote_file_fd, (ut64)R_MIN(data_sz, max_len - ret),
			    (ut64)ret)) < 0) {
			ret = -1;
			goto end;
		}
		if (send_msg (g, command) < 0) {
			ret = -1;
			goto end;
		}
		if (read_packet (g, false) < 0) {
			ret = -1;
			goto end;
		}
		if ((ret1 = handle_vFile_pread (g, buf + ret, max_len - ret)) < 0) {
			ret = ret1;
			goto end;
		}
		if (ret1 == 0) {
			goto end;
		}
		ret += ret1;
	}
end:
	gdbr_lock_leave (g);
	return ret;
}

int gdbr_close_file(libgdbr_t *g) {
	int ret = -1;
	char buf[64];

	if (!g) {
		return -1;
	}
	if (g->remote_file_fd < 0) {
		R_LOG_ERROR ("%s: No remote file opened", __func__);
		return -1;
	}

	if (!gdbr_lock_enter (g)) {
		goto end;
	}
	snprintf (buf, sizeof (buf) - 1, "vFile:close:%x", g->remote_file_fd);
	if ((ret = send_msg (g, buf)) < 0) {
		goto end;
	}
	read_packet (g, false);
	if ((ret = handle_vFile_close (g)) < 0) {
		goto end;
	}
	g->remote_file_fd = -1;

	ret = 0;
end:
	gdbr_lock_leave (g);
	return ret;
}

void gdbr_invalidate_reg_cache(libgdbr_t *g) {
	R_RETURN_IF_FAIL (g);
	gdbr_regs_invalidate (g);
}

int gdbr_send_qRcmd(libgdbr_t *g, const char *cmd, RStrBuf *output) {
	int ret = -1;
	char *buf;
	size_t len;

	if (!g || !cmd || !output) {
		return -1;
	}
	len = strlen (cmd) * 2 + 8;
	if (!(buf = calloc (len, sizeof (char)))) {
		return -1;
	}
	strcpy (buf, "qRcmd,");

	if (!gdbr_lock_enter (g)) {
		goto end;
	}
	g->stop_reason.is_valid = false;
	gdbr_regs_invalidate (g);
	pack_hex (cmd, strlen (cmd), buf + 6);
	if ((ret = send_msg (g, buf)) < 0) {
		goto end;
	}
	if ((ret = read_packet (g, false)) < 0) {
		goto end;
	}
	while (1) {
		if (g->data_len == 0) {
			ret = -1;
			goto end;
		}
		if (g->data_len == 3 && g->data[0] == 'E'
			    && isxdigit ((unsigned char)g->data[1]) && isxdigit ((unsigned char)g->data[2])) {
			ret = -1;
			goto end;
		}
		if (g->data_len == 2 && !memcmp (g->data, "OK", 2)) {
			break;
		}
		size_t length;
		if (!decode_console_output (g, &length) || !r_strbuf_append_n (output, g->data + 1, length)) {
			ret = -1;
			goto end;
		}
		if ((ret = read_packet (g, false)) < 0) {
			goto end;
		}
	}

	ret = 0;
end:
	free (buf);
	gdbr_lock_leave (g);
	return ret;
}

char *gdbr_read_xfer(libgdbr_t *g, const char *object, const char *annex, size_t limit, size_t *size) {
	if (size) {
		*size = 0;
	}
	if (!g || g->stub_features.pkt_sz <= 2) {
		return NULL;
	}
	if (!gdbr_lock_enter (g)) {
		gdbr_lock_leave (g);
		return NULL;
	}
	const ut32 chunk = g->stub_features.pkt_sz - 2;
	RStrBuf request;
	r_strbuf_init (&request);
	RStrBuf *reply = r_strbuf_new ("");
	char *result = NULL;
	size_t offset = 0;
	while (reply) {
		const char *packet = r_strbuf_setf (&request, "qXfer:%s:read:%s:%"PFMT64x",%x",
			object, annex, (ut64)offset, chunk);
		if (!packet || send_msg (g, packet) < 0 || read_packet (g, false) < 0 || !g->data_len) {
			break;
		}
		const char status = g->data[0];
		const size_t count = g->data_len - 1;
		if ((status != 'l' && (status != 'm' || !count)) || count > chunk || count > limit - offset
		    || memchr (g->data + 1, '\0', count) || !r_strbuf_append_n (reply, g->data + 1, count)) {
			break;
		}
		offset += count;
		if (status == 'l') {
			if (offset) {
				result = r_strbuf_drain (reply);
				reply = NULL;
				if (result && size) {
					*size = offset;
				}
			}
			break;
		}
	}
	r_strbuf_free (reply);
	r_strbuf_fini (&request);
	gdbr_lock_leave (g);
	return result;
}

char *gdbr_exec_file_read(libgdbr_t *g, int pid) {
	char annex[16] = {0};
	if (g && g->stub_features.multiprocess && pid > 0) {
		snprintf (annex, sizeof (annex), "%x", (unsigned int)pid);
	}
	return gdbr_read_xfer (g, "exec-file", annex, GDBR_PATH_MAX, NULL);
}

static bool query_thread_address(libgdbr_t *g, const char *query, const char *suffix, ut64 *address) {
	bool ok = false;
	if (gdbr_lock_enter (g)) {
		char thread[32];
		if (g->tid > 0 && write_thread_id (thread, sizeof (thread), g->pid, g->tid, g->stub_features.multiprocess) >= 0) {
			r_strf_var (packet, 96, "%s:%s%s", query, thread, suffix);
			if (send_msg (g, packet) >= 0 && read_packet (g, false) >= 0 && !reply_refused (g)) {
				ut64 value;
				const char *end = gdbr_parse_hex_value (g->data, &value);
				if (end == g->data + g->data_len) {
					*address = value;
					ok = true;
				}
			}
		}
	}
	gdbr_lock_leave (g);
	return ok;
}

bool gdbr_get_tls_addr(libgdbr_t *g, ut64 module, ut64 offset, ut64 *address) {
	r_strf_var (suffix, 36, ",%"PFMT64x",%"PFMT64x, offset, module);
	return query_thread_address (g, "qGetTLSAddr", suffix, address);
}

bool gdbr_get_tib_addr(libgdbr_t *g, ut64 *address) {
	return query_thread_address (g, "qGetTIBAddr", "", address);
}

bool gdbr_catch_syscalls(libgdbr_t *g, bool enable, const ut32 *numbers, size_t count) {
	if (!g || !g->stub_features.QCatchSyscalls || (count && (!enable || !numbers))
	    || count > g->stub_features.pkt_sz / 2) {
		return false;
	}
	RStrBuf packet;
	r_strbuf_init (&packet);
	size_t i;
	bool ok = r_strbuf_append (&packet, enable? "QCatchSyscalls:1": "QCatchSyscalls:0");
	for (i = 0; ok && i < count; i++) {
		ok = r_strbuf_appendf (&packet, ";%"PFMT32x, numbers[i]);
	}
	if (ok) {
		ok = gdbr_lock_enter (g) && send_msg (g, r_strbuf_get (&packet)) >= 0 && read_packet (g, false) >= 0
			&& g->data_len == 2 && !memcmp (g->data, "OK", 2);
		gdbr_lock_leave (g);
	}
	r_strbuf_fini (&packet);
	return ok;
}

bool gdbr_is_thread_dead(libgdbr_t *g, int pid, int tid) {
	bool ret = false;

	if (!g) {
		return false;
	}
	if (g->stub_features.multiprocess && pid <= 0) {
		return false;
	}

	if (!gdbr_lock_enter (g)) {
		goto end;
	}
	char msg[64] = {0}, thread_id[63] = { 0 };
	if (write_thread_id (thread_id, sizeof (thread_id) - 1, pid, tid,
		    g->stub_features.multiprocess) < 0) {
		goto end;
	}
	if (snprintf (msg, sizeof (msg) - 1, "T%s", thread_id) < 0) {
		goto end;
	}
	if (send_msg (g, msg) < 0 || read_packet (g, false) < 0) {
		goto end;
	}
	ret = (g->data_len == 3 && g->data[0] == 'E');
end:
	gdbr_lock_leave (g);
	return ret;
}

RList* gdbr_pids_list(libgdbr_t *g, int pid) {
	int ret = -1;
	RList *list = NULL;
	int tpid = -1, ttid = -1;
	size_t nids = 0;
	char *ptr, *ptr2, *exec_file;
	RDebugPid *dpid = NULL;
	RListIter *iter = NULL;

	if (!g) {
		return NULL;
	}

	if (!gdbr_lock_enter (g)) {
		goto end;
	}
	if (!(list = r_list_new ())) {
		ret = -1;
		goto end;
	}
	// Use qfThreadInfo as a fallback since it doesn't actually show all children
	if (g->stub_features.qXfer_osdata_read) {
		if (gdbr_read_processes_xml (g, pid, list) == 0) {
			ret = 0;
			goto end;
		}
	}
	// Child processes will only show up in ThreadInfo if gdbr is currently processing a
	// fork/vfork/exec event or if the children weren't detached yet. This is intended
	// gdb `info inferiors` behavior that can only be avoided using xml.
	R_LOG_WARN ("Showing possibly incomplete pid list due to xml protocol failure");

	if (!g->stub_features.qXfer_exec_file_read
		    || !(exec_file = gdbr_exec_file_read (g, pid))) {
		exec_file = "";
	}
	if (send_msg (g, "qfThreadInfo") < 0 || read_packet (g, false) < 0
		    || g->data_len == 0 || g->data[0] != 'm') {
		ret = -1;
		goto end;
	}
	while (1) {
		g->data[g->data_len] = '\0';
		ptr = g->data + 1;
		while (ptr) {
			if (++nids > GDBR_THREADS_MAX) {
				ret = -1;
				goto end;
			}
			if ((ptr2 = strchr (ptr, ','))) {
				*ptr2 = '\0';
				ptr2++;
			}
			if (read_thread_id (ptr, &tpid, &ttid, g->stub_features.multiprocess) < 0) {
				ptr = ptr2;
				continue;
			}
			// Avoid adding the same pid twice(could show more than once if it has threads)
			r_list_foreach (list, iter, dpid) {
				if (tpid == dpid->pid) {
					continue;
				}
			}
			dpid = R_NEW0 (RDebugPid);
			if (!(dpid->path = strdup (exec_file))) {
				ret = -1;
				goto end;
			}
			dpid->pid = tpid;
			// If the pid isn't the debugged pid it must be a child pid
			if (tpid != g->pid) {
				dpid->ppid = g->pid;
			}
			dpid->uid = dpid->gid = -1;
			dpid->runnable = true;
			dpid->status = R_DBG_PROC_STOP;
			r_list_append (list, dpid);
			dpid = NULL;
			ptr = ptr2;
		}
		if (send_msg (g, "qsThreadInfo") < 0 || read_packet (g, false) < 0
			    || g->data_len == 0
			    || (g->data[0] != 'm' && g->data[0] != 'l')) {
			ret = -1;
			goto end;
		}
		if (g->data[0] == 'l') {
			break;
		}
	}

	ret = 0;
end:
	gdbr_lock_leave (g);
	if (ret != 0) {
		if (dpid) {
			free (dpid->path);
			free (dpid);
		}
		// We can't use r_debug_pid_free here
		if (list) {
			r_list_foreach (list, iter, dpid) {
				free (dpid->path);
				free (dpid);
			}
			r_list_free (list);
		}
		return NULL;
	}
	return list;
}

RList* gdbr_threads_list(libgdbr_t *g, int pid) {
	int ret = -1;
	RList *list = NULL;
	int tpid = -1, ttid = -1;
	size_t nids = 0;
	char *ptr, *ptr2, *exec_file;
	RDebugPid *dpid = NULL;
	RListIter *iter = NULL;

	if (!g) {
		return NULL;
	}

	if (!gdbr_lock_enter (g)) {
		goto end;
	}
	if (!g->stub_features.qXfer_exec_file_read
		    || !(exec_file = gdbr_exec_file_read (g, pid))) {
		exec_file = "";
	}
	if (g->stub_features.qXfer_threads_read) {
		// XML thread description is supported
		// TODO: Handle this case
	}
	if (send_msg (g, "qfThreadInfo") < 0 || read_packet (g, false) < 0
		    || g->data_len == 0 || g->data[0] != 'm') {
		ret = -1;
		goto end;
	}
	if (!(list = r_list_new ())) {
		ret = -1;
		goto end;
	}
	while (1) {
		g->data[g->data_len] = '\0';
		ptr = g->data + 1;
		while (ptr) {
			if (++nids > GDBR_THREADS_MAX) {
				ret = -1;
				goto end;
			}
			if ((ptr2 = strchr (ptr, ','))) {
				*ptr2 = '\0';
				ptr2++;
			}
			if (read_thread_id (ptr, &tpid, &ttid,
				    g->stub_features.multiprocess) < 0) {
				ptr = ptr2;
				continue;
			}
			if (g->stub_features.multiprocess && tpid != pid) {
				ptr = ptr2;
				continue;
			}
			dpid = R_NEW0 (RDebugPid);
			if (!(dpid->path = strdup (exec_file))) {
				ret = -1;
				goto end;
			}
			dpid->uid = dpid->gid = -1; // TODO
			dpid->pid = ttid;
			dpid->runnable = true;
			// This is what linux native does as fallback, but
			// probably not correct.
			// TODO: Implement getting correct thread status from GDB
			dpid->status = R_DBG_PROC_STOP;
			r_list_append (list, dpid);
			dpid = NULL;
			ptr = ptr2;
		}
		if (send_msg (g, "qsThreadInfo") < 0 || read_packet (g, false) < 0
			    || g->data_len == 0
			    || (g->data[0] != 'm' && g->data[0] != 'l')) {
			ret = -1;
			goto end;
		}
		if (g->data[0] == 'l') {
			break;
		}
	}
	// This is the all I've been able to extract from gdb so far
	r_list_foreach (list, iter, dpid) {
		if (gdbr_is_thread_dead (g, pid, dpid->pid)) {
			dpid->status = R_DBG_PROC_DEAD;
		}
	}

	ret = 0;
end:
	gdbr_lock_leave (g);
	if (ret != 0) {
		if (dpid) {
			free (dpid->path);
			free (dpid);
		}
		// We can't use r_debug_pid_free here
		if (list) {
			r_list_foreach (list, iter, dpid) {
				free (dpid->path);
				free (dpid);
			}
			r_list_free (list);
		}
		return NULL;
	}
	return list;
}

ut64 gdbr_get_baddr(libgdbr_t *g) {
	ut64 off, min = UT64_MAX;
	char *ptr;
	if (!g) {
		return UT64_MAX;
	}

	if (!gdbr_lock_enter (g)) {
		goto end;
	}
	if (send_msg (g, "qOffsets") < 0 || read_packet (g, false) < 0
		    || g->data_len == 0) {
		min = UT64_MAX;
		goto end;
	}
	if (r_str_startswith (g->data, "TextSeg=")) {
		ptr = g->data + strlen ("TextSeg=");
		if (!isxdigit ((unsigned char)*ptr)) {
			goto end;
		}
		off = strtoull (ptr, NULL, 16);
		if (off < min) {
			min = off;
		}
		if (!(ptr = strchr (ptr, ';'))) {
			goto end;
		}
		ptr++;
		if (*ptr && r_str_startswith (ptr, "DataSeg=")) {
			ptr += strlen ("DataSeg=");
			if (!isxdigit ((unsigned char)*ptr)) {
				goto end;
			}
			off = strtoull (ptr, NULL, 16);
			if (off < min) {
				min = off;
			}
		}
		goto end;
	}
	if (!r_str_startswith (g->data, "Text=")) {
		goto end;
	}
	ptr = g->data + strlen ("Text=");
	if (!isxdigit ((unsigned char)*ptr)) {
		goto end;
	}
	off = strtoull (ptr, NULL, 16);
	if (off < min) {
		min = off;
	}
	if (!(ptr = strchr (ptr, ';')) || !r_str_startswith (ptr + 1, "Data=")) {
		min = UT64_MAX;
		goto end;
	}
	ptr += strlen (";Data=");
	if (!isxdigit ((unsigned char)*ptr)) {
		min = UT64_MAX;
		goto end;
	}
	off = strtoull (ptr, NULL, 16);
	if (off < min) {
		min = off;
	}
	if (!(ptr = strchr (ptr, ';'))) {
		goto end;
	}
	ptr++;
	if (r_str_startswith (ptr, "Bss=")) {
		ptr += strlen ("Bss=");
		if (!isxdigit ((unsigned char)*ptr)) {
			goto end;
		}
		off = strtoull (ptr, NULL, 16);
		if (off < min) {
			min = off;
		}
	}
end:
	gdbr_lock_leave (g);
	return min;
}
