/* libgdbr - LGPL - Copyright 2014-2018 - defragger */

#include "gdbclient/responses.h"
#include "gdbclient/commands.h"
#include "gdbclient/core.h"
#include "gdbclient/xml.h"
#include "arch.h"
#include "libgdbr.h"
#include "gdbr_common.h"
#include "packet.h"
#include "r_util/r_strbuf.h"
#include "r_cons.h"
#include "r_debug.h"

#if __UNIX__
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <termios.h>
#endif

#if __UNIX__
#include <signal.h>
#endif

#include <assert.h>

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

static struct {
	ut8 *buf;
	ut64 buflen, maxlen;
	bool valid, init;
} reg_cache;

static void reg_cache_init(libgdbr_t *g) {
	reg_cache.maxlen = g->data_max;
	reg_cache.buflen = 0;
	reg_cache.valid = false;
	reg_cache.init = false;
	if ((reg_cache.buf = malloc (reg_cache.maxlen))) {
		reg_cache.init = true;
	}
}

static void gdbr_break_process(void *arg) {
	libgdbr_t *g = (libgdbr_t *)arg;
	(void)g;
	g->isbreaked = true;
}

bool gdbr_lock_tryenter(libgdbr_t *g) {
	if (!r_th_lock_tryenter (g->gdbr_lock)) {
		return false;
	}
	g->gdbr_lock_depth++;
	r_cons_break_push (gdbr_break_process, g);
	return true;
}

bool gdbr_lock_enter(libgdbr_t *g) {
	r_cons_break_push (gdbr_break_process, g);
	void *bed = r_cons_sleep_begin ();
	r_th_lock_enter (g->gdbr_lock);
	g->gdbr_lock_depth++;
	r_cons_sleep_end (bed);
	if (g->isbreaked) {
		return false;
	}
	return true;
}

void gdbr_lock_leave(libgdbr_t *g) {
	r_cons_break_pop ();
	assert (g->gdbr_lock_depth > 0);
	bool last_leave = g->gdbr_lock_depth == 1;
	g->gdbr_lock_depth--;
	r_th_lock_leave (g->gdbr_lock);
	// if this is the last lock this thread holds make sure that we disable the break
	if (last_leave) {
		g->isbreaked = false;
	}
}

static int gdbr_connect_lldb(libgdbr_t *g) {
	int ret = -1;
	if (!gdbr_lock_enter (g)) {
		goto end;
	}
	reg_cache_init (g);
	if (g->stub_features.qXfer_features_read) {
		gdbr_read_target_xml (g);
	}
	// Check if 'g' packet is supported
	if (send_msg (g, "g") < 0 || read_packet (g, false) < 0 || send_ack (g) < 0) {
		ret = -1;
		goto end;
	}
	if (g->data_len == 0 || (g->data_len == 3 && g->data[0] == 'E')) {
		ret = -1;
		goto end;
	}
	g->stub_features.lldb.g = true;

	ret = 0;
end:
	gdbr_lock_leave (g);
	return ret;
}

int gdbr_connect(libgdbr_t *g, const char *host, int port) {
	const char *message = "qSupported:multiprocess+;qRelocInsn+;xmlRegisters=i386";
	int i;
	int ret = -1;
	void *bed = NULL;

	if (!g || !host) {
		return -1;
	}
	if (!gdbr_lock_enter (g)) {
		goto end;
	}
	// Initial max_packet_size for remote target (minimum so far for AVR = 64)
	g->stub_features.pkt_sz = 64;
	char *env_pktsz_str;
	ut32 env_pktsz = 0;
	if ((env_pktsz_str = r_sys_getenv ("R2_GDB_PKTSZ"))) {
		if ((env_pktsz = (ut32)strtoul (env_pktsz_str, NULL, 10))) {
			g->stub_features.pkt_sz = R_MAX (env_pktsz, GDB_MAX_PKTSZ);
		}
	}
	// Use the default break handler for r_socket_connect to send a signal
	r_cons_break_pop ();
	bed = r_cons_sleep_begin ();
	if (*host == '/') {
		ret = r_socket_connect_serial (g->sock, host, port, 1);
	} else {
		ret = r_socket_connect_tcp (g->sock, host, sdb_fmt ("%d", port), 1);
	}
	r_cons_sleep_end (bed);
	r_cons_break_push (gdbr_break_process, g);
	if (!ret) {
		ret = -1;
		goto end;
	}
	if ((ret = send_ack (g)) < 0) {
		goto end;
	}
	read_packet (g, true); // vcont=true lets us skip if we get no reply
	g->connected = 1;
	bed = r_cons_sleep_begin ();
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
	r_cons_sleep_end (bed);
	if (g->isbreaked) {
		g->isbreaked = false;
		ret = -1;
		goto end;
	}
	if (ret < 0) {
		goto end;
	}
	if (env_pktsz > 0) {
		g->stub_features.pkt_sz = R_MAX (R_MIN (env_pktsz, g->stub_features.pkt_sz), GDB_MAX_PKTSZ);
	}
	// If no-ack supported, enable no-ack mode (should speed up things)
	if (g->stub_features.QStartNoAckMode) {
		if ((ret = send_msg (g, "QStartNoAckMode")) < 0) {
			goto end;
		}
		read_packet (g, false);
		if (!strncmp (g->data, "OK", 2)) {
			// Just in case, send ack
			send_ack (g);
			g->no_ack = true;
		}
	}
	if (g->remote_type == GDB_REMOTE_TYPE_LLDB) {
		if ((ret = gdbr_connect_lldb (g)) < 0) {
			goto end;
		}
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
	read_packet (g, false);
	ret = send_ack (g);
	if (ret < 0) {
		goto end;
	}
	if (strcmp (g->data, "OK")) {
		// return -1;
	}
	if (g->stub_features.qXfer_features_read) {
		gdbr_read_target_xml (g);
	}
	reg_cache_init (g);

	ret = 0;
end:
	if (ret != 0) {
		r_socket_close (g->sock);
	}
	gdbr_lock_leave (g);
	return ret;
}

int gdbr_disconnect(libgdbr_t *g) {
	// TODO Disconnect maybe send something to gdbserver
	if (!g || !r_socket_close (g->sock)) {
		return -1;
	}
	if (!gdbr_lock_enter (g)) {
		goto end;
	}
	reg_cache.valid = false;
	g->stop_reason.is_valid = false;
	free (reg_cache.buf);
	if (g->target.valid) {
		free (g->target.regprofile);
		free (g->registers);
	}
	g->connected = 0;
end:
	gdbr_lock_leave (g);
	return 0;
}

int gdbr_select(libgdbr_t *g, int pid, int tid) {
	char cmd[64] = { 0 };
	int ret = -1;

	if (!gdbr_lock_enter (g)) {
		goto end;
	}
	reg_cache.valid = false;
	g->pid = pid;
	g->tid = tid;
	strcpy (cmd, "Hg");
	if ((ret = write_thread_id (cmd + 2, sizeof (cmd) - 3, pid, tid,
		    g->stub_features.multiprocess)) < 0) {
		goto end;
	}
	g->stop_reason.is_valid = false;
	if (send_msg (g, cmd) < 0 || read_packet (g, false) < 0 || send_ack (g) < 0) {
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

	if (!g) {
		return -1;
	}

	if (!gdbr_lock_enter (g)) {
		goto end;
	}
	if (send_msg (g, "vCont?") < 0 || read_packet (g, false) < 0 || send_ack (g) < 0) {
		ret = -1;
		goto end;
	}
	if (g->data_len == 0) {
		g->stub_features.vContSupported = false;
		ret = 0;
		goto end;
	}
	g->data[g->data_len] = '\0';
	if (!(ptr = strtok (g->data + strlen ("vCont;"), ";"))) {
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
		ptr = strtok (NULL, ";");
	}

	ret = 0;
end:
	gdbr_lock_leave (g);
	return ret;
}

int gdbr_stop_reason(libgdbr_t *g) {
	int ret = -1;
	if (!gdbr_lock_enter (g)) {
		goto end;
	}
	if (!g || send_msg (g, "?") < 0 || read_packet (g, false) < 0) {
		ret = -1;
		goto end;
	}
	ret = handle_stop_reason (g);
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
	reg_cache.valid = false;
	// Activate extended mode if possible.
	ret = send_msg (g, "!");
	if (ret < 0) {
		g->stub_features.extended_mode = 0;
		goto end;
	}
	read_packet (g, false);
	ret = send_ack (g);
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
	reg_cache.valid = false;

	if (g->stub_features.extended_mode == -1) {
		gdbr_check_extended_mode (g);
	}

	if (!g->stub_features.extended_mode) {
		// vAttach needs extended mode to do anything.
		ret = -2;
		goto end;
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

	if (read_packet (g, false) < 0) {
		ret = -1;
		goto end;
	}

	ret = handle_attach (g);
end:
	if (cmd) {
		free (cmd);
	}
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

	reg_cache.valid = false;
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

	reg_cache.valid = false;
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

	read_packet (g, false);
	if ((ret = send_ack (g)) < 0) {
		goto end;
	}

	if (strncmp (g->data, "OK", 2)) {
		ret = -1;
		goto end;
	}

	ret = 0;
end:
	if (cmd) {
		free (cmd);
	}
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

	reg_cache.valid = false;
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

	reg_cache.valid = false;
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

	read_packet (g, false);
	if ((ret = send_ack (g)) < 0) {
		goto end;
	}
	if (strncmp (g->data, "OK", 2)) {
		ret = -1;
		goto end;
	}

end:
	if (cmd) {
		free (cmd);
	}
	gdbr_lock_leave (g);
	return ret;
}

static int gdbr_read_registers_lldb(libgdbr_t *g) {
	// Send the stop reply query packet and get register info
	// (this is what lldb does)
	int ret = -1;

	if (!g || !g->sock) {
		return -1;
	}

	if (!gdbr_lock_enter (g)) {
		goto end;
	}

	if (send_msg (g, "?") < 0 || read_packet (g, false) < 0) {
		ret = -1;
		goto end;
	}
	if ((ret = handle_lldb_read_reg (g)) < 0) {
		goto end;
	}
	if (reg_cache.init) {
		reg_cache.buflen = g->data_len;
		memcpy (reg_cache.buf, g->data, reg_cache.buflen);
		reg_cache.valid = true;
	}

	ret = 0;
end:
	gdbr_lock_leave (g);
	return ret;
}

int gdbr_read_registers(libgdbr_t *g) {
	int ret = -1;

	if (!g || !g->data) {
		return -1;
	}
	if (reg_cache.init && reg_cache.valid) {
		g->data_len = reg_cache.buflen;
		memcpy (g->data, reg_cache.buf, reg_cache.buflen);
		return 0;
	}
	// Don't wait on the lock in read_registers since it's frequently called, including
	// each time "enter" is pressed. Otherwise the user will be forced to interrupt exit
	// read_registers constantly while another task is in progress
	if (!gdbr_lock_tryenter (g)) {
		return -1;
	}

	if (g->remote_type == GDB_REMOTE_TYPE_LLDB && !g->stub_features.lldb.g) {
		ret = gdbr_read_registers_lldb (g);
		goto end;
	}
	if ((ret = send_msg (g, CMD_READREGS)) < 0) {
		goto end;
	}
	if (read_packet (g, false) < 0 || handle_g (g) < 0) {
		ret = -1;
		goto end;
	}
	if (reg_cache.init) {
		reg_cache.buflen = g->data_len;
		memset (reg_cache.buf, 0, reg_cache.buflen);
		memcpy (reg_cache.buf, g->data, reg_cache.buflen);
		reg_cache.valid = true;
	}

	ret = 0;
end:
	gdbr_lock_leave (g);
	return ret;
}

static int gdbr_read_memory_page(libgdbr_t *g, ut64 address, ut8 *buf, int len) {
	char command[128] = { 0 };
	int last, ret_len, pkt;
	ret_len = 0;

	if (!g) {
		return -1;
	}
	if (len < 1) {
		return len;
	}

	if (!gdbr_lock_enter (g)) {
		goto end;
	}

	g->stub_features.pkt_sz = R_MAX (g->stub_features.pkt_sz, GDB_MAX_PKTSZ);
	int data_sz = g->stub_features.pkt_sz / 2;
	int num_pkts = len / data_sz;
	last = len % data_sz;
	ret_len = 0;
	for (pkt = 0; pkt < num_pkts; pkt++) {
		if (snprintf (command, sizeof (command) - 1,
			    "%s%"PFMT64x ",%"PFMT64x, CMD_READMEM,
			    (ut64)address + (pkt * data_sz),
			    (ut64)data_sz) < 0) {
			ret_len = -1;
			goto end;
		}
		if (send_msg (g, command) < 0) {
			ret_len = -1;
			goto end;
		}
		if (read_packet (g, false) < 0) {
			ret_len = -1;
			goto end;
		}
		if (handle_m (g) < 0) {
			ret_len = -1;
			goto end;
		}
		int delta = (pkt * data_sz);

		if (delta > len) {
			eprintf ("oops\n");
			break;
		}
		int left = R_MIN (g->data_len, len - delta);
		if (left > 0) {
			memcpy (buf + delta, g->data, left);
			ret_len += g->data_len;
		}
	}
	if (last) {
		if (snprintf (command, sizeof (command) - 1,
			    "%s%016"PFMT64x ",%"PFMT64x, CMD_READMEM,
			    (ut64)(address + (num_pkts * data_sz)),
			    (ut64)last) < 0) {
			ret_len = -1;
			goto end;
		}
		if (send_msg (g, command) < 0) {
			ret_len = -1;
			goto end;
		}
		if (read_packet (g, false) < 0) {
			ret_len = -1;
			goto end;
		}
		if (handle_m (g) < 0) {
			ret_len = -1;
			goto end;
		}
		int delta = num_pkts * data_sz;
		int left = R_MIN (g->data_len, len - delta);
		if (left > 0) {
			memcpy (buf + delta, g->data, left);
			ret_len += g->data_len;
		}
	}
end:
	gdbr_lock_leave (g);
	return ret_len;
}

int gdbr_read_memory(libgdbr_t *g, ut64 address, ut8 *buf, int len) {
	int ret_len, ret, tmp;
	int page_size = g->page_size;
	ret_len = 0;

	if (!gdbr_lock_enter (g)) {
		goto end;
	}

	// Read and round up to page size
	tmp = page_size - (address & (page_size - 1));
	if (tmp >= len) {
		ret_len = gdbr_read_memory_page (g, address, buf, len);
		goto end;
	}
	if ((ret = gdbr_read_memory_page (g, address, buf, tmp)) != tmp) {
		ret_len = ret;
		goto end;
	}
	len -= tmp;
	address += tmp;
	buf += tmp;
	ret_len += ret;
	// Read complete pages
	while (len > page_size) {
		if ((ret = gdbr_read_memory_page (g, address, buf, page_size)) != page_size) {
			if (ret < 1) {
				goto end;
			}
			ret_len += ret;
			goto end;
		}
		len -= page_size;
		address += page_size;
		buf += page_size;
		ret_len += page_size;
	}
	// Read left-overs
	if ((ret = gdbr_read_memory_page (g, address, buf, len)) < 0) {
		goto end;
	}

	ret_len += ret;
end:
	gdbr_lock_leave (g);
	return ret_len;
}

int gdbr_write_memory(libgdbr_t *g, ut64 address, const uint8_t *data, ut64 len) {
	int ret = -1;
	int command_len, pkt, max_cmd_len = 64;
	ut64 num_pkts, last, data_sz;
	char *tmp;
	if (!g || !data) {
		return -1;
	}
	g->stub_features.pkt_sz = R_MAX (g->stub_features.pkt_sz, GDB_MAX_PKTSZ);
	data_sz = g->stub_features.pkt_sz / 2;
	if (data_sz < 1) {
		return -1;
	}
	num_pkts = len / data_sz;
	last = len % data_sz;
	if (!(tmp = calloc (max_cmd_len + g->stub_features.pkt_sz, sizeof (char)))) {
		return -1;
	}

	if (!gdbr_lock_enter (g)) {
		goto end;
	}

	for (pkt = num_pkts - 1; pkt >= 0; pkt--) {
		if ((command_len = snprintf (tmp, max_cmd_len,
			    "%s%016"PFMT64x ",%"PFMT64x ":", CMD_WRITEMEM,
			    address + (pkt * data_sz), data_sz)) < 0) {
			ret = -1;
			goto end;
		}
		pack_hex ((char *)data + (pkt * data_sz), data_sz, (tmp + command_len));
		if ((ret = send_msg (g, tmp)) < 0) {
			goto end;
		}
		if ((ret = read_packet (g, false)) < 0) {
			goto end;
		}
		if ((ret = handle_M (g)) < 0) {
			goto end;
		}
	}
	if (last) {
		if ((command_len = snprintf (tmp, max_cmd_len,
			    "%s%016"PFMT64x ",%"PFMT64x ":", CMD_WRITEMEM,
			    address + (num_pkts * data_sz), last)) < 0) {
			ret = -1;
			goto end;
		}
		pack_hex ((char *)data + (num_pkts * data_sz), last, (tmp + command_len));
		if ((ret = send_msg (g, tmp)) < 0) {
			goto end;
		}
		if ((ret = read_packet (g, false)) < 0) {
			goto end;
		}
		if ((ret = handle_M (g)) < 0) {
			goto end;
		}
	}

	ret = 0;
end:
	gdbr_lock_leave (g);
	if (tmp) {
		free (tmp);
	}
	return ret;
}

int gdbr_step(libgdbr_t *g, int tid) {
	int ret = -1;
	char thread_id[64] = { 0 };

	if (!gdbr_lock_enter (g)) {
		goto end;
	}

	if (tid <= 0 || write_thread_id (thread_id, sizeof (thread_id) - 1, g->pid, tid,
		    g->stub_features.multiprocess) < 0) {
		send_vcont (g, "vCont?", NULL);
		send_vcont (g, sdb_fmt ("Hc%d", tid), NULL);
		ret = send_vcont (g, CMD_C_STEP, NULL);
		goto end;
	}

	ret = send_vcont (g, CMD_C_STEP, thread_id);
end:
	gdbr_lock_leave (g);
	return ret;
}

int gdbr_continue(libgdbr_t *g, int pid, int tid, int sig) {
	char thread_id[64] = { 0 };
	char command[16] = { 0 };
	int ret = -1;

	if (!gdbr_lock_enter (g)) {
		goto end;
	}

	if (sig <= 0) {
		strncpy (command, CMD_C_CONT, sizeof (command) - 1);
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
	reg_cache.valid = false;

	command = calloc (buffer_size, sizeof (char));
	if (!command) {
		ret = -1;
		goto end;
	}
	snprintf (command, buffer_size, "%s", CMD_WRITEREGS);
	pack_hex (regs, len, command + 1);
	if (send_msg (g, command) < 0) {
		ret = -1;
		goto end;
	}
	if (read_packet (g, false) >= 0) {
		handle_G (g);
	} else {
		ret = -1;
		goto end;
	}

	ret = 0;
end:
	gdbr_lock_leave (g);
	if (command) {
		free (command);
	}
	return ret;
}

int gdbr_write_register(libgdbr_t *g, int index, char *value, int len) {
	int ret = -1;
	char command[255] = { 0 };
	if (!g || !g->stub_features.P) {
		return -1;
	}
	if (!gdbr_lock_enter (g)) {
		goto end;
	}

	reg_cache.valid = false;
	ret = snprintf (command, sizeof (command) - 1, "%s%x=", CMD_WRITEREG, index);
	if (len + ret >= sizeof (command)) {
		eprintf ("command is too small\n");
		ret = -1;
		goto end;
	}
	// Pad with zeroes
	memset (command + ret, atoi ("0"), len);
	pack_hex (value, len, (command + ret));
	if (send_msg (g, command) < 0) {
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

	reg_cache.valid = false;
	while (g->registers[i].size > 0) {
		if (!strcmp (g->registers[i].name, name)) {
			break;
		}
		i++;
	}
	if (g->registers[i].size == 0) {
		eprintf ("Error registername <%s> not found in profile\n", name);
		ret = -1;
		goto end;
	}
	if (g->stub_features.P && (ret = gdbr_write_register (g, i, value, len)) == 0) {
		goto end;
	}

	// Use 'G' if write_register failed/isn't supported
	gdbr_read_registers (g);
	memcpy (g->data + g->registers[i].offset, value, len);
	gdbr_write_bin_registers (g, g->data, g->data_len);

	ret = 0;
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
	// read current register set
	
	command = buff = value = NULL;

	if (!g) {
		return -1;
	}

	if (!gdbr_lock_enter (g)) {
		goto end;
	}

	gdbr_read_registers (g);
	reg_cache.valid = false;
	len = strlen (registers);
	buff = calloc (len, sizeof (char));
	if (!buff) {
		ret = -1;
		goto end;
	}
	memcpy (buff, registers, len);
	reg = strtok (buff, ",");
	while (reg) {
		char *name_end = strchr (reg, '=');
		if (name_end == NULL) {
			eprintf ("Malformed argument: %s\n", reg);
			ret = -1;
			goto end;
		}
		*name_end = '\0'; // change '=' to '\0'

		// time to find the current register
		while (g->registers[i].size > 0) {
			if (strcmp (g->registers[i].name, reg) == 0) {
				const ut64 register_size = g->registers[i].size;
				const ut64 offset = g->registers[i].offset;
				value = calloc (register_size + 1, 2);
				if (!value) {
					ret = -1;
					goto end;
				}

				memset (value, '0', register_size * 2);
				name_end++;
				// be able to take hex with and without 0x
				if (name_end[1] == 'x' || name_end[1] == 'X') {
					name_end += 2;
				}
				const int val_len = strlen (name_end); // size of the rest
				strcpy (value + (register_size * 2 - val_len), name_end);

				for (x = 0; x < register_size; x++) {
					g->data[offset + register_size - x - 1] = hex2char (&value[x * 2]);
				}
				R_FREE (value);
			}
			i++;
		}
		reg = strtok (NULL, " ,");
	}

	buffer_size = g->data_len * 2 + 8;
	command = calloc (buffer_size, sizeof (char));
	if (!command) {
		ret = -1;
		goto end;
	}
	snprintf (command, buffer_size, "%s", CMD_WRITEREGS);
	pack_hex (g->data, g->data_len, command + 1);
	ret = send_msg (g, command);
	if (ret < 0) {
		goto end;
	}
	read_packet (g, false);
	handle_G (g);

	ret = 0;
end:
	if (command) {
		free (command);
	}
	if (buff) {
		free (buff);
	}
	if (value) {
		free (value);
	}
	gdbr_lock_leave (g);
	return ret;
}

int test_command(libgdbr_t *g, const char *command) {
	int ret = -1;

	if (!gdbr_lock_enter (g)) {
		goto end;
	}

	if ((ret = send_msg (g, command)) < 0) {
		goto end;
	}
	read_packet (g, false);
	hexdump (g->read_buff, g->data_len, 0);

	ret = 0;
end:
	gdbr_lock_leave (g);
	return ret;
}

int send_vcont(libgdbr_t *g, const char *command, const char *thread_id) {
	char tmp[255] = { 0 };
	int ret = -1;
	void *bed = NULL;

	if (!g) {
		return -1;
	}

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
	reg_cache.valid = false;
	g->stop_reason.is_valid = false;
	ret = send_msg (g, tmp);
	if (ret < 0) {
		goto end;
	}

	bed = r_cons_sleep_begin ();
	while ((ret = read_packet (g, true)) < 0 && !g->isbreaked && r_socket_is_connected (g->sock));
	if (g->isbreaked) {
		g->isbreaked = false;
		// Stop target
		r_socket_write (g->sock, "\x03", 1);
		// Read the stop reason
		if (read_packet (g, false) < 0) {
			ret = -1;
			goto end;
		}
	}

	ret = handle_cont (g);
end:
	r_cons_sleep_end (bed);
	gdbr_lock_leave (g);
	return ret;
}

int set_bp(libgdbr_t *g, ut64 address, const char *conditions, enum Breakpoint type, int sizebp) {
	char tmp[255] = { 0 };
	int ret = -1;

	if (!g) {
		return -1;
	}

	switch (type) {
	case BREAKPOINT:
		ret = snprintf (tmp, sizeof (tmp) - 1,
			"%s,%"PFMT64x ",%d", CMD_BP, address, sizebp);
		break;
	case HARDWARE_BREAKPOINT:
		ret = snprintf (tmp, sizeof (tmp) - 1,
			"%s,%"PFMT64x ",%d", CMD_HBP, address, sizebp);
		break;
	case WRITE_WATCHPOINT:
		ret = snprintf (tmp, sizeof (tmp) - 1,
			"%s,%"PFMT64x ",%d", CMD_HWW, address, sizebp);
		break;
	case READ_WATCHPOINT:
		ret = snprintf (tmp, sizeof (tmp) - 1,
			"%s,%"PFMT64x ",%d", CMD_HWR, address, sizebp);
		break;
	case ACCESS_WATCHPOINT:
		ret = snprintf (tmp, sizeof (tmp) - 1,
			"%s,%"PFMT64x ",%d", CMD_HWA, address, sizebp);
		break;
	default:
		break;
	}
	if (ret < 0) {
		return ret;
	}

	if (!gdbr_lock_enter (g)) {
		goto end;
	}

	g->stop_reason.is_valid = false;
	if ((ret = send_msg (g, tmp)) < 0) {
		goto end;
	}

	if ((ret = read_packet (g, false)) < 0) {
		goto end;
	}

	ret = handle_setbp (g);
end:
	gdbr_lock_leave (g);
	return ret;
}

int gdbr_set_bp(libgdbr_t *g, ut64 address, const char *conditions, int sizebp) {
	return set_bp (g, address, conditions, BREAKPOINT, sizebp);
}

int gdbr_set_hwbp(libgdbr_t *g, ut64 address, const char *conditions, int sizebp) {
	return set_bp (g, address, conditions, HARDWARE_BREAKPOINT, sizebp);
}

int gdbr_set_hww(libgdbr_t *g, ut64 address, const char *conditions, int sizebp) {
	return set_bp (g, address, conditions, WRITE_WATCHPOINT, sizebp);
}

int gdbr_set_hwr(libgdbr_t *g, ut64 address, const char *conditions, int sizebp) {
	return set_bp (g, address, conditions, READ_WATCHPOINT, sizebp);
}

int gdbr_set_hwa(libgdbr_t *g, ut64 address, const char *conditions, int sizebp) {
	return set_bp (g, address, conditions, ACCESS_WATCHPOINT, sizebp);
}

int gdbr_remove_bp(libgdbr_t *g, ut64 address, int sizebp) {
	return remove_bp (g, address, BREAKPOINT, sizebp);
}
int gdbr_remove_hwbp(libgdbr_t *g, ut64 address, int sizebp) {
	return remove_bp (g, address, HARDWARE_BREAKPOINT, sizebp);
}

int gdbr_remove_hww(libgdbr_t *g, ut64 address, int sizebp) {
	return remove_bp (g, address, WRITE_WATCHPOINT, sizebp);
}

int gdbr_remove_hwr(libgdbr_t *g, ut64 address, int sizebp) {
	return remove_bp (g, address, READ_WATCHPOINT, sizebp);
}

int gdbr_remove_hwa(libgdbr_t *g, ut64 address, int sizebp) {
	return remove_bp (g, address, ACCESS_WATCHPOINT, sizebp);
}


int remove_bp(libgdbr_t *g, ut64 address, enum Breakpoint type, int sizebp) {
	char tmp[255] = { 0 };
	int ret = -1;

	if (!g) {
		return -1;
	}

	switch (type) {
	case BREAKPOINT:
		ret = snprintf (tmp, sizeof (tmp) - 1, "%s,%"PFMT64x ",%d", CMD_RBP, address, sizebp);
		break;
	case HARDWARE_BREAKPOINT:
		ret = snprintf (tmp, sizeof (tmp) - 1, "%s,%"PFMT64x ",%d", CMD_RHBP, address, sizebp);
		break;
	case WRITE_WATCHPOINT:
		ret = snprintf (tmp, sizeof (tmp) - 1, "%s,%"PFMT64x ",%d", CMD_RHWW, address, sizebp);
		break;
	case READ_WATCHPOINT:
		ret = snprintf (tmp, sizeof (tmp) - 1, "%s,%"PFMT64x ",%d", CMD_RHWR, address, sizebp);
		break;
	case ACCESS_WATCHPOINT:
		ret = snprintf (tmp, sizeof (tmp) - 1, "%s,%"PFMT64x ",%d", CMD_RHWA, address, sizebp);
		break;
	default:
		break;
	}
	if (ret < 0) {
		return ret;
	}

	if (!gdbr_lock_enter (g)) {
		goto end;
	}

	g->stop_reason.is_valid = false;
	if ((ret = send_msg (g, tmp)) < 0) {
		goto end;
	}
	if ((ret = read_packet (g, false)) < 0) {
		goto end;
	}

	ret = handle_removebp (g);
end:
	gdbr_lock_leave (g);
	return ret;
}

int gdbr_open_file(libgdbr_t *g, const char *filename, int flags, int mode) {
	int ret = -1;
	char *buf;
	size_t buf_len;

	if (!g || !filename || !*filename) {
		return -1;
	}
	if (g->remote_file_fd >= 0) {
		eprintf ("%s: Remote file already open\n", __func__);
		return -1;
	}
	buf_len = (strlen (filename) * 2) + strlen ("vFile:open:") + 30;
	if (!(buf = calloc (buf_len, sizeof (char)))) {
		return -1;
	}

	if (!gdbr_lock_enter (g)) {
		goto end;
	}
	strcpy (buf, "vFile:open:");
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
	if (buf) {
		free (buf);
	}
	gdbr_lock_leave (g);
	return ret;
}

int gdbr_read_file(libgdbr_t *g, ut8 *buf, ut64 max_len) {
	int ret, ret1;
	char command[64];
	ut64 data_sz;
	ret = 0;
	if (!g || !buf || !max_len) {
		return -1;
	}
	if (max_len >= INT32_MAX) {
		eprintf ("%s: Too big a file read requested: %"PFMT64d, __func__, max_len);
		return -1;
	}
	if (g->remote_file_fd < 0) {
		eprintf ("%s: No remote file opened\n", __func__);
		return -1;
	}

	if (!gdbr_lock_enter (g)) {
		goto end;
	}
	g->stub_features.pkt_sz = R_MAX (g->stub_features.pkt_sz, GDB_MAX_PKTSZ);
	data_sz = g->stub_features.pkt_sz / 2;
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
		if ((ret1 = handle_vFile_pread (g, buf + ret)) < 0) {
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
		eprintf ("%s: No remote file opened\n", __func__);
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

void gdbr_invalidate_reg_cache() {
	reg_cache.valid = false;
}

int gdbr_send_qRcmd(libgdbr_t *g, const char *cmd, PrintfCallback cb_printf) {
	int ret = -1;
	char *buf;
	size_t len;

	if (!g || !cmd) {
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
	reg_cache.valid = false;
	pack_hex (cmd, strlen (cmd), buf + 6);
	if ((ret = send_msg (g, buf)) < 0) {
		goto end;
	}
	if ((ret = read_packet (g, false)) < 0) {
		goto end;
	}
	while (1) {
		if ((ret = send_ack (g)) < 0) {
			goto end;
		}
		if (g->data_len == 0) {
			ret = -1;
			goto end;
		}
		if (g->data_len == 3 && g->data[0] == 'E'
			    && isxdigit (g->data[1]) && isxdigit (g->data[2])) {
			ret = -1;
			goto end;
		}
		if (!strncmp (g->data, "OK", 2)) {
			break;
		}
		if (g->data[0] == 'O' && g->data_len % 2 == 1) {
			// Console output from gdbserver
			unpack_hex (g->data + 1, g->data_len - 1, g->data + 1);
			g->data[g->data_len - 1] = '\0';
			cb_printf ("%s", g->data + 1);
		}
		if ((ret = read_packet (g, false)) < 0) {
			goto end;
		}
	}

	ret = 0;
end:
	if (buf) {
		free (buf);
	}
	gdbr_lock_leave (g);
	return ret;
}

char* gdbr_exec_file_read(libgdbr_t *g, int pid) {
	char msg[128], pidstr[16];
	char *path = NULL;
	ut64 len, off = 0;
	int ret = -1;

	if (!g) {
		return NULL;
	}

	len = g->stub_features.pkt_sz;
	memset (pidstr, 0, sizeof (pidstr));
	if (g->stub_features.multiprocess && pid > 0) {
		snprintf (pidstr, sizeof (pidstr), "%x", pid);
	}

	if (!gdbr_lock_enter (g)) {
		goto end;
	}
	while (1) {
		if (snprintf (msg, sizeof (msg) - 1,
			    "qXfer:exec-file:read:%s:%"PFMT64x",%"PFMT64x,
			    pidstr, off, len) < 0) {
			ret = -1;
			goto end;
		}
		if (send_msg (g, msg) < 0 || read_packet (g, false) < 0
			    || send_ack (g) < 0 || g->data_len == 0) {
			ret = -1;
			goto end;
		}
		g->data[g->data_len] = '\0';
		if (g->data[0] == 'l') {
			if (g->data_len == 1) {
				break;
			}
			path = r_str_append (path, g->data + 1);
			break;
		}
		if (g->data[0] != 'm') {
			ret = -1;
			goto end;
		}
		off += strlen (g->data + 1);
		if (!(path = r_str_append (path, g->data + 1))) {
			ret = -1;
			goto end;
		}
	}

	ret = 0;
end:
	gdbr_lock_leave (g);
	if (ret != 0) {
		if (path) {
			free (path);
		}
		return NULL;
	}
	return path;
}

bool gdbr_is_thread_dead (libgdbr_t *g, int pid, int tid) {
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
	char msg[64] = { 0 }, thread_id[63] = { 0 };
	if (write_thread_id (thread_id, sizeof (thread_id) - 1, pid, tid,
		    g->stub_features.multiprocess) < 0) {
		goto end;
	}
	if (snprintf (msg, sizeof (msg) - 1, "T%s", thread_id) < 0) {
		goto end;
	}
	if (send_msg (g, msg) < 0 || read_packet (g, false) < 0 || send_ack (g) < 0) {
		goto end;
	}
	if (g->data_len == 3 && g->data[0] == 'E') {
		ret = true;
	} else {
		ret = false;
	}

end:
	gdbr_lock_leave (g);
	return ret;
}

RList* gdbr_pids_list(libgdbr_t *g, int pid) {
	int ret = -1;
	RList *list = NULL;
	int tpid = -1, ttid = -1;
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
	if (g->stub_features.qXfer_threads_read) {
		if (gdbr_read_processes_xml(g, pid, list) == 0) {
			ret = 0;
			goto end;
		}
	}
	// Child processes will only show up in ThreadInfo if gdbr is currently processing a
	// fork/vfork/exec event or if the children weren't detached yet. This is intended
	// gdb `info inferiors` behavior that can only be avoided using xml.
	eprintf ("WARNING: Showing possibly incomplete pid list due to xml protocol failure\n");

	if (!g->stub_features.qXfer_exec_file_read
		    || !(exec_file = gdbr_exec_file_read (g, pid))) {
		exec_file = "";
	}
	if (send_msg (g, "qfThreadInfo") < 0 || read_packet (g, false) < 0 || send_ack (g) < 0
		    || g->data_len == 0 || g->data[0] != 'm') {
		ret = -1;
		goto end;
	}
	while (1) {
		g->data[g->data_len] = '\0';
		ptr = g->data + 1;
		while (ptr) {
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
			if (!(dpid = R_NEW0 (RDebugPid)) || !(dpid->path = strdup (exec_file))) {
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
			ptr = ptr2;
		}
		if (send_msg (g, "qsThreadInfo") < 0 || read_packet (g, false) < 0
			    || send_ack (g) < 0 || g->data_len == 0
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
			free (dpid);
		}
		// We can't use r_debug_pid_free here
		if (list) {
			r_list_foreach (list, iter, dpid) {
				if (dpid->path) {
					free (dpid->path);
				}
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
	if (send_msg (g, "qfThreadInfo") < 0 || read_packet (g, false) < 0 || send_ack (g) < 0
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
			if (!(dpid = R_NEW0 (RDebugPid)) || !(dpid->path = strdup (exec_file))) {
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
			ptr = ptr2;
		}
		if (send_msg (g, "qsThreadInfo") < 0 || read_packet (g, false) < 0
			    || send_ack (g) < 0 || g->data_len == 0
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
			free (dpid);
		}
		// We can't use r_debug_pid_free here
		if (list) {
			r_list_foreach (list, iter, dpid) {
				if (dpid->path) {
					free (dpid->path);
				}
				free (dpid);
			}
			r_list_free (list);
		}
		return NULL;
	}
	return list;
}

ut64 gdbr_get_baddr(libgdbr_t *g) {
	ut64 off, min = UINT64_MAX;
	char *ptr;
	if (!g) {
		return UINT64_MAX;
	}

	if (!gdbr_lock_enter (g)) {
		goto end;
	}
	if (send_msg (g, "qOffsets") < 0 || read_packet (g, false) < 0
		    || send_ack (g) < 0 || g->data_len == 0) {
		min = UINT64_MAX;
		goto end;
	}
	if (r_str_startswith (g->data, "TextSeg=")) {
		ptr = g->data + strlen ("TextSeg=");
		if (!isxdigit (*ptr)) {
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
			if (!isxdigit (*ptr)) {
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
	if (!isxdigit (*ptr)) {
		goto end;
	}
	off = strtoull (ptr, NULL, 16);
	if (off < min) {
		min = off;
	}
	if (!(ptr = strchr (ptr, ';')) || !r_str_startswith (ptr + 1, "Data=")) {
		min = UINT64_MAX;
		goto end;
	}
	ptr += strlen (";Data=");
	if (!isxdigit (*ptr)) {
		min = UINT64_MAX;
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
		if (!isxdigit (*ptr)) {
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
