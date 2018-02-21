/* libgdbr - LGPL - Copyright 2014-2017 - defragger */

#include "gdbclient/responses.h"
#include "gdbclient/commands.h"
#include "gdbclient/core.h"
#include "gdbclient/xml.h"
#include "arch.h"
#include "libgdbr.h"
#include "gdbr_common.h"
#include "packet.h"
#include "r_util/r_strbuf.h"

#if __UNIX__
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <termios.h>
#endif

#if __UNIX__ || __CYGWIN__
#include <signal.h>
#endif

extern char hex2char(char *hex);

#if 0
static int set_interface_attribs (int fd, int speed, int parity) {
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
	ut8  *buf;
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

static int gdbr_connect_lldb(libgdbr_t *g) {
	reg_cache_init (g);
	if (g->stub_features.qXfer_features_read) {
		gdbr_read_target_xml (g);
	}
	// Check if 'g' packet is supported
	if (send_msg (g, "g") < 0 || read_packet (g, false) < 0 || send_ack (g) < 0) {
		return -1;
	}
	if (g->data_len == 0 || (g->data_len == 3 && g->data[0] == 'E')) {
		return 0;
	}
	g->stub_features.lldb.g = true;
	return 0;
}

int gdbr_connect(libgdbr_t *g, const char *host, int port) {
	const char *message = "qSupported:multiprocess+;qRelocInsn+;xmlRegisters=i386";
	RStrBuf tmp;
	r_strbuf_init (&tmp);
	int ret;
	if (!g || !host) {
		return -1;
	}
	// Initial max_packet_size for remote target (minimum so far for AVR = 64)
	g->stub_features.pkt_sz = 64;
	char *env_pktsz_str;
	ut32 env_pktsz;
	if ((env_pktsz_str = r_sys_getenv ("R2_GDB_PKTSZ"))) {
		if ((env_pktsz = (ut32) strtoul (env_pktsz_str, NULL, 10))) {
			g->stub_features.pkt_sz = R_MAX (env_pktsz, GDB_MAX_PKTSZ);
		}
	}
	ret = snprintf (tmp.buf, sizeof (tmp.buf) - 1, "%d", port);
	if (!ret) {
		return -1;
	}
	if (*host == '/') {
		ret = r_socket_connect_serial (g->sock, host, port, 1);
	} else {
		ret = r_socket_connect_tcp (g->sock, host, tmp.buf, 400);
	}
	if (!ret) {
		return -1;
	}
	if (send_ack (g) < 0) {
		return -1;
	}
	read_packet (g, true); // vcont=true lets us skip if we get no reply
	g->connected = 1;
	// TODO add config possibility here
	ret = send_msg (g, message);
	if (ret < 0) {
		return ret;
	}
	read_packet (g, false);
	ret = handle_qSupported (g);
	if (ret < 0) {
		return ret;
	}
	if (env_pktsz > 0) {
		g->stub_features.pkt_sz = R_MAX (R_MIN (env_pktsz, g->stub_features.pkt_sz), GDB_MAX_PKTSZ);
	}
	// If no-ack supported, enable no-ack mode (should speed up things)
	if (g->stub_features.QStartNoAckMode) {
		if (send_msg (g, "QStartNoAckMode") < 0) {
			return -1;
		}
		read_packet (g, false);
		if (!strncmp (g->data, "OK", 2)) {
			// Just in case, send ack
			send_ack (g);
			g->no_ack = true;
		}
	}
	if (g->remote_type == GDB_REMOTE_TYPE_LLDB) {
		return gdbr_connect_lldb (g);
	}
	// Query the thread / process id
	g->stub_features.qC = true;
	g->pid = g->tid = 0;
	ret = send_msg (g, "qC");
	if (ret < 0) {
		return ret;
	}
	read_packet (g, false);
	ret = handle_qC (g);
	if (ret < 0) {
		g->stub_features.qC = false;
	}
	// Check if vCont is supported
	gdbr_check_vcont (g);
	// Set pid/thread for operations other than "step" and "continue"
	if (gdbr_select (g, g->pid, 0) < 0) {
		// return -1;
	}
	// Set thread for "step" and "continue" operations
	snprintf (tmp.buf, sizeof (tmp.buf) - 1, "Hc-1");
	ret = send_msg (g, tmp.buf);
	if (ret < 0) {
		return ret;
	}
	read_packet (g, false);
	ret = send_ack (g);
	if (strcmp (g->data, "OK")) {
		// return -1;
	}
	if (g->stub_features.qXfer_features_read) {
		gdbr_read_target_xml (g);
	}
	reg_cache_init (g);
	return ret;
}

int gdbr_disconnect(libgdbr_t *g) {
	// TODO Disconnect maybe send something to gdbserver
	if (!g || !r_socket_close (g->sock)) {
		return -1;
	}
	reg_cache.valid = false;
	g->stop_reason.is_valid = false;
	free (reg_cache.buf);
	if (g->target.valid) {
		free (g->target.regprofile);
		free (g->registers);
	}
	g->connected = 0;
	return 0;
}

int gdbr_select(libgdbr_t *g, int pid, int tid) {
	char cmd[64] = { 0 };
	reg_cache.valid = false;
	g->pid = pid;
	g->tid = tid;
	strcpy (cmd, "Hg");
	if (write_thread_id (cmd + 2, sizeof (cmd) - 3, pid, tid,
			     g->stub_features.multiprocess) < 0) {
		return -1;
	}
	g->stop_reason.is_valid = false;
	if (send_msg (g, cmd) < 0 || read_packet (g, false) < 0 || send_ack (g) < 0) {
		return -1;
	}
	if (strcmp (g->data, "OK")) {
		return -1;
	}
	return 0;
}

int gdbr_check_vcont(libgdbr_t *g) {
	if (!g) {
		return -1;
	}
	char *ptr = NULL;
	if (send_msg (g, "vCont?") < 0 || read_packet (g, false) < 0 || send_ack (g) < 0) {
		return -1;
	}
	if (g->data_len == 0) {
		g->stub_features.vContSupported = false;
		return 0;
	}
	g->data[g->data_len] = '\0';
	if (!(ptr = strtok (g->data + strlen ("vCont;"), ";"))) {
		return 0;
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
	return 0;
}

int gdbr_stop_reason(libgdbr_t *g) {
	if (!g || send_msg (g, "?") < 0 || read_packet (g, false) < 0) {
		return -1;
	}
	return handle_stop_reason (g);
}

int gdbr_check_extended_mode(libgdbr_t *g) {
	int ret;
	g->stop_reason.is_valid = false;
	reg_cache.valid = false;
	// Activate extended mode if possible.
	ret = send_msg (g, "!");
	if (ret < 0) {
		g->stub_features.extended_mode = 0;
		return ret;
	}
	read_packet (g, false);
	ret = send_ack (g);
	if (strncmp (g->data, "OK", 2)) {
		g->stub_features.extended_mode = 0;
		return -1;
	}

	g->stub_features.extended_mode = 1;
	return 0;
}

int gdbr_attach(libgdbr_t *g, int pid) {
	int ret;
	char *cmd;
	size_t buffer_size;

	if (!g || !g->sock) {
		return -1;
	}
	g->stop_reason.is_valid = false;
	reg_cache.valid = false;

	if (g->stub_features.extended_mode == -1) {
		gdbr_check_extended_mode (g);
	}

	if (!g->stub_features.extended_mode) {
		// vAttach needs extended mode to do anything.
		return -2;
	}

	buffer_size = strlen (CMD_ATTACH) + (sizeof (int) * 2) + 1;
	cmd = calloc (buffer_size, sizeof (char));
	if (!cmd) {
		return -1;
	}

	ret = snprintf (cmd, buffer_size, "%s%x", CMD_ATTACH, pid);
	if (ret < 0) {
		free (cmd);
		return ret;
	}

	ret = send_msg (g, cmd);
	free(cmd);
	if (ret < 0) {
		return ret;
	}

	if (read_packet (g, false) >= 0) {
		return handle_attach (g);
	}
	return -1;
}

int gdbr_detach(libgdbr_t *g) {
	int ret;

	if (!g || !g->sock) {
		return -1;
	}
	reg_cache.valid = false;
	g->stop_reason.is_valid = false;
	ret = send_msg (g, "D");
	if (ret < 0) {
		return -1;
	}
	// Disconnect
	return gdbr_disconnect (g);
}

int gdbr_detach_pid(libgdbr_t *g, int pid) {
	char *cmd;
	int ret;
	size_t buffer_size;

	if (!g || !g->sock || !g->stub_features.multiprocess) {
		return -1;
	}
	reg_cache.valid = false;
	g->stop_reason.is_valid = false;

	buffer_size = strlen (CMD_DETACH_MP) + (sizeof (pid) * 2) + 1;
	cmd = calloc (buffer_size, sizeof (char));
	if (!cmd) {
		return -1;
	}

	if ((snprintf (cmd, buffer_size, "%s%x", CMD_DETACH_MP, g->pid)) < 0) {
		free(cmd);
		return -1;
	}

	ret = send_msg (g, cmd);
	free(cmd);
	if (ret < 0) {
		return ret;
	}

	read_packet (g, false);
	if ((ret = send_ack (g)) < 0) {
		return ret;
	}

	if (strncmp (g->data, "OK", 2)) {
		return -1;
	}
	return 0;
}

bool gdbr_kill(libgdbr_t *g) {
	int ret;
	if (!g || !g->sock) {
		return false;
	}
	reg_cache.valid = false;
	g->stop_reason.is_valid = false;

	if (g->stub_features.multiprocess) {
		if (g->pid <= 0) {
			return false;
		}
		return gdbr_kill_pid (g, g->pid);
	}

	ret = send_msg (g, "k");
	if (ret < 0) {
		return false;
	}
	return true;
}

bool gdbr_kill_pid(libgdbr_t *g, int pid) {
	char *cmd;
	int ret;
	size_t buffer_size;

	if (!g || !g->sock || !g->stub_features.multiprocess) {
		return false;
	}
	reg_cache.valid = false;
	g->stop_reason.is_valid = false;

	buffer_size = strlen (CMD_KILL_MP) + (sizeof (pid) * 2) + 1;
	cmd = calloc (buffer_size, sizeof (char));
	if (!cmd) {
		return false;
	}

	if ((snprintf (cmd, buffer_size, "%s%x", CMD_KILL_MP, g->pid)) < 0) {
		free(cmd);
		return false;
	}
	ret = send_msg (g, cmd);
	free(cmd);
	if (ret < 0) {
		return false;
	}

	read_packet (g, false);
	if ((ret = send_ack (g)) < 0) {
		return false;
	}
	if (strncmp (g->data, "OK", 2)) {
		return false;
	}
	return true;
}

static int gdbr_read_registers_lldb(libgdbr_t *g) {
	// Send the stop reply query packet and get register info
	// (this is what lldb does)
	int ret;
	if (send_msg (g, "?") < 0 || read_packet (g, false) < 0) {
		return -1;
	}
	if ((ret = handle_lldb_read_reg (g)) < 0) {
		return ret;
	}
	if (reg_cache.init) {
		reg_cache.buflen = g->data_len;
		memcpy (reg_cache.buf, g->data, reg_cache.buflen);
		reg_cache.valid = true;
	}
	return 0;
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
	if (g->remote_type == GDB_REMOTE_TYPE_LLDB
	    && !g->stub_features.lldb.g) {
		return gdbr_read_registers_lldb (g);
	}
	ret = send_msg (g, CMD_READREGS);
	if (ret < 0) {
		return ret;
	}
	if (read_packet (g, false) < 0 || handle_g (g) < 0) {
		return -1;
	}
	if (reg_cache.init) {
		reg_cache.buflen = g->data_len;
		memset (reg_cache.buf, 0, reg_cache.buflen);
		memcpy (reg_cache.buf, g->data, reg_cache.buflen);
		reg_cache.valid = true;
	}
	return 0;
}

static int gdbr_read_memory_page(libgdbr_t *g, ut64 address, ut8 *buf, int len) {
	char command[128] = {0};
	int last, ret_len, pkt;
	if (!g) {
		return -1;
	}
	if (len < 1) {
		return len;
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
			return -1;
		}
		if (send_msg (g, command) < 0) {
			return -1;
		}
		if (read_packet (g, false) < 0) {
			return -1;
		}
		if (handle_m (g) < 0) {
			return -1;
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
			return -1;
		}
		if (send_msg (g, command) < 0) {
			return -1;
		}
		if (read_packet (g, false) < 0) {
			return -1;
		}
		if (handle_m (g) < 0) {
			return -1;
		}
		int delta = num_pkts * data_sz;
		int left = R_MIN (g->data_len, len - delta);
		if (left > 0) {
			memcpy (buf + delta, g->data, left);
			ret_len += g->data_len;
		}
	}
	return ret_len;
}

int gdbr_read_memory(libgdbr_t *g, ut64 address, ut8 *buf, int len) {
	int ret_len, ret, tmp;
	int page_size = g->page_size;
	ret_len = 0;
	// Read and round up to page size
	tmp = page_size - (address & (page_size - 1));
	if (tmp >= len) {
		return gdbr_read_memory_page (g, address, buf, len);
	}
	if ((ret = gdbr_read_memory_page (g, address, buf, tmp)) != tmp) {
		return ret;
	}
	len -= tmp;
	address += tmp;
	buf += tmp;
	ret_len += ret;
	// Read complete pages
	while (len > page_size) {
		if ((ret = gdbr_read_memory_page (g, address, buf, page_size)) != page_size) {
			if (ret < 1) {
				return ret_len;
			}
			return ret_len + ret;
		}
		len -= page_size;
		address += page_size;
		buf += page_size;
		ret_len += page_size;
	}
	// Read left-overs
	if ((ret = gdbr_read_memory_page (g, address, buf, len)) < 0) {
		return ret_len;
	}
	return ret_len + ret;
}

int gdbr_write_memory(libgdbr_t *g, ut64 address, const uint8_t *data, ut64 len) {
	int ret = 0;
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
	for (pkt = num_pkts - 1; pkt >= 0; pkt--) {
		if ((command_len = snprintf (tmp, max_cmd_len,
					     "%s%016"PFMT64x ",%"PFMT64x ":", CMD_WRITEMEM,
					     address + (pkt * data_sz), data_sz)) < 0) {
			goto fail;
		}
		pack_hex ((char *) data + (pkt * data_sz), data_sz, (tmp + command_len));
		if ((ret = send_msg (g, tmp)) < 0) {
			goto fail;
		}
		if ((ret = read_packet (g, false)) < 0) {
			goto fail;
		}
		if ((ret = handle_M (g)) < 0) {
			goto fail;
		}
        }
	if (last) {
		if ((command_len = snprintf (tmp, max_cmd_len,
					     "%s%016"PFMT64x ",%"PFMT64x ":", CMD_WRITEMEM,
					     address + (num_pkts * data_sz), last)) < 0) {
			goto fail;
		}
		pack_hex ((char *) data + (num_pkts * data_sz), last, (tmp + command_len));
		if ((ret = send_msg (g, tmp)) < 0) {
			goto fail;
		}
		if ((ret = read_packet (g, false)) < 0) {
			goto fail;
		}
		if ((ret = handle_M (g)) < 0) {
			goto fail;
		}
	}
	free (tmp);
	return 0;
fail:
	free (tmp);
	return -1;
}

int gdbr_step(libgdbr_t *g, int tid) {
	char thread_id[64] = {0};
	if (tid <= 0 || write_thread_id (thread_id, sizeof (thread_id) - 1, g->pid, tid,
			     g->stub_features.multiprocess) < 0) {
		send_vcont (g, "vCont?", NULL);
		send_vcont (g, "Hc0", NULL);
		return send_vcont (g, CMD_C_STEP, NULL);
	}
	return send_vcont (g, CMD_C_STEP, thread_id);
}

int gdbr_continue(libgdbr_t *g, int pid, int tid, int sig) {
	char thread_id[64] = { 0 };
	char command[16] = { 0 };
	if (sig <= 0) {
		strncpy (command, CMD_C_CONT, sizeof (command) - 1);
	} else {
		snprintf (command, sizeof (command) - 1, "%s%02x", CMD_C_CONT_SIG, sig);
	}
	if (tid <= 0 || write_thread_id (thread_id, sizeof (thread_id) - 1, g->pid, tid,
			     g->stub_features.multiprocess) < 0) {
		return send_vcont (g, command, NULL);
	}
	return send_vcont (g, command, thread_id);
}

int gdbr_write_bin_registers(libgdbr_t *g){
	if (!g) {
		return -1;
	}
	reg_cache.valid = false;
	uint64_t buffer_size = g->data_len * 2 + 8;
	char *command = calloc (buffer_size, sizeof (char));
	if (!command) {
		return -1;
	}
	snprintf (command, buffer_size, "%s", CMD_WRITEREGS);
	pack_hex (g->data, g->data_len, command + 1);
	if (send_msg (g, command) < 0) {
		free (command);
		return -1;
	}
	read_packet (g, false);
	free (command);
	handle_G (g);
	return 0;
}

int gdbr_write_register(libgdbr_t *g, int index, char *value, int len) {
	int ret;
	char command[255] = { 0 };
	if (!g) {
		return -1;
	}
	reg_cache.valid = false;
	ret = snprintf (command, sizeof (command) - 1, "%s%d=", CMD_WRITEREG, index);
	if (len + ret >= sizeof (command)) {
		eprintf ("command is too small\n");
		return -1;
	}
	memcpy (command + ret, value, len);
	pack_hex (value, len, (command + ret));
	if (send_msg (g, command) < 0) {
		return -1;
	}
	if (read_packet (g, false) >= 0) {
		handle_P (g);
	}
	return 0;
}

int gdbr_write_reg(libgdbr_t *g, const char *name, char *value, int len) {
	// static variable that keeps the information if writing
	// register through packet <P> was possible
	static int P = 1;
	int i = 0;
	if (!g) {
		return -1;
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
		return -1;
	}
	if (P) {
		gdbr_write_register (g, i, value, len);
		if (g->last_code == MSG_OK) {
			return 0;
		}
		P = 0;
	}
	gdbr_read_registers (g);
	memcpy (g->data + g->registers[i].offset, value, len);
	gdbr_write_bin_registers (g);
	return 0;
}

int gdbr_write_registers(libgdbr_t *g, char *registers) {
	uint64_t buffer_size;
	int ret, i = 0;
	unsigned int x, len;
	char *command, *reg, *buff;
	// read current register set

	if (!g) {
		return -1;
	}
	gdbr_read_registers (g);
	reg_cache.valid = false;
	len = strlen (registers);
	buff = calloc (len, sizeof (char));
	if (!buff) {
		return -1;
	}
	memcpy (buff, registers, len);
	reg = strtok (buff, ",");
	while (reg) {
		char *name_end = strchr (reg, '=');
		if (name_end == NULL) {
			eprintf ("Malformed argument: %s\n", reg);
			free (buff);
			return -1;
		}
		*name_end = '\0'; // change '=' to '\0'

		// time to find the current register
		while (g->registers[i].size > 0) {
			if (strcmp (g->registers[i].name, reg) == 0) {
				const ut64 register_size = g->registers[i].size;
				const ut64 offset = g->registers[i].offset;
				char *value = calloc (register_size + 1, 2);
				if (!value) {
					free (buff);
					return -1;
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
				free (value);
			}
			i++;
		}
		reg = strtok (NULL, " ,");
	}

	free (buff);

	buffer_size = g->data_len * 2 + 8;
	command = calloc (buffer_size, sizeof(char));
	if (!command) {
		return -1;
	}
	snprintf (command, buffer_size, "%s", CMD_WRITEREGS);
	pack_hex (g->data, g->data_len, command + 1);
	ret = send_msg (g, command);
	if (ret < 0) {
		free (command);
		return ret;
	}
	read_packet (g, false);
	free (command);
	handle_G (g);
	return 0;
}

int test_command(libgdbr_t *g, const char *command) {
	int ret = send_msg (g, command);
	if (ret < 0) {
		return ret;
	}
	read_packet (g, false);
	hexdump (g->read_buff, g->data_len, 0);
	return 0;
}

static bool _isbreaked = false;

#if __WINDOWS__ && !__CYGWIN__
static HANDLE h;
static BOOL __w32_signal(DWORD type) {
	if (type == CTRL_C_EVENT) {
		_isbreaked = true;
		return true;
	}
	return false;
}
// TODO
#define SET_SIGINT_HANDLER(g,x)
#define UNSET_SIGINT_HANDLER()

#elif __UNIX__ || __CYGWIN__
static void _sigint_handler(int signo) {
	_isbreaked = true;
}
#define SET_SIGINT_HANDLER(g,x)	\
	_isbreaked = false;	\
	signal (SIGINT, x);
#define UNSET_SIGINT_HANDLER()	\
	signal (SIGINT, SIG_DFL);

#endif

int send_vcont(libgdbr_t *g, const char *command, const char *thread_id) {
	char tmp[255] = {0};
	int ret;
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
	reg_cache.valid = false;
	g->stop_reason.is_valid = false;
	ret = send_msg (g, tmp);
	if (ret < 0) {
		return ret;
	}

	SET_SIGINT_HANDLER (g, _sigint_handler);
	while ((ret = read_packet (g, true)) < 0 && !_isbreaked && r_socket_is_connected (g->sock));
	UNSET_SIGINT_HANDLER ();
	if (_isbreaked) {
		_isbreaked = false;
		// Stop target
		r_socket_write (g->sock, "\x03", 1);
		// Read the stop reason
		if (read_packet (g, false) < 0) {
			return -1;
		}
	}
	return handle_cont (g);
}

int set_bp(libgdbr_t *g, ut64 address, const char *conditions, enum Breakpoint type) {
	char tmp[255] = {0};
	int ret = -1;
	if (!g) {
		return -1;
	}
	switch (type) {
	case BREAKPOINT:
		ret = snprintf (tmp, sizeof (tmp) - 1,
			"%s,%"PFMT64x ",1", CMD_BP, address);
		break;
	case HARDWARE_BREAKPOINT:
		ret = snprintf (tmp, sizeof (tmp) - 1,
			"%s,%"PFMT64x ",1", CMD_HBP, address);
		break;
	case WRITE_WATCHPOINT:
		break;
	case READ_WATCHPOINT:
		break;
	case ACCESS_WATCHPOINT:
		break;
	default:
		break;
	}
	if (ret < 0) {
		return ret;
	}
	g->stop_reason.is_valid = false;
	ret = send_msg (g, tmp);
	if (ret < 0) {
		return ret;
	}

	if (read_packet (g, false) >= 0) {
		return handle_setbp (g);
	}
	return 0;
}

int gdbr_set_bp(libgdbr_t *g, ut64 address, const char *conditions) {
	return set_bp (g, address, conditions, BREAKPOINT);
}

int gdbr_set_hwbp(libgdbr_t *g, ut64 address, const char *conditions) {
	return set_bp (g, address, conditions, HARDWARE_BREAKPOINT);
}

int gdbr_remove_bp(libgdbr_t *g, ut64 address) {
	return remove_bp (g, address, BREAKPOINT);
}

int gdbr_remove_hwbp(libgdbr_t *g, ut64 address) {
	return remove_bp (g, address, HARDWARE_BREAKPOINT);
}

int remove_bp(libgdbr_t *g, ut64 address, enum Breakpoint type) {
	char tmp[255] = {0};
	int ret = -1;
	if (!g) {
		return -1;
	}
	switch (type) {
	case BREAKPOINT:
		ret = snprintf (tmp, sizeof (tmp) - 1, "%s,%"PFMT64x ",1", CMD_RBP, address);
		break;
	case HARDWARE_BREAKPOINT:
		ret = snprintf (tmp, sizeof (tmp) - 1, "%s,%"PFMT64x ",1", CMD_RHBP, address);
		break;
	case WRITE_WATCHPOINT:
		break;
	case READ_WATCHPOINT:
		break;
	case ACCESS_WATCHPOINT:
		break;
	default:
		break;
	}
	if (ret < 0) {
		return ret;
	}
	g->stop_reason.is_valid = false;
	ret = send_msg (g, tmp);
	if (ret < 0) {
		return ret;
	}
	if (read_packet (g, false) >= 0) {
		return handle_removebp (g);
	}
	return 0;
}

int gdbr_open_file(libgdbr_t *g, const char *filename, int flags, int mode) {
	if (!g || !filename || !*filename) {
		return -1;
	}
	if (g->remote_file_fd >= 0) {
		eprintf ("%s: Remote file already open\n", __func__);
		return -1;
	}
	char *buf;
	size_t buf_len = (strlen (filename) * 2) + strlen ("vFile:open:") + 30;
	if (!(buf = calloc (buf_len, sizeof (char)))) {
		return -1;
	}
	strcpy (buf, "vFile:open:");
	pack_hex (filename, strlen (filename), buf + strlen (buf));
	snprintf (buf + strlen (buf), buf_len - strlen (buf) - 1, ",%x,%x", flags, mode);
	if (send_msg (g, buf) < 0) {
		free (buf);
		return -1;
	}
	read_packet (g, false);
	if (handle_vFile_open (g) < 0) {
		free (buf);
		return -1;
	}
	free (buf);
	return 0;
}

int gdbr_read_file(libgdbr_t *g, ut8 *buf, ut64 max_len) {
	int ret, ret1;
	char command[64];
	ut64 data_sz;
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
	g->stub_features.pkt_sz = R_MAX (g->stub_features.pkt_sz, GDB_MAX_PKTSZ);
	data_sz = g->stub_features.pkt_sz / 2;
	ret = 0;
	while (ret < max_len) {
		if ((ret1 = snprintf (command, sizeof (command) - 1,
				      "vFile:pread:%x,%"PFMT64x",%"PFMT64x,
				      (int)g->remote_file_fd, (ut64)R_MIN(data_sz, max_len - ret),
				      (ut64)ret)) < 0) {
			return -1;
		}
		if (send_msg (g, command) < 0) {
			return -1;
		}
		if (read_packet (g, false) < 0) {
			return -1;
		}
		if ((ret1 = handle_vFile_pread (g, buf + ret)) < 0) {
			return -1;
		}
		if (ret1 == 0) {
			return ret;
		}
		ret += ret1;
        }
	return ret;
}

int gdbr_close_file(libgdbr_t *g) {
	if (!g) {
		return -1;
	}
	if (g->remote_file_fd < 0) {
		eprintf ("%s: No remote file opened\n", __func__);
		return -1;
	}
	char buf[64];
	snprintf (buf, sizeof (buf) - 1, "vFile:close:%x", g->remote_file_fd);
	if (send_msg (g, buf) < 0) {
		return -1;
	}
	read_packet (g, false);
	if (handle_vFile_close (g) < 0) {
		return -1;
	}
	g->remote_file_fd = -1;
	return 0;
}

void gdbr_invalidate_reg_cache() {
	reg_cache.valid = false;
}

int gdbr_send_qRcmd(libgdbr_t *g, const char *cmd, void (*cb_printf) (const char *fmt, ...)) {
	if (!g || !cmd) {
		return -1;
	}
	char *buf;
	size_t len = strlen (cmd) * 2 + 8;
	if (!(buf = calloc (len, sizeof (char)))) {
		return -1;
	}
	strcpy (buf, "qRcmd,");
	g->stop_reason.is_valid = false;
	reg_cache.valid = false;
	pack_hex (cmd, strlen (cmd), buf + 6);
	if (send_msg (g, buf) < 0) {
		free (buf);
		return -1;
	}
	if (read_packet (g, false) < 0) {
		free (buf);
		return -1;
	}
	while (1) {
		if (send_ack (g) < 0) {
			free (buf);
			return -1;
		}
		if (g->data_len == 0) {
			free (buf);
			return -1;
		}
		if (g->data_len == 3 && g->data[0] == 'E'
		    && isxdigit (g->data[1]) && isxdigit (g->data[2])) {
			free (buf);
			return -1;
		}
		if (!strncmp (g->data, "OK", 2)) {
			free (buf);
			return 0;
		}
		if (g->data[0] == 'O' && g->data_len % 2 == 1) {
			// Console output from gdbserver
			unpack_hex (g->data + 1, g->data_len - 1, g->data + 1);
			g->data[g->data_len - 1] = '\0';
			cb_printf ("%s", g->data + 1);
		}
		if (read_packet (g, false) < 0) {
			free (buf);
			return -1;
		}
	}
	free (buf);
	return -1;
}

char* gdbr_exec_file_read(libgdbr_t *g, int pid) {
	if (!g) {
		return NULL;
	}
	char msg[128], pidstr[16];
	char *path = NULL;
	ut64 len = g->stub_features.pkt_sz, off = 0;
	memset (pidstr, 0, sizeof (pidstr));
	if (g->stub_features.multiprocess && pid > 0) {
		snprintf (pidstr, sizeof (pidstr), "%x", pid);
	}
	while (1) {
		if (snprintf (msg, sizeof (msg) - 1,
			      "qXfer:exec-file:read:%s:%"PFMT64x",%"PFMT64x,
			      pidstr, off, len) < 0) {
			free (path);
			return NULL;
		}
		if (send_msg (g, msg) < 0 || read_packet (g, false) < 0
		    || send_ack (g) < 0 || g->data_len == 0) {
			free (path);
			return NULL;
		}
		g->data[g->data_len] = '\0';
		if (g->data[0] == 'l') {
			if (g->data_len == 1) {
				return path;
			}
			return r_str_append (path, g->data + 1);
		}
		if (g->data[0] != 'm') {
			free (path);
			return NULL;
		}
		off += strlen (g->data + 1);
		if (!(path = r_str_append (path, g->data + 1))) {
			return NULL;
		}
	}
}

bool gdbr_is_thread_dead (libgdbr_t *g, int pid, int tid) {
	if (!g) {
		return false;
	}
	if (g->stub_features.multiprocess && pid <= 0) {
		return false;
	}
	char msg[64] = { 0 }, thread_id[63] = { 0 };
	if (write_thread_id (thread_id, sizeof (thread_id) - 1, pid, tid,
			     g->stub_features.multiprocess) < 0) {
		return false;
	}
	if (snprintf (msg, sizeof (msg) - 1, "T%s", thread_id) < 0) {
		return false;
	}
	if (send_msg (g, msg) < 0 || read_packet (g, false) < 0 || send_ack (g) < 0) {
		return false;
	}
	if (g->data_len == 3 && g->data[0] == 'E') {
		return true;
	}
	return false;
}

#include <r_debug.h>

RList* gdbr_threads_list(libgdbr_t *g, int pid) {
	if (!g) {
		return NULL;
	}
	RList *list;
	int tpid = -1, ttid = -1;
	char *ptr, *ptr2, *exec_file;
	RDebugPid *dpid;
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
		return NULL;
	}
	if (!(list = r_list_new())) {
		return NULL;
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
				r_list_free (list);
				free (dpid);
				return NULL;
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
			r_list_free (list);
			return NULL;
		}
		if (g->data[0] == 'l') {
			break;
		}
	}
	RListIter *iter;
	// This is the all I've been able to extract from gdb so far
	r_list_foreach (list, iter, dpid) {
		if (gdbr_is_thread_dead (g, pid, dpid->pid)) {
			dpid->status = R_DBG_PROC_DEAD;
		}
	}
	return list;
}

ut64 gdbr_get_baddr(libgdbr_t *g) {
	if (!g || send_msg (g, "qOffsets") < 0 || read_packet (g, false) < 0
	    || send_ack (g) < 0 || g->data_len == 0) {
		return UINT64_MAX;
	}
	ut64 off, min = UINT64_MAX;
	char *ptr;
	if (r_str_startswith (g->data, "TextSeg=")) {
		ptr = g->data + strlen ("TextSeg=");
		if (!isxdigit (*ptr)) {
			return min;
		}
		off = strtoull (ptr, NULL, 16);
		if (off < min) {
			min = off;
		}
		if (!(ptr = strchr (ptr, ';'))) {
			return min;
		}
		ptr++;
		if (*ptr && r_str_startswith (ptr, "DataSeg=")) {
			ptr += strlen ("DataSeg=");
			if (!isxdigit (*ptr)) {
				return min;
			}
			off = strtoull (ptr, NULL, 16);
			if (off < min) {
				min = off;
			}
		}
		return min;
	}
	if (!r_str_startswith (g->data, "Text=")) {
		return min;
	}
	ptr = g->data + strlen ("Text=");
	if (!isxdigit (*ptr)) {
		return min;
	}
	off = strtoull (ptr, NULL, 16);
	if (off < min) {
		min = off;
	}
	if (!(ptr = strchr (ptr, ';')) || !r_str_startswith (ptr + 1, "Data=")) {
		return UINT64_MAX;
	}
	ptr += strlen (";Data=");
	if (!isxdigit (*ptr)) {
		return UINT64_MAX;
	}
	off = strtoull (ptr, NULL, 16);
	if (off < min) {
		min = off;
	}
	if (!(ptr = strchr (ptr, ';'))) {
		return min;
	}
	ptr++;
	if (r_str_startswith (ptr, "Bss=")) {
		ptr += strlen ("Bss=");
		if (!isxdigit (*ptr)) {
			return min;
		}
		off = strtoull (ptr, NULL, 16);
		if (off < min) {
			min = off;
		}
	}
	return min;
}
