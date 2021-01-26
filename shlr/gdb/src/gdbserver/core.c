// Notes and useful links:
// This conversation (https://www.sourceware.org/ml/gdb/2009-02/msg00100.html) suggests GDB clients usually ignore error codes
// Useful, but not to be blindly trusted - http://www.embecosm.com/appnotes/ean4/embecosm-howto-rsp-server-ean4-issue-2.html
// https://github.com/llvm-mirror/lldb/blob/master/docs/lldb-gdb-remote.txt
// http://www.cygwin.com/ml/gdb/2008-05/msg00166.html

#include "gdbserver/core.h"
#include "gdbr_common.h"
#include "libgdbr.h"
#include "packet.h"
#include "utils.h"
#include "r_util/r_str.h"

static int _server_handle_qSupported(libgdbr_t *g) {
	int ret;
	char *buf;
	if (!(buf = malloc (128))) {
		return -1;
	}
	snprintf (buf, 127, "PacketSize=%x;QStartNoAckMode+;qXfer:exec-file:read+",
		  (ut32) (g->read_max - 1));
	if ((ret = handle_qSupported (g)) < 0) {
		free (buf);
		return -1;
	}
	ret = send_msg (g, buf);
	free (buf);
	return ret;
}

static int _server_handle_qTStatus(libgdbr_t *g) {
	int ret;
	// TODO Handle proper reporting of trace status
	const char *message = "";
	if ((ret = send_ack (g)) < 0) {
		return -1;
	}
	return send_msg (g, message);
}

static int _server_handle_qOffsets(libgdbr_t *g, gdbr_server_cmd_cb cmd_cb, void *core_ptr) {
	char buf[64], *ptr;
	ptr = buf + sprintf (buf, "TextSeg=");
	if (send_ack (g) < 0) {
		return -1;
	}
	if (cmd_cb (g, core_ptr, "dm", ptr, sizeof (buf) - (ptr - buf) - 1) < 0) {
		send_msg (g, "");
		return -1;
	}
	return send_msg (g, buf);
}

static int _server_handle_exec_file_read(libgdbr_t *g, gdbr_server_cmd_cb cb,
					 void *core_ptr) {
	char *buf, *ptr, cmd[64] = { 0 };
	size_t buflen = 512;
	int ret;
	if (send_ack (g) < 0) {
		return -1;
	}
	ptr = g->data + strlen ("qXfer:exec-file:read:");
	if (*ptr != ':') {
		int pid;
		if ((pid = (int) strtol (ptr, NULL, 16)) <= 0 || pid != g->pid) {
			return send_msg (g, "E00");
		}
	}
	if (!(ptr = strchr (ptr, ':'))) {
		return send_msg (g, "E00");
	}
	ptr++;
	snprintf (cmd, sizeof (cmd) - 1, "if%s", ptr);
	if (!(buf = malloc (buflen))) {
		send_msg (g, "E01");
		return -1;
	}
	if (cb (g, core_ptr, cmd, buf, buflen) < 0) {
		free (buf);
		return send_msg (g, "E01");
	}
	ret = send_msg (g, buf);
	free (buf);
	return ret;
}

static int _server_handle_M(libgdbr_t *g, gdbr_server_cmd_cb cmd_cb, void *core_ptr) {
	if (send_ack (g) < 0) {
		return -1;
	}
	char *memstr, *buf;
	ut64 memlen, memlen2, addr;
	g->data[g->data_len] = '\0';
	if (sscanf (g->data + 1, "%"PFMT64x",%"PFMT64x, &addr, &memlen) != 2) {
		return send_msg (g, "E01");
	}
	memlen2 = memlen * 2;
	if (!(memstr = strchr (g->data, ':')) || !*(++memstr)) {
		return send_msg (g, "E01");
	}
	if (memlen2 != strlen (memstr)) {
		return send_msg (g, "E01");
	}
	if (!(buf = malloc (memlen2 + 64))) {
		return send_msg (g, "E01");
	}
	snprintf (buf, memlen2 + 63, "wx 0x%s @ 0x%"PFMT64x, memstr, addr);
	buf[memlen2 + 63] = '\0';
	eprintf ("buf: %s\n", buf);
	if (cmd_cb (g, core_ptr, buf, NULL, 0) < 0) {
		free (buf);
		return send_msg (g, "E01");
	}
	free (buf);
	return send_msg (g, "OK");
}

static int _server_handle_s(libgdbr_t *g, gdbr_server_cmd_cb cmd_cb, void *core_ptr) {
	char message[64];
	if (send_ack (g) < 0) {
		return -1;
	}
	if (g->data_len > 1) {
		// We don't handle s[addr] packet
		return send_msg (g, "E01");
	}
	if (cmd_cb (g, core_ptr, "ds", NULL, 0) < 0) {
		send_msg (g, "E01");
		return -1;
	}
	if (cmd_cb (g, core_ptr, "?", message, sizeof (message)) < 0) {
		send_msg (g, "");
		return -1;
	}
	return send_msg (g, message);
}

static int _server_handle_c(libgdbr_t *g, gdbr_server_cmd_cb cmd_cb, void *core_ptr) {
	char message[64];
	if (send_ack (g) < 0) {
		return -1;
	}
	if (g->data_len > 1) {
		// We don't handle s[addr] packet
		return send_msg (g, "E01");
	}
	if (cmd_cb (g, core_ptr, "dc", NULL, 0) < 0) {
		send_msg (g, "E01");
		return -1;
	}
	if (cmd_cb (g, core_ptr, "?", message, sizeof (message)) < 0) {
		send_msg (g, "");
		return -1;
	}
	return send_msg (g, message);
}

static int _server_handle_ques(libgdbr_t *g, gdbr_server_cmd_cb cmd_cb, void *core_ptr) {
	char message[64] = { 0 };
	if (send_ack (g) < 0) {
		return -1;
	}
	if (cmd_cb (g, core_ptr, "?", message, sizeof (message)) < 0) {
		send_msg (g, "");
		return -1;
	}
	return send_msg (g, message);
}

static int _server_handle_qC(libgdbr_t *g, gdbr_server_cmd_cb cmd_cb, void *core_ptr) {
	char *buf;
	int ret;
	size_t buf_len = 80;
	if ((ret = send_ack (g)) < 0) {
		return -1;
	}
	if (!(buf = malloc (buf_len))) {
		return -1;
	}
	if ((ret = cmd_cb (g, core_ptr, "dp", buf, buf_len)) < 0) {
		free (buf);
		return -1;
	}
	ret = send_msg (g, buf);
	free (buf);
	return ret;
}

static int _server_handle_k(libgdbr_t *g, gdbr_server_cmd_cb cmd_cb, void *core_ptr) {
	send_ack (g);
	return -1;
}

static int _server_handle_vKill(libgdbr_t *g, gdbr_server_cmd_cb cmd_cb, void *core_ptr) {
	if (send_ack (g) < 0) {
		return -1;
	}
	// TODO handle killing of pid
	send_msg (g, "OK");
	return -1;
}

static int _server_handle_z(libgdbr_t *g, gdbr_server_cmd_cb cmd_cb, void *core_ptr) {
	if (send_ack (g) < 0) {
		return -1;
	}
	char set; // Z = set, z = remove
	int type;
	ut64 addr;
	char cmd[64];
	sscanf (g->data, "%c%d,%"PFMT64x, &set, &type, &addr);
	if (type != 0) {
		// TODO handle hw breakpoints and watchpoints
		return send_msg (g, "E01");
	}
	switch (set) {
	case 'Z':
		// Set
		snprintf (cmd, sizeof (cmd) - 1, "db 0x%"PFMT64x, addr);
		break;
	case 'z':
		// Remove
		snprintf (cmd, sizeof (cmd) - 1, "db- 0x%"PFMT64x, addr);
		break;
	default:
		return send_msg (g, "E01");
	}
	if (cmd_cb (g, core_ptr, cmd, NULL, 0) < 0) {
		send_msg (g, "E01");
		return -1;
	}
	return send_msg (g, "OK");
}

static int _server_handle_vCont(libgdbr_t *g, gdbr_server_cmd_cb cmd_cb, void *core_ptr) {
	char *action = NULL;
	if (send_ack (g) < 0) {
		return -1;
	}
	g->data[g->data_len] = '\0';
	if (g->data[5] == '?') {
		// Query about everything we support
		return send_msg (g, "vCont;c;s");
	}
	if (!(action = strtok (g->data, ";"))) {
		return send_msg (g, "E01");
	}
	while ((action = strtok (NULL, ";"))) {
		eprintf ("action: %s\n", action);
		switch (action[0]) {
		case 's':
			// TODO handle thread selections
			if (cmd_cb (g, core_ptr, "ds", NULL, 0) < 0) {
				send_msg (g, "E01");
				return -1;
			}
			return send_msg (g, "OK");
		case 'c':
			// TODO handle thread selections
			if (cmd_cb (g, core_ptr, "dc", NULL, 0) < 0) {
				send_msg (g, "E01");
				return -1;
			}
			return send_msg (g, "OK");
		default:
			// TODO support others
			return send_msg (g, "E01");
		}
	}
	return -1;
}

static int _server_handle_qAttached(libgdbr_t *g, gdbr_server_cmd_cb cmd_cb, void *core_ptr) {
	if (send_ack (g) < 0) {
		return -1;
	}
	// TODO check if process was attached or created
	// Right now, says that process was created
	return send_msg (g, "0");
}

// TODO, proper handling of Hg and Hc (right now handled identically)

// Set thread for all operations other than "step" and "continue"
static int _server_handle_Hg(libgdbr_t *g, gdbr_server_cmd_cb cmd_cb, void *core_ptr) {
	// We don't yet support multiprocess. Client is not supposed to send Hgp. If we receive it anyway,
	// send error
	char cmd[32];
	int tid;
	if (send_ack (g) < 0) {
		return -1;
	}
	if (g->data_len <= 2 || isalpha ((unsigned char)g->data[2])) {
		return send_msg (g, "E01");
	}
	// Hg-1 = "all threads", Hg0 = "pick any thread"
	if (g->data[2] == '0' || !strncmp (g->data + 2, "-1", 2)) {
		return send_msg (g, "OK");
	}
	sscanf (g->data + 2, "%x", &tid);
	snprintf (cmd, sizeof (cmd) - 1, "dpt=%d", tid);
	// Set thread for future operations
	if (cmd_cb (g, core_ptr, cmd, NULL, 0) < 0) {
		send_msg (g, "E01");
		return -1;
	}
	return send_msg (g, "OK");
}

// Set thread for "step" and "continue"
static int _server_handle_Hc(libgdbr_t *g, gdbr_server_cmd_cb cmd_cb, void *core_ptr) {
	// Usually this is only sent with Hc-1. Still. Set the threads for next operations
	char cmd[32];
	int tid;
	if (send_ack (g) < 0) {
		return -1;
	}
	if (g->data_len <= 2 || isalpha ((unsigned char)g->data[2])) {
		return send_msg (g, "E01");
	}
	// Hc-1 = "all threads", Hc0 = "pick any thread"
	if (g->data[2] == '0' || !strncmp (g->data + 2, "-1", 2)) {
		return send_msg (g, "OK");
	}
	sscanf (g->data + 2, "%x", &tid);
	snprintf (cmd, sizeof (cmd) - 1, "dpt=%d", tid);
	// Set thread for future operations
	if (cmd_cb (g, core_ptr, cmd, NULL, 0) < 0) {
		send_msg (g, "E01");
		return -1;
	}
	return send_msg (g, "OK");
}

static int _server_handle_qfThreadInfo(libgdbr_t *g, gdbr_server_cmd_cb cmd_cb, void *core_ptr) {
	char *buf;
	int ret;
	size_t buf_len = g->stub_features.pkt_sz;
	if ((ret = send_ack (g)) < 0) {
		return -1;
	}
	if (!(buf = malloc (buf_len))) {
		return -1;
	}
	if ((ret = cmd_cb (g, core_ptr, "dpt", buf, buf_len)) < 0) {
		free (buf);
		return -1;
	}
	ret = send_msg (g, buf);
	free (buf);
	return ret;
}

static int _server_handle_qsThreadInfo(libgdbr_t *g, gdbr_server_cmd_cb cmd_cb, void *core_ptr) {
	// TODO handle overflow from qfThreadInfo. Otherwise this won't work with programs with many threads
	if (send_ack (g) < 0 || send_msg (g, "l") < 0) {
		return -1;
	}
	return 0;
}

static int _server_handle_g(libgdbr_t *g, gdbr_server_cmd_cb cmd_cb, void *core_ptr) {
	char *buf;
	// To be very safe
	int buf_len = 4096;
	int ret;
	if (send_ack (g) < 0) {
		return -1;
	}
	if (!(buf = malloc (buf_len))) {
		send_msg (g, "E01");
		return -1;
	}
	memset (buf, 0, buf_len);
	if ((buf_len = cmd_cb (g, core_ptr, "dr", buf, buf_len)) < 0) {
		free (buf);
		send_msg (g, "E01");
		return -1;
	}
	ret = send_msg (g, buf);
	free (buf);
	return ret;
}

static int _server_handle_m(libgdbr_t *g, gdbr_server_cmd_cb cmd_cb, void *core_ptr) {
	ut64 addr;
	int length;
	char *cmd, *buf;
	if (send_ack (g) < 0) {
		return -1;
	}
	g->data[g->data_len] = 0;
	sscanf (g->data, "m%"PFMT64x, &addr);
	if (!(cmd = strdup (g->data))) {
		send_msg (g, "E01");
		return -1;
	}
	if (!(buf = malloc (g->data_max / 2))) {
		free (cmd);
		send_msg (g, "E01");
		return -1;
	}
	if ((length = cmd_cb (g, core_ptr, cmd, buf, (g->data_max / 2) - 1)) < 0
	    || length >= g->data_max / 2) {
		free (cmd);
		free (buf);
		return send_msg (g, "E01");
	}
	pack_hex (buf, length, g->data);
	free (cmd);
	free (buf);
	g->data[length * 2] = '\0';
	return send_msg (g, g->data);
}

// Read register number
static int _server_handle_p(libgdbr_t *g, gdbr_server_cmd_cb cmd_cb, void *core_ptr) {
	char message[128] = { 0 }, cmd[128] = { 0 };
	int regnum, i;
	if (send_ack (g) < 0) {
		return -1;
	}
	if (!isxdigit ((unsigned char)g->data[1])) {
		return send_msg (g, "E01");
	}
	regnum = strtol (g->data + 1, NULL, 16);
	// We need to do this because length of register set is not known
	for (i = 0; i < regnum; i++) {
		if (!*g->registers[i].name) {
			return send_msg (g, "E01");
		}
	}
	if (snprintf (cmd, sizeof (cmd) - 1, "dr %s", g->registers[regnum].name) < 0) {
		send_msg (g, "E01");
		return -1;
	}
	if (cmd_cb (g, core_ptr, cmd, message, sizeof (message)) < 0) {
		send_msg (g, "E01");
		return -1;
	}
	return send_msg (g, message);
}

// Write register number
static int _server_handle_P(libgdbr_t *g, gdbr_server_cmd_cb cmd_cb, void *core_ptr) {
	char *ptr, *cmd;
	int regnum, len, i;
	if (send_ack (g) < 0) {
		return -1;
	}
	if (!isxdigit ((unsigned char)g->data[1]) || !(ptr = strchr (g->data, '='))) {
		return send_msg (g, "E01");
	}
	ptr++;
	if (!isxdigit ((unsigned char)*ptr)) {
		return send_msg (g, "E01");
	}
	regnum = strtol (g->data + 1, NULL, 16);
	// We need to do this because length of register set is not known
	for (i = 0; i < regnum; i++) {
		if (!*g->registers[i].name) {
			return send_msg (g, "E01");
		}
	}
	len = strlen (g->registers[regnum].name) + strlen (ptr) + 10;
	if (!(cmd = calloc (len, sizeof (char)))) {
		return send_msg (g, "E01");
	}
	snprintf (cmd, len - 1, "dr %s=0x%s", g->registers[regnum].name, ptr);
	if (cmd_cb (g, core_ptr, cmd, NULL, 0) < 0) {
		free (cmd);
		send_msg (g, "E01");
		return -1;
	}
	free (cmd);
	return send_msg (g, "OK");
}

static int _server_handle_vMustReplyEmpty(libgdbr_t *g) {
	if (send_ack (g) < 0) {
		return -1;
	}
	return send_msg (g, "");
}

static int _server_handle_qTfV(libgdbr_t *g, gdbr_server_cmd_cb cmd_cb, void *core_ptr) {
	// TODO
	if (send_ack (g) < 0) {
		return -1;
	}
	return send_msg (g, "");
}

int gdbr_server_serve(libgdbr_t *g, gdbr_server_cmd_cb cmd_cb, void *core_ptr) {
	int ret;
	if (!g) {
		return -1;
	}
	while (1) {
		if (read_packet (g, false) < 0) {
			continue;
		}
		if (g->data_len == 0) {
			continue;
		}
		if (r_str_startswith (g->data, "k")) {
			return _server_handle_k (g, cmd_cb, core_ptr);
		}
		if (r_str_startswith (g->data, "vKill")) {
			return _server_handle_vKill (g, cmd_cb, core_ptr);
		}
		if (r_str_startswith (g->data, "qSupported")) {
			if ((ret = _server_handle_qSupported (g)) < 0) {
				return ret;
			}
			continue;
		}
		if (r_str_startswith (g->data, "qTStatus")) {
			if ((ret = _server_handle_qTStatus (g)) < 0) {
				return ret;
			}
			continue;
		}
		if (r_str_startswith (g->data, "qC") && g->data_len == 2) {
			if ((ret = _server_handle_qC (g, cmd_cb, core_ptr)) < 0) {
				return ret;
			}
			continue;
		}
		if (r_str_startswith (g->data, "qAttached")) {
			if ((ret = _server_handle_qAttached (g, cmd_cb, core_ptr)) < 0) {
				return ret;
			}
			continue;
		}
		if (r_str_startswith (g->data, "vMustReplyEmpty")) {
			if ((ret = _server_handle_vMustReplyEmpty (g)) < 0) {
				return ret;
			}
			continue;
		}
		if (r_str_startswith (g->data, "qTfV")) {
			if ((ret = _server_handle_qTfV (g, cmd_cb, core_ptr)) < 0) {
				return ret;
			}
			continue;
		}
		if (r_str_startswith (g->data, "qfThreadInfo")) {
			if ((ret = _server_handle_qfThreadInfo (g, cmd_cb, core_ptr)) < 0) {
				return ret;
			}
			continue;
		}
		if (r_str_startswith (g->data, "qsThreadInfo")) {
			if ((ret = _server_handle_qsThreadInfo (g, cmd_cb, core_ptr)) < 0) {
				return ret;
			}
			continue;
		}
		if (r_str_startswith (g->data, "Hg")) {
			if ((ret = _server_handle_Hg (g, cmd_cb, core_ptr)) < 0) {
				return ret;
			}
			continue;
		}
		if (r_str_startswith (g->data, "Hc")) {
			if ((ret = _server_handle_Hc (g, cmd_cb, core_ptr)) < 0) {
				return ret;
			}
			continue;
		}
		if (r_str_startswith (g->data, "?")) {
			if ((ret = _server_handle_ques (g, cmd_cb, core_ptr)) < 0) {
				return ret;
			}
			continue;
		}
		if (r_str_startswith (g->data, "g") && g->data_len == 1) {
			if ((ret = _server_handle_g (g, cmd_cb, core_ptr)) < 0) {
				return ret;
			}
			continue;
		}
		if (r_str_startswith (g->data, "vCont")) {
			if ((ret = _server_handle_vCont (g, cmd_cb, core_ptr)) < 0) {
				return ret;
			}
			continue;
		}
		if (r_str_startswith (g->data, "qOffsets")) {
			if ((ret = _server_handle_qOffsets (g, cmd_cb, core_ptr)) < 0) {
				return ret;
			}
			continue;
		}
		if (g->data[0] == 'z' || g->data[0] == 'Z') {
			if ((ret = _server_handle_z (g, cmd_cb, core_ptr)) < 0) {
				return ret;
			}
			continue;
		}
		if (g->data[0] == 's') {
			if ((ret = _server_handle_s (g, cmd_cb, core_ptr)) < 0) {
				return ret;
			}
			continue;
		}
		if (g->data[0] == 'c') {
			if ((ret = _server_handle_c (g, cmd_cb, core_ptr)) < 0) {
				return ret;
			}
			continue;
		}
		if (r_str_startswith (g->data, "m")) {
			if ((ret = _server_handle_m (g, cmd_cb, core_ptr)) < 0) {
				return ret;
			}
			continue;
		}
		if (r_str_startswith (g->data, "M")) {
			if ((ret = _server_handle_M (g, cmd_cb, core_ptr)) < 0) {
				return ret;
			}
			continue;
		}
		if (r_str_startswith (g->data, "P")) {
			if ((ret = _server_handle_P (g, cmd_cb, core_ptr)) < 0) {
				return ret;
			}
			continue;
		}
		if (r_str_startswith (g->data, "p")) {
			if ((ret = _server_handle_p (g, cmd_cb, core_ptr)) < 0) {
				return ret;
			}
			continue;
		}
		if (r_str_startswith (g->data, "qXfer:exec-file:read:")) {
			if ((ret = _server_handle_exec_file_read (g, cmd_cb, core_ptr)) < 0 ) {
				return ret;
			}
			continue;
		}
		if (r_str_startswith (g->data, "QStartNoAckMode")) {
			if (send_ack (g) < 0) {
				return -1;
			}
			g->no_ack = true;
			if (g->server_debug) {
				eprintf ("[noack mode enabled]\n");
			}
			if (send_msg (g, "OK") < 0) {
				return -1;
			}
			continue;
		}
		// Unrecognized packet
		if (send_ack (g) < 0 || send_msg (g, "") < 0) {
			g->data[g->data_len] = '\0';
			eprintf ("Unknown packet: %s\n", g->data);
			return -1;
		}
	};
	return ret;
}
