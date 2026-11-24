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
#include <r_util.h>

static int _server_handle_qSupported(libgdbr_t *g) {
	int ret;
	char buf[128];
	snprintf (buf, sizeof (buf), "PacketSize=%x;QStartNoAckMode+;qXfer:exec-file:read+", (ut32) (g->read_max - 1));
	if ((ret = handle_qSupported (g)) < 0) {
		return -1;
	}
	return send_msg (g, buf);
}

static int _server_handle_qOffsets(libgdbr_t *g, gdbr_server_cmd_cb cmd_cb, void *core_ptr) {
	char buf[64], *ptr;
	ptr = buf + snprintf (buf, sizeof (buf), "TextSeg=");
	if (cmd_cb (g, core_ptr, "dm", ptr, sizeof (buf) - (ptr - buf) - 1) < 0) {
		send_msg (g, "");
		return -1;
	}
	return send_msg (g, buf);
}

static int _server_handle_exec_file_read(libgdbr_t *g, gdbr_server_cmd_cb cb,
					 void *core_ptr) {
	char *buf, *ptr, cmd[64] = {0};
	size_t buflen = 512;
	int ret;
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
	R_LOG_DEBUG ("%s: buf: %s", __func__, buf);
	if (cmd_cb (g, core_ptr, buf, NULL, 0) < 0) {
		free (buf);
		return send_msg (g, "E01");
	}
	free (buf);
	return send_msg (g, "OK");
}

static int server_stop_reply(libgdbr_t *g, gdbr_server_cmd_cb cb, void *user) {
	char reply[128] = {0};
	return send_msg (g, cb (g, user, "?", reply, sizeof (reply)) < 0? "E01": reply);
}

static bool server_select_thread(libgdbr_t *g, gdbr_server_cmd_cb cb, void *user, int tid) {
	if (tid <= 0) {
		return true;
	}
	r_strf_var (cmd, 32, "dpt=%d", tid);
	return cb (g, user, cmd, NULL, 0) >= 0;
}

static int server_resume(libgdbr_t *g, gdbr_server_cmd_cb cb, void *user, char action, int tid) {
	if ((action != 's' && action != 'c') || !server_select_thread (g, cb, user, tid)
	    || cb (g, user, action == 's'? "ds": "dc", NULL, 0) < 0) {
		return send_msg (g, "E01");
	}
	return server_stop_reply (g, cb, user);
}

static int _server_handle_qC(libgdbr_t *g, gdbr_server_cmd_cb cmd_cb, void *core_ptr) {
	char *buf;
	int ret;
	size_t buf_len = 80;
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

static int server_kill(libgdbr_t *g, gdbr_server_cmd_cb cb, void *user, bool extended) {
	if (extended) {
		ut64 pid;
		const char *end = gdbr_parse_hex_value (g->data + strlen ("vKill;"), &pid);
		if (!end || *end || !pid || pid != g->pid) {
			return send_msg (g, "E01");
		}
	}
	bool killed = cb (g, user, "dk 9", NULL, 0) >= 0;
	if (extended && send_msg (g, killed? "OK": "E01") < 0) {
		return -1;
	}
	return killed || !extended? -1: 0;
}

static int _server_handle_z(libgdbr_t *g, gdbr_server_cmd_cb cmd_cb, void *core_ptr) {
	char set; // Z = set, z = remove
	int type;
	ut64 addr;
	char cmd[64];
	if (sscanf (g->data, "%c%d,%"PFMT64x, &set, &type, &addr) != 3) {
		return send_msg (g, "E01");
	}
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

static bool parse_server_tid(const char *text, int *tid) {
	if (!strcmp (text, "-1")) {
		*tid = -1;
		return true;
	}
	ut64 value;
	const char *end = gdbr_parse_hex_value (text, &value);
	if (!end || *end || value > INT_MAX) {
		return false;
	}
	*tid = value;
	return true;
}

static int server_vcont(libgdbr_t *g, gdbr_server_cmd_cb cb, void *user) {
	if (!strcmp (g->data, "vCont?")) {
		return send_msg (g, "vCont;c;s");
	}
	const char *action = g->data + strlen ("vCont;");
	int tid = 0;
	if (!*action || (action[1] && (action[1] != ':' || !parse_server_tid (action + 2, &tid)))) {
		return send_msg (g, "E01");
	}
	return server_resume (g, cb, user, *action, tid);
}

static int server_set_thread(libgdbr_t *g, gdbr_server_cmd_cb cb, void *user, int *continue_tid) {
	int tid;
	if (!parse_server_tid (g->data + 2, &tid)) {
		return send_msg (g, "E01");
	}
	if (g->data[1] == 'c') {
		*continue_tid = tid;
	} else if (!server_select_thread (g, cb, user, tid)) {
		return send_msg (g, "E01");
	}
	return send_msg (g, "OK");
}

static int _server_handle_qfThreadInfo(libgdbr_t *g, gdbr_server_cmd_cb cmd_cb, void *core_ptr) {
	char *buf;
	int ret;
	size_t buf_len = g->stub_features.pkt_sz;
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
	if (send_msg (g, "l") < 0) {
		return -1;
	}
	return 0;
}

static int server_read_registers(libgdbr_t *g, gdbr_server_cmd_cb cmd_cb, void *core_ptr, const char *cmd, size_t size) {
	if (size > INT_MAX - 4) {
		return send_msg (g, "E01");
	}
	if (size + 4 > g->send_max) {
		char *buf = realloc (g->send_buff, size + 4);
		if (!buf) {
			return send_msg (g, "E01");
		}
		g->send_buff = buf;
		g->send_max = size + 4;
	}
	char *buf = calloc (1, size);
	if (!buf) {
		return send_msg (g, "E01");
	}
	int len = cmd_cb (g, core_ptr, cmd, buf, size);
	int ret = send_msg (g, len < 0 || len >= size? "E01": buf);
	free (buf);
	return ret;
}

static int _server_handle_g(libgdbr_t *g, gdbr_server_cmd_cb cmd_cb, void *core_ptr) {
	if (!g->registers) {
		return send_msg (g, "E01");
	}
	size_t size = 1;
	gdb_reg_t *reg;
	for (reg = g->registers; *reg->name; reg++) {
		if (!reg->size || (reg->size & 7) || reg->size / 4 > INT_MAX - size) {
			return send_msg (g, "E01");
		}
		size += reg->size / 4;
	}
	return server_read_registers (g, cmd_cb, core_ptr, "dr", size);
}

static int _server_handle_m(libgdbr_t *g, gdbr_server_cmd_cb cmd_cb, void *core_ptr) {
	int length;
	g->data[g->data_len] = 0;
	char *cmd = strdup (g->data);
	char *buf = malloc (g->data_max / 2);
	if (!buf) {
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
	char cmd[128];
	int regnum, i;
	if (!isxdigit ((ut8)g->data[1]) || !g->registers) {
		return send_msg (g, "E01");
	}
	regnum = strtol (g->data + 1, NULL, 16);
	if (regnum < 0) {
		return send_msg (g, "E01");
	}
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
	const ut64 size = g->registers[regnum].size;
	if (!*g->registers[regnum].name || !size || (size & 7) || size / 4 > INT_MAX - 1) {
		return send_msg (g, "E01");
	}
	return server_read_registers (g, cmd_cb, core_ptr, cmd, size / 4 + 1);
}

// Write register number
static int _server_handle_P(libgdbr_t *g, gdbr_server_cmd_cb cmd_cb, void *core_ptr) {
	char *ptr, *end, *cmd;
	int regnum, i;
	if (g->data_len < 4 || !g->registers || !isxdigit ((ut8)g->data[1])) {
		return send_msg (g, "E01");
	}
	ptr = memchr (g->data + 2, '=', g->data_len - 2);
	if (!ptr) {
		return send_msg (g, "E01");
	}
	long parsed_regnum = strtol (g->data + 1, &end, 16);
	if (parsed_regnum < 0 || parsed_regnum > INT_MAX || end != ptr) {
		return send_msg (g, "E01");
	}
	regnum = (int)parsed_regnum;
	ptr++;
	size_t value_len = g->data_len - (ptr - g->data);
	if (!value_len || value_len > ST32_MAX) {
		return send_msg (g, "E01");
	}
	size_t value_pos;
	for (value_pos = 0; value_pos < value_len; value_pos++) {
		if (!isxdigit ((ut8)ptr[value_pos])) {
			return send_msg (g, "E01");
		}
	}
	// We need to do this because length of register set is not known
	for (i = 0; i < regnum; i++) {
		if (!*g->registers[i].name) {
			return send_msg (g, "E01");
		}
	}
	cmd = r_str_newf ("dr %s=0x%.*s", g->registers[regnum].name, (int)value_len, ptr);
	if (!cmd) {
		return send_msg (g, "E01");
	}
	if (cmd_cb (g, core_ptr, cmd, NULL, 0) < 0) {
		free (cmd);
		send_msg (g, "E01");
		return -1;
	}
	free (cmd);
	return send_msg (g, "OK");
}

int gdbr_server_serve(libgdbr_t *g, gdbr_server_cmd_cb cmd_cb, void *core_ptr) {
	R_RETURN_VAL_IF_FAIL (g, -1);
	int ret = -1;
	int continue_tid = 0;
	for (;;) {
		if (read_packet (g, false) < 0) {
			return 0;
		}
		if (g->data_len == 0) {
			continue;
		}
		if (!strcmp (g->data, "k")) {
			return server_kill (g, cmd_cb, core_ptr, false);
		}
		if (r_str_startswith (g->data, "vKill;")) {
			if ((ret = server_kill (g, cmd_cb, core_ptr, true)) < 0) {
				return ret;
			}
			continue;
		}
		if (r_str_startswith (g->data, "qSupported")) {
			if ((ret = _server_handle_qSupported (g)) < 0) {
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
			if ((ret = send_msg (g, g->attached? "1": "0")) < 0) {
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
		if (r_str_startswith (g->data, "Hg") || r_str_startswith (g->data, "Hc")) {
			if ((ret = server_set_thread (g, cmd_cb, core_ptr, &continue_tid)) < 0) {
				return ret;
			}
			continue;
		}
		if (r_str_startswith (g->data, "?")) {
			if ((ret = server_stop_reply (g, cmd_cb, core_ptr)) < 0) {
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
		if ((!strcmp (g->data, "vCont?") || r_str_startswith (g->data, "vCont;"))) {
			if ((ret = server_vcont (g, cmd_cb, core_ptr)) < 0) {
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
		if (g->data[0] == 's' || g->data[0] == 'c') {
			if ((ret = g->data_len == 1?
					server_resume (g, cmd_cb, core_ptr, g->data[0], continue_tid): send_msg (g, "E01")) < 0) {
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
		if (!strcmp (g->data, "QStartNoAckMode")) {
			if (send_msg (g, "OK") < 0) {
				return -1;
			}
			g->no_ack = true;
			continue;
		}
		if (send_msg (g, "") < 0) {
			return -1;
		}
	}
}
