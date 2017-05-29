// Notes:
// - This conversation (https://www.sourceware.org/ml/gdb/2009-02/msg00100.html) suggests that GDB clients usually ignore error codes
// - Useful resource, though not to be blindly trusted - http://www.embecosm.com/appnotes/ean4/embecosm-howto-rsp-server-ean4-issue-2.html

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
	snprintf (buf, 127, "PacketSize=%x", (ut32) (g->read_max - 1));
	if ((ret = handle_qSupported (g)) < 0) {
		return -1;
	}
	ret = send_msg (g, buf);
	free (buf);
	return ret;
}

static int _server_handle_qTStatus(libgdbr_t *g) {
	int ret;
	// Trace is not running, and was never run
	const char *message = "T0;tnotrun:0";
	if ((ret = send_ack (g)) < 0) {
		return -1;
	}
	return send_msg (g, message);
}

static int _server_handle_qC(libgdbr_t *g, int (*cmd_cb) (void*, const char*, char*, size_t), void *core_ptr) {
	char *buf;
	int ret;
	size_t buf_len = 80;
	if ((ret = send_ack (g)) < 0) {
		return -1;
	}
	if (!(buf = malloc (buf_len))) {
		return -1;
	}
	if ((ret = cmd_cb (core_ptr, "dp", buf, buf_len)) < 0) {
		free (buf);
		return -1;
	}
	ret = send_msg (g, buf);
	free (buf);
	return ret;
}

static int _server_handle_k(libgdbr_t *g, int (*cmd_cb) (void*, const char*, char*, size_t), void *core_ptr) {
	send_ack (g);
	return -1;
}

static int _server_handle_vKill(libgdbr_t *g, int (*cmd_cb) (void*, const char*, char*, size_t), void *core_ptr) {
	if (send_ack (g) < 0) {
		return -1;
	}
	// TODO handle killing of pid
	send_msg (g, "OK");
	return -1;
}

static int _server_handle_qAttached(libgdbr_t *g, int (*cmd_cb) (void*, const char*, char*, size_t), void *core_ptr) {
	if (send_ack (g) < 0) {
		return -1;
	}
	// TODO check if process was attached or created
	// Right now, says that process was created
	return send_msg (g, "0");
}

static int _server_handle_Hg(libgdbr_t *g, int (*cmd_cb) (void*, const char*, char*, size_t), void *core_ptr) {
	// We don't yet support multiprocess. Client is not supposed to send Hgp. If we receive it anyway,
	// send error
	char cmd[32];
	int tid;
	if (send_ack (g) < 0) {
		return -1;
	}
	if (g->data_len <= 2 || isalpha (g->data[2])) {
		return send_msg (g, "E01");
	}
	sscanf (g->data + 2, "%x", &tid);
	snprintf (cmd, sizeof (cmd) - 1, "dpt=%d", tid);
	// Set thread for future operations
	if (cmd_cb (core_ptr, cmd, NULL, 0) < 0) {
		send_msg (g, "E01");
		return -1;
	}
	return send_msg (g, "OK");
}

static int _server_handle_g(libgdbr_t *g, int (*cmd_cb) (void*, const char*, char*, size_t), void *core_ptr) {
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
	if ((buf_len = cmd_cb (core_ptr, "dr", buf, buf_len)) < 0) {
		free (buf);
		send_msg (g, "E01");
		return -1;
	}
	ret = send_msg (g, buf);
	free (buf);
	return ret;
}

static int _server_handle_m(libgdbr_t *g, int (*cmd_cb) (void*, const char*, char*, size_t), void *core_ptr) {
	int ret;
	ut64 addr;
	int length;
	char *buf1, *buf2, cmd[64];
	int buf1_len, buf2_len;

	if (send_ack (g) < 0) {
		return -1;
	}
	g->data[g->data_len] = 0;
	sscanf (g->data, "m%"PFMT64x",%d", &addr, &length);
	if (g->data_len < 4 || !strchr (g->data, ',')) {
		return send_msg (g, "E01");
	}
	buf1_len = length;
	buf2_len = length * 2 + 1;
	if (!(buf1 = malloc (buf1_len))) {
		return -1;
	}
	if (!(buf2 = malloc (buf2_len))) {
		free (buf1);
		return -1;
	}
	memset (buf2, 0, buf2_len);
	snprintf (cmd, sizeof (cmd) - 1, "m %"PFMT64x" %d", addr, length);
	if ((buf1_len = cmd_cb (core_ptr, cmd, buf1, buf1_len)) < 0) {
		free (buf1);
		free (buf2);
		send_msg (g, "E01");
		return -1;
	}
	pack_hex (buf1, buf1_len, buf2);
	ret = send_msg (g, buf2);
	free (buf1);
	free (buf2);
	return ret;
}

int gdbr_server_serve(libgdbr_t *g, int (*cmd_cb) (void*, const char*, char*, size_t), void *core_ptr) {
	int ret;
	if (!g) {
		return -1;
	}
	while (1) {
		read_packet (g);
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
		if (r_str_startswith (g->data, "Hg")) {
			if ((ret = _server_handle_Hg (g, cmd_cb, core_ptr)) < 0) {
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
		if (r_str_startswith (g->data, "m")) {
			if ((ret = _server_handle_m (g, cmd_cb, core_ptr)) < 0) {
				return ret;
			}
			continue;
		}
	};
	return ret;
}
