#include "gdbserver/core.h"
#include "gdbr_common.h"
#include "libgdbr.h"
#include "packet.h"
#include "r_util/r_str.h"

static int _server_handle_qSupported(libgdbr_t *g) {
	int ret;
	char *buf;
	if (!(buf = malloc (128))) {
		return -1;
	}
	snprintf (buf, 127, "PacketSize=%x", (ut32) (g->read_max - 1));
	ret = handle_qSupported (g);
	if (ret < 0) {
		return ret;
	}
	int res = send_msg (g, buf);
	free (buf);
	return res;
}

static int _server_handle_qTStatus(libgdbr_t *g) {
	int ret;
	// Trace is not running, and was never run
	const char *message = "T0;tnotrun:0";
	ret = send_ack (g);
	if (ret < 0) {
		return ret;
	}
	return send_msg (g, message);
}

static int _server_handle_qC(libgdbr_t *g, char *buf, size_t max_len) {
	if (max_len <= 2) {
		return -1;
	}
	strcpy (buf, "dp");
	return send_ack (g);
}

int gdbr_server_read(libgdbr_t *g, char *buf, size_t max_len) {
	bool loop_continue;
	int ret = -1;
	if (!g) {
		return -1;
	}
	memset (buf, 0, max_len);

	do {
		loop_continue = false;
		read_packet (g);
		while (!*g->data) {
			read_packet (g);
		}

		if (r_str_startswith (g->data, "qSupported")) {
			loop_continue = true;
			if ((ret = _server_handle_qSupported (g)) < 0) {
				return ret;
			}
		} else if (r_str_startswith (g->data, "qTStatus")) {
			loop_continue = true;
			if ((ret = _server_handle_qTStatus (g)) < 0) {
				return ret;
			}
		} else if (r_str_startswith (g->data, "qC")) {
			if ((ret = _server_handle_qC (g, buf, max_len)) < 0) {
				return ret;
			}
		}
	} while (loop_continue);
	return ret;
}

int gdbr_server_send(libgdbr_t *g, const char *buf, size_t max_len) {
	return 0;
}
