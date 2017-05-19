#include "gdbserver/core.h"
#include "gdbr_common.h"
#include "libgdbr.h"
#include "packet.h"
#include "r_util/r_str.h"

int gdbr_server_read(libgdbr_t *g, char *buf, size_t max_len) {
	int ret;
	if (!g) {
		return -1;
	}
	memset (buf, 0, max_len);
	read_packet (g);
	if (r_str_startswith (g->read_buff, "qSupported")) {
		ret = handle_qSupported (g);
	}
	strncpy (buf, g->read_buff, max_len);
	return ret;
}
