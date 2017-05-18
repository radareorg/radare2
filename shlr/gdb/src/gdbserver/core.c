#include "gdbserver/core.h"
#include "libgdbr.h"
#include "packet.h"

int gdbr_server_read(libgdbr_t *g, char *buf, size_t max_len) {
	int ret;
	if (!g) {
		return -1;
	}
	read_packet (g);
	strncpy (g->read_buff, buf, max_len);
	return 0;
}
