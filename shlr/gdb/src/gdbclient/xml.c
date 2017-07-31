#include "gdbclient/xml.h"
#include "gdbclient/core.h"
#include "arch.h"
#include "gdbr_common.h"
#include "packet.h"

static char* gdbr_read_feature(libgdbr_t *g, const char *file);

// If xml target description is supported, read it
int gdbr_read_target_xml(libgdbr_t *g) {
	if (!g->stub_features.qXfer_features_read) {
		return -1;
	}
	char *data, *ptr;
	data = gdbr_read_feature (g, "target.xml");

	// Parse
	if (!(ptr = strstr (data, "<target"))) {
		free (data);
		return -1;
	}


	eprintf ("data: %s\n", data);
	free (data);
	return 0;
}


static char* gdbr_read_feature(libgdbr_t *g, const char *file) {
	ut64 retlen = 0, retmax = 0, off = 0, len = g->stub_features.pkt_sz - 2,
		blksz = g->data_max;
	char *tmp, *ret = NULL, msg[128] = { 0 };
	while (1) {
		snprintf (msg, sizeof (msg), "qXfer:features:read:%s:%"PFMT64x
			  ",%"PFMT64x, file, off, len);
		if (send_msg (g, msg) < 0
		    || read_packet (g) < 0 || send_ack (g) < 0) {
			free(ret);
			return -1;
		}
		if (g->data_len == 0) {
			free(ret);
			return NULL;
		}
		if (g->data_len == 1 && g->data[0] == 'l') {
			return ret;
		}
		if (retmax - retlen < g->data_len) {
			if (!(tmp = realloc (ret, retmax + blksz))) {
				free (ret);
				return NULL;
			}
			retmax += blksz;
			ret = tmp;
		}
		strcpy (ret + retlen, g->data + 1);
		retlen += g->data_len - 1;
		if (g->data[0] == 'l') {
			return ret;
		}
		if (g->data[0] != 'm') {
			free(ret);
			return NULL;
		}
	}
	free(ret);
	return NULL;
}
