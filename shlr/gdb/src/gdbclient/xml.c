#include "gdbclient/xml.h"
#include "gdbclient/core.h"
#include "arch.h"
#include "gdbr_common.h"
#include "packet.h"

static char* gdbr_read_feature(libgdbr_t *g, const char *file, ut64 *tot_len);

// If xml target description is supported, read it
int gdbr_read_target_xml(libgdbr_t *g) {
	if (!g->stub_features.qXfer_features_read) {
		return -1;
	}
	char *data, *ptr;
	ut64 len;
	data = gdbr_read_feature (g, "target.xml", &len);

	// Parse
	if (!(ptr = strstr (data, "<target"))) {
		free (data);
		return -1;
	}


	eprintf ("data: %s\n", data);
	free (data);
	return 0;
}


static char* gdbr_read_feature(libgdbr_t *g, const char *file, ut64 *tot_len) {
	ut64 retlen = 0, retmax = 0, off = 0, len = g->stub_features.pkt_sz - 2,
		blksz = g->data_max, subret_space = 0, subret_len = 0;
	char *tmp, *tmp2, *tmp3, *ret = NULL, *subret = NULL, msg[128] = { 0 },
		status, tmpchar;
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
			*tot_len = retlen;
			return ret;
		}
		status = g->data[0];
		if (retmax - retlen < g->data_len) {
			if (!(tmp = realloc (ret, retmax + blksz))) {
				free (ret);
				return NULL;
			}
			retmax += blksz;
			ret = tmp;
		}
		strcpy (ret + retlen, g->data + 1);
		tmp = strstr (ret + retlen, "<xi:include");
		retlen += g->data_len - 1;
		off += g->data_len - 1;
		while (tmp) {
			// inclusion
			if (!(tmp2 = strstr (tmp, "/>"))) {
				free (ret);
				return NULL;
			}
			subret_space = tmp2 + 2 - tmp;
			if (!(tmp2 = strstr (tmp, "href="))) {
				free (ret);
				return NULL;
			}
			tmp2 += 6;
			if (!(tmp3 = strchr (tmp2, '"'))) {
				free (ret);
				return NULL;
			}
			tmpchar = *tmp3;
			*tmp3 = '\0';
			subret = gdbr_read_feature (g, tmp2, &subret_len);
			*tmp3 = tmpchar;
			if (subret) {
				if (subret_len <= subret_space) {
					memcpy (tmp, subret, subret_len);
					memcpy (tmp + subret_len, tmp + subret_space,
						subret_space - subret_len);
					retlen -= subret_space - subret_len;
					ret[retlen] = '\0';
					tmp = strstr (tmp3, "<xi:include");
					continue;
				}
				if (subret_len > retmax - retlen - 1) {
					// Yes
					tmp3 = NULL;
					if (!(tmp3 = realloc (ret, retmax + subret_len))) {
						free (ret);
						free (subret);
						return NULL;
					}
					tmp = tmp3 + (tmp - ret);
					ret = tmp3;
					retmax += subret_len + 1;
				}
				memmove (tmp + subret_len, tmp + subret_space,
					 retlen - (tmp + subret_space - ret));
				memcpy (tmp, subret, subret_len);
				retlen += subret_len - subret_space;
				free (subret);
			}
			tmp = strstr (tmp3, "<xi:include");
		}
		if (status == 'l') {
			*tot_len = retlen;
			return ret;
		}
		if (status != 'm') {
			free(ret);
			return NULL;
		}
	}
	free(ret);
	return NULL;
}
