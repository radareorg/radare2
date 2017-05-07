/* libgdbr - LGPL - Copyright 2014 - defragger */

#include "arch.h"
#include "gdbclient/responses.h"
#include "gdbclient/core.h"
#include "utils.h"
#include "r_util/r_str.h"


int handle_g(libgdbr_t *g) {
	if (unpack_hex (g->data, g->data_len, g->data) < 0) {
		return -1;
	}
	g->data_len = g->data_len / 2;
	return send_ack (g);
}

int handle_G(libgdbr_t *g) {
	return send_ack (g);
}

int handle_M(libgdbr_t *g) {
	return send_ack (g);
}

int handle_P(libgdbr_t *g) {
	if (g->data_len == 0) {
		g->last_code = MSG_NOT_SUPPORTED;
	} else {
		g->last_code = MSG_OK;
	}
	return send_ack (g);
}

int handle_m(libgdbr_t *g) {
	int len = strlen (g->data);
	g->data_len = strlen (g->data) / 2;
	unpack_hex (g->data, len, g->data);
	return send_ack (g);
}

int handle_cmd(libgdbr_t *g) {
	unpack_hex (g->data, strlen (g->data), g->data);
	g->data_len = strlen (g->data) / 2;
	return send_ack (g);
}

int handle_qStatus(libgdbr_t *g) {
	if (!g || !g->data || !*g->data) {
		return -1;
	}
	char *data = strdup (g->data);
	char *tok = strtok (data, ";");
	if (!tok) {
		free (data);
		return -1;
	}
	// TODO: We do not yet handle the case where a trace is already running
	if (strncmp (tok, "T0", 2)) {
		send_ack (g);
		free (data);
		return -1;
	}
	// Ensure that trace was never run
	while (tok != NULL) {
		if (!strncmp (tok, "tnotrun:0", 9)) {
			free (data);
			return send_ack (g);
		}
		tok = strtok (NULL, ";");
	}
	send_ack (g);
	free (data);
	return -1;
}

int handle_qC(libgdbr_t *g) {
	char *t1, *t2;
	// We get process and thread ID
	if (strncmp (g->data, "QC", 2)) {
		send_ack (g);
		return -1;
	}
	t2 = g->data + 2;
	if ((t1 = strchr (g->data, 'p'))) {
		if (!(t2 = strchr (g->data, '.'))) {
			send_ack (g);
			return -1;
		} else {
			t1++;
			g->pid = strtol (t1, NULL, 16);
			t2++;
		}
	}
	g->tid = strtol (t2, NULL, 16);
	return send_ack (g);
}

int handle_execFileRead(libgdbr_t *g) {
	if (g->data[0] == 'E') {
		send_ack (g);
		return -1;
	}
	if (!g->data[1]) {
		// We're supposed to get filename too
		send_ack (g);
		return -1;
	}
	g->exec_file_name = strdup (g->data + 1);
	return send_ack (g);
}

int handle_fOpen(libgdbr_t *g) {
	if (!*g->data || g->data[0] != 'F') {
		send_ack (g);
		return -1;
	}
	g->exec_fd = strtol (g->data + 1, NULL, 16);
	return send_ack (g);
}

int handle_fstat(libgdbr_t *g) {
	// no data just mean this is not supported by gdb
	if (!*g->data) {
        send_ack (g);
        return 0;
    }

    if (g->data[0] != 'F' || g->data[1] == '-') {
		send_ack (g);
		return -1;
	}
	int size = strtol (g->data + 1, NULL, 16);
	if (size < sizeof (libgdbr_fstat_t)) {
		send_ack (g);
		return -1;
	}
	char *ptr = strchr (g->data, ';');
	if (!ptr) {
		send_ack (g);
		return -1;
	}
/*
        libgdbr_fstat_t *fstat = (libgdbr_fstat_t*) (ptr + 1);
        g->exec_file_sz = 0;
        unsigned char *c = &fstat->size;
        for (int i = 0; i < 8; i++) {
                g->exec_file_sz <<= 4;
                g->exec_file_sz |= *c;
        }
 */
	return send_ack (g);
}

int handle_qSupported(libgdbr_t *g) {
	// TODO handle the message correct and set all infos like packetsize, thread stuff and features
	char *tok = NULL;
	tok = strtok (g->data, ";");
	while (tok) {
		if (r_str_startswith (tok, "PacketSize=")) {
			g->stub_features.pkt_sz = strtoul (tok + strlen ("PacketSize="), NULL, 16);
		} else if (r_str_startswith (tok, "qXfer:")) {
			if (!tok[6]) {
				tok = strtok (NULL, ";");
				continue;
			}
			char *p = tok + 6;
			if (r_str_startswith (p, "btrace:read")) {
				g->stub_features.qXfer_btrace_read = (p[strlen ("btrace:read")] == '+');
			} else if (r_str_startswith (p, "btrace-conf:read")) {
				g->stub_features.qXfer_btrace_conf_read = (p[strlen ("btrace-conf:read")] == '+');
			} else if (r_str_startswith (p, "spu:read")) {
				g->stub_features.qXfer_spu_read = (p[strlen ("spu:read")] == '+');
			} else if (r_str_startswith (p, "spu:write")) {
				g->stub_features.qXfer_spu_write = (p[strlen ("spu:write")] == '+');
			} else if (r_str_startswith (p, "libraries:read")) {
				g->stub_features.qXfer_libraries_read = (p[strlen ("libraries:read")] == '+');
			} else if (r_str_startswith (p, "libraries-svr4:read")) {
				g->stub_features.qXfer_libraries_svr4_read = (p[strlen ("libraries-svr4:read")] == '+');
			} else if (r_str_startswith (p, "memory-map:read")) {
				g->stub_features.qXfer_memory_map_read = (p[strlen ("memory-map:read")] == '+');
			} else if (r_str_startswith (p, "auxv:read")) {
				g->stub_features.qXfer_auxv_read = (p[strlen ("auxv:read")] == '+');
			} else if (r_str_startswith (p, "exec-file:read")) {
				g->stub_features.qXfer_exec_file_read = (p[strlen ("exec-file:read")] == '+');
			} else if (r_str_startswith (p, "features:read")) {
				g->stub_features.qXfer_features_read = (p[strlen ("features:read")] == '+');
			} else if (r_str_startswith (p, "sdata:read")) {
				g->stub_features.qXfer_sdata_read = (p[strlen ("sdata:read")] == '+');
			} else if (r_str_startswith (p, "siginfo:read")) {
				g->stub_features.qXfer_siginfo_read = (p[strlen ("siginfo:read")] == '+');
			} else if (r_str_startswith (p, "siginfo:write")) {
				g->stub_features.qXfer_siginfo_write = (p[strlen ("siginfo:write")] == '+');
			} else if (r_str_startswith (p, "threads:read")) {
				g->stub_features.qXfer_threads_read = (p[strlen ("threads:read")] == '+');
			} else if (r_str_startswith (p, "traceframe-info:read")) {
				g->stub_features.qXfer_traceframe_info_read = (p[strlen ("traceframe-info:read")] == '+');
			} else if (r_str_startswith (p, "uib:read")) {
				g->stub_features.qXfer_uib_read = (p[strlen ("uib:read")] == '+');
			} else if (r_str_startswith (p, "fdpic:read")) {
				g->stub_features.qXfer_fdpic_read = (p[strlen ("fdpic:read")] == '+');
			} else if (r_str_startswith (p, "osdata:read")) {
				g->stub_features.qXfer_osdata_read = (p[strlen ("osdata:read")] == '+');
			}
		} else if (tok[0] == 'Q') {
			if (r_str_startswith (tok, "Qbtrace")) {
				if (!tok[strlen ("Qbtrace")]) {
					tok = strtok (NULL, ";");
					continue;
				}
				char *p = tok + 7;
				if (r_str_startswith (p, ":off")) {
					g->stub_features.Qbtrace_off = (p[4] == '+');
				} else if (r_str_startswith (p, ":bts")) {
					g->stub_features.Qbtrace_bts = (p[4] == '+');
				} else if (r_str_startswith (p, ":pt")) {
					g->stub_features.Qbtrace_pt = (p[3] == '+');
				} else if (r_str_startswith (p, "-conf:bts:size")) {
					g->stub_features.Qbtrace_conf_bts_size = (p[strlen ("-conf:bts:size")] == '+');
				} else if (r_str_startswith (p, ":-conf:pt:size")) {
					g->stub_features.Qbtrace_conf_pt_size = (p[strlen ("-conf:pt:size")] == '+');
				}
			} else if (r_str_startswith (tok, "QNonStop")) {
				g->stub_features.QNonStop = (tok[strlen ("QNonStop")] == '+');
			} else if (r_str_startswith (tok, "QCatchSyscalls")) {
				g->stub_features.QCatchSyscalls = (tok[strlen ("QCatchSyscalls")] == '+');
			} else if (r_str_startswith (tok, "QPassSignals")) {
				g->stub_features.QPassSignals = (tok[strlen ("QPassSignals")] == '+');
			} else if (r_str_startswith (tok, "QStartNoAckMode")) {
				g->stub_features.QStartNoAckMode = (tok[strlen ("QStartNoAckMode")] == '+');
			} else if (r_str_startswith (tok, "QAgent")) {
				g->stub_features.QAgent = (tok[strlen ("QAgent")] == '+');
			} else if (r_str_startswith (tok, "QAllow")) {
				g->stub_features.QAllow = (tok[strlen ("QAllow")] == '+');
			} else if (r_str_startswith (tok, "QDisableRandomization")) {
				g->stub_features.QDisableRandomization = (tok[strlen ("QDisableRandomization")] == '+');
			} else if (r_str_startswith (tok, "QTBuffer:size")) {
				g->stub_features.QTBuffer_size = (tok[strlen ("QTBuffer:size")] == '+');
			} else if (r_str_startswith (tok, "QThreadEvents")) {
				g->stub_features.QThreadEvents = (tok[strlen ("QThreadEvents")] == '+');
			}
		} else if (r_str_startswith (tok, "multiprocess")) {
			g->stub_features.multiprocess = (tok[strlen ("multiprocess")] == '+');
		}
		// TODO
		tok = strtok (NULL, ";");
	}
	return send_ack (g);
}

int handle_cont(libgdbr_t *g) {
	// Possible answers here 'S,T,W,X,O,F'
	return send_ack (g);
}

int handle_setbp(libgdbr_t *g) {
	return send_ack (g);
}

int handle_removebp(libgdbr_t *g) {
	return send_ack (g);
}
