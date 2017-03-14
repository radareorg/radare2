/* libgdbr - LGPL - Copyright 2014 - defragger */

#include "messages.h"
#include "arch.h"
#include "core.h"
#include "utils.h"


int handle_g(libgdbr_t* g) {
	if (unpack_hex (g->data, g->data_len, g->data) < 0) {
		return -1;
	}
	g->data_len = g->data_len / 2;
	return send_ack (g);
}

int handle_G(libgdbr_t* g) {
	return send_ack (g);
}

int handle_M(libgdbr_t* g) {
	return send_ack (g);
}

int handle_P(libgdbr_t* g) {
	if (g->data_len == 0) {
		g->last_code = MSG_NOT_SUPPORTED;
	}
	else {
		g->last_code = MSG_OK;
	}
	return send_ack (g);
}

int handle_m(libgdbr_t* g) {
	int len = strlen (g->data);
	g->data_len = strlen (g->data) / 2;
	unpack_hex (g->data, len, g->data);
	return send_ack (g);
}

int handle_cmd(libgdbr_t* g) {
	unpack_hex (g->data, strlen (g->data), g->data);
	g->data_len = strlen (g->data) / 2;
	return send_ack (g);
}

int handle_qStatus(libgdbr_t* g) {
	char *tok = NULL;
	tok = strtok (g->data, ";");
	// TODO: We do not yet handle the case where a trace is already running
	if (strncmp (tok, "T0", 2)) {
		send_ack (g);
		return -1;
	}
	// Ensure that trace was never run
	while (tok != NULL) {
		if (!strncmp (tok, "tnotrun:0", 9)) {
			return send_ack (g);
		}
	    tok = strtok (NULL, ";");
	}
	send_ack (g);
	return -1;
}

int handle_qC(libgdbr_t* g) {
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
			unpack_hex (t1, t2 - t1, (char*) &g->pid);
			t2++;
		}
	}
	unpack_hex (t2, strlen (t2), (char*) &g->tid);
	return send_ack (g);
}

int handle_qSupported(libgdbr_t* g) {
	// TODO handle the message correct and set all infos like packetsize, thread stuff and features
	char *tok = NULL;
	tok = strtok (g->data, ";");
	while (tok != NULL) {
		if (!strncmp (tok, "PacketSize=", 11)) {
			char temp_buf[20] = { 0 };
			temp_buf[0] = '0';
			temp_buf[1] = 'x';
			snprintf (temp_buf + 2, 16, "%s", tok + 11);
			g->stub_features.pkt_sz = strtoul (temp_buf, NULL, 16);
		} else if (!strncmp (tok, "qXfer:", 6)) {
			if (!*(tok + 6)) {
				tok = strtok(NULL, ";");
				continue;
			}
			char *p = tok + 6;
			if (!strncmp (p, "btrace:read", 11)) {
				g->stub_features.qXfer_btrace_read = (p[11] == '+') ? 1 : 0;
			} else if (!strncmp (p, "btrace-conf:read", 16)) {
				g->stub_features.qXfer_btrace_conf_read = (p[16] == '+') ? 1 : 0;
			} else if (!strncmp (p, "spu:read", 8)) {
				g->stub_features.qXfer_spu_read = (p[8] == '+') ? 1 : 0;
			} else if (!strncmp (p, "spu:write", 9)) {
				g->stub_features.qXfer_spu_write = (p[9] == '+') ? 1 : 0;
			} else if (!strncmp (p, "libraries:read", 14)) {
				g->stub_features.qXfer_libraries_read = (p[14] == '+') ? 1 : 0;
			} else if (!strncmp (p, "libraries-svr4:read", 19)) {
				g->stub_features.qXfer_libraries_svr4_read = (p[19] == '+') ? 1 : 0;
			} else if (!strncmp (p, "memory-map:read", 15)) {
				g->stub_features.qXfer_memory_map_read = (p[15] == '+') ? 1 : 0;
			} else if (!strncmp (p, "auxv:read", 9)) {
				g->stub_features.qXfer_auxv_read = (p[9] == '+') ? 1 : 0;
			} else if (!strncmp (p, "exec-file:read", 14)) {
				g->stub_features.qXfer_exec_file_read = (p[14] == '+') ? 1 : 0;
			} else if (!strncmp (p, "features:read", 13)) {
				g->stub_features.qXfer_features_read = (p[13] == '+') ? 1 : 0;
			} else if (!strncmp (p, "sdata:read", 10)) {
				g->stub_features.qXfer_sdata_read = (p[10] == '+') ? 1 : 0;
			} else if (!strncmp (p, "siginfo:read", 12)) {
				g->stub_features.qXfer_siginfo_read = (p[12] == '+') ? 1 : 0;
			} else if (!strncmp (p, "siginfo:write", 13)) {
				g->stub_features.qXfer_siginfo_write = (p[13] == '+') ? 1 : 0;
			} else if (!strncmp (p, "threads:read", 12)) {
				g->stub_features.qXfer_threads_read = (p[12] == '+') ? 1 : 0;
			} else if (!strncmp (p, "traceframe-info:read", 20)) {
				g->stub_features.qXfer_traceframe_info_read = (p[20] == '+') ? 1 : 0;
			} else if (!strncmp (p, "uib:read", 8)) {
				g->stub_features.qXfer_uib_read = (p[8] == '+') ? 1 : 0;
			} else if (!strncmp (p, "fdpic:read", 10)) {
				g->stub_features.qXfer_fdpic_read = (p[10] == '+') ? 1 : 0;
			} else if (!strncmp (p, "osdata:read", 11)) {
				g->stub_features.qXfer_osdata_read = (p[11] == '+') ? 1 : 0;
			}
		} else if (tok[0] == 'Q') {
			if (!strncmp (tok, "Qbtrace", 7)) {
				if (!*(tok + 7)) {
					tok = strtok(NULL, ";");
					continue;
				}
				char *p = tok + 7;
				if (!strncmp (p, ":off", 4)) {
					g->stub_features.Qbtrace_off = (p[4] == '+') ? 1 : 0;
				} else if (!strncmp (p, ":bts", 4)) {
					g->stub_features.Qbtrace_bts = (p[4] == '+') ? 1 : 0;
				} else if (!strncmp (p, ":pt", 3)) {
					g->stub_features.Qbtrace_pt = (p[3] == '+') ? 1 : 0;
				} else if (!strncmp (p, "-conf:bts:size", 14)) {
					g->stub_features.Qbtrace_conf_bts_size = (p[14] == '+') ? 1 : 0;
				} else if (!strncmp (p, ":-conf:pt:size", 14)) {
					g->stub_features.Qbtrace_conf_pt_size = (p[14] == '+') ? 1 : 0;
				}
			} else if (!strncmp (tok, "QNonStop", 8)) {
				g->stub_features.QNonStop = (tok[8] == '+') ? 1 : 0;
			} else if (!strncmp (tok, "QCatchSyscalls", 14)) {
				g->stub_features.QCatchSyscalls = (tok[14] == '+') ? 1 : 0;
			} else if (!strncmp (tok, "QPassSignals", 12)) {
				g->stub_features.QPassSignals = (tok[12] == '+') ? 1 : 0;
			} else if (!strncmp (tok, "QStartNoAckMode", 15)) {
				g->stub_features.QStartNoAckMode = (tok[15] == '+') ? 1 : 0;
			} else if (!strncmp (tok, "QAgent", 6)) {
				g->stub_features.QAgent = (tok[6] == '+') ? 1 : 0;
			} else if (!strncmp (tok, "QAllow", 6)) {
				g->stub_features.QAllow = (tok[6] == '+') ? 1 : 0;
			} else if (!strncmp (tok, "QDisableRandomization", 21)) {
				g->stub_features.QDisableRandomization = (tok[21] == '+') ? 1 : 0;
			} else if (!strncmp (tok, "QTBuffer:size", 13)) {
				g->stub_features.QTBuffer_size = (tok[13] == '+') ? 1 : 0;
			} else if (!strncmp (tok, "QThreadEvents", 13)) {
				g->stub_features.QThreadEvents = (tok[13] == '+') ? 1 : 0;
			}
		} else if (!strncmp (tok, "multiprocess", 12)) {
		    g->stub_features.multiprocess = (tok[12] == '+') ? 1 : 0;
		}
		// TODO
		tok = strtok(NULL, ";");
	}
	return send_ack (g);
}

int handle_cont(libgdbr_t* g) {
	// Possible answers here 'S,T,W,X,O,F'
	return send_ack (g);
}

int handle_setbp(libgdbr_t* g) {
	return send_ack (g);
}

int handle_removebp(libgdbr_t* g) {
	return send_ack (g);
}
