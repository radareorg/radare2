/* Common functions for both client and server. Not part of the libgdbr interface */

#include "libgdbr.h"
#include "gdbr_common.h"
#include "packet.h"
#include "utils.h"
#include "r_util/r_str.h"

int handle_qSupported(libgdbr_t *g) {
	char *tok = NULL;
	// Catch no data received
	if (!*g->data) {
		return -1;
	}
	// TODO handle the message correct and set all infos like packetsize, thread stuff and features
	tok = strtok (g->data, ";");
	while (tok) {
		if (r_str_startswith (tok, "PacketSize=")) {
			// Largest packet size we support is 2048
			g->stub_features.pkt_sz = R_MIN (strtoul (tok + strlen ("PacketSize="), NULL, 16), 2048);
			// Shouldn't be smaller than 64 (Erroneous 0 etc.)
			g->stub_features.pkt_sz = R_MAX (g->stub_features.pkt_sz, 64);
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
			} else if (r_str_startswith (tok, "QThreadSuffixSupported")) {
				g->remote_type = GDB_REMOTE_TYPE_LLDB;
				g->stub_features.lldb.QThreadSuffixSupported
					= (tok[strlen ("QThreadSuffixSupported")] == '+');
			} else if (r_str_startswith (tok, "QListThreadsInStopReply")) {
				g->remote_type = GDB_REMOTE_TYPE_LLDB;
				g->stub_features.lldb.QListThreadsInStopReply
					= (tok[strlen ("QListThreadsInStopReply")] == '+');
			}
		} else if (r_str_startswith (tok, "multiprocess")) {
			g->stub_features.multiprocess = (tok[strlen ("multiprocess")] == '+');
		} else if (r_str_startswith (tok, "qEcho")) {
			g->remote_type = GDB_REMOTE_TYPE_LLDB;
			g->stub_features.lldb.qEcho = (tok[strlen ("qEcho")] == '+');
		} else if (r_str_startswith (tok, "ReverseStep")) {
			g->stub_features.ReverseStep = (tok[strlen ("ReverseStep")] == '+');
		} else if (r_str_startswith (tok, "ReverseContinue")) {
			g->stub_features.ReverseContinue = (tok[strlen ("ReverseContinue")] == '+');
		}
		// TODO
		tok = strtok (NULL, ";");
	}
	return send_ack (g);
}


// SENDING MESSAGES/ACK

int send_ack(libgdbr_t *g) {
	if (g) {
		if (g->no_ack) {
			return 0;
		}
		if (r_socket_write (g->sock, "+", 1) < 0) {
			return -1;
		}
		if (g->server_debug) {
			eprintf ("[sent ack]\n");
		}
		return 0;
	}
	return -1;
}

int send_msg(libgdbr_t *g, const char *msg) {
	int ret;
	if (!g || !msg) {
		return -1;
	}
	ret = pack (g, msg);
	if (ret < 0) {
		return -1;
	}
	ret = send_packet (g);
	g->send_len = ret;
	return ret;
}
