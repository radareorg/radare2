/* Common functions for both client and server. Not part of the libgdbr interface */

#include "libgdbr.h"
#include "gdbr_common.h"
#include "packet.h"
#include "utils.h"
#include "r_util/r_str.h"
#include "r_util/r_log.h"

#define FEATURE(name, field) { name, offsetof (libgdbr_stub_features_t, field) }
static const struct {
	const char *name;
	size_t offset;
} features[] = {
	FEATURE ("BreakpointCommands", BreakpointCommands),
	FEATURE ("ConditionalBreakpoints", ConditionalBreakpoints),
	FEATURE ("ConditionalTracepoints", ConditionalTracepoints),
	FEATURE ("EnableDisableTracepoints", EnableDisableTracepoints),
	FEATURE ("InstallInTrace", InstallInTrace),
	FEATURE ("QAgent", QAgent),
	FEATURE ("QAllow", QAllow),
	FEATURE ("QCatchSyscalls", QCatchSyscalls),
	FEATURE ("QDisableRandomization", QDisableRandomization),
	FEATURE ("QListThreadsInStopReply", lldb.QListThreadsInStopReply),
	FEATURE ("QNonStop", QNonStop),
	FEATURE ("QPassSignals", QPassSignals),
	FEATURE ("QStartNoAckMode", QStartNoAckMode),
	FEATURE ("QTBuffer:size", QTBuffer_size),
	FEATURE ("QThreadEvents", QThreadEvents),
	FEATURE ("QThreadSuffixSupported", lldb.QThreadSuffixSupported),
	FEATURE ("Qbtrace-conf:bts:size", Qbtrace_conf_bts_size),
	FEATURE ("Qbtrace-conf:pt:size", Qbtrace_conf_pt_size),
	FEATURE ("Qbtrace:bts", Qbtrace_bts),
	FEATURE ("Qbtrace:off", Qbtrace_off),
	FEATURE ("Qbtrace:pt", Qbtrace_pt),
	FEATURE ("ReverseContinue", ReverseContinue),
	FEATURE ("ReverseStep", ReverseStep),
	FEATURE ("StaticTracepoint", StaticTracepoint),
	FEATURE ("TracepointSource", TracepointSource),
	FEATURE ("augmented-libraries-svr4-read", augmented_libraries_svr4_read),
	FEATURE ("exec-events", exec_events),
	FEATURE ("fork-events", fork_events),
	FEATURE ("hwbreak", hwbreak),
	FEATURE ("multiprocess", multiprocess),
	FEATURE ("no-resumed", no_resumed),
	FEATURE ("qEcho", lldb.qEcho),
	FEATURE ("qXfer:auxv:read", qXfer_auxv_read),
	FEATURE ("qXfer:btrace-conf:read", qXfer_btrace_conf_read),
	FEATURE ("qXfer:btrace:read", qXfer_btrace_read),
	FEATURE ("qXfer:exec-file:read", qXfer_exec_file_read),
	FEATURE ("qXfer:fdpic:read", qXfer_fdpic_read),
	FEATURE ("qXfer:features:read", qXfer_features_read),
	FEATURE ("qXfer:libraries-svr4:read", qXfer_libraries_svr4_read),
	FEATURE ("qXfer:libraries:read", qXfer_libraries_read),
	FEATURE ("qXfer:memory-map:read", qXfer_memory_map_read),
	FEATURE ("qXfer:osdata:read", qXfer_osdata_read),
	FEATURE ("qXfer:sdata:read", qXfer_sdata_read),
	FEATURE ("qXfer:siginfo:read", qXfer_siginfo_read),
	FEATURE ("qXfer:siginfo:write", qXfer_siginfo_write),
	FEATURE ("qXfer:spu:read", qXfer_spu_read),
	FEATURE ("qXfer:spu:write", qXfer_spu_write),
	FEATURE ("qXfer:threads:read", qXfer_threads_read),
	FEATURE ("qXfer:traceframe-info:read", qXfer_traceframe_info_read),
	FEATURE ("qXfer:uib:read", qXfer_uib_read),
	FEATURE ("swbreak", swbreak),
	FEATURE ("tracenz", tracenz),
	FEATURE ("vContSupported", vContSupported),
	FEATURE ("vfork-events", vfork__events),
};
#undef FEATURE

int handle_qSupported(libgdbr_t *g) {
	char *save = NULL;
	char *token = r_str_tok_r (g->data, ";", &save);
	libgdbr_stub_features_t *stub = &g->stub_features;
	for (; token; token = r_str_tok_r (NULL, ";", &save)) {
		if (r_str_startswith (token, "PacketSize=")) {
			ut64 size;
			const char *end = gdbr_parse_hex_value (token + strlen ("PacketSize="), &size);
			if (!end || *end || !size) {
				stub->pkt_sz = 0;
				return -1;
			}
			stub->pkt_sz = R_MIN (size, 2048);
			continue;
		}
		size_t length = strlen (token);
		if (length < 2) {
			continue;
		}
		const char state = token[length - 1];
		if (state != '+' && state != '-') {
			continue;
		}
		token[length - 1] = '\0';
		size_t i;
		for (i = 0; i < R_ARRAY_SIZE (features); i++) {
			if (!strcmp (token, features[i].name)) {
				bool *enabled = (bool *)((char *)stub + features[i].offset);
				*enabled = state == '+';
				break;
			}
		}
	}
	if (stub->lldb.qEcho || stub->lldb.QThreadSuffixSupported || stub->lldb.QListThreadsInStopReply) {
		g->remote_type = GDB_REMOTE_TYPE_LLDB;
	}
	return 0;
}

int send_ack(libgdbr_t *g) {
	if (g) {
		if (g->no_ack) {
			return 0;
		}
		if (r_socket_write (g->sock, "+", 1) != 1) {
			return -1;
		}
		R_LOG_DEBUG ("[sent ack]");
		return 0;
	}
	return -1;
}

int send_msg(libgdbr_t *g, const char *msg) {
	int ret;
	if (!g || !msg) {
		return -1;
	}
	g->ack_retries = -1;
	ret = pack (g, msg);
	if (ret < 0) {
		return -1;
	}
	ret = send_packet (g);
	if (ret >= 0 && !g->no_ack) {
		g->ack_retries = 0;
	}
	return ret;
}
