#include <r_debug.h>
#include <gdbclient/commands.h>
#include <gdbclient/responses.h>
#include <gdbclient/xml.h>
#include <gdbr_common.h>
#include <packet.h>
#include <gdbserver/core.h>
#include "minunit.h"
#include "../../libr/core/rtr_gdb.inc.c"

static bool test_gdb_server_register_values(void) {
	const int widths[] = { 8, 16, 24, 32, 64, 80, 96, 128, 256, 384, 512, 2048 };
	RDebug *dbg = r_debug_new (false);
	int endian, width, i;
	for (endian = 0; endian < 2; endian++) {
		for (width = 0; width < R_ARRAY_SIZE (widths); width++) {
			const int size = widths[width] / 8;
			char *profile = r_str_newf ("gpr before .64 0 0\nfpu wide .%d 8 0\nfpu after .64 %d 0\n", widths[width], size + 8);
			mu_assert_true (r_reg_set_profile_string (dbg->reg, profile), "server register profile");
			free (profile);
			dbg->reg->endian = endian? R_SYS_ENDIAN_BIG: R_SYS_ENDIAN_LITTLE;
			gdb_reg_t registers[] = { { .name = "wide", .size = widths[width] }, { .name = "after", .size = 64 }, { .name = "" } };
			ut8 bytes[256], actual[256];
			for (i = 0; i < size; i++) {
				bytes[i] = i + 1;
			}
			char *hex = r_hex_bin2strdup (bytes, size);
			char *cmd = r_str_newf (" wide=0x%s", hex);
			mu_assert_eq (gdb_cmd_reg (dbg, registers, cmd, NULL, 0), 0, "write raw target bytes");
			free (cmd);
			RRegItem *item = r_reg_get (dbg->reg, "wide", R_REG_TYPE_ALL);
			mu_assert_true (r_reg_get_value_bytes (dbg->reg, item, actual, size), "read back register storage");
			mu_assert_memeq (actual, bytes, size, "wire preserves target byte layout");
			char output[530];
			mu_assert_eq (gdb_cmd_reg (dbg, registers, " wide", output, size * 2 + 1), size * 2, "exact output buffer including terminator");
			mu_assert_streq (output, hex, "single register packet");
			mu_assert_eq (gdb_cmd_reg (dbg, registers, " wide", output, size * 2), -1, "reject short output buffer");
			mu_assert_eq (gdb_cmd_reg (dbg, registers, " wide=0x", NULL, 0), -1, "reject short input");
			cmd = r_str_newf (" wide=0x%s00", hex);
			mu_assert_eq (gdb_cmd_reg (dbg, registers, cmd, NULL, 0), -1, "reject oversized input");
			cmd[strlen (cmd) - 2] = 0;
			cmd[8] = 'z';
			mu_assert_eq (gdb_cmd_reg (dbg, registers, cmd, NULL, 0), -1, "reject invalid input");
			free (cmd);
			mu_assert_eq (gdb_cmd_reg (dbg, registers, "", output, sizeof (output)), size * 2 + 16, "all-register packet length");
			char *expected = r_str_newf ("%s0000000000000000", hex);
			mu_assert_streq_free (expected, output, "all-register bytes and untouched neighbor");
			free (hex);
			r_unref (item);
		}
		mu_assert_true (r_reg_set_profile_string (dbg->reg, "gpr small .16 0 0\ngpr large .64 8 0\n"), "scalar width differences");
		gdb_reg_t registers[] = { { .name = "small", .size = 32 }, { .name = "large", .size = 32 }, { .name = "" } };
		r_reg_setv (dbg->reg, "small", 0x1234);
		r_reg_setv (dbg->reg, "large", 0x1122334455667788ULL);
		char output[17];
		mu_assert_eq (gdb_cmd_reg (dbg, registers, "", output, sizeof (output)), 16, "scalar wire widths");
		mu_assert_streq (output, endian? "0000123455667788": "3412000088776655", "scalar padding and truncation");
		mu_assert_eq (gdb_cmd_reg (dbg, registers, " large=0x12345678", NULL, 0), 0, "write narrower scalar packet");
		mu_assert_eq (r_reg_getv (dbg->reg, "large"), endian? 0x12345678: 0x78563412, "scalar write zero-extends");
	}
	r_debug_free (dbg);
	mu_end;
}

static bool test_gdb_packet_limits(void) {
	libgdbr_t g;
	mu_assert_eq (gdbr_init (&g, false), 0, "initialize packet limits");
	g.stub_features.pkt_sz = 4;
	mu_assert_eq (pack (&g, "abcd"), 8, "exact peer payload limit");
	mu_assert_eq (pack (&g, "abcde"), -1, "reject one byte beyond peer limit");
	mu_assert_eq (pack (&g, "ab#"), 8, "escaped payload fits peer limit");
	mu_assert_eq (pack (&g, "abc#"), -1, "escaping also consumes peer capacity");
	g.stub_features.pkt_sz = 64;
	g.send_max = 10;
	mu_assert_eq (pack (&g, "abcde"), 9, "local framing and terminator fit");
	mu_assert_eq (pack (&g, "abcdef"), -1, "local capacity includes framing");
	mu_assert_eq (pack (&g, "abc#"), 9, "escaped payload fits local capacity");
	mu_assert_eq (pack (&g, "abcd#"), -1, "escaping consumes local capacity");
	g.send_max = 4;
	mu_assert_eq (pack (&g, ""), -1, "even an empty frame needs its terminator");
	g.send_max = 2500;
	g.stub_features.pkt_sz = 4;
	g.is_server = true;
	mu_assert_eq (pack (&g, "abcdefgh"), 12, "peer request limit does not restrict server replies");
	g.no_ack = true;
	const struct {
		const char *reply;
		ut32 limit;
	} cases[] = {
		{ "PacketSize=20", 32 }, { "PacketSize=3", 3 }, { "PacketSize=1", 1 },
		{ "PacketSize=8000", 2048 }, { "PacketSize=0", 0 }, { "PacketSize=", 0 },
		{ "PacketSize=garbage", 0 }, { "PacketSize=20junk", 0 }, { "PacketSize=+20", 0 },
		{ "PacketSize=0x20", 0 }, { "PacketSize=fffffffffffffffffffffffff", 0 }
	};
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (cases); i++) {
		r_str_ncpy (g.data, cases[i].reply, g.data_max);
		g.stub_features.pkt_sz = 64;
		mu_assert_eq (handle_qSupported (&g), cases[i].limit? 0: -1, "validate advertised capacity");
		mu_assert_eq (g.stub_features.pkt_sz, cases[i].limit, "never invent peer capacity");
	}
	gdbr_cleanup (&g);
	mu_end;
}

#if R2__UNIX__ && !__wasi__
#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

static bool send_response(int fd, const char *payload) {
	ut8 checksum = 0;
	const char *p;
	for (p = payload; *p; p++) {
		checksum += (ut8)*p;
	}
	char *packet = r_str_newf ("$%s#%02x", payload, checksum);
	size_t len = strlen (packet);
	bool ret = write (fd, packet, len) == len;
	free (packet);
	return ret;
}

static bool test_gdb_processes_xml(void) {
	const char *tails[] = {
		"",
		"<item>",
		"<item></item>",
		"<item><column name=\"pid\">2</item>",
		"<item><column name=\"pid\">123456</column></item>",
		"<item><column name=\"pid\">2</column></item>",
		"<item><column name=\"pid\">2</column><column name=\"command\">bad</item>"
	};
	RCons *cons = r_cons_new ();
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (tails); i++) {
		int fds[2];
		mu_assert_eq (socketpair (AF_UNIX, SOCK_STREAM, 0, fds), 0, "create GDB socket pair");
		libgdbr_t g;
		mu_assert_eq (gdbr_init (&g, false), 0, "initialize GDB client");
		g.sock->fd = fds[0];
		g.stub_features.qXfer_features_read = true;
		g.stub_features.pkt_sz = 4096;
		g.num_retries = 1;
		char *response = r_str_newf (
			"l<osdata type=\"processes\">"
			"<item><column name=\"pid\">1234</column>"
			"<column name=\"command\">/bin/test</column></item>%s</osdata>", tails[i]);
		// Queue the XML reply and the failed /proc/1234/status open reply.
		mu_assert_true (send_response (fds[1], response), "send process XML");
		free (response);
		mu_assert_true (send_response (fds[1], "F-1,2"), "send procfs open failure");
		RList *list = r_list_newf ((RListFree)r_debug_pid_free);
		int ret = gdbr_read_processes_xml (&g, 0, list);
		gdbr_cleanup (&g);
		close (fds[1]);
		mu_assert_eq (ret, i? -1: 0, "reject malformed process XML");
		mu_assert_eq (r_list_length (list), 1, "retain the valid process entry");
		RDebugPid *process = r_list_first (list);
		mu_assert_notnull (process, "valid process entry");
		mu_assert_eq (process->pid, 1234, "retained process PID");
		mu_assert_streq (process->path, "/bin/test", "retained process command");
		r_list_free (list);
	}
	r_cons_free (cons);
	mu_end;
}

// A scripted stub: it answers each packet the client sends with the next reply of
// its transcript and records the packets, one per line, until the client hangs up
typedef struct {
	int fd;
	int listen_fd;
	const char **replies;
	RStrBuf *sent;
} Stub;

static bool stub_getc(int fd, char *ch) {
	struct pollfd pfd = { .fd = fd, .events = POLLIN };
	return poll (&pfd, 1, 3000) == 1 && read (fd, ch, 1) == 1;
}

static char *stub_recv(int fd) {
	RStrBuf *sb = r_strbuf_new ("");
	bool in_packet = false;
	char ch;
	while (stub_getc (fd, &ch)) {
		if (!in_packet) {
			// acks and anything else between packets
			in_packet = ch == '$';
		} else if (ch == '#') {
			char sum[2];
			if (stub_getc (fd, sum) && stub_getc (fd, sum + 1)) {
				return r_strbuf_drain (sb);
			}
			break;
		} else {
			r_strbuf_append_n (sb, &ch, 1);
		}
	}
	r_strbuf_free (sb);
	return NULL;
}

typedef struct {
	libgdbr_t g;
	RDebug *dbg;
} RegisterServer;

static int register_server_cmd(libgdbr_t *g, void *user, const char *cmd, char *out, size_t size) {
	return r_str_startswith (cmd, "dr")? gdb_cmd_reg (user, g->registers, cmd + 2, out, size): -1;
}

static RThreadFunctionRet register_server_run(RThread *th) {
	RegisterServer *server = th->user;
	gdbr_server_serve (&server->g, register_server_cmd, server->dbg);
	return R_TH_STOP;
}

static bool test_gdb_server_wide_packets(void) {
	const int widths[] = { 512, 2048 };
	int width, i;
	for (width = 0; width < R_ARRAY_SIZE (widths); width++) {
		RegisterServer server = {0};
		server.dbg = r_debug_new (false);
		mu_assert_eq (gdbr_init (&server.g, true), 0, "initialize GDB server");
		RStrBuf *profile = r_strbuf_new ("");
		RStrBuf *expected = r_strbuf_new ("");
		char *hex = r_str_pad (NULL, 0, 'a', widths[width] / 4);
		for (i = 0; hex[i]; i++) {
			hex[i] = "0123456789abcdef"[i & 15];
		}
		for (i = 0; i < 9; i++) {
			r_strbuf_appendf (profile, "fpu v%d .%d 0 0\n", i, widths[width]);
			r_strbuf_append (expected, hex);
		}
		mu_assert_true (r_reg_set_profile_string (server.dbg->reg, r_strbuf_get (profile)), "server storage profile");
		mu_assert_eq (gdbr_set_reg_profile (&server.g, r_strbuf_get (profile)), 0, "server packet profile");
		int fds[2];
		mu_assert_eq (socketpair (AF_UNIX, SOCK_STREAM, 0, fds), 0, "server socket pair");
		server.g.sock->fd = fds[0];
		server.g.no_ack = true;
		RThread *thread = r_th_new (register_server_run, &server, 0);
		r_th_start (thread);
		char *packet = r_str_newf ("P0=%s", hex);
		mu_assert_true (send_response (fds[1], packet), "send wide register write");
		free (packet);
		mu_assert_streq_free (stub_recv (fds[1]), "OK", "accept wide register packet");
		mu_assert_true (send_response (fds[1], "p0"), "request wide register");
		mu_assert_streq_free (stub_recv (fds[1]), hex, "complete single-register reply");
		mu_assert_true (send_response (fds[1], "g"), "request all registers");
		mu_assert_streq_free (stub_recv (fds[1]), r_strbuf_get (expected), "complete reply beyond old fixed buffer");
		mu_assert_true (send_response (fds[1], "k"), "stop server");
		r_th_wait (thread);
		r_th_free (thread);
		gdbr_cleanup (&server.g);
		close (fds[1]);
		r_debug_free (server.dbg);
		r_strbuf_free (profile);
		r_strbuf_free (expected);
		free (hex);
	}
	mu_end;
}

static RThreadFunctionRet stub_run(RThread *th) {
	Stub *stub = th->user;
	if (stub->listen_fd >= 0) {
		stub->fd = accept (stub->listen_fd, NULL, NULL);
	}
	const char **reply = stub->replies;
	char *packet;
	while ((packet = stub_recv (stub->fd))) {
		r_strbuf_appendf (stub->sent, "%s\n", packet);
		free (packet);
		if (*reply) {
			send_response (stub->fd, *reply++);
		}
	}
	return R_TH_STOP;
}

static RThread *stub_start(Stub *stub, int fd, int listen_fd, const char **replies) {
	stub->fd = fd;
	stub->listen_fd = listen_fd;
	stub->replies = replies;
	stub->sent = r_strbuf_new ("");
	RThread *th = r_th_new (stub_run, stub, 0);
	r_th_start (th);
	return th;
}

// Hang up on the stub and return what the client sent it
static char *stub_finish(Stub *stub, RThread *th, int client_fd) {
	shutdown (client_fd, SHUT_WR);
	r_th_wait (th);
	r_th_free (th);
	close (stub->fd);
	return r_strbuf_drain (stub->sent);
}

// Three registers at bit offsets 0, 64 and 96: a 14 byte block
#define PROFILE "gpr a .64 0 0\ngpr b .32 8 0\ngpr c .16 12 0\n"

static bool session_open(libgdbr_t *g, int fds[2], int remote_type) {
	if (socketpair (AF_UNIX, SOCK_STREAM, 0, fds) || gdbr_init (g, false)) {
		return false;
	}
	g->sock->fd = fds[0];
	g->no_ack = true;
	g->num_retries = 4;
	g->remote_type = remote_type;
	g->pid = g->tid = 0x1c03;
	return !gdbr_set_reg_profile (g, PROFILE);
}

static bool check_memory_packets(char *sent, ut64 address, const ut8 *data, size_t len, size_t limit, size_t *written) {
	char *save_ptr = NULL;
	char *packet = r_str_tok_r (sent, "\n", &save_ptr);
	*written = 0;
	while (packet) {
		ut64 at = 0, size = 0;
		int header_len = 0;
		mu_assert ("payload respects the negotiated budget", strlen (packet) <= limit);
		mu_assert_eq (sscanf (packet, "M%"PFMT64x",%"PFMT64x":%n", &at, &size, &header_len), 2, "parse memory write");
		mu_assert ("complete memory header", header_len > 0);
		mu_assert_eq (at, address + *written, "chunks cover consecutive addresses");
		mu_assert ("nonempty bounded chunk", size && size <= len - *written && size <= 256);
		mu_assert_eq (strlen (packet + header_len), size * 2, "declared memory size matches payload");
		ut8 bytes[256];
		mu_assert_eq (r_hex_str2bin (packet + header_len, bytes), size, "valid memory bytes");
		mu_assert_memeq (bytes, data + *written, size, "wire data reconstructs the original write");
		*written += size;
		packet = r_str_tok_r (NULL, "\n", &save_ptr);
	}
	return true;
}

static bool test_gdb_memory_packet_sizes(void) {
	const struct {
		ut32 limit;
		int send_max;
		ut64 address;
		size_t len;
	} cases[] = {
		{ 64, 2500, 0x1000, 256 }, { 63, 2500, 0x1000, 27 }, { 63, 2500, 0x1000, 28 },
		{ 8, 2500, 0xf, 3 }, { 39, 2500, 0xfffffff0, 70 },
		{ 64, 2500, 0x123456789abcdef0ULL, 128 }, { 64, 2500, UT64_MAX, 1 },
		{ 64, 36, 0x1000, 75 }
	};
	RCons *cons = r_cons_new ();
	ut8 bytes[256];
	const char *replies[257];
	size_t i;
	for (i = 0; i < sizeof (bytes); i++) {
		bytes[i] = i;
		replies[i] = "OK";
	}
	replies[256] = NULL;
	for (i = 0; i < R_ARRAY_SIZE (cases); i++) {
		libgdbr_t g;
		int fds[2];
		mu_assert_true (session_open (&g, fds, GDB_REMOTE_TYPE_GDB), "open memory session");
		g.stub_features.pkt_sz = cases[i].limit;
		g.send_max = cases[i].send_max;
		Stub stub;
		RThread *th = stub_start (&stub, fds[1], -1, replies);
		mu_assert_eq (gdbr_write_memory (&g, cases[i].address, bytes, cases[i].len), 0, "complete memory write");
		char *sent = stub_finish (&stub, th, fds[0]);
		size_t written;
		mu_assert_true (check_memory_packets (sent, cases[i].address, bytes, cases[i].len,
			R_MIN (cases[i].limit, cases[i].send_max - 5), &written), "validate memory transcript");
		mu_assert_eq (written, cases[i].len, "all input bytes reached the peer");
		mu_assert_eq (g.stub_features.pkt_sz, cases[i].limit, "writes preserve the peer limit");
		free (sent);
		gdbr_cleanup (&g);
	}
	r_cons_free (cons);
	mu_end;
}

static bool test_gdb_memory_packet_failures(void) {
	const struct {
		ut32 limit;
		int send_max;
		ut64 address;
		ut64 len;
	} cases[] = {
		{ 0, 2500, 0, 1 }, { 1, 2500, 0, 1 }, { 6, 2500, 0, 1 },
		{ 7, 2500, 0xf, 2 }, { 64, 9, 0, 1 }, { 64, 2500, UT64_MAX, 2 }
	};
	RCons *cons = r_cons_new ();
	const ut8 bytes[32] = { 1, 2, 3, 4 };
	const char *replies[] = { "OK", "E01", NULL };
	size_t i;
	for (i = 0; i <= R_ARRAY_SIZE (cases); i++) {
		libgdbr_t g;
		int fds[2];
		mu_assert_true (session_open (&g, fds, GDB_REMOTE_TYPE_GDB), "open memory failure session");
		const bool rejected = i == R_ARRAY_SIZE (cases);
		g.stub_features.pkt_sz = rejected? 16: cases[i].limit;
		g.send_max = rejected? 2500: cases[i].send_max;
		Stub stub;
		RThread *th = stub_start (&stub, fds[1], -1, replies);
		mu_assert_eq (gdbr_write_memory (&g, 0, NULL, 0), 0, "zero bytes need no packet");
		mu_assert_eq (gdbr_write_memory (&g, rejected? 0: cases[i].address, bytes,
			rejected? sizeof (bytes): cases[i].len), -1, "invalid or refused write fails");
		if (!rejected && cases[i].limit < 2) {
			ut8 byte;
			g.remote_file_fd = 1;
			mu_assert_eq (gdbr_read_memory (&g, 0, &byte, 1), -1, "tiny read budget cannot divide by zero");
			mu_assert_eq (gdbr_read_file (&g, &byte, 1), -1, "tiny file budget makes no progress");
			mu_assert_eq (g.stub_features.pkt_sz, cases[i].limit, "read paths preserve tiny limits");
		}
		char *sent = stub_finish (&stub, th, fds[0]);
		if (rejected) {
			mu_assert_eq (r_str_char_count (sent, '\n'), 2, "stop sending after a failed chunk");
			size_t written;
			mu_assert_true (check_memory_packets (sent, 0, bytes, sizeof (bytes), 16, &written), "rejected transcript remains bounded");
			mu_assert ("later bytes are not attempted", written < sizeof (bytes));
		} else {
			mu_assert_streq (sent, "", "impossible writes send no packets");
		}
		free (sent);
		gdbr_cleanup (&g);
	}
	r_cons_free (cons);
	mu_end;
}

static bool test_gdb_runtime_console_flows(void) {
	const char *requests[] = { "?", "s", "c", "vAttach;4d2" };
	const ut8 expected[] = { ' ', ' ', '%', 's', '\n', 'A', 0, 'B' };
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (requests); i++) {
		RCons *cons = r_cons_new ();
		cons->context->noflush = true;
		libgdbr_t g;
		int fds[2];
		mu_assert_true (session_open (&g, fds, GDB_REMOTE_TYPE_GDB), "open console session");
		g.connected = 1;
		g.stub_features.extended_mode = 0;
		mu_assert_true (send_response (fds[1], "O"), "queue empty console output");
		mu_assert_true (send_response (fds[1], "O202025730a"), "queue literal formatted text");
		mu_assert_true (send_response (fds[1], "O410042"), "queue binary console output");
		mu_assert_true (send_response (fds[1], i == 1? "T05thread:1c03;": "S02"), "queue actual stop");
		int ret;
		switch (i) {
		case 0: ret = gdbr_stop_reason (&g); break;
		case 1: ret = gdbr_step (&g, 1); break;
		case 2: ret = gdbr_continue (&g, g.pid, 1, 0); break;
		default: ret = gdbr_attach (&g, 0x4d2); break;
		}
		mu_assert_eq (ret, 0, "console packets do not complete the command");
		mu_assert_true (g.stop_reason.is_valid, "actual stop is reported");
		mu_assert_eq (g.stop_reason.signum, i == 1? 5: 2, "terminal signal survives output");
		size_t length;
		const char *output = r_cons_get_buffer (cons, &length);
		mu_assert_eq (length, sizeof (expected), "console output preserves exact length");
		mu_assert_memeq (output, expected, length, "console output preserves whitespace percent and NUL bytes");
		mu_assert_streq_free (stub_recv (fds[1]), requests[i], "send only the original request");
		struct pollfd pollfd = { .fd = fds[1], .events = POLLIN };
		mu_assert_eq (poll (&pollfd, 1, 0), 0, "no extra resume or stop query");
		gdbr_cleanup (&g);
		close (fds[1]);
		r_cons_free (cons);
	}
	mu_end;
}

static bool test_gdb_console_terminal_replies(void) {
	const char *replies[] = { "W00", "X0b", "E01", NULL };
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (replies); i++) {
		RCons *cons = r_cons_new ();
		cons->context->noflush = true;
		libgdbr_t g;
		int fds[2];
		mu_assert_true (session_open (&g, fds, GDB_REMOTE_TYPE_GDB), "open terminal console session");
		g.connected = 1;
		g.stop_reason.reason = R_DEBUG_REASON_SIGNAL;
		g.stop_reason.signum = 9;
		g.stop_reason.exec.path = strdup ("previous");
		g.stop_reason.exec.present = true;
		mu_assert_true (send_response (fds[1], "O6279650a"), "queue output before terminal reply");
		if (replies[i]) {
			mu_assert_true (send_response (fds[1], replies[i]), "queue terminal reply");
		} else {
			shutdown (fds[1], SHUT_WR);
		}
		mu_assert_eq (gdbr_continue (&g, g.pid, 1, 0), i < 2? 0: -1, "terminal reply or EOF result");
		size_t length;
		const char *output = r_cons_get_buffer (cons, &length);
		mu_assert_eq (length, 4, "output survives errors and termination");
		mu_assert_memeq (output, "bye\n", length, "terminal output is visible");
		mu_assert_eq (g.stop_reason.is_valid, i < 2, "only actual terminal stops are valid");
		if (i < 2) {
			mu_assert_eq (g.stop_reason.reason, R_DEBUG_REASON_DEAD, "exit survives disconnect cleanup");
			if (i == 1) {
				mu_assert_eq (g.stop_reason.signum, 0x0b, "termination signal survives disconnect cleanup");
			}
			mu_assert_eq (g.connected, 0, "terminal reply closes the single-process connection");
		} else {
			mu_assert_eq (g.stop_reason.signum, 9, "output is not a replacement stop");
			mu_assert_streq (g.stop_reason.exec.path, "previous", "output preserves prior owned metadata");
		}
		gdbr_cleanup (&g);
		close (fds[1]);
		r_cons_free (cons);
	}
	mu_end;
}

static bool test_gdb_console_rejections(void) {
	const char *replies[] = { "O1", "Ogg", "O41gg", "O000", "O0x", "O 0", "OKextra" };
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (replies); i++) {
		RCons *cons = r_cons_new ();
		cons->context->noflush = true;
		libgdbr_t g;
		int fds[2];
		mu_assert_true (session_open (&g, fds, GDB_REMOTE_TYPE_GDB), "open invalid console session");
		g.connected = 1;
		mu_assert_true (send_response (fds[1], "O61"), "queue prior valid output");
		mu_assert_true (send_response (fds[1], replies[i]), "queue invalid console packet");
		mu_assert_true (send_response (fds[1], "S05"), "queue later stop");
		mu_assert_eq (gdbr_stop_reason (&g), -1, "malformed console bytes are rejected");
		mu_assert_false (g.stop_reason.is_valid, "malformed output does not publish a stop");
		size_t length;
		const char *output = r_cons_get_buffer (cons, &length);
		mu_assert_eq (length, 1, "malformed bytes are not printed");
		mu_assert_memeq (output, "a", 1, "valid prior output remains visible");
		gdbr_cleanup (&g);
		close (fds[1]);
		r_cons_free (cons);
	}
	mu_end;
}

static bool test_gdb_console_acknowledgements(void) {
	RCons *cons = r_cons_new ();
	cons->context->noflush = true;
	libgdbr_t g;
	int fds[2];
	mu_assert_true (session_open (&g, fds, GDB_REMOTE_TYPE_GDB), "open acknowledged console session");
	g.no_ack = false;
	const char *replies[] = { "O", "O61", "O62", "S05" };
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (replies); i++) {
		mu_assert_true (send_response (fds[1], replies[i]), "queue acknowledged reply");
	}
	mu_assert_eq (gdbr_stop_reason (&g), 0, "wait through every console packet");
	mu_assert_streq_free (stub_recv (fds[1]), "?", "query is sent once");
	for (i = 0; i < R_ARRAY_SIZE (replies); i++) {
		char ack;
		mu_assert_true (stub_getc (fds[1], &ack), "receive one packet acknowledgement");
		mu_assert_eq (ack, '+', "positive packet acknowledgement");
	}
	struct pollfd pollfd = { .fd = fds[1], .events = POLLIN };
	mu_assert_eq (poll (&pollfd, 1, 0), 0, "no duplicate acknowledgement");
	gdbr_cleanup (&g);
	close (fds[1]);
	r_cons_free (cons);
	mu_end;
}

static bool test_gdb_console_attach_compatibility(void) {
	const char *replies[] = { "OK", "", "E01" };
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (replies); i++) {
		RCons *cons = r_cons_new ();
		cons->context->noflush = true;
		libgdbr_t g;
		int fds[2];
		mu_assert_true (session_open (&g, fds, GDB_REMOTE_TYPE_GDB), "open console attach session");
		g.stub_features.extended_mode = 0;
		mu_assert_true (send_response (fds[1], "O61"), "queue attach output");
		mu_assert_true (send_response (fds[1], replies[i]), "queue legacy attach reply");
		mu_assert_eq (gdbr_attach (&g, 0x4d2), i == 0? 0: i == 1? -2: -1, "legacy and refused attach results");
		mu_assert_false (g.stop_reason.is_valid, "legacy OK and output do not invent stop metadata");
		size_t length;
		const char *output = r_cons_get_buffer (cons, &length);
		mu_assert_eq (length, 1, "attach output remains visible");
		mu_assert_memeq (output, "a", 1, "literal attach output");
		gdbr_cleanup (&g);
		close (fds[1]);
		r_cons_free (cons);
	}
	mu_end;
}

typedef struct {
	int fd;
	char *request;
	bool ok;
} ConsolePeer;

static RThreadFunctionRet delayed_console_peer(RThread *thread) {
	ConsolePeer *peer = thread->user;
	peer->request = stub_recv (peer->fd);
	const char *payload = "T0500:0*,;thread:1c03;";
	char *stop = r_str_newf ("$%s#%02x", payload, cmd_checksum (payload));
	const size_t split = strchr (stop, '*') - stop;
	char *prefix = r_str_newf ("$O6869#%02x%.*s", cmd_checksum ("O6869"), (int)split, stop);
	char ack;
	if (peer->request && write (peer->fd, prefix, strlen (prefix)) == strlen (prefix)
	    && stub_getc (peer->fd, &ack) && ack == '+') {
		r_sys_usleep (350000);
		peer->ok = write (peer->fd, stop + split, strlen (stop) - split) == strlen (stop) - split
			&& stub_getc (peer->fd, &ack) && ack == '+';
	}
	free (prefix);
	free (stop);
	shutdown (peer->fd, SHUT_WR);
	return R_TH_STOP;
}

static bool test_gdb_console_waiting(void) {
	RCons *cons = r_cons_new ();
	cons->context->noflush = true;
	libgdbr_t g;
	int fds[2];
	mu_assert_true (session_open (&g, fds, GDB_REMOTE_TYPE_GDB), "open delayed console session");
	g.connected = 1;
	g.no_ack = false;
	ConsolePeer peer = { .fd = fds[1] };
	RThread *thread = r_th_new (delayed_console_peer, &peer, 0);
	r_th_start (thread);
	int ret = gdbr_continue (&g, g.pid, 1, 0);
	r_th_wait (thread);
	r_th_free (thread);
	mu_assert_true (peer.ok, "peer completed the delayed exchange");
	mu_assert_eq (ret, 0, "running wait survives a partial-frame poll timeout");
	mu_assert_streq_free (peer.request, "c", "send the resume request once");
	mu_assert_true (g.stop_reason.is_valid, "output alone does not stop execution");
	mu_assert_eq (g.stop_reason.signum, 5, "actual stop follows output");
	mu_assert_streq (g.data, "T0500:0000000000000000", "RLE at a continuation boundary retains its predecessor");
	size_t length;
	const char *output = r_cons_get_buffer (cons, &length);
	mu_assert_eq (length, 2, "output survives polling");
	mu_assert_memeq (output, "hi", length, "console bytes before delayed stop");
	gdbr_cleanup (&g);
	close (fds[1]);
	r_cons_free (cons);
	mu_end;
}

static bool test_gdb_console_interrupt(void) {
	RCons *cons = r_cons_new ();
	libgdbr_t g;
	int fds[2];
	mu_assert_true (session_open (&g, fds, GDB_REMOTE_TYPE_GDB), "open interrupted console session");
	g.connected = 1;
	g.isbreaked = true;
	cons->context->breaked = true;
	char *packet = r_str_newf ("$O6166746572#%02x", cmd_checksum ("O6166746572"));
	memcpy (g.read_buff, packet, 5);
	g.read_len = 5;
	mu_assert_eq (write (fds[1], packet + 5, strlen (packet) - 5), strlen (packet) - 5, "queue partial output continuation");
	free (packet);
	mu_assert_true (send_response (fds[1], "S02"), "queue stop after interrupt output");
	mu_assert_eq (read_packet (&g, true), 0, "interrupt preserves partial output framing");
	mu_assert_streq (g.data, "O6166746572", "complete console packet remains available");
	mu_assert_false (cons->context->breaked, "processed interrupt permits subsequent console writes");
	mu_assert_false (g.stop_reason.is_valid, "output packet is not a stop");
	mu_assert_eq (read_packet (&g, true), 0, "read actual stop after output");
	mu_assert_eq (handle_stop_reason (&g), 0, "parse interrupt stop");
	mu_assert_eq (g.stop_reason.signum, 2, "actual interrupt signal");
	char interrupt;
	mu_assert_true (stub_getc (fds[1], &interrupt), "receive run interrupt");
	mu_assert_eq (interrupt, 3, "single raw interrupt byte");
	struct pollfd pollfd = { .fd = fds[1], .events = POLLIN };
	mu_assert_eq (poll (&pollfd, 1, 0), 0, "no duplicate interrupt");
	gdbr_cleanup (&g);
	close (fds[1]);
	r_cons_free (cons);
	mu_end;
}

static bool test_gdb_console_query_timeout(void) {
	RCons *cons = r_cons_new ();
	cons->context->noflush = true;
	libgdbr_t g;
	int fds[2];
	mu_assert_true (session_open (&g, fds, GDB_REMOTE_TYPE_GDB), "open bounded console query");
	g.connected = 1;
	g.num_retries = 1;
	mu_assert_true (send_response (fds[1], "O61"), "queue output without a stop reply");
	mu_assert_eq (gdbr_stop_reason (&g), -1, "ordinary queries retain bounded timeouts");
	mu_assert_false (g.stop_reason.is_valid, "output followed by timeout is not a stop");
	mu_assert_streq_free (stub_recv (fds[1]), "?", "query is sent once");
	size_t length;
	const char *output = r_cons_get_buffer (cons, &length);
	mu_assert_eq (length, 1, "output before query timeout is retained");
	mu_assert_memeq (output, "a", 1, "literal query output");
	gdbr_cleanup (&g);
	close (fds[1]);
	r_cons_free (cons);
	mu_end;
}

static bool test_gdb_console_transport_failures(void) {
	RCons *cons = r_cons_new ();
	libgdbr_t g;
	int fds[2];
	mu_assert_true (session_open (&g, fds, GDB_REMOTE_TYPE_GDB), "open transport failure session");
	g.isbreaked = true;
	mu_assert_eq (read_packet (&g, true), -1, "cancel pre-handshake probing");
	struct pollfd pollfd = { .fd = fds[1], .events = POLLIN };
	mu_assert_eq (poll (&pollfd, 1, 0), 0, "connection cancellation sends no run interrupt");
	mu_assert_eq (gdbr_stop_reason (&g), -1, "cancel a pending ordinary query");
	g.isbreaked = true;
	mu_assert_eq (gdbr_attach (&g, 0x4d2), -1, "cancel a pending attach");
	mu_assert_eq (poll (&pollfd, 1, 0), 0, "canceled queries and attach send no request or run interrupt");
	g.isbreaked = false;
	memcpy (g.read_buff, "$S05#00", 7);
	g.read_len = 7;
	mu_assert_true (send_response (fds[1], "S05"), "queue valid reply after bad buffered frame");
	mu_assert_eq (read_packet (&g, true), -1, "buffered checksum errors are not discarded");
	gdbr_cleanup (&g);
	close (fds[1]);
	r_cons_free (cons);
	mu_end;
}

static bool test_gdb_monitor_output(void) {
	const struct {
		const char *replies[4];
		const char *output;
		int result;
	} cases[] = {
		{ { "O68656c6c6f20", "O25730a", "OK", NULL }, "hello %s\n", 0 },
		{ { "OK", NULL }, "", 0 },
		{ { "E01", NULL }, "", -1 },
		{ { "O68656c6c6f20", "E01", NULL }, "hello ", -1 },
		{ { "O20203132330a0a", "OK", NULL }, "  123\n\n", 0 },
		{ { "O", "OK", NULL }, "", 0 },
		{ { "Ogg", NULL }, "", -1 },
		{ { "O000", NULL }, "", -1 },
	};
	RCons *cons = r_cons_new ();
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (cases); i++) {
		libgdbr_t g;
		int fds[2];
		mu_assert_true (session_open (&g, fds, GDB_REMOTE_TYPE_GDB), "open monitor session");
		const char *const *reply;
		for (reply = cases[i].replies; *reply; reply++) {
			mu_assert_true (send_response (fds[1], *reply), "queue monitor reply");
		}
		RStrBuf output;
		r_strbuf_init (&output);
		mu_assert_eq (gdbr_send_qRcmd (&g, "help", &output), cases[i].result, "monitor command status");
		mu_assert_streq (r_strbuf_get (&output), cases[i].output, "monitor output is returned unchanged");
		r_strbuf_fini (&output);
		size_t len;
		r_cons_get_buffer (cons, &len);
		mu_assert_eq (len, 0, "monitor output does not print to the console");
		gdbr_cleanup (&g);
		close (fds[1]);
	}
	r_cons_free (cons);
	mu_end;
}

static bool test_gdb_short_stop_replies(void) {
	const struct {
		const char *short_reply;
		const char *full_reply;
		int signal;
	} cases[] = {
		{ "S05", "T05", 5 }, { "S02", "T02", 2 }, { "S0a", "T0a", 10 },
		{ "SFF", "TFF", 255 }, { "S00", "T00", 0 }
	};
	const char *replies[13];
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (cases); i++) {
		replies[i * 2] = cases[i].short_reply;
		replies[i * 2 + 1] = cases[i].full_reply;
	}
	replies[10] = "T05thread:1c03;core:2;00:1122334455667788;exec:2f62696e2f74657374;";
	replies[11] = "S02";
	replies[12] = NULL;
	RCons *cons = r_cons_new ();
	libgdbr_t g;
	int fds[2];
	mu_assert_true (session_open (&g, fds, GDB_REMOTE_TYPE_GDB), "open short-stop session");
	Stub stub;
	RThread *th = stub_start (&stub, fds[1], -1, replies);
	for (i = 0; i < R_ARRAY_SIZE (cases); i++) {
		mu_assert_eq (gdbr_stop_reason (&g), 0, "query a short stop reply");
		mu_assert_true (g.stop_reason.is_valid, "short stop is valid");
		mu_assert_eq (g.stop_reason.signum, cases[i].signal, "two hexadecimal signal digits");
		mu_assert_eq (g.stop_reason.reason, cases[i].signal == 5? R_DEBUG_REASON_BREAKPOINT: R_DEBUG_REASON_SIGNAL, "classify the signal");
		mu_assert_eq (g.stop_reason.core, -1, "no invented core");
		mu_assert_false (g.stop_reason.thread.present, "no invented thread");
		const libgdbr_stop_reason_t short_stop = g.stop_reason;
		mu_assert_eq (gdbr_stop_reason (&g), 0, "query the equivalent T reply");
		mu_assert_eq (g.stop_reason.signum, short_stop.signum, "Sxx and empty Txx agree on signum");
		mu_assert_eq (g.stop_reason.reason, short_stop.reason, "Sxx and empty Txx agree on reason");
		mu_assert_eq (g.stop_reason.core, short_stop.core, "Sxx and empty Txx agree on core");
		mu_assert_eq (g.stop_reason.is_valid, short_stop.is_valid, "Sxx and empty Txx agree on is_valid");
		mu_assert_eq (g.stop_reason.thread.present, short_stop.thread.present, "Sxx and empty Txx agree on thread.present");
		mu_assert_eq (g.stop_reason.exec.present, short_stop.exec.present, "Sxx and empty Txx agree on exec.present");
		mu_assert_eq (g.stop_reason.watchpoint.present, short_stop.watchpoint.present, "Sxx and empty Txx agree on watchpoint.present");
		mu_assert_eq (g.stop_reason.library, short_stop.library, "Sxx and empty Txx agree on library");
		mu_assert_eq (g.stop_reason.swbreak, short_stop.swbreak, "Sxx and empty Txx agree on swbreak");
		mu_assert_eq (g.stop_reason.hwbreak, short_stop.hwbreak, "Sxx and empty Txx agree on hwbreak");
		mu_assert_eq (g.stop_reason.create, short_stop.create, "Sxx and empty Txx agree on create");
		mu_assert_eq (g.stop_reason.vforkdone, short_stop.vforkdone, "Sxx and empty Txx agree on vforkdone");
		mu_assert_eq (g.stop_reason.syscall, short_stop.syscall, "Sxx and empty Txx agree on syscall");
		mu_assert_eq (g.stop_reason.fork.present, short_stop.fork.present, "Sxx and empty Txx agree on fork.present");
		mu_assert_eq (g.stop_reason.vfork.present, short_stop.vfork.present, "Sxx and empty Txx agree on vfork.present");
	}
	mu_assert_eq (gdbr_stop_reason (&g), 0, "query rich T stop metadata");
	mu_assert_true (g.stop_reason.exec.present, "rich stop owns an exec path");
	mu_assert_streq (g.stop_reason.exec.path, "/bin/test", "decoded exec path");
	mu_assert_true (g.stop_reason.thread.present, "rich stop names a thread");
	mu_assert_eq (g.stop_reason.core, 2, "rich stop names a core");
	mu_assert_eq (gdbr_stop_reason (&g), 0, "short stop replaces rich metadata");
	mu_assert_false (g.stop_reason.exec.present, "exec metadata cleared");
	mu_assert_null (g.stop_reason.exec.path, "owned exec path released");
	mu_assert_false (g.stop_reason.thread.present, "thread metadata cleared");
	mu_assert_eq (g.stop_reason.core, -1, "core metadata cleared");
	mu_assert_eq (g.stop_reason.signum, 2, "replacement stop signal");
	char *sent = stub_finish (&stub, th, fds[0]);
	mu_assert_eq (r_str_char_count (sent, '\n'), 12, "each stop came from a query");
	free (sent);
	gdbr_cleanup (&g);
	r_cons_free (cons);
	mu_end;
}

static bool test_gdb_invalid_stop_signals(void) {
	const char *replies[] = {
		"S", "S0", "S0g", "Sg0", "S+5", "S 5", "S005", "S05;", "S05thread:1;", "S05junk",
		"T", "T0", "T0g", "Tg0", "T+5", "T 5"
	};
	libgdbr_t g;
	mu_assert_eq (gdbr_init (&g, false), 0, "initialize invalid-stop session");
	g.no_ack = true;
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (replies); i++) {
		r_str_ncpy (g.data, replies[i], g.data_max);
		g.data_len = strlen (replies[i]);
		mu_assert_eq (handle_stop_reason (&g), -1, "reject malformed signal replies");
		mu_assert_false (g.stop_reason.is_valid, "malformed replies do not publish a stop");
	}
	g.no_ack = false;
	r_str_ncpy (g.data, "S05", g.data_max);
	g.data_len = 3;
	mu_assert_eq (handle_stop_reason (&g), -1, "failed acknowledgement rejects the stop");
	mu_assert_false (g.stop_reason.is_valid, "failed acknowledgement does not publish a stop");
	gdbr_cleanup (&g);
	mu_end;
}

static bool test_gdb_short_execution_stops(void) {
	RCons *cons = r_cons_new ();
	libgdbr_t g;
	int fds[2];
	mu_assert_true (session_open (&g, fds, GDB_REMOTE_TYPE_GDB), "open short execution-stop session");
	g.pid = g.tid = 0;
	g.stub_features.extended_mode = 0;
	const char *replies[] = { "S02", "S05", "S02", "S05junk", NULL };
	Stub stub;
	RThread *th = stub_start (&stub, fds[1], -1, replies);
	mu_assert_eq (gdbr_attach (&g, 0x4d2), 0, "attach accepts a short stop");
	mu_assert_true (g.stop_reason.is_valid, "attach parsed the stop reply");
	mu_assert_eq (g.stop_reason.signum, 2, "attach stop signal");
	mu_assert_eq (g.tid, 0, "attach does not invent a thread");
	mu_assert_eq (gdbr_step (&g, 1), 0, "step accepts a short stop");
	mu_assert_eq (g.stop_reason.reason, R_DEBUG_REASON_BREAKPOINT, "step trap classification");
	mu_assert_eq (gdbr_continue (&g, g.pid, 1, 0), 0, "continue accepts a short stop");
	mu_assert_eq (g.stop_reason.signum, 2, "continue stop signal");
	mu_assert_eq (gdbr_attach (&g, 0x4d3), -1, "attach rejects a malformed short stop");
	mu_assert_eq (g.pid, 0x4d2, "failed attach preserves the previous pid");
	char *sent = stub_finish (&stub, th, fds[0]);
	mu_assert_streq_free (sent, "vAttach;4d2\ns\nc\nvAttach;4d3\n", "execution packets");
	gdbr_cleanup (&g);
	r_cons_free (cons);
	mu_end;
}

static bool test_gdb_gdbserver_reads_g(void) {
	RCons *cons = r_cons_new ();
	libgdbr_t g;
	int fds[2];
	mu_assert_true (session_open (&g, fds, GDB_REMOTE_TYPE_GDB), "open session");
	const char *replies[] = {
		"T0500:1122334455667788;thread:1c03;",
		"0102030405060708090a0b0c0d0e",
		NULL
	};
	Stub stub;
	RThread *th = stub_start (&stub, fds[1], -1, replies);
	mu_assert_eq (gdbr_stop_reason (&g), 0, "stop reply");
	mu_assert_eq (gdbr_read_registers (&g), 0, "read registers");
	mu_assert_eq (gdbr_read_registers (&g), 0, "read cached registers");
	char *sent = stub_finish (&stub, th, fds[0]);
	// a stop reply stating registers does not replace the one 'g' of a gdbserver
	mu_assert_streq_free (sent, "?\ng\n", "packets sent");
	mu_assert_eq (g.caps.g, 1, "g answered");
	mu_assert_eq (g.data_len, 14, "block size");
	mu_assert_memeq ((ut8 *)g.data, (ut8 *)"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e", 14, "block");
	gdbr_cleanup (&g);
	r_cons_free (cons);
	mu_end;
}

static bool test_gdb_lldb_reads_g_with_thread(void) {
	RCons *cons = r_cons_new ();
	libgdbr_t g;
	int fds[2];
	mu_assert_true (session_open (&g, fds, GDB_REMOTE_TYPE_LLDB), "open session");
	g.caps.thread_suffix = true;
	const char *replies[] = { "0102030405060708090a0b0c0d0e", NULL };
	Stub stub;
	RThread *th = stub_start (&stub, fds[1], -1, replies);
	mu_assert_eq (gdbr_read_registers (&g), 0, "read registers");
	char *sent = stub_finish (&stub, th, fds[0]);
	mu_assert_streq_free (sent, "g;thread:1c03;\n", "g names the thread");
	mu_assert_eq (g.caps.g, 1, "g answered");
	gdbr_cleanup (&g);
	r_cons_free (cons);
	mu_end;
}

static bool test_gdb_lldb_reads_p(void) {
	RCons *cons = r_cons_new ();
	libgdbr_t g;
	int fds[2];
	mu_assert_true (session_open (&g, fds, GDB_REMOTE_TYPE_LLDB), "open session");
	g.caps.thread_suffix = true;
	const char *replies[] = {
		"T05thread:1c03;00:1122334455667788;",
		"E15",
		"aabbccdd",
		"eeff",
		"0102030405060708",
		"090a0b0c",
		"0d0e",
		NULL
	};
	Stub stub;
	RThread *th = stub_start (&stub, fds[1], -1, replies);
	mu_assert_eq (gdbr_stop_reason (&g), 0, "stop reply");
	mu_assert_eq (gdbr_read_registers (&g), 0, "read registers");
	ut8 first[14];
	memcpy (first, g.data, sizeof (first));
	// the thread ran: nothing is known, and 'g' is not asked again
	gdbr_invalidate_reg_cache (&g);
	mu_assert_eq (gdbr_read_registers (&g), 0, "read registers again");
	char *sent = stub_finish (&stub, th, fds[0]);
	mu_assert_streq_free (sent,
		"?\n"
		"g;thread:1c03;\n"
		"p1;thread:1c03;\n"
		"p2;thread:1c03;\n"
		"p0;thread:1c03;\n"
		"p1;thread:1c03;\n"
		"p2;thread:1c03;\n", "p for the registers the stop reply did not state");
	mu_assert_eq (g.caps.g, 0, "g refused");
	mu_assert_eq (g.caps.p, 1, "p answered");
	// c is at bit 96, byte 12
	mu_assert_memeq (first, (ut8 *)"\x11\x22\x33\x44\x55\x66\x77\x88\xaa\xbb\xcc\xdd\xee\xff", 14, "stop reply and p values");
	mu_assert_eq (g.data_len, 14, "block size");
	mu_assert_memeq ((ut8 *)g.data, (ut8 *)"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e", 14, "p values");
	gdbr_cleanup (&g);
	r_cons_free (cons);
	mu_end;
}

static bool test_gdb_stop_reply_of_another_thread(void) {
	RCons *cons = r_cons_new ();
	libgdbr_t g;
	int fds[2];
	mu_assert_true (session_open (&g, fds, GDB_REMOTE_TYPE_LLDB), "open session");
	g.caps.g = 0;
	const char *replies[] = {
		"T05thread:1c04;00:1122334455667788;",
		"0102030405060708",
		"090a0b0c",
		"0d0e",
		NULL
	};
	Stub stub;
	RThread *th = stub_start (&stub, fds[1], -1, replies);
	mu_assert_eq (gdbr_stop_reason (&g), 0, "stop reply");
	mu_assert_eq (gdbr_read_registers (&g), 0, "read registers");
	char *sent = stub_finish (&stub, th, fds[0]);
	// the stop reply stated thread 1c04's registers, not those of the selected 1c03
	mu_assert_streq_free (sent, "?\np0\np1\np2\n", "packets sent");
	mu_assert_memeq ((ut8 *)g.data, (ut8 *)"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e", 14, "registers");
	gdbr_cleanup (&g);
	r_cons_free (cons);
	mu_end;
}

static bool test_gdb_reads_p_without_thread_suffix(void) {
	RCons *cons = r_cons_new ();
	libgdbr_t g;
	int fds[2];
	mu_assert_true (session_open (&g, fds, GDB_REMOTE_TYPE_LLDB), "open session");
	const char *replies[] = { "", "0102030405060708", "090a0b0c", "0d0e", NULL };
	Stub stub;
	RThread *th = stub_start (&stub, fds[1], -1, replies);
	mu_assert_eq (gdbr_read_registers (&g), 0, "read registers");
	char *sent = stub_finish (&stub, th, fds[0]);
	mu_assert_streq_free (sent, "g\np0\np1\np2\n", "unsupported g, then p");
	mu_assert_eq (g.caps.g, 0, "g unsupported");
	gdbr_cleanup (&g);
	r_cons_free (cons);
	mu_end;
}

static bool test_gdb_refuses_oversized(void) {
	RCons *cons = r_cons_new ();
	libgdbr_t g;
	int fds[2];
	mu_assert_true (session_open (&g, fds, GDB_REMOTE_TYPE_LLDB), "open session");
	const char *replies[] = {
		"T05thread:1c03;01:00112233445566778899;",
		"E15",
		"0102030405060708",
		"aabbccddeeff",
		NULL
	};
	Stub stub;
	RThread *th = stub_start (&stub, fds[1], -1, replies);
	mu_assert_eq (gdbr_stop_reason (&g), 0, "stop reply");
	mu_assert_eq (gdbr_read_registers (&g), -1, "a register wider than its profile is refused");
	// the stub answers the same until the thread runs, so it is not asked again
	mu_assert_eq (gdbr_read_registers (&g), -1, "a refused read stays refused");
	char *sent = stub_finish (&stub, th, fds[0]);
	// the oversized value in the stop reply was not kept, so b is asked for
	mu_assert_streq_free (sent, "?\ng\np0\np1\n", "packets sent");
	mu_assert_eq (g.caps.g, GDBR_CAP_UNKNOWN, "a refused g stays unknown while p fails");
	// growing to a length whose buffer size would wrap is refused
	char *data = g.data;
	const ssize_t data_max = g.data_max;
	size_t size;
	mu_assert_false (gdbr_grow_size (GDBR_GROW_MAX, &size), "refuse the growth limit");
	mu_assert_false (gdbr_grow_size (SIZE_MAX / 2 + 1, &size), "refuse half of SIZE_MAX");
	mu_assert_false (gdbr_data_reserve (&g, SIZE_MAX), "refuse SIZE_MAX");
	mu_assert_true (g.data == data && g.data_max == data_max, "a refused growth keeps the buffer");
	mu_assert_true (gdbr_data_reserve (&g, 5000), "grow");
	mu_assert_eq (g.data_max, 8192, "next power of two above the length and its terminator");
	gdbr_cleanup (&g);
	r_cons_free (cons);
	mu_end;
}

static bool test_gdb_refuses_unaddressable_profile(void) {
	RCons *cons = r_cons_new ();
	libgdbr_t g;
	int fds[2];
	mu_assert_true (session_open (&g, fds, GDB_REMOTE_TYPE_LLDB), "open session");
	// b's offset in bits wraps once its size is added
	mu_assert_eq (gdbr_set_reg_profile (&g, "gpr a .64 0 0\ngpr b .64 0x1fffffffffffffff 0\n"), 0, "set profile");
	g.caps.g = 0;
	const char *replies[] = { "T05thread:1c03;01:1122334455667788;", NULL };
	Stub stub;
	RThread *th = stub_start (&stub, fds[1], -1, replies);
	mu_assert_eq (gdbr_stop_reason (&g), 0, "a stop reply stating b");
	mu_assert_false (gdbr_regs_store (&g, 1, "1122334455667788", 16), "b is refused");
	mu_assert_false (gdbr_regs_store (&g, 0, "1122334455667788", 16), "the profile is not laid out");
	mu_assert_eq (gdbr_read_registers (&g), -1, "no read by that profile");
	// a block larger than any register file is refused too, and one just inside is laid out
	mu_assert_eq (gdbr_set_reg_profile (&g, "gpr a .64 0 0\ngpr b .64 0x100000 0\n"), 0, "set profile");
	mu_assert_false (gdbr_regs_store (&g, 0, "1122334455667788", 16), "a block past the limit");
	mu_assert_eq (gdbr_set_reg_profile (&g, "gpr a .64 0 0\ngpr b .64 0xffff8 0\n"), 0, "set profile");
	mu_assert_true (gdbr_regs_store (&g, 1, "1122334455667788", 16), "a block up to the limit");
	char *sent = stub_finish (&stub, th, fds[0]);
	mu_assert_streq_free (sent, "?\n", "no register packet");
	gdbr_cleanup (&g);
	r_cons_free (cons);
	mu_end;
}

// 'G' rewrites the whole block, so a write through it needs the block first
static bool test_gdb_write_reg_needs_registers(void) {
	RCons *cons = r_cons_new ();
	libgdbr_t g;
	int fds[2];
	mu_assert_true (session_open (&g, fds, GDB_REMOTE_TYPE_GDB), "open session");
	// a is 8 bytes, so a 10 byte value is refused
	const char *replies[] = { "", "", "00112233445566778899", NULL };
	Stub stub;
	RThread *th = stub_start (&stub, fds[1], -1, replies);
	char value[] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, (char)0x88 };
	mu_assert_eq (gdbr_write_reg (&g, "a", value, sizeof (value)), -1, "write refused");
	char *sent = stub_finish (&stub, th, fds[0]);
	// 'P' is unsupported and the registers are refused: no 'G' is built from the refused reply
	mu_assert_streq_free (sent, "P0=1122334455667788\ng\np0\n", "packets sent");
	mu_assert_false (g.stub_features.P, "P unsupported");
	gdbr_cleanup (&g);
	r_cons_free (cons);
	mu_end;
}

static bool test_gdb_register_packets_name_thread(void) {
	RCons *cons = r_cons_new ();
	libgdbr_t g;
	int fds[2];
	mu_assert_true (session_open (&g, fds, GDB_REMOTE_TYPE_LLDB), "open session");
	g.caps.thread_suffix = true;
	const char *replies[] = {
		"0102030405060708090a0b0c0d0e",
		"OK",
		"OK",
		"0e0d0c0b0a090807060504030201",
		"OK",
		"OK",
		NULL
	};
	Stub stub;
	RThread *th = stub_start (&stub, fds[1], -1, replies);
	mu_assert_eq (gdbr_read_registers (&g), 0, "read registers");
	// selecting the thread already selected keeps its registers
	mu_assert_eq (gdbr_select (&g, 0x1c03, 0x1c03), 0, "select the same thread");
	mu_assert_eq (gdbr_read_registers (&g), 0, "read cached registers");
	mu_assert_eq (gdbr_select (&g, 0x1c03, 0x1c04), 0, "select another thread");
	mu_assert_eq (gdbr_read_registers (&g), 0, "read the other thread's registers");
	mu_assert_memeq ((ut8 *)g.data, (ut8 *)"\x0e\x0d\x0c\x0b\x0a\x09\x08\x07\x06\x05\x04\x03\x02\x01", 14, "other thread");
	char value[] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, (char)0x88 };
	mu_assert_eq (gdbr_write_register (&g, 0, value, sizeof (value)), 0, "write one register");
	mu_assert_eq (gdbr_write_bin_registers (&g, "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e", 14), 0, "write the block");
	char *sent = stub_finish (&stub, th, fds[0]);
	// every register packet names the selected thread, writes included
	mu_assert_streq_free (sent,
		"g;thread:1c03;\n"
		"Hg1c03\n"
		"Hg1c04\n"
		"g;thread:1c04;\n"
		"P0=1122334455667788;thread:1c04;\n"
		"G0102030405060708090a0b0c0d0e;thread:1c04;\n", "packets sent");
	gdbr_cleanup (&g);
	r_cons_free (cons);
	mu_end;
}

static bool test_gdb_attach_stop_reply(void) {
	RCons *cons = r_cons_new ();
	libgdbr_t g;
	int fds[2];
	mu_assert_true (session_open (&g, fds, GDB_REMOTE_TYPE_LLDB), "open session");
	g.pid = g.tid = 0;
	g.stub_features.qXfer_features_read = true;
	g.stub_features.pkt_sz = 4096;
	const char *replies[] = {
		"",
		"T13thread:1c03;00:1122334455667788;",
		"E01",
		"E15",
		"aabbccdd",
		"eeff",
		NULL
	};
	Stub stub;
	RThread *th = stub_start (&stub, fds[1], -1, replies);
	mu_assert_eq (gdbr_attach (&g, 0x4d2), 0, "attach");
	mu_assert_eq (gdbr_read_registers (&g), 0, "read registers");
	char *sent = stub_finish (&stub, th, fds[0]);
	// without extended mode vAttach is still asked, and its T reply is a stop reply.
	// The attached process is then asked for its register layout; this one states none
	mu_assert_streq_free (sent, "!\nvAttach;4d2\nqXfer:features:read:target.xml:0,ffe\ng\np1\np2\n", "packets sent");
	mu_assert_eq (g.pid, 0x4d2, "attached pid");
	mu_assert_eq (g.tid, 0x1c03, "stopped thread");
	mu_assert_true (g.stop_reason.is_valid, "stop reason");
	mu_assert_eq (g.stop_reason.signum, 0x13, "stop signal");
	mu_assert_memeq ((ut8 *)g.data, (ut8 *)"\x11\x22\x33\x44\x55\x66\x77\x88\xaa\xbb\xcc\xdd\xee\xff", 14, "registers");
	gdbr_cleanup (&g);
	r_cons_free (cons);
	mu_end;
}

static bool test_gdb_target_xml_offsets(void) {
	RCons *cons = r_cons_new ();
	libgdbr_t g;
	int fds[2];
	mu_assert_true (session_open (&g, fds, GDB_REMOTE_TYPE_LLDB), "open session");
	g.stub_features.qXfer_features_read = true;
	g.stub_features.pkt_sz = 4096;
	g.caps.g = 0;
	// as lldb-server states them: a 'g' block in user_regs_struct order, and eax inside rax
	const char *replies[] = {
		"l<?xml version=\"1.0\"?><target version=\"1.0\"><architecture>x86_64</architecture><feature>"
		"<reg name=\"rax\" bitsize=\"64\" regnum=\"0\" offset=\"8\" group=\"General Purpose Registers\" />"
		"<reg name=\"rbx\" bitsize=\"64\" regnum=\"1\" offset=\"0\" group=\"General Purpose Registers\" />"
		"<reg name=\"eax\" bitsize=\"32\" regnum=\"2\" offset=\"8\" value_regnums=\"0\" />"
		"</feature></target>",
		"1122334455667788",
		"0102030405060708",
		NULL
	};
	Stub stub;
	RThread *th = stub_start (&stub, fds[1], -1, replies);
	mu_assert_eq (gdbr_read_target_xml (&g), 0, "read target.xml");
	mu_assert_eq (gdbr_read_registers (&g), 0, "read registers");
	char *sent = stub_finish (&stub, th, fds[0]);
	// eax lies inside rax, so it is not asked for
	mu_assert_streq_free (sent, "qXfer:features:read:target.xml:0,ffe\np0\np1\n", "packets sent");
	mu_assert_eq (g.target.arch, R_SYS_ARCH_X86, "arch");
	mu_assert_eq (g.target.bits, 64, "bits");
	mu_assert_eq (g.registers[0].offset, 64, "rax offset in bits");
	mu_assert_eq (g.registers[1].offset, 0, "rbx offset in bits");
	mu_assert_eq (g.registers[2].offset, 64, "eax offset in bits");
	mu_assert_eq (g.data_len, 16, "block size");
	mu_assert_memeq ((ut8 *)g.data, (ut8 *)"\x01\x02\x03\x04\x05\x06\x07\x08\x11\x22\x33\x44\x55\x66\x77\x88", 16, "rbx then rax");
	gdbr_cleanup (&g);
	r_cons_free (cons);
	mu_end;
}

// target.xml may skip register numbers, as gdb's arm-core.xml does for cpsr
static bool test_gdb_target_xml_regnums(void) {
	RCons *cons = r_cons_new ();
	libgdbr_t g;
	int fds[2];
	mu_assert_true (session_open (&g, fds, GDB_REMOTE_TYPE_GDB), "open session");
	g.stub_features.qXfer_features_read = true;
	g.stub_features.pkt_sz = 4096;
	g.caps.g = 0;
	const char *replies[] = {
		"l<?xml version=\"1.0\"?><target version=\"1.0\"><architecture>arm</architecture><feature>"
		"<reg name=\"r0\" bitsize=\"32\" regnum=\"0\" />"
		"<reg name=\"cpsr\" bitsize=\"32\" regnum=\"25\" />"
		"<reg name=\"d0\" bitsize=\"64\" />"
		"</feature></target>",
		"T05thread:1c03;18:55667788;19:11223344;",
		"aabbccdd",
		"0102030405060708",
		"OK",
		NULL
	};
	Stub stub;
	RThread *th = stub_start (&stub, fds[1], -1, replies);
	mu_assert_eq (gdbr_read_target_xml (&g), 0, "read target.xml");
	// 0x18 is a number the stub skips, so its value belongs to no register
	mu_assert_eq (gdbr_stop_reason (&g), 0, "a stop reply stating cpsr");
	mu_assert_eq (gdbr_read_registers (&g), 0, "read registers");
	mu_assert_memeq ((ut8 *)g.data, (ut8 *)"\xaa\xbb\xcc\xdd\x11\x22\x33\x44\x01\x02\x03\x04\x05\x06\x07\x08", 16, "r0, cpsr, d0");
	// a value with unavailable bytes is refused, and leaves the register as it was
	mu_assert_false (gdbr_regs_store (&g, 0x19, "5566xx88", 8), "unavailable bytes");
	mu_assert_eq (gdbr_read_registers (&g), 0, "read cached registers");
	mu_assert_memeq ((ut8 *)g.data + 4, (ut8 *)"\x11\x22\x33\x44", 4, "cpsr kept");
	char value[] = { 0x11, 0x22, 0x33, 0x44 };
	mu_assert_eq (gdbr_write_reg (&g, "cpsr", value, sizeof (value)), 0, "write cpsr");
	char *sent = stub_finish (&stub, th, fds[0]);
	// registers are named by the stub's numbers, not by their place in the profile
	mu_assert_streq_free (sent, "qXfer:features:read:target.xml:0,ffe\n?\np0\np1a\nP19=11223344\n", "packets sent");
	gdbr_cleanup (&g);
	r_cons_free (cons);
	mu_end;
}

// register and flag field names from the stub become profile tokens and .dr* command
// arguments, so anything but identifier characters must be filtered out of them
static bool test_gdb_target_xml_names(void) {
	RCons *cons = r_cons_new ();
	libgdbr_t g;
	int fds[2];
	mu_assert_true (session_open (&g, fds, GDB_REMOTE_TYPE_GDB), "open session");
	g.stub_features.qXfer_features_read = true;
	g.stub_features.pkt_sz = 4096;
	const char *replies[] = {
		"l<?xml version=\"1.0\"?><target version=\"1.0\"><architecture>x86_64</architecture><feature>"
		"<flags id=\"fl\" size=\"8\">"
		"<field name=\"CF\" start=\"0\" end=\"0\"/>"
		"<field name=\"ZF;!id\" start=\"6\" end=\"6\"/>"
		"</flags>"
		"<reg name=\"rax\" bitsize=\"64\" />"
		"<reg name=\"r15;!id\" bitsize=\"64\" />"
		"<reg name=\"eflags\" bitsize=\"64\" type=\"fl\" />"
		"<reg name=\"rip\" bitsize=\"64\" type=\"code_ptr\" />"
		"</feature></target>",
		NULL
	};
	Stub stub;
	RThread *th = stub_start (&stub, fds[1], -1, replies);
	mu_assert_eq (gdbr_read_target_xml (&g), 0, "read target.xml");
	char *sent = stub_finish (&stub, th, fds[0]);
	free (sent);
	const char *profile = g.target.regprofile;
	mu_assert_notnull (profile, "register profile");
	mu_assert_null (strpbrk (profile, ";!`|&$"), "no command characters in profile");
	mu_assert_notnull (strstr (profile, "gpr\trax\t.64\t.0\t0\t"), "plain register name kept");
	mu_assert_notnull (strstr (profile, "gpr\tr15__id\t.64\t.64\t0\t"), "register name filtered");
	mu_assert_notnull (strstr (profile, "gpr\tZF__id\t.1\t.134\t0\n"), "flag field name filtered");
	mu_assert_notnull (strstr (profile, "=PC\trip\n"), "pc alias");
	mu_assert_streq (g.registers[1].name, "r15__id", "filtered name in register list");
	gdbr_cleanup (&g);
	r_cons_free (cons);
	mu_end;
}

// Connect over TCP to a stub that answers with transcript; return what the client sent
static char *connect_transcript(libgdbr_t *g, const char **replies) {
	struct sockaddr_in sa = { .sin_family = AF_INET, .sin_addr.s_addr = htonl (INADDR_LOOPBACK) };
	socklen_t salen = sizeof (sa);
	int lfd = socket (AF_INET, SOCK_STREAM, 0);
	if (lfd < 0 || bind (lfd, (struct sockaddr *)&sa, salen) || listen (lfd, 1)
	    || getsockname (lfd, (struct sockaddr *)&sa, &salen) || gdbr_init (g, false)) {
		if (lfd >= 0) {
			close (lfd);
		}
		return NULL;
	}
	g->num_retries = 4;
	Stub stub;
	RThread *th = stub_start (&stub, -1, lfd, replies);
	int ret = gdbr_connect (g, "127.0.0.1", ntohs (sa.sin_port));
	char *sent = stub_finish (&stub, th, g->sock->fd);
	close (lfd);
	if (ret) {
		R_FREE (sent);
	}
	return sent;
}

static bool test_gdb_connect_packet_limits(void) {
	const struct {
		const char *reply;
		const char *override;
		ut32 limit;
		bool connected;
	} cases[] = {
		{ "PacketSize=20", "1024", 32, true },
		{ "PacketSize=20", "16", 16, true },
		{ "PacketSize=1", "1024", 1, false }
	};
	RCons *cons = r_cons_new ();
	char *saved = r_sys_getenv ("R2_GDB_PKTSZ");
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (cases); i++) {
		const char *replies[] = { cases[i].reply, "QC1", "vCont;c;s", "OK", "OK", NULL };
		libgdbr_t g;
		r_sys_setenv ("R2_GDB_PKTSZ", cases[i].override);
		char *sent = connect_transcript (&g, replies);
		r_sys_setenv ("R2_GDB_PKTSZ", saved);
		mu_assert_eq (sent != NULL, cases[i].connected, "connection observes effective capacity");
		mu_assert_eq (g.stub_features.pkt_sz, cases[i].limit, "override only lowers the peer capacity");
		if (sent) {
			mu_assert ("initial negotiation is not inflated by the override", r_str_startswith (sent,
				"qSupported:multiprocess+;qRelocInsn+;xmlRegisters=i386\n"));
		}
		free (sent);
		gdbr_cleanup (&g);
	}
	free (saved);
	r_cons_free (cons);
	mu_end;
}

static bool test_gdb_connect_probes(void) {
	RCons *cons = r_cons_new ();
	libgdbr_t g;
	const char *gdbserver[] = {
		"PacketSize=1000;QStartNoAckMode+", "OK", "QC1", "vCont;c;C;s;S", "OK", "OK", NULL
	};
	char *sent = connect_transcript (&g, gdbserver);
	mu_assert_notnull (sent, "connect to gdbserver stub");
	// no lldb packet, no qProcessInfo, and 'g' is not asked before registers are read
	mu_assert_streq_free (sent,
		"qSupported:multiprocess+;qRelocInsn+;xmlRegisters=i386\n"
		"QStartNoAckMode\nqC\nvCont?\nHg1\nHc-1\n", "gdbserver connect");
	mu_assert_eq (g.remote_type, GDB_REMOTE_TYPE_GDB, "gdb flavor");
	mu_assert_false (g.caps.thread_suffix, "no thread suffix");
	mu_assert_eq (g.caps.g, GDBR_CAP_UNKNOWN, "g not probed yet");
	gdbr_cleanup (&g);

	const char *lldb[] = {
		"PacketSize=20000;QStartNoAckMode+;qEcho+;QThreadSuffixSupported+",
		"OK", "OK", "QC1c03", "vCont;c;C;s;S", "OK", "OK", NULL
	};
	sent = connect_transcript (&g, lldb);
	mu_assert_notnull (sent, "connect to lldb stub");
	mu_assert_streq_free (sent,
		"qSupported:multiprocess+;qRelocInsn+;xmlRegisters=i386\n"
		"QStartNoAckMode\nQThreadSuffixSupported\nqC\nvCont?\nHg1c03\nHc-1\n", "lldb connect");
	mu_assert_eq (g.remote_type, GDB_REMOTE_TYPE_LLDB, "lldb flavor");
	mu_assert_true (g.caps.thread_suffix, "thread suffix accepted");
	mu_assert_eq (g.caps.g, GDBR_CAP_UNKNOWN, "g not probed yet");
	gdbr_cleanup (&g);
	r_cons_free (cons);
	mu_end;
}

static bool test_gdb_io_monitor_output(void) {
	RCons *cons = r_cons_new ();
	RIO *io = r_io_new ();
	struct sockaddr_in sa = { .sin_family = AF_INET, .sin_addr.s_addr = htonl (INADDR_LOOPBACK) };
	socklen_t salen = sizeof (sa);
	int lfd = socket (AF_INET, SOCK_STREAM, 0);
	mu_assert ("create monitor listener", lfd >= 0);
	mu_assert_eq (bind (lfd, (struct sockaddr *)&sa, salen), 0, "bind monitor listener");
	mu_assert_eq (listen (lfd, 1), 0, "listen for monitor connection");
	mu_assert_eq (getsockname (lfd, (struct sockaddr *)&sa, &salen), 0, "get monitor listener port");
	const char *replies[] = {
		"PacketSize=1000;QStartNoAckMode+", "OK", "QC1", "vCont;c;C;s;S", "OK", "OK", "l/bin/test", NULL
	};
	Stub stub;
	RThread *th = stub_start (&stub, -1, lfd, replies);
	char *uri = r_str_newf ("gdb://127.0.0.1:%u", ntohs (sa.sin_port));
	RIODesc *desc = r_io_open_nomap (io, uri, R_PERM_R, 0);
	free (uri);
	mu_assert_notnull (desc, "open GDB IO plugin");
	mu_assert_true (send_response (stub.fd, "O20203132330a0a"), "send monitor output");
	mu_assert_true (send_response (stub.fd, "OK"), "complete monitor command");
	char *output = r_io_system (io, "monitor help");
	mu_assert_streq_free (output, "  123\n\n", "IO returns monitor whitespace unchanged");
	mu_assert_true (send_response (stub.fd, "O7061727469616c"), "send partial monitor output");
	mu_assert_true (send_response (stub.fd, "E01"), "fail monitor command");
	output = r_io_system (io, "monitor help");
	mu_assert_streq_free (output, "partial", "IO preserves output before a monitor error");
	mu_assert_true (send_response (stub.fd, "OK"), "complete silent monitor command");
	mu_assert_null (r_io_system (io, "monitor help"), "silent monitor command returns no text");
	mu_assert_true (send_response (stub.fd, "E01"), "fail silent monitor command");
	mu_assert_null (r_io_system (io, "monitor help"), "silent monitor failure returns no text");
	size_t len;
	r_cons_get_buffer (cons, &len);
	mu_assert_eq (len, 0, "IO returns output without printing it");
	free (r_io_system (io, "pktsz 16"));
	mu_assert_streq_free (r_io_system (io, "pktsz"), "packet size: 16 bytes\n", "IO can lower the budget");
	free (r_io_system (io, "pktsz 0xffffffffffffffff"));
	mu_assert_streq_free (r_io_system (io, "pktsz"), "packet size: 16 bytes\n", "IO cannot raise or truncate the budget");
	free (r_io_system (io, "pktsz 1"));
	mu_assert_streq_free (r_io_system (io, "pktsz"), "packet size: 1 bytes\n", "IO preserves a tiny user limit");
	r_io_free (io);
	r_th_wait (th);
	r_th_free (th);
	close (stub.fd);
	close (lfd);
	r_strbuf_free (stub.sent);
	r_cons_free (cons);
	mu_end;
}
#endif

int main(int argc, char **argv) {
	mu_run_test (test_gdb_server_register_values);
	mu_run_test (test_gdb_packet_limits);
#if R2__UNIX__ && !__wasi__
	mu_run_test (test_gdb_server_wide_packets);
	mu_run_test (test_gdb_processes_xml);
	mu_run_test (test_gdb_memory_packet_sizes);
	mu_run_test (test_gdb_memory_packet_failures);
	mu_run_test (test_gdb_runtime_console_flows);
	mu_run_test (test_gdb_console_terminal_replies);
	mu_run_test (test_gdb_console_rejections);
	mu_run_test (test_gdb_console_acknowledgements);
	mu_run_test (test_gdb_console_attach_compatibility);
	mu_run_test (test_gdb_console_waiting);
	mu_run_test (test_gdb_console_interrupt);
	mu_run_test (test_gdb_console_query_timeout);
	mu_run_test (test_gdb_console_transport_failures);
	mu_run_test (test_gdb_monitor_output);
	mu_run_test (test_gdb_short_stop_replies);
	mu_run_test (test_gdb_invalid_stop_signals);
	mu_run_test (test_gdb_short_execution_stops);
	mu_run_test (test_gdb_gdbserver_reads_g);
	mu_run_test (test_gdb_lldb_reads_g_with_thread);
	mu_run_test (test_gdb_lldb_reads_p);
	mu_run_test (test_gdb_stop_reply_of_another_thread);
	mu_run_test (test_gdb_reads_p_without_thread_suffix);
	mu_run_test (test_gdb_refuses_oversized);
	mu_run_test (test_gdb_refuses_unaddressable_profile);
	mu_run_test (test_gdb_write_reg_needs_registers);
	mu_run_test (test_gdb_register_packets_name_thread);
	mu_run_test (test_gdb_attach_stop_reply);
	mu_run_test (test_gdb_target_xml_offsets);
	mu_run_test (test_gdb_target_xml_regnums);
	mu_run_test (test_gdb_target_xml_names);
	mu_run_test (test_gdb_connect_packet_limits);
	mu_run_test (test_gdb_connect_probes);
	mu_run_test (test_gdb_io_monitor_output);
#endif
	return tests_passed != tests_run;
}
