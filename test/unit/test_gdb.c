#include <r_debug.h>
#include <gdbclient/commands.h>
#include <gdbclient/responses.h>
#include <gdbclient/xml.h>
#include <gdbr_common.h>
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
#if R2__UNIX__ && !__wasi__
	mu_run_test (test_gdb_server_wide_packets);
	mu_run_test (test_gdb_processes_xml);
	mu_run_test (test_gdb_monitor_output);
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
	mu_run_test (test_gdb_connect_probes);
	mu_run_test (test_gdb_io_monitor_output);
#endif
	return tests_passed != tests_run;
}
