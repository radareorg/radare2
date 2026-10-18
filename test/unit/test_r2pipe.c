#include <r_util.h>
#include <r_socket.h>
#include <r_io.h>
#include "minunit.h"

static bool test_r2pipe(void) {
	R2Pipe *r = r2pipe_open ("radare2 -N -q0 -");
	mu_assert ("r2pipe can spawn", r);
	char *hello = r2pipe_cmd (r, "?e hello world");
	if (hello) {
		mu_assert_streq (hello, "hello world\n", "r2pipe hello world");
		free (hello);
	}
	r2pipe_close (r);
	mu_end;
}

static bool test_r2pipe_404(void) {
	R2Pipe *r = r2pipe_open ("rodoro2 -N -q0 -");
	mu_assert_null (r, "r2pipe should not spawn");
	// mu_assert ("r2pipe can spawn", !r);
	mu_end;
}

#if R2__UNIX__
static const char *self;
static const ut64 io_high_base = 0xfedcba9876543000ULL;
static const char *bad_replies[] = {
	"null", "{\"result\":2,\"data\":[1]}", "{\"result\":-1}",
	"{\"result\":1,\"data\":[256]}", "{\"result\":1,\"data\":[null]}",
	"{\"result\":\"1\",\"data\":[1]}", "{\"result\":65536,\"data\":[]}"
};

static int io_backend(void) {
	ut8 memory[8192] = {0};
	char line[65536];
	char wire_address[32] = "";
	ut64 last_address = 0;
	putchar (0);
	fflush (stdout);
	while (fgets (line, sizeof (line), stdin)) {
		RJson *request = r_json_parseref (line);
		if (!request) {
			return 1;
		}
		const char *op = r_json_get_str (request, "op");
		const RJson *field = r_json_get (request, "address");
		ut64 address = 0;
		if (field) {
			address = field->type == R_JSON_STRING? r_num_get (NULL, field->str_value): field->num.u_value;
			r_str_ncpy (wire_address, field->type == R_JSON_STRING? field->str_value: "number", sizeof (wire_address));
			last_address = address;
		}
		if (address >= io_high_base && address - io_high_base < sizeof (memory)) {
			address -= io_high_base;
		}
		if (address == 9010) {
			printf (" { \"data\" : [ 7 ], \"result\" : 1 }%c", 0);
		} else if (address == 9011) {
			printf ("{\"result\":0}%c", 0);
		} else if (address >= 9000 && address < 9000 + R_ARRAY_SIZE (bad_replies)) {
			printf ("%s%c", bad_replies[address - 9000], 0);
		} else {
			PJ *pj = pj_new ();
			pj_o (pj);
			if (!strcmp (op, "system")) {
				const char *cmd = r_json_get_str (request, "cmd");
				char parsed_address[19];
				snprintf (parsed_address, sizeof (parsed_address), "0x%"PFMT64x, last_address);
				pj_ks (pj, "result", !strcmp (cmd, "wire-address")? wire_address:
					!strcmp (cmd, "last-address")? parsed_address: cmd);
			} else {
				const RJson *data = r_json_get (request, "data");
				int count = data? data->children.count: r_json_get_num (request, "count");
				count = address < sizeof (memory)? R_MIN (count, sizeof (memory) - address): 0;
				pj_ki (pj, "result", count);
				if (!strcmp (op, "write")) {
					const RJson *item = data->children.first;
					int i;
					for (i = 0; i < count; i++, item = item->next) {
						memory[address + i] = item->num.u_value;
					}
				} else {
					pj_k (pj, "data");
					pj_a (pj);
					int i;
					for (i = 0; i < count; i++) {
						pj_n (pj, memory[address + i]);
					}
					pj_end (pj);
				}
			}
			pj_end (pj);
			printf ("%s%c", pj_string (pj), 0);
			pj_free (pj);
		}
		fflush (stdout);
		r_json_free (request);
	}
	return 0;
}

static bool test_r2pipe_io(void) {
	RIO *io = r_io_new ();
	char *uri = r_str_newf ("r2pipe://\"%s\" --io-backend", self);
	RIODesc *a = r_io_open_nomap (io, uri, R_PERM_RW, 0);
	RIODesc *b = r_io_open_nomap (io, uri, R_PERM_RW, 0);
	free (uri);
	mu_assert_notnull (a, "first IO backend");
	mu_assert_notnull (b, "second IO backend");
	ut8 expected[2048], actual[2048];
	int i;
	for (i = 0; i < sizeof (expected); i++) {
		expected[i] = (i * 17 + i / 256) & 0xff;
	}
	io->off = 0xdeadbeef;
	mu_assert_eq (r_io_fd_write_at (io, a->fd, 32, expected, sizeof (expected)), sizeof (expected), "write acknowledgement");
	mu_assert_eq (r_io_desc_seek (a, 0, R_IO_SEEK_CUR), 32 + sizeof (expected), "write advances descriptor");
	mu_assert_eq (r_io_desc_seek (b, 0, R_IO_SEEK_CUR), 0, "independent descriptor offset");
	mu_assert_eq (r_io_fd_read_at (io, a->fd, 32, actual, sizeof (actual)), sizeof (actual), "read beyond 1024 bytes");
	mu_assert_memeq (actual, expected, sizeof (actual), "read contents");
	mu_assert_eq (r_io_desc_seek (a, 0, R_IO_SEEK_CUR), 32 + sizeof (actual), "read advances descriptor");
	mu_assert_notnull (r_io_map_add (io, a->fd, R_PERM_RW, 32, 0x3c000000, sizeof (actual)), "nonzero map delta");
	io->va = true;
	memset (actual, 0, sizeof (actual));
	mu_assert ("mapped read", r_io_read_at (io, 0x3c000000, actual, sizeof (actual)));
	mu_assert_memeq (actual, expected, sizeof (actual), "mapped read translates address");
	mu_assert_eq (r_io_fd_read_at (io, a->fd, 8190, actual, 4), 2, "short read");
	mu_assert_eq (r_io_fd_read_at (io, a->fd, 8192, actual, 4), 0, "EOF");
	for (i = 0; i < R_ARRAY_SIZE (bad_replies); i++) {
		mu_assert_eq (r_io_fd_read_at (io, a->fd, 9000 + i, actual, 4), -1, "reject invalid read reply");
	}
	mu_assert_eq (r_io_fd_write_at (io, a->fd, 9006, expected, 4), -1, "reject oversized write result");
	mu_assert_eq (r_io_fd_read_at (io, a->fd, 9010, actual, 4), 1, "whitespace and reordered keys");
	mu_assert_eq (actual[0], 7, "decode spaced array");
	mu_assert_eq (r_io_fd_read_at (io, a->fd, 9011, actual, 4), 0, "EOF without data");
	char *result = r_io_desc_system (a, "hello \"world\"");
	mu_assert_streq (result, "hello \"world\"", "decode system reply");
	free (result);
	mu_assert_eq (r_io_fd_write_at (io, a->fd, io_high_base + 17, expected, 4), 4, "high uint64 write");
	result = r_io_desc_system (a, "wire-address");
	mu_assert_streq (result, "0xfedcba9876543011", "write address is an exact hexadecimal string");
	free (result);
	mu_assert_eq (r_io_fd_read_at (io, a->fd, io_high_base + 17, actual, 4), 4, "high uint64 read");
	mu_assert_memeq (actual, expected, 4, "high uint64 round trip");
	result = r_io_desc_system (a, "wire-address");
	mu_assert_streq (result, "0xfedcba9876543011", "read address is an exact hexadecimal string");
	free (result);
	mu_assert_eq (r_io_fd_read_at (io, a->fd, UT64_MAX, actual, 1), 0, "maximum uint64 offset");
	result = r_io_desc_system (a, "wire-address");
	mu_assert_streq (result, "0xffffffffffffffff", "maximum uint64 wire value");
	free (result);
	r_io_free (io);
	mu_end;
}
static bool test_r2pipe_io_numeric_address(void) {
	char *command = r_str_newf ("\"%s\" --io-backend", self);
	R2Pipe *pipe = r2pipe_open (command);
	free (command);
	mu_assert_notnull (pipe, "legacy numeric backend");
	char *reply = r2pipe_cmd (pipe, "{\"op\":\"read\",\"address\":18446744073709551615,\"count\":1}");
	free (reply);
	reply = r2pipe_cmd (pipe, "{\"op\":\"system\",\"cmd\":\"last-address\"}");
	mu_assert_streq (reply, "{\"result\":\"0xffffffffffffffff\"}", "legacy uint64 number stays exact in C");
	free (reply);
	r2pipe_close (pipe);
	mu_end;
}

#endif

static int all_tests(void) {
	r_sys_setenv ("R2_NOPLUGINS", "1");
	mu_run_test (test_r2pipe);
	mu_run_test (test_r2pipe_404);
#if R2__UNIX__
	mu_run_test (test_r2pipe_io);
	mu_run_test (test_r2pipe_io_numeric_address);
#endif
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	int result;
#if R2__UNIX__
	if (argc > 1 && !strcmp (argv[1], "--io-backend")) {
		return io_backend ();
	}
	char *path = r_file_abspath (argv[0]);
	self = path;
	result = all_tests ();
	free (path);
#else
	result = all_tests ();
#endif
	return result;
}
