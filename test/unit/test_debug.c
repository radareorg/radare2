#include <r_core.h>
#include <r_debug.h>
#include <r_main.h>
#include <r_util/r_file.h>
#include <r_util/r_str.h>
#include <r_util/r_sys.h>
#include "../../shlr/gdb/include/arch.h"
#include "minunit.h"
#if __linux__
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef offsetof
#define offsetof(type, field) ((size_t) &((type *)0)->field)
#endif

#endif //__linux__

bool test_r_debug_use(void) {
	RDebug *dbg;
	bool res;

	dbg = r_debug_new (true);
	mu_assert_notnull (dbg, "r_debug_new () failed");

	res = r_debug_use (dbg, "null");
	mu_assert_eq (res, true, "r_debug_use () failed");

	r_debug_free (dbg);
	mu_end;
}

bool test_gdb_reg_profile_parser(void) {
	gdb_reg_t *regs = arch_parse_reg_profile (
		"gpr eax .32 0\n"
		"# unterminated comment");
	mu_assert_notnull (regs, "valid profile with unterminated comment");
	mu_assert_streq (regs[0].name, "eax", "parsed register name");
	free (regs);

	regs = arch_parse_reg_profile ("gpr short\n");
	mu_assert_null (regs, "short first profile line must fail");

	regs = arch_parse_reg_profile (
		"gpr eax .32 0\n"
		"gpr short\n");
	mu_assert_null (regs, "short profile line must fail");

	regs = arch_parse_reg_profile ("gpr eax .32 invalid\n");
	mu_assert_null (regs, "invalid register offset must fail");
	mu_end;
}

#if __linux__
static int pick_free_port(void) {
	int sockfd = socket (AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) {
		return -1;
	}
	struct sockaddr_in addr;
	memset (&addr, 0, sizeof (addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
	addr.sin_port = 0;
	if (bind (sockfd, (struct sockaddr *)&addr, sizeof (addr)) < 0) {
		close (sockfd);
		return -1;
	}
	socklen_t len = sizeof (addr);
	if (getsockname (sockfd, (struct sockaddr *)&addr, &len) < 0) {
		close (sockfd);
		return -1;
	}
	int port = ntohs (addr.sin_port);
	close (sockfd);
	return port;
}
#endif

#if __linux__
static bool write_all(int fd, const char *buf, size_t len) {
	while (len > 0) {
		ssize_t ret = write (fd, buf, len);
		if (ret < 0) {
			if (errno == EINTR) {
				continue;
			}
			return false;
		}
		if (ret == 0) {
			return false;
		}
		buf += ret;
		len -= ret;
	}
	return true;
}

static bool read_all(int fd, char *buf, size_t len) {
	while (len > 0) {
		ssize_t ret = read (fd, buf, len);
		if (ret < 0) {
			if (errno == EINTR) {
				continue;
			}
			return false;
		}
		if (ret == 0) {
			return false;
		}
		buf += ret;
		len -= ret;
	}
	return true;
}

static bool send_gdb_packet(int fd, const char *payload) {
	ut8 checksum = 0;
	const char *p = payload;
	while (*p) {
		checksum += (ut8)*p++;
	}
	char tail[4];
	snprintf (tail, sizeof (tail), "#%02x", checksum);
	return write_all (fd, "+", 1)
		&& write_all (fd, "$", 1)
		&& write_all (fd, payload, strlen (payload))
		&& write_all (fd, tail, 3);
}

static int recv_gdb_packet(int fd, char *buf, size_t buflen) {
	char ch;
	for (;;) {
		ssize_t ret = read (fd, &ch, 1);
		if (ret < 0 && errno == EINTR) {
			continue;
		}
		if (ret <= 0) {
			return -1;
		}
		if (ch == '$') {
			break;
		}
	}
	size_t len = 0;
	for (;;) {
		ssize_t ret = read (fd, &ch, 1);
		if (ret < 0 && errno == EINTR) {
			continue;
		}
		if (ret <= 0) {
			return -1;
		}
		if (ch == '#') {
			char checksum[2];
			if (!read_all (fd, checksum, sizeof (checksum))) {
				return -1;
			}
			if (buflen > 0) {
				buf[len < buflen ? len : buflen - 1] = '\0';
			}
			return (int)len;
		}
		if (len + 1 < buflen) {
			buf[len] = ch;
		}
		len++;
	}
}

static void run_oversized_gdb_server(int port) {
	int sockfd = socket (AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) {
		r_sys_exit (1, true);
	}
	int one = 1;
	setsockopt (sockfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof (one));
	struct sockaddr_in addr;
	memset (&addr, 0, sizeof (addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
	addr.sin_port = htons (port);
	if (bind (sockfd, (struct sockaddr *)&addr, sizeof (addr)) < 0 || listen (sockfd, 1) < 0) {
		close (sockfd);
		r_sys_exit (1, true);
	}
	int client = accept (sockfd, NULL, NULL);
	if (client < 0) {
		close (sockfd);
		r_sys_exit (1, true);
	}
	const int decoded_bytes = 5000;
	char *reg_response = malloc ((decoded_bytes * 2) + 1);
	if (!reg_response) {
		close (client);
		close (sockfd);
		r_sys_exit (1, true);
	}
	int i;
	for (i = 0; i < decoded_bytes * 2; i++) {
		reg_response[i] = 'a';
	}
	reg_response[i] = '\0';
	char packet[256];
	while (recv_gdb_packet (client, packet, sizeof (packet)) >= 0) {
		if (r_str_startswith (packet, "qSupported")) {
			send_gdb_packet (client, "PacketSize=ff00");
		} else if (r_str_startswith (packet, "qC")) {
			send_gdb_packet (client, "QCp1.1");
		} else if (r_str_startswith (packet, "vCont?")) {
			send_gdb_packet (client, "vCont;c;C;s;S");
		} else if (r_str_startswith (packet, "H")) {
			send_gdb_packet (client, "OK");
		} else if (!strcmp (packet, "?")) {
			send_gdb_packet (client, "S05");
		} else if (!strcmp (packet, "g")) {
			send_gdb_packet (client, reg_response);
		} else if (!strcmp (packet, "D")) {
			send_gdb_packet (client, "OK");
			break;
		} else {
			send_gdb_packet (client, "");
		}
	}
	free (reg_response);
	close (client);
	close (sockfd);
	r_sys_exit (0, true);
}

static void run_xml_gdb_server(int port, bool recursive_include, ut32 regnum) {
	int sockfd = socket (AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) {
		r_sys_exit (1, true);
	}
	int one = 1;
	setsockopt (sockfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof (one));
	struct sockaddr_in addr;
	memset (&addr, 0, sizeof (addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
	addr.sin_port = htons (port);
	if (bind (sockfd, (struct sockaddr *)&addr, sizeof (addr)) < 0 || listen (sockfd, 1) < 0) {
		close (sockfd);
		r_sys_exit (1, true);
	}
	int client = accept (sockfd, NULL, NULL);
	if (client < 0) {
		close (sockfd);
		r_sys_exit (1, true);
	}
	RStrBuf *xml = r_strbuf_new (recursive_include
		? "<?xml version=\"1.0\"?>\n"
		  "<target version=\"1.0\">\n"
		  "<xi:include href=\"target.xml\"/>\n"
		  "</target>"
		: "<?xml version=\"1.0\"?>\n"
		  "<target version=\"1.0\">\n"
		  "<architecture>i386:x86-64</architecture>\n"
		  "<feature name=\"org.gnu.gdb.i386.core\">\n"
		  "<reg name=\"");
	if (!xml) {
		close (client);
		close (sockfd);
		r_sys_exit (1, true);
	}
	if (!recursive_include) {
		r_strbuf_pad (xml, 'A', 200);
		r_strbuf_appendf (xml, "\" bitsize=\"64\" type=\"code_ptr\" regnum=\"%u\"/>", regnum);
	}
	const char *target_xml = r_strbuf_get (xml);
	const size_t xml_len = strlen (target_xml);
	char packet[256];
	while (recv_gdb_packet (client, packet, sizeof (packet)) >= 0) {
		if (r_str_startswith (packet, "qSupported")) {
			send_gdb_packet (client, "PacketSize=1000;qXfer:features:read+");
		} else if (r_str_startswith (packet, "qXfer:features:read:target.xml:")) {
			char *range = strrchr (packet, ':');
			if (!range) {
				send_gdb_packet (client, "");
				continue;
			}
			range++;
			char *comma = strchr (range, ',');
			if (!comma) {
				send_gdb_packet (client, "");
				continue;
			}
			*comma++ = '\0';
			size_t offset = strtoul (range, NULL, 16);
			size_t length = strtoul (comma, NULL, 16);
			if (offset >= xml_len) {
				send_gdb_packet (client, "l");
				continue;
			}
			size_t chunk_len = R_MIN (length, xml_len - offset);
			RStrBuf *response = r_strbuf_new (offset + chunk_len >= xml_len? "l": "m");
			if (!response) {
				r_strbuf_free (response);
				break;
			}
			r_strbuf_append_n (response, target_xml + offset, chunk_len);
			char *response_str = r_strbuf_drain (response);
			if (!response_str) {
				break;
			}
			send_gdb_packet (client, response_str);
			free (response_str);
		} else if (r_str_startswith (packet, "qC")) {
			send_gdb_packet (client, "QCp1.1");
		} else if (r_str_startswith (packet, "vCont?")) {
			send_gdb_packet (client, "vCont;c;C;s;S");
		} else if (r_str_startswith (packet, "H")) {
			send_gdb_packet (client, "OK");
		} else if (!strcmp (packet, "?")) {
			send_gdb_packet (client, "S05");
		} else if (!strcmp (packet, "g")) {
			send_gdb_packet (client, "0000000000000000");
		} else if (!strcmp (packet, "D")) {
			send_gdb_packet (client, "OK");
			break;
		} else {
			send_gdb_packet (client, "");
		}
	}
	r_strbuf_free (xml);
	close (client);
	close (sockfd);
	r_sys_exit (0, true);
}
#endif

bool test_r2_gdb_remote_open(void) {
#if __linux__
	char *gdbserver = r_file_path ("gdbserver");
	if (!gdbserver) {
		mu_ignore;
	}
	int port = pick_free_port ();
	if (port <= 0) {
		free (gdbserver);
		mu_ignore;
	}
	char *portstr = r_str_newf ("%d", port);
	char *listen = r_str_newf ("127.0.0.1:%s", portstr);
	char *uri = r_str_newf ("gdb://%s", listen);
	pid_t pid = r_sys_fork ();
	if (pid < 0) {
		free (gdbserver);
		free (portstr);
		free (listen);
		free (uri);
		mu_assert ("fork failed", false);
	}
	if (pid == 0) {
		execl (gdbserver, "gdbserver", "--once", listen, "/bin/sleep", "2", NULL);
		r_sys_exit (1, true);
	}

	r_sys_usleep (500000);
	const char *argv[] = { "radare2", "-q", "-d", "-D", "gdb", "-Qc", "q", uri, NULL };
	int ret = r_main_radare2 (8, argv);
	int status = 0;
	int waited = 0;
	int wpid = 0;
	while (waited < 20) {
		wpid = waitpid (pid, &status, WNOHANG);
		if (wpid == pid) {
			break;
		}
		r_sys_usleep (100000);
		waited++;
	}
	if (wpid == 0) {
		kill (pid, SIGKILL);
		waitpid (pid, &status, 0);
	}

	free (gdbserver);
	free (portstr);
	free (listen);
	free (uri);

	mu_assert_eq (ret, 0, "r2 gdb remote open failed");
	mu_end;
#else
	mu_ignore;
#endif
}

bool test_r2_gdb_oversized_reg_response(void) {
#if __linux__
	int port = pick_free_port ();
	if (port <= 0) {
		mu_ignore;
	}
	pid_t pid = r_sys_fork ();
	if (pid < 0) {
		mu_assert ("fork failed", false);
	}
	if (pid == 0) {
		run_oversized_gdb_server (port);
	}

	r_sys_usleep (500000);
	char *uri = r_str_newf ("gdb://127.0.0.1:%d", port);
	const char *argv[] = { "radare2", "-q", "-d", "-D", "gdb", "-escr.null=true", "-Qc", "dr;q", uri, NULL };
	int ret = r_main_radare2 (9, argv);
	int status = 0;
	int waited = 0;
	int wpid = 0;
	while (waited < 20) {
		wpid = waitpid (pid, &status, WNOHANG);
		if (wpid == pid) {
			break;
		}
		r_sys_usleep (100000);
		waited++;
	}
	if (wpid == 0) {
		kill (pid, SIGKILL);
		waitpid (pid, &status, 0);
	}
	free (uri);

	mu_assert_eq (ret, 0, "oversized gdb register response failed");
	mu_end;
#else
	mu_ignore;
#endif
}

bool test_r2_gdb_long_xml_reg_name(void) {
#if __linux__
	int port = pick_free_port ();
	if (port <= 0) {
		mu_ignore;
	}
	pid_t pid = r_sys_fork ();
	if (pid < 0) {
		mu_assert ("fork failed", false);
	}
	if (pid == 0) {
		run_xml_gdb_server (port, false, 16);
	}

	r_sys_usleep (500000);
	char *uri = r_str_newf ("gdb://127.0.0.1:%d", port);
	const char *argv[] = { "radare2", "-q", "-d", "-D", "gdb", "-Qc", "q", uri, NULL };
	int ret = r_main_radare2 (8, argv);
	int status = 0;
	int waited = 0;
	int wpid = 0;
	while (waited < 20) {
		wpid = waitpid (pid, &status, WNOHANG);
		if (wpid == pid) {
			break;
		}
		r_sys_usleep (100000);
		waited++;
	}
	if (wpid == 0) {
		kill (pid, SIGKILL);
		waitpid (pid, &status, 0);
	}
	free (uri);

	mu_assert_eq (ret, 0, "long gdb xml register name failed");
	mu_end;
#else
	mu_ignore;
#endif
}

bool test_r2_gdb_recursive_xml_include(void) {
#if __linux__
	int port = pick_free_port ();
	if (port <= 0) {
		mu_ignore;
	}
	pid_t pid = r_sys_fork ();
	if (pid < 0) {
		mu_assert ("fork failed", false);
	}
	if (pid == 0) {
		run_xml_gdb_server (port, true, 0);
	}

	r_sys_usleep (500000);
	char *uri = r_str_newf ("gdb://127.0.0.1:%d", port);
	const char *argv[] = { "radare2", "-q", "-d", "-D", "gdb", "-Qc", "q", uri, NULL };
	int ret = r_main_radare2 (8, argv);
	int status = 0;
	int waited = 0;
	int wpid = 0;
	while (waited < 20) {
		wpid = waitpid (pid, &status, WNOHANG);
		if (wpid == pid) {
			break;
		}
		r_sys_usleep (100000);
		waited++;
	}
	if (wpid == 0) {
		kill (pid, SIGKILL);
		waitpid (pid, &status, 0);
	}
	free (uri);

	mu_assert_eq (ret, 0, "recursive gdb XML include failed");
	mu_end;
#else
	mu_ignore;
#endif
}

bool test_r2_gdb_oversized_xml_regnum(void) {
#if __linux__
	int port = pick_free_port ();
	if (port <= 0) {
		mu_ignore;
	}
	pid_t pid = r_sys_fork ();
	if (pid < 0) {
		mu_assert ("fork failed", false);
	}
	if (pid == 0) {
		run_xml_gdb_server (port, false, 200000000);
	}

	r_sys_usleep (500000);
	char *uri = r_str_newf ("gdb://127.0.0.1:%d", port);
	const char *argv[] = { "radare2", "-q", "-d", "-D", "gdb", "-Qc", "q", uri, NULL };
	int ret = r_main_radare2 (8, argv);
	int status = 0;
	int waited = 0;
	int wpid = 0;
	while (waited < 20) {
		wpid = waitpid (pid, &status, WNOHANG);
		if (wpid == pid) {
			break;
		}
		r_sys_usleep (100000);
		waited++;
	}
	if (wpid == 0) {
		kill (pid, SIGKILL);
		waitpid (pid, &status, 0);
	}
	free (uri);

	mu_assert_eq (ret, 0, "oversized gdb XML regnum failed");
	mu_end;
#else
	mu_ignore;
#endif
}

bool test_r_debug_reg_offset(void) {
#if __linux__
#ifdef __x86_64__
#define FPREGS struct user_fpregs_struct
	FPREGS regs;
	mu_assert_eq (sizeof (regs.cwd), 2, "cwd size");
	mu_assert_eq (offsetof (FPREGS, cwd), 0, "cwd offset");

	mu_assert_eq (sizeof (regs.rip), 8, "rip size");
	mu_assert_eq (offsetof (FPREGS, rip), 8, "rip offset");

	mu_assert_eq (sizeof (regs.mxcsr), 4, "mxcsr size");
	mu_assert_eq (offsetof (FPREGS, mxcsr), 24, "mxcsr offset");

	mu_assert_eq (sizeof (regs.mxcr_mask), 4, "mxcr_mask size");
	mu_assert_eq (offsetof (FPREGS, mxcr_mask), 28, "mxcr_mask offset");

	mu_assert_eq (sizeof (regs.st_space[0]) * 2, 8, "st0 size");
	mu_assert_eq (offsetof (FPREGS, st_space[0]), 32, "st0 offset");

	mu_assert_eq (sizeof (regs.xmm_space[0]) * 4, 16, "xmm0 size");
	mu_assert_eq (offsetof (FPREGS, xmm_space[0]), 160, "xmm0 offset");

	mu_assert_eq (offsetof (FPREGS, padding[0]), 416, "x64");
#endif //__x86_64__
#endif //__linux__
	mu_end;
}

int all_tests(void) {
	mu_run_test (test_r_debug_use);
	mu_run_test (test_gdb_reg_profile_parser);
	mu_run_test (test_r2_gdb_remote_open);
	mu_run_test (test_r2_gdb_oversized_reg_response);
	mu_run_test (test_r2_gdb_long_xml_reg_name);
	mu_run_test (test_r2_gdb_recursive_xml_include);
	mu_run_test (test_r2_gdb_oversized_xml_regnum);
	mu_run_test (test_r_debug_reg_offset);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
