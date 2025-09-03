#ifndef R2_SOCKET_H
#define R2_SOCKET_H

#ifdef __cplusplus
extern "C" {
#endif

#include "r_types.h"
#include "r_bind.h"
#include "r_list.h"

R_LIB_VERSION_HEADER(r_socket);

#if R2__UNIX__
#include <netinet/in.h>
#include <sys/un.h>
#include <poll.h>
#include <arpa/inet.h>
#ifndef __wasi__
#include <netdb.h>
#include <sys/wait.h>
#endif
#include <sys/socket.h>
#endif

#if HAVE_LIB_SSL
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif

#if R2__UNIX__
#include <netinet/tcp.h>
#endif

/* For the Mingw-W64 toolchain */
#ifndef MSG_DONTWAIT
#define MSG_DONTWAIT 0
#endif
#ifndef SD_BOTH
#define SD_RECEIVE 0
#define SD_SEND    1
#define SD_BOTH    2
#endif

#if _MSC_VER
#define R_INVALID_SOCKET INVALID_SOCKET
#else
#define R_INVALID_SOCKET -1
#endif

typedef struct {
#if R2__WINDOWS__
	HANDLE pipe;
	HANDLE child;
#else
	int child;
	int input[2];
	int output[2];
#endif
	RCoreBind coreb;
	/* HTTP/r2web support: when is_http is true, http_url contains
	 * the base endpoint where commands are POSTed using the
	 * r_socket_http_post API and r2pipe_cmd will return the
	 * HTTP response instead of using fork+pipe. */
	char *http_url;
	bool is_http;
} R2Pipe;

typedef struct r_socket_t {
#ifdef _MSC_VER
	SOCKET fd;
#else
	int fd;
#endif
	bool is_ssl;
	int proto;
	int local; // TODO: merge ssl with local -> flags/options
	int port;
	struct sockaddr_in sa;
#if HAVE_LIB_SSL
	SSL_CTX *ctx;
	SSL *sfd;
	BIO *bio;
#endif
} RSocket;

typedef struct r_socket_http_options {
	RList *authtokens;
	bool accept_timeout;
	int timeout;
	bool httpauth;
} RSocketHTTPOptions;

#define R_SOCKET_PROTO_TCP     IPPROTO_TCP
#define R_SOCKET_PROTO_UDP     IPPROTO_UDP
#define R_SOCKET_PROTO_CAN     0xc42b05
#define R_SOCKET_PROTO_SERIAL  0x534147
#define R_SOCKET_PROTO_UNIX    0x1337
#define R_SOCKET_PROTO_NONE    0
#define R_SOCKET_PROTO_DEFAULT R_SOCKET_PROTO_TCP

// backward compat for yara-r2
#define r2p_cmd   r2pipe_cmd
#define r2p_open  r2pipe_open
#define r2p_close r2pipe_close

#ifdef R_API
R_API RSocket *r_socket_new_from_fd(int fd);
R_API RSocket *r_socket_new(bool is_ssl);
R_API bool r_socket_spawn(RSocket *s, const char *cmd, unsigned int timeout);
R_API bool r_socket_connect(RSocket *s, const char *host, const char *port, int proto, unsigned int timeout);
R_API int r_socket_connect_serial(RSocket *sock, const char *path, int speed, int parity);
#define r_socket_connect_tcp(a, b, c, d) r_socket_connect(a, b, c, R_SOCKET_PROTO_TCP, d)
#define r_socket_connect_udp(a, b, c, d) r_socket_connect(a, b, c, R_SOCKET_PROTO_UDP, d)
#if R2__UNIX__
#define r_socket_connect_unix(a, b) r_socket_connect(a, b, b, R_SOCKET_PROTO_UNIX, 0)
#else
#define r_socket_connect_unix(a, b) (false)
#endif
R_API bool r_socket_listen(RSocket *s, const char *port, const char *certfile);
R_API int r_socket_port_by_name(const char *name);
R_API bool r_socket_close_fd(RSocket *s);
R_API bool r_socket_close(RSocket *s);
R_API void r_socket_free(RSocket *s);
R_API RSocket *r_socket_accept(RSocket *s);
R_API RSocket *r_socket_accept_timeout(RSocket *s, unsigned int timeout);
R_API bool r_socket_block_time(RSocket *s, bool block, int sec, int usec);
R_API int r_socket_flush(RSocket *s);
R_API int r_socket_ready(RSocket *s, int secs, int usecs);
R_API char *r_socket_tostring(RSocket *s);
R_API int r_socket_write(RSocket *s, const void *buf, int len);
R_API int r_socket_puts(RSocket *s, char *buf);
R_API void r_socket_printf(RSocket *s, const char *fmt, ...) R_PRINTF_CHECK(2, 3);
R_API int r_socket_read(RSocket *s, ut8 *read, int len);
R_API int r_socket_read_block(RSocket *s, unsigned char *buf, int len);
R_API int r_socket_gets(RSocket *s, char *buf, int size);
R_API ut8 *r_socket_slurp(RSocket *s, int *len);
R_API bool r_socket_is_connected(RSocket *);

/* process */
typedef struct r_socket_proc_t {
	int fd0[2];
	int fd1[2];
	int pid;
} RSocketProc;

R_API RSocketProc *r_socket_proc_open(char *const argv[]);
R_API int r_socket_proc_close(RSocketProc *sp);
R_API int r_socket_proc_read(RSocketProc *sp, unsigned char *buf, int len);
R_API int r_socket_proc_gets(RSocketProc *sp, char *buf, int size);
R_API int r_socket_proc_write(RSocketProc *sp, void *buf, int len);
R_API void r_socket_proc_printf(RSocketProc *sp, const char *fmt, ...) R_PRINTF_CHECK(2, 3);
R_API int r_socket_proc_ready(RSocketProc *sp, int secs, int usecs);

/* HTTP */
R_API char *r_socket_http_get(const char *url, const char **headers, int *code, int *rlen);
R_API char *r_socket_http_post(const char *url, const char **headers, const char *data, int *code, int *rlen);
R_API void r_socket_http_server_set_breaked(bool *b);

typedef struct r_socket_http_request {
	RSocket *s;
	char *path;
	char *host;
	char *agent;
	char *method;
	char *referer;
	ut8 *data;
	int data_length;
	bool auth;
} RSocketHTTPRequest;

R_API RSocketHTTPRequest *r_socket_http_accept(RSocket *s, RSocketHTTPOptions *so);
R_API void r_socket_http_response(RSocketHTTPRequest *rs, int code, const char *out, int x, const char *headers);
R_API void r_socket_http_close(RSocketHTTPRequest *rs);
R_API ut8 *r_socket_http_handle_upload(const ut8 *str, int len, int *olen);
R_API void r_socket_http_free(RSocketHTTPRequest *rs);

typedef int (*rap_server_open)(void *user, const char *file, int flg, int mode);
typedef int (*rap_server_seek)(void *user, ut64 offset, int whence);
typedef int (*rap_server_read)(void *user, ut8 *buf, int len);
typedef int (*rap_server_write)(void *user, ut8 *buf, int len);
typedef char *(*rap_server_cmd)(void *user, const char *command);
typedef int (*rap_server_close)(void *user, int fd);

enum {
	RAP_PACKET_OPEN = 1,
	RAP_PACKET_READ = 2,
	RAP_PACKET_WRITE = 3,
	RAP_PACKET_SEEK = 4,
	RAP_PACKET_CLOSE = 5,
	// system was deprecated in slot 6,
	RAP_PACKET_CMD = 7,
	RAP_PACKET_REPLY = 0x80,
	RAP_PACKET_MAX = 4096
};

typedef struct r_socket_rap_server_t {
	RSocket *fd;
	char *port;
	ut8 buf[RAP_PACKET_MAX + 32]; // This should be used as a static buffer for everything done by the server
	rap_server_open open;
	rap_server_seek seek;
	rap_server_read read;
	rap_server_write write;
	rap_server_cmd system;
	rap_server_cmd cmd;
	rap_server_close close;
	void *user; // Always first arg for callbacks
} RSocketRapServer;

R_API RSocketRapServer *r_socket_rap_server_new(bool is_ssl, const char *port);
R_API RSocketRapServer *r_socket_rap_server_create(const char *pathname);
R_API void r_socket_rap_server_free(RSocketRapServer *rap_s);
R_API bool r_socket_rap_server_listen(RSocketRapServer *rap_s, const char *certfile);
R_API RSocket *r_socket_rap_server_accept(RSocketRapServer *rap_s);
R_API bool r_socket_rap_server_continue(RSocketRapServer *rap_s);

/* rap client */
R_API int r_socket_rap_client_open(RSocket *s, const char *file, int rw);
R_API char *r_socket_rap_client_command(RSocket *s, const char *cmd, RCoreBind *c);
R_API int r_socket_rap_client_write(RSocket *s, const ut8 *buf, int count);
R_API int r_socket_rap_client_read(RSocket *s, ut8 *buf, int count);
R_API ut64 r_socket_rap_client_seek(RSocket *s, ut64 offset, int whence);

/* run.c */
#define R_RUN_PROFILE_NARGS 512
typedef struct r_run_profile_t {
	char *_args[R_RUN_PROFILE_NARGS];
	int _argc;
	bool _daemon;
	char *_system;
	char *_program;
	char *_runlib;
	char *_runlib_fcn;
	char *_stdio;
	char *_stdin;
	char *_stdout;
	char *_stderr;
	char *_chgdir;
	char *_chroot;
	char *_libpath;
	RList *_preload;
	int _bits;
	bool _time;
	int _pid;
	char *_pidfile;
	bool _r2preload;
	bool _docore;
	bool _dofork;
	int _aslr;
	int _maxstack;
	int _maxproc;
	int _maxfd;
	int _r2sleep;
	int _execve;
	char *_setuid;
	char *_seteuid;
	char *_setgid;
	char *_setegid;
	char *_input;
	char *_connect;
	char *_listen;
	int _pty;
	int _timeout;
	int _timeout_sig;
	int _nice;
	bool _stderrout;
	bool _noprogram;
} RRunProfile;

R_API RRunProfile *r_run_new(const char *R_NULLABLE str);
R_API bool r_run_parse(RRunProfile *pf, const char *profile);
R_API void r_run_free(RRunProfile *r);
R_API bool r_run_parseline(RRunProfile *p, const char *b);
R_API const char *r_run_help(void);
R_API bool r_run_config_env(RRunProfile *p);
R_API bool r_run_start(RRunProfile *p);
R_API void r_run_reset(RRunProfile *p);
R_API bool r_run_parsefile(RRunProfile *p, const char *b);
R_API char *r_run_get_environ_profile(char **env);

/* rapipe */
R_API R2Pipe *rap_open(const char *cmd);
R_API R2Pipe *rap_open_corebind(RCoreBind *coreb);
R_API int rap_close(R2Pipe *rap);

R_API char *rap_cmd(R2Pipe *rap, const char *str);
R_API char *rap_cmdf(R2Pipe *rap, const char *fmt, ...) R_PRINTF_CHECK(2, 3);

R_API int rap_write(R2Pipe *rap, const char *str);
R_API char *rap_read(R2Pipe *rap);

R_API int r2pipe_write(R2Pipe *r2pipe, const char *str);
R_API char *r2pipe_read(R2Pipe *r2pipe);
R_API int r2pipe_close(R2Pipe *r2pipe);
R_API R2Pipe *r2pipe_open_corebind(RCoreBind *coreb);
R_API R2Pipe *r2pipe_open(const char *cmd);
R_API R2Pipe *r2pipe_open_dl(const char *file);
R_API char *r2pipe_cmd(R2Pipe *r2pipe, const char *str);
R_API char *r2pipe_cmdf(R2Pipe *r2pipe, const char *fmt, ...) R_PRINTF_CHECK(2, 3);
#endif

#ifdef __cplusplus
}
#endif

#endif
