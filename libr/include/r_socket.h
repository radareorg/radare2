#ifndef R2_SOCKET_H
#define R2_SOCKET_H

#include "r_types.h"

#ifdef __cplusplus
extern "C" {
#endif

R_LIB_VERSION_HEADER(r_socket);

#if __UNIX__ || __CYGWIN__
#include <netinet/in.h>
#include <sys/un.h>
#include <poll.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#endif

#if HAVE_LIB_SSL
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif

#if defined(__WINDOWS__) && !defined(__CYGWIN__) && !defined(MINGW32)
#include <ws2tcpip.h>
#endif

typedef struct r_socket_t {
	int fd;
	int is_ssl;
	int local; // TODO: merge ssl with local -> flags/options
	int port;
	struct sockaddr_in sa;
#if HAVE_LIB_SSL
	SSL_CTX *ctx;
	SSL *sfd;
	BIO *bio;
#endif
} RSocket;

#define R_SOCKET_PROTO_TCP IPPROTO_TCP
#define R_SOCKET_PROTO_UDP IPPROTO_UDP
#define R_SOCKET_PROTO_UNIX 0x1337

#ifdef R_API
R_API RSocket *r_socket_new_from_fd (int fd);
R_API RSocket *r_socket_new (int is_ssl);
R_API int r_socket_connect (RSocket *s, const char *host, const char *port, int proto, int timeout);
#define r_socket_connect_tcp(a,b,c,d) r_socket_connect(a,b,c,R_SOCKET_PROTO_TCP,d)
#define r_socket_connect_udp(a,b,c,d) r_socket_connect(a,b,c,R_SOCKET_PROTO_UDP,d)
#if __UNIX__
#define r_socket_connect_unix(a,b) r_socket_connect(a,b,NULL,R_SOCKET_PROTO_UNIX)
R_API int r_socket_unix_listen (RSocket *s, const char *file);
#endif
R_API int r_socket_port_by_name(const char *name);
R_API int r_socket_close (RSocket *s);
R_API int r_socket_free (RSocket *s);
R_API int r_socket_listen (RSocket *s, const char *port, const char *certfile);
R_API RSocket *r_socket_accept (RSocket *s);
R_API int r_socket_block_time (RSocket *s, int block, int sec);
R_API int r_socket_flush (RSocket *s);
R_API int r_socket_ready (RSocket *s, int secs, int usecs);
R_API char *r_socket_to_string (RSocket *s);
R_API int r_socket_write (RSocket *s, void *buf, int len);
R_API int r_socket_puts (RSocket *s, char *buf);
R_API void r_socket_printf (RSocket *s, const char *fmt, ...);
R_API int r_socket_read (RSocket *s, ut8 *read, int len);
R_API int r_socket_read_block (RSocket *s, unsigned char *buf, int len);
R_API int r_socket_gets (RSocket *s, char *buf, int size);
R_API int r_socket_is_connected (RSocket *);

/* process */
typedef struct r_socket_proc_t {
	int fd0[2];
	int fd1[2];
	int pid;
} RSocketProc;

R_API RSocketProc *r_socket_proc_open(char* const argv[]);
R_API int r_socket_proc_close(RSocketProc *sp);
R_API int r_socket_proc_read (RSocketProc *sp, unsigned char *buf, int len);
R_API int r_socket_proc_gets (RSocketProc *sp, char *buf, int size);
R_API int r_socket_proc_write (RSocketProc *sp, void *buf, int len);
R_API void r_socket_proc_printf (RSocketProc *sp, const char *fmt, ...);
R_API int r_socket_proc_ready (RSocketProc *sp, int secs, int usecs);

/* HTTP */
R_API char *r_socket_http_get (const char *url, int *code, int *rlen);
R_API char *r_socket_http_post (const char *url, const char *data, int *code, int *rlen);

typedef struct r_socket_http_request {
	RSocket *s;
	char *path;
	char *host;
	char *agent;
	char *method;
	ut8 *data;
	int data_length;
} RSocketHTTPRequest;

R_API RSocketHTTPRequest *r_socket_http_accept (RSocket *s, int timeout);
R_API void r_socket_http_response (RSocketHTTPRequest *rs, int code, const char *out, int x, const char *headers);
R_API void r_socket_http_close (RSocketHTTPRequest *rs);
R_API ut8 *r_socket_http_handle_upload(const ut8 *str, int len, int *olen);

typedef int (*rap_server_open)(void *user, const char *file, int flg, int mode);
typedef int (*rap_server_seek)(void *user, ut64 offset, int whence);
typedef int (*rap_server_read)(void *user, ut8 *buf, int len);
typedef int (*rap_server_write)(void *user, ut8 *buf, int len);
typedef char *(*rap_server_cmd)(void *user, const char *command);
typedef int (*rap_server_close)(void *user, int fd);

enum {
	RAP_RMT_OPEN = 0x01,
	RAP_RMT_READ,
	RAP_RMT_WRITE,
	RAP_RMT_SEEK,
	RAP_RMT_CLOSE,
	RAP_RMT_SYSTEM,
	RAP_RMT_CMD,
	RAP_RMT_REPLY = 0x80,
	RAP_RMT_MAX = 4096
};

typedef struct r_socket_rap_server_t {
	RSocket *fd;
	char port[5];
	ut8 buf[4101];					//This should be used as a static buffer for everything done by the server
	rap_server_open open;
	rap_server_seek seek;
	rap_server_read read;
	rap_server_write write;
	rap_server_cmd system;
	rap_server_cmd cmd;
	rap_server_close close;
	void *user;					//Always first arg for callbacks
} RSocketRapServer;

R_API RSocketRapServer *r_socket_rap_server_new (int is_ssl, const char *port);
R_API RSocketRapServer *r_socket_rap_server_create (const char *pathname);
R_API void r_socket_rap_server_free (RSocketRapServer *rap_s);
R_API int r_socket_rap_server_listen (RSocketRapServer *rap_s, const char *certfile);
R_API RSocket* r_socket_rap_server_accept (RSocketRapServer *rap_s);
R_API int r_socket_rap_server_continue (RSocketRapServer *rap_s);

/* run.c */
#define R_RUN_PROFILE_NARGS 512
typedef struct r_run_profile_t {
	char *_args[R_RUN_PROFILE_NARGS];
	char *_system;
	char *_program;
	char *_stdin;
	char *_stdout;
	char *_stderr;
	char *_chgdir;
	char *_chroot;
	char *_libpath;
	char *_preload;
	int _bits;
	int _pid;
	int _r2preload;
	int _docore;
	int _aslr;
	int _maxstack;
	int _maxproc;
	int _maxfd;
	int _r2sleep;
	char *_setuid;
	char *_seteuid;
	char *_setgid;
	char *_setegid;
	char *_input;
	char *_connect;
	char *_listen;
	int _timeout;
} RRunProfile;

R_API RRunProfile *r_run_new(const char *str);
R_API int r_run_parseline (RRunProfile *p, char *b);
R_API int r_run_parse(RRunProfile *pf, const char *profile);
R_API void r_run_free (RRunProfile *r);
R_API int r_run_parseline (RRunProfile *p, char *b);
R_API const char *r_run_help();
R_API int r_run_start(RRunProfile *p);
R_API void r_run_reset(RRunProfile *p);
R_API int r_run_parsefile (RRunProfile *p, const char *b);

#endif

#ifdef __cplusplus
}
#endif

#endif
