#ifndef _INCLUDE_SOCKET_H_
#define _INCLUDE_SOCKET_H_

#include "r_types.h"

#ifdef __cplusplus
extern "C" {
#endif

R_LIB_VERSION_HEADER(r_socket);

#if __UNIX__
#include <netinet/in.h>
#endif
#if HAVE_LIB_SSL
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif

typedef struct r_socket_t {
	int fd;
	int is_ssl;
	int local; // TODO: merge ssl with local -> flags/options
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

R_API RSocketProc *r_socket_proc_open(char *const argv[]);
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
#endif

#ifdef __cplusplus
}
#endif

#endif
