#ifndef _INCLUDE_SOCKET_H_
#define _INCLUDE_SOCKET_H_

#include "r_types.h"

#ifdef HAVE_LIB_SSL
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif

typedef struct r_socket_t {
	int fd;
	int is_ssl;
#ifdef HAVE_LIB_SSL
	SSL_CTX *ctx;
	SSL *sfd;
	BIO *bio;
#endif
} RSocket;

#ifdef R_API
R_API RSocket *r_socket_new_from_fd (int fd);
R_API RSocket *r_socket_new (const char *host, const char *port, int is_ssl);
R_API void r_socket_free (RSocket *s);
#if __UNIX__
R_API RSocket *r_socket_unix_connect (const char *file);
R_API int r_socket_unix_listen (const char *file);
#endif
R_API int r_socket_connect (const char *host, const char *port);
R_API RSocket *r_socket_listen (const char *port, int is_ssl,const char *certfile);
R_API void r_socket_block (RSocket *s, int block);
R_API RSocket *r_socket_accept (RSocket *s);
R_API int r_socket_flush (RSocket *s);
R_API int r_socket_close (RSocket *s);
R_API int r_socket_ready (RSocket *s, int secs, int usecs);
R_API char *r_socket_to_string (RSocket *s);
R_API RSocket *r_socket_udp_connect (const char *host, const char *port, int is_ssl);
R_API int r_socket_write (RSocket *s, void *buf, int len);
R_API int r_socket_puts (RSocket *s, char *buf);
R_API void r_socket_printf (RSocket *s, const char *fmt, ...);
R_API int r_socket_read (RSocket *s, ut8 *read, int len);
R_API int r_socket_read_block (RSocket *s, unsigned char *buf, int len);
R_API int r_socket_gets (RSocket *s, char *buf, int size);

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

#endif
#endif
