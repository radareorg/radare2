#ifndef _INCLUDE_SOCKET_H_
#define _INCLUDE_SOCKET_H_

#include "r_types.h"

/* TODO: major refactoring of r_socket */
/* make it work like the rest of apis */
/* struct r_socket_t *sock = r_socket_new(R_SOCKET_TCP, "gogle.com", 80); */
/* struct r_socket_t *sock = r_socket_proc_new(R_SOCKET_PROCESS, "/bin/ls", 80); */

/* process */

struct r_socket_proc_t {
	int fd0[2];
	int fd1[2];
	int pid;
};

R_API struct r_socket_proc_t *r_socket_proc_open(char *const argv[]);
R_API int r_socket_proc_close(struct r_socket_proc_t *sp);
#define r_socket_proc_read(x,y,z) r_socket_read(x->fd1[0],y,z)
#define r_socket_proc_fgets(x,y,z) r_socket_fgets(x->fd1[0],y,z)
#define r_socket_proc_write(x,y,z) r_socket_write(x->fd0[1],y,z)
#define r_socket_proc_printf(x,y) r_socket_printf(x->fd0[1],y)
#define r_socket_proc_ready(x,y,z) r_socket_ready(x->fd1[0],y,z)

// read from stdout of process is fd1[0]
// write to stdin of process is fd0[1]


/* socket */

#if __UNIX__
R_API int r_socket_unix_connect(const char *file);
R_API int r_socket_unix_listen(const char *file);
#endif

R_API int r_socket_flush(int fd);
R_API void r_socket_block(int fd, int block);
R_API int r_socket_ready(int fd, int secs, int usecs);
R_API int r_socket_read(int fd, unsigned char *read, int len);
R_API int r_socket_puts(int fd, char *buf);
R_API int r_socket_write(int fd, void *buf, int len);
R_API int r_socket_connect(char *host, int port);
R_API int r_socket_listen(int port);
R_API int r_socket_accept(int fd);
R_API int r_socket_gets(int fd, char *buf, int size);
R_API void r_socket_printf(int fd, const char *fmt, ...);
R_API char *r_socket_to_string(int fd);

#endif
