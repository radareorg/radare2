#ifndef _INCLUDE_SOCKET_H_
#define _INCLUDE_SOCKET_H_

#include "r_types.h"

R_API int r_socket_ready(int fd, int secs, int usecs);
R_API int r_socket_read(int fd, unsigned char *read, int len);
R_API int r_socket_write(int fd, unsigned char *buf, int len);
R_API int r_socket_connect(char *host, int port);
R_API int r_socket_listen(int port);
R_API int r_socket_accept(int fd);
R_API int r_socket_fgets(int fd, char *buf, int size);
R_API void r_socket_printf(int fd, const char *fmt, ...);
R_API char *r_socket_to_string(int fd);

#endif
