#ifndef _INCLUDE_SOCKET_H_
#define _INCLUDE_SOCKET_H_

int r_socket_ready(int fd, int secs, int usecs);
int r_socket_read(int fd, unsigned char *read, int len);
int r_socket_write(int fd, unsigned char *buf, int len);
int r_socket_connect(char *host, int port);
int r_socket_listen(int port);
int r_socket_accept(int fd);
int r_socket_fgets(int fd, char *buf, int size);
void r_socket_printf(int fd, const char *fmt, ...);

#endif
