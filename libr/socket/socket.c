/* radare - LGPL - Copyright 2006-2009 pancake<nopcode.org> */
#define USE_SOCKETS

#include "r_types.h"
#include "r_socket.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#if __UNIX__
#include <sys/un.h>
#include <netinet/in.h>
#include <poll.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/fcntl.h>
#endif

#define BUFFER_SIZE 4096

int r_socket_write(int fd, unsigned char *buf, int len)
{
	int delta = 0;
	int ret;
	do {
		ret = send(fd, buf+delta, len, 0);
		if (ret == 0)
			return -1;
		if( ret == len)
			return len;
		if (ret<0)
			break;
		delta+=ret;
		len-=ret;
	} while(1);

	if (ret == -1)
		return -1;
	return delta;
}

// XXX: rewrite it to use select //
/* waits secs until new data is received.     */
/* returns -1 on error, 0 is false, 1 is true */
int r_socket_ready(int fd, int secs,int usecs)
{
	int ret;
#if __UNIX__
	struct pollfd fds[1];
	fds[0].fd = fd;
	fds[0].events = POLLIN|POLLPRI;
	fds[0].revents = POLLNVAL|POLLHUP|POLLERR;
	ret = poll((struct pollfd *)&fds, 1, usecs);
	return ret;
#elif _WINDOWS_
	fd_set rfds;
	struct timeval tv;
	int retval;
	if (fd==-1)
		return -1;

	FD_ZERO(&rfds);
	FD_SET(fd, &rfds);
	tv.tv_sec = secs;
	tv.tv_usec = usecs;

	retval = select(1, &rfds, NULL, NULL, &tv);
	if (retval==-1)
		return -1;
	return FD_ISSET(0, &rfds);
#else
	return 1; /* always ready if unknown */
#endif
}

void r_socket_block(int fd, int block)
{
#if _UNIX_
	fcntl(fd, F_SETFL, O_NONBLOCK, !block);
#elif _WINDOWS_
	ioctlsocket(fd, FIONBIO, (u_long FAR*)&block);
#endif
}

void r_socket_printf(int fd, const char *fmt, ...)
{
#if !__linux__
	char buf[BUFFER_SIZE];
#endif
	va_list ap;
	va_start(ap, fmt);

	if (fd <= 0)
		return;
#if __linux__
	dprintf(fd, fmt, ap); 
#else
	snprintf(buf,BUFFER_SIZE,fmt,ap); 
	socket_write(fd, buf, strlen(buf));
#endif
	
	va_end(ap);
}

#if __UNIX__
int r_socket_unix_connect(char *file)
{
	struct sockaddr_un addr;
	int sock;

	sock = socket(PF_UNIX, SOCK_STREAM, 0);
	if (sock <0)
		return -1;
	// TODO: set socket options
	addr.sun_family = AF_UNIX;
	strncpy (addr.sun_path, file, sizeof(addr.sun_path));

	if (connect(sock, (struct sockaddr *)&addr, sizeof(addr))==-1) {
		close(sock);
		return -1;
	}

	return sock;
}

int r_socket_unix_listen(const char *file)
{
	struct sockaddr_un unix_name;
	int sock;

	sock = socket(PF_UNIX, SOCK_STREAM, 0);
	if (sock <0)
		return -1;
	// TODO: set socket options
	unix_name.sun_family = AF_UNIX;
	strncpy (unix_name.sun_path, file, sizeof(unix_name.sun_path));

	/* just to make sure there is no other socket file */
	unlink (unix_name.sun_path);

	if (bind (sock, (struct sockaddr *) &unix_name, sizeof (unix_name)) < 0)
		return -1;

	/* change permissions */
	if (chmod (unix_name.sun_path, 0777) != 0)
		return -1;

	if (listen(sock, 1))
		return -1;
	
	return sock;
}
#endif

int r_socket_connect(char *host, int port)
{
	struct sockaddr_in sa;
	struct hostent *he;
	int s;

#if __WINDOWS__
	WSADATA wsadata;
	if (WSAStartup(MAKEWORD(1,1), &wsadata) == SOCKET_ERROR) {
		eprintf("Error creating socket.");
		return -1;
	}
#endif

#if __UNIX__
	signal(SIGPIPE, SIG_IGN);
#endif
	s = socket(AF_INET, SOCK_STREAM, 0);
	if (s == -1)
		return -1;

	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	he = (struct hostent *)gethostbyname( host );
	if (he == (struct hostent*)0)
		return -1;

	sa.sin_addr = *((struct in_addr *)he->h_addr);
	sa.sin_port = htons( port );

	if (connect(s, (const struct sockaddr*)&sa, sizeof(struct sockaddr)))
		return -1;

	return s;
}

int r_socket_listen(int port)
{
	int s;
	int ret;
	struct sockaddr_in sa;
	struct linger linger = { 0 };
	linger.l_onoff = 1;
	linger.l_linger = 1;

 	s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (s <0)
		return -1;

	setsockopt(s, 
		SOL_SOCKET, SO_LINGER, (const char *) &linger, sizeof(linger));

	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = htonl(INADDR_ANY);
	sa.sin_port = htons( port );

	ret = bind(s, (struct sockaddr *)&sa, sizeof(sa));
	if (ret < 0)
		return -1;

	ret = listen(s, 1);
	if (ret < 0)
		return -1;
	
	return s;
}

int r_socket_close(int fd)
{
#if __UNIX__
	shutdown(fd, SHUT_RDWR);
	return close(fd);
#else
	WSACleanup();
	return closesocket(fd);
#endif
}

int r_socket_read(int fd, unsigned char *buf, int len)
{
#if __UNIX__
	return read(fd, buf, len);
#else
	return recv(fd, buf, len, 0);
#endif
}

int r_socket_accept(int fd)
{
	return accept(fd, NULL, NULL);
}

int r_socket_flush(int fd)
{
	/* TODO */
}


int r_socket_fgets(int fd, char *buf,  int size)
{
	int i = 0;
	int ret = 0;

	if (fd == -1)
		return -1;

	while(i<size-1) {
		ret = r_socket_read(fd, (u8 *)buf+i, 1);
		if (ret==0)
			return -1;
		if (ret<0) {
			r_socket_close(fd);
			return -1;
		}
		if (buf[i]=='\r'||buf[i]=='\n')
			break;
		i+=ret;
	}
	buf[i]='\0';

	return ret;
}
