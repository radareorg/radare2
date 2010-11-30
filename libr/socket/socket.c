/* radare - LGPL - Copyright 2006-2010 pancake<nopcode.org> */

#define USE_SOCKETS

#include <errno.h>
#include <r_types.h>
#include <r_socket.h>
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

R_API int r_socket_write(int fd, void *buf, int len) {
	int ret, delta = 0;
	for (;;) {
		ret = send (fd, buf+delta, len, 0);
		if (ret == 0)
			return -1;
		if (ret == len)
			return len;
		if (ret<0)
			break;
		delta += ret;
		len -= ret;
	}
	if (ret == -1)
		return -1;
	return delta;
}

R_API int r_socket_puts(int fd, char *buf) {
	return r_socket_write (fd, buf, strlen (buf));
}

// XXX: rewrite it to use select //
/* waits secs until new data is received.     */
/* returns -1 on error, 0 is false, 1 is true */
R_API int r_socket_ready(int fd, int secs, int usecs) {
#if __UNIX__
	int ret;
	struct pollfd fds[1];
	fds[0].fd = fd;
	fds[0].events = POLLIN|POLLPRI;
	fds[0].revents = POLLNVAL|POLLHUP|POLLERR;
	ret = poll((struct pollfd *)&fds, 1, usecs);
	return ret;
#elif __WINDOWS__
	fd_set rfds;
	struct timeval tv;
	int retval;
	if (fd==-1)
		return -1;
	FD_ZERO(&rfds);
	FD_SET(fd, &rfds);
	tv.tv_sec = secs;
	tv.tv_usec = usecs;
	if (select (1, &rfds, NULL, NULL, &tv) == -1)
		return -1;
	return FD_ISSET (0, &rfds);
#else
	return R_TRUE; /* always ready if unknown */
#endif
}

R_API void r_socket_block(int fd, int block) {
#if __UNIX__
	fcntl (fd, F_SETFL, O_NONBLOCK, !block);
#elif __WINDOWS__
	ioctlsocket (fd, FIONBIO, (u_long FAR*)&block);
#endif
}

R_API void r_socket_printf(int fd, const char *fmt, ...) {
	char buf[BUFFER_SIZE];
	va_list ap;
	if (fd >= 0) {
		va_start (ap, fmt);
		vsnprintf (buf, BUFFER_SIZE, fmt, ap); 
		r_socket_write (fd, buf, strlen(buf));
		va_end (ap);
	}
}

#if __UNIX__
R_API int r_socket_unix_connect(const char *file) {
	struct sockaddr_un addr;
	int sock = socket (PF_UNIX, SOCK_STREAM, 0);
	if (sock <0)
		return -1;
	// TODO: set socket options
	addr.sun_family = AF_UNIX;
	strncpy (addr.sun_path, file, sizeof(addr.sun_path));

	if (connect (sock, (struct sockaddr *)&addr, sizeof(addr))==-1) {
		close (sock);
		return -1;
	}
	return sock;
}

R_API int r_socket_unix_listen(const char *file) {
	struct sockaddr_un unix_name;
	int sock = socket (PF_UNIX, SOCK_STREAM, 0);
	if (sock <0)
		return -1;
	// TODO: set socket options
	unix_name.sun_family = AF_UNIX;
	strncpy (unix_name.sun_path, file, sizeof(unix_name.sun_path));

	/* just to make sure there is no other socket file */
	unlink (unix_name.sun_path);

	if (bind (sock, (struct sockaddr *) &unix_name, sizeof (unix_name)) < 0) {
		close (sock);
		return -1;
	}
	signal (SIGPIPE, SIG_IGN);

	/* change permissions */
	if (chmod (unix_name.sun_path, 0777) != 0) {
		close (sock);
		return -1;
	}
	if (listen (sock, 1)) {
		close (sock);
		return -1;
	}
	return sock;
}
#endif

R_API int r_socket_connect(char *host, int port) {
	struct sockaddr_in sa;
	struct hostent *he;
	int s;
#if __WINDOWS__
	WSADATA wsadata;
	if (WSAStartup (MAKEWORD(1,1), &wsadata) == SOCKET_ERROR) {
		eprintf ("Error creating socket.");
		return -1;
	}
#elif __UNIX__
	signal (SIGPIPE, SIG_IGN);
#endif
	s = socket (AF_INET, SOCK_STREAM, 0);
	if (s == -1)
		return -1;

	memset (&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	he = (struct hostent *)gethostbyname (host);
	if (he == (struct hostent*)0) {
		close (s);
		return -1;
	}

	sa.sin_addr = *((struct in_addr *)he->h_addr);
	sa.sin_port = htons( port );

	if (connect (s, (const struct sockaddr*)&sa, sizeof (struct sockaddr))) {
		close (s);
		return -1;
	}
	return s;
}

R_API int r_socket_listen(int port) {
	int s;
	struct sockaddr_in sa;
	struct linger linger = { 0 };

 	if ((s = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP))<0)
		return -1;
	linger.l_onoff = 1;
	linger.l_linger = 1;
	setsockopt (s, SOL_SOCKET, SO_LINGER, (const char *) &linger, sizeof (linger));
	memset (&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = htonl(INADDR_ANY);
	sa.sin_port = htons (port);

	if (bind (s, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		close (s);
		return -1;
	}
	if (listen (s, 1) < 0) {
		close (s);
		return -1;
	}
	return s;
}

R_API int r_socket_close(int fd) {
#if __WINDOWS__
	WSACleanup ();
	return closesocket (fd);
#else
	shutdown (fd, SHUT_RDWR);
	return close (fd);
#endif
}

R_API int r_socket_read_block(int fd, unsigned char *buf, int len) {
	int r, ret = 0;
	for (ret=0;ret<len;) {
		r = r_socket_read (fd, buf+ret, len-ret);
		if (r==-1)
			break;
		ret += r;
	}
	return ret;
}

R_API int r_socket_read(int fd, unsigned char *buf, int len) {
#if __WINDOWS__
	return recv (fd, (void *)buf, len, 0);
#else
	return read (fd, buf, len);
#endif
}

R_API int r_socket_accept(int fd) {
	return accept (fd, NULL, NULL);
}

R_API int r_socket_flush(int fd) {
	/* TODO */
	return 0;
}

R_API int r_socket_gets(int fd, char *buf,  int size) {
	int i = 0;
	int ret = 0;

	if (fd == -1)
		return -1;

	while (i<size) {
		ret = r_socket_read (fd, (ut8 *)buf+i, 1);
		if (ret==0)
			break;
		if (ret<0) {
			r_socket_close (fd);
			return i;
		}
		if (buf[i]=='\r'||buf[i]=='\n') {
			buf[i]='\0';
			break;
		}
		i += ret;
	}
	buf[i]='\0';

	return i;
}

R_API char *r_socket_to_string(int fd) {
#if __WINDOWS__
	char *str = malloc (32);
	snprintf (str, sizeof (str), "fd%d", fd);
	return str;
#elif __UNIX__
	char *str = NULL;
	struct sockaddr sa;
	socklen_t sl = sizeof (sa);
	memset (&sa, 0, sizeof (sa));
	if (!getpeername (fd, &sa, &sl)) {
		struct sockaddr_in *sain = (struct sockaddr_in*) &sa;
		ut8 *a = (ut8*) &(sain->sin_addr);
		if ((str = malloc (32)))
			sprintf (str, "%d.%d.%d.%d:%d",
				a[0],a[1],a[2],a[3], ntohs (sain->sin_port));
	} else eprintf ("getperrname: failed\n"); //r_sys_perror ("getpeername");
	return str;
#else
	return NULL;
#endif
}

R_API int r_socket_udp_connect(const char *host, int port) {
	struct sockaddr_in sa;
	struct hostent *he;
	int s;

#if __WINDOWS__
	WSADATA wsadata;
	if (WSAStartup (MAKEWORD (1,1), &wsadata) == SOCKET_ERROR) {
		eprintf ("Error creating socket.");
		return -1;
	}
#elif __UNIX__
	signal (SIGPIPE, SIG_IGN);
#endif
	s = socket (AF_INET, SOCK_DGRAM, 0);
	if (s == -1)
		return -1;

	memset (&sa, 0, sizeof (sa));
	sa.sin_family = AF_INET;
	he = (struct hostent *)gethostbyname (host);
	if (he == (struct hostent*)0) {
		close (s);
		return -1;
	}

	sa.sin_addr = *((struct in_addr *)he->h_addr);
	sa.sin_port = htons( port );

	if (connect (s, (const struct sockaddr*)&sa, sizeof (struct sockaddr))) {
		close (s);
		return -1;
	}

	return s;
}
