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

R_API RSocket *r_socket_new (const char *host, int port, int is_ssl) {
	RSocket *s = R_NEW (RSocket);
	s->is_ssl = is_ssl;
	if ((s->fd = r_socket_connect (host, port)) < 0)
		return NULL;
	if (is_ssl) {
		s->sfd = NULL;
		s->ctx = NULL;
#ifdef HAVE_LIB_SSL
		if (!SSL_library_init ())
			return NULL;
		SSL_load_error_strings ();
		s->ctx = SSL_CTX_new (SSLv23_client_method ());
		if (s->ctx == NULL)
			return NULL;
		s->sfd = SSL_new (s->ctx);
		SSL_set_fd (s->sfd, s->fd);
		if (SSL_connect (s->sfd) != 1)
			return NULL;
#endif
	}
	return s;
}

R_API void r_socket_free (RSocket *s) {
	r_socket_close (s);
	free (s);
}

#if __UNIX__
R_API RSocket *r_socket_unix_connect(const char *file) {
	RSocket *s = R_NEW (RSocket);
	struct sockaddr_un addr;
	int sock = socket (PF_UNIX, SOCK_STREAM, 0);
	if (sock < 0)
		return NULL;
	// TODO: set socket options
	addr.sun_family = AF_UNIX;
	strncpy (addr.sun_path, file, sizeof(addr.sun_path));

	if (connect (sock, (struct sockaddr *)&addr, sizeof(addr))==-1) {
		close (sock);
		return NULL;
	}
	s->fd =sock;
	s->is_ssl = R_FALSE;
	return s;
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

R_API int r_socket_connect(const char *host, int port) {
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

R_API RSocket *r_socket_listen(int port) {
	RSocket *s;
	int fd;
	struct sockaddr_in sa;
	struct linger linger = { 0 };

	if ((fd = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP))<0)
		return NULL;
	linger.l_onoff = 1;
	linger.l_linger = 1;
	setsockopt (fd, SOL_SOCKET, SO_LINGER, (const char *) &linger, sizeof (linger));
	memset (&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = htonl(INADDR_ANY);
	sa.sin_port = htons (port);

	if (bind (fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		close (fd);
		return NULL;
	}
#if __UNIX_
	signal (SIGPIPE, SIG_IGN);
#endif
	if (listen (fd, 1) < 0) {
		close (fd);
		return NULL;
	}
	s = R_NEW (RSocket);
	s->fd = fd;
	s->is_ssl = R_FALSE;
	return s;
}

R_API void r_socket_block(RSocket *s, int block) {
#if __UNIX__
	fcntl (s->fd, F_SETFL, O_NONBLOCK, !block);
#elif __WINDOWS__
	ioctlsocket (s->fd, FIONBIO, (u_long FAR*)&block);
#endif
}

//TODO: Support SSL
R_API RSocket *r_socket_accept(RSocket *s) {
	RSocket *sock = R_NEW (RSocket);
	sock->is_ssl = R_FALSE;
	sock->fd = accept (s->fd, NULL, NULL);
	return sock;
}

R_API int r_socket_flush(RSocket *s) {
	/* TODO */
	return 0;
}

R_API int r_socket_close(RSocket *s) {
	int ret;

#if __WINDOWS__
	WSACleanup ();
	ret = closesocket (s->fd);
#else
	shutdown (s->fd, SHUT_RDWR);
	ret = close (s->fd);
#endif
#ifdef HAVE_LIB_SSL
	if (s->is_ssl) {
		SSL_shutdown (s->sfd);
		SSL_free (s->sfd);
		SSL_CTX_free (s->ctx);
	}
#endif
	return ret;
}

// XXX: rewrite it to use select //
/* waits secs until new data is received.     */
/* returns -1 on error, 0 is false, 1 is true */
R_API int r_socket_ready(RSocket *s, int secs, int usecs) {
#if __UNIX__
	int ret;
	struct pollfd fds[1];
	fds[0].fd = s->fd;
	fds[0].events = POLLIN|POLLPRI;
	fds[0].revents = POLLNVAL|POLLHUP|POLLERR;
	ret = poll((struct pollfd *)&fds, 1, usecs);
	return ret;
#elif __WINDOWS__
	fd_set rfds;
	struct timeval tv;
	int retval;
	if (s->fd==-1)
		return -1;
	FD_ZERO(&rfds);
	FD_SET(s->fd, &rfds);
	tv.tv_sec = secs;
	tv.tv_usec = usecs;
	if (select (1, &rfds, NULL, NULL, &tv) == -1)
		return -1;
	return FD_ISSET (0, &rfds);
#else
	return R_TRUE; /* always ready if unknown */
#endif
}

R_API char *r_socket_to_string(RSocket *s) {
#if __WINDOWS__
	char *str = malloc (32);
	snprintf (str, sizeof (str), "fd%d", s->fd);
	return str;
#elif __UNIX__
	char *str = NULL;
	struct sockaddr sa;
	socklen_t sl = sizeof (sa);
	memset (&sa, 0, sizeof (sa));
	if (!getpeername (s->fd, &sa, &sl)) {
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

//XXX: Merge with r_new
R_API RSocket *r_socket_udp_connect(const char *host, int port, int is_ssl) {
	struct sockaddr_in sa;
	struct hostent *he;
	int s;
	RSocket *sock = R_NEW (RSocket);

	sock->is_ssl = is_ssl;
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
		return NULL;

	memset (&sa, 0, sizeof (sa));
	sa.sin_family = AF_INET;
	he = (struct hostent *)gethostbyname (host);
	if (he == (struct hostent*)0) {
		close (s);
		return NULL;
	}

	sa.sin_addr = *((struct in_addr *)he->h_addr);
	sa.sin_port = htons( port );

	if (connect (s, (const struct sockaddr*)&sa, sizeof (struct sockaddr))) {
		close (s);
		return NULL;
	}
	sock->fd = s;
	if (is_ssl) {
		sock->sfd = NULL;
		sock->ctx = NULL;
#ifdef HAVE_LIB_SSL
		if (!SSL_library_init ())
			return NULL;
		SSL_load_error_strings ();
		sock->ctx = SSL_CTX_new (SSLv23_client_method ());
		if (sock->ctx == NULL)
			return NULL;
		sock->sfd = SSL_new (sock->ctx);
		SSL_set_fd (sock->sfd, sock->fd);
		if (SSL_connect (sock->sfd) != 1)
			return NULL;
#endif
	}
	return sock;
}

/* Read/Write functions */
R_API int r_socket_write(RSocket *s, void *buf, int len) {
	int ret, delta = 0;
	for (;;) {
#ifdef HAVE_LIB_SSL
		if (s->is_ssl)
			ret = SSL_write (s->sfd, buf+delta, len);
		else
#endif
			ret = send (s->fd, buf+delta, len, 0);
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

R_API int r_socket_puts(RSocket *s, char *buf) {
	return r_socket_write (s, buf, strlen (buf));
}

R_API void r_socket_printf(RSocket *s, const char *fmt, ...) {
	char buf[BUFFER_SIZE];
	va_list ap;
	if (s->fd >= 0) {
		va_start (ap, fmt);
		vsnprintf (buf, BUFFER_SIZE, fmt, ap);
		r_socket_write (s, buf, strlen(buf));
		va_end (ap);
	}
}

R_API int r_socket_read(RSocket *s, unsigned char *buf, int len) {
#ifdef HAVE_LIB_SSL
	if (s->is_ssl)
		return SSL_read (s->sfd, buf, len);
	else
#endif
#if __WINDOWS__
	return recv (s->fd, (void *)buf, len, 0);
#else
	return read (s->fd, buf, len);
#endif
}

R_API int r_socket_read_block(RSocket *s, unsigned char *buf, int len) {
	int r, ret = 0;
	for (ret=0;ret<len;) {
		r = r_socket_read (s, buf+ret, len-ret);
		if (r==-1)
			break;
		ret += r;
	}
	return ret;
}

R_API int r_socket_gets(RSocket *s, char *buf,  int size) {
	int i = 0;
	int ret = 0;

	if (s->fd == -1)
		return -1;

	while (i<size) {
		ret = r_socket_read (s, (ut8 *)buf+i, 1);
		if (ret==0)
			break;
		if (ret<0) {
			r_socket_close (s);
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
