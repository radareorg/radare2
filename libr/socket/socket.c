/* radare - LGPL - Copyright 2006-2012 - pancake */

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
//#include <sys/fcntl.h>
#endif

#define BUFFER_SIZE 4096

#if __UNIX__
static int r_socket_unix_connect(RSocket *s, const char *file) {
	struct sockaddr_un addr;
	int sock = socket (PF_UNIX, SOCK_STREAM, 0);
	if (sock < 0) {
		free (s);
		return R_FALSE;
	}
	// TODO: set socket options
	addr.sun_family = AF_UNIX;
	strncpy (addr.sun_path, file, sizeof (addr.sun_path)-1);

	if (connect (sock, (struct sockaddr *)&addr, sizeof(addr))==-1) {
		close (sock);
		free (s);
		return R_FALSE;
	}
	s->fd = sock;
	s->is_ssl = R_FALSE;
	return R_TRUE;
}

R_API int r_socket_unix_listen (RSocket *s, const char *file) {
	struct sockaddr_un unix_name;
	int sock = socket (PF_UNIX, SOCK_STREAM, 0);
	if (sock <0)
		return R_FALSE;
	// TODO: set socket options
	unix_name.sun_family = AF_UNIX;
	strncpy (unix_name.sun_path, file, sizeof (unix_name.sun_path)-1);

	/* just to make sure there is no other socket file */
	unlink (unix_name.sun_path);

	if (bind (sock, (struct sockaddr *) &unix_name, sizeof (unix_name)) < 0) {
		close (sock);
		return R_FALSE;
	}
	signal (SIGPIPE, SIG_IGN);

	/* change permissions */
	if (chmod (unix_name.sun_path, 0777) != 0) {
		close (sock);
		return R_FALSE;
	}
	if (listen (sock, 1)) {
		close (sock);
		return R_FALSE;
	}
	s->fd = sock;
	return R_TRUE;
}
#endif

R_API RSocket *r_socket_new (int is_ssl) {
	RSocket *s = R_NEW (RSocket);
	s->is_ssl = is_ssl;
#if __UNIX_
	signal (SIGPIPE, SIG_IGN);
#endif
	s->local = 0;
#if HAVE_LIB_SSL
	if (is_ssl) {
		s->sfd = NULL;
		s->ctx = NULL;
		s->bio = NULL;
		s->fd = -1;
		if (!SSL_library_init ()) {
			r_socket_free (s);
			return NULL;
		}
		SSL_load_error_strings ();
	}
#endif
	return s;
}

R_API int r_socket_connect (RSocket *s, const char *host, const char *port, int proto, int timeout) {
#if __WINDOWS__
	struct sockaddr_in sa;
	struct hostent *he;
	WSADATA wsadata;
	if (WSAStartup (MAKEWORD (1, 1), &wsadata) == SOCKET_ERROR) {
		eprintf ("Error creating socket.");
		return R_FALSE;
	}
	s->fd = socket (AF_INET, SOCK_STREAM, 0);
	if (s->fd == -1)
		return R_FALSE;

	memset (&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	he = (struct hostent *)gethostbyname (host);
	if (he == (struct hostent*)0) {
		close (s->fd);
		return R_FALSE;
	}

	sa.sin_addr = *((struct in_addr *)he->h_addr);
	sa.sin_port = htons (atoi (port));
#warning TODO: implement connect timeout on w32
	if (connect (s->fd, (const struct sockaddr*)&sa, sizeof (struct sockaddr))) {
		close (s->fd);
		return R_FALSE;
	}
	return R_TRUE;
#elif __UNIX__
	if (proto==0) proto= R_SOCKET_PROTO_TCP;
	int gai, ret;
	struct addrinfo hints, *res, *rp;
	signal (SIGPIPE, SIG_IGN);
	if (proto == R_SOCKET_PROTO_UNIX) {
		if (!r_socket_unix_connect (s, host))
			return R_FALSE;
	} else {
		memset (&hints, 0, sizeof (struct addrinfo));
		hints.ai_family = AF_UNSPEC; /* Allow IPv4 or IPv6 */
		hints.ai_protocol = proto;
		gai = getaddrinfo (host, port, &hints, &res);
		if (gai != 0) {
			//eprintf ("Error in getaddrinfo: %s\n", gai_strerror (gai));
			return R_FALSE;
		}
		for (rp = res; rp != NULL; rp = rp->ai_next) {
			s->fd = socket (rp->ai_family, rp->ai_socktype, rp->ai_protocol);
			if (s->fd == -1)
				continue;
			if (timeout>0)
				fcntl (s->fd, F_SETFL, O_NONBLOCK, 1);
			ret = connect (s->fd, rp->ai_addr, rp->ai_addrlen);
			if (timeout<1 && ret != -1)
				break;
			if (timeout>0) {
				struct timeval tv;
				fd_set fdset;
				FD_ZERO (&fdset);
				FD_SET (s->fd, &fdset);
				tv.tv_sec = timeout;
				tv.tv_usec = 0;
				if (select (s->fd + 1, NULL, &fdset, NULL, &tv) == 1) {
					int so_error;
					socklen_t len = sizeof so_error;
					ret = getsockopt (s->fd, SOL_SOCKET, SO_ERROR, &so_error, &len);
					fcntl (s->fd, F_SETFL, O_NONBLOCK, 0);
				} else {
					close (s->fd);
					return R_FALSE;
				}
			}
			//rp = NULL;
			close (s->fd);
			s->fd = -1;
		}
		freeaddrinfo (res);
		if (rp == NULL) {
			//eprintf ("Could not connect\n");
			return R_FALSE;
		}
	}
#endif
#if HAVE_LIB_SSL
	if (s->is_ssl) {
		s->ctx = SSL_CTX_new (SSLv23_client_method ());
		if (s->ctx == NULL) {
			r_socket_free (s);
			return R_FALSE;
		}
		s->sfd = SSL_new (s->ctx);
		SSL_set_fd (s->sfd, s->fd);
		if (SSL_connect (s->sfd) != 1) {
			r_socket_free (s);
			return R_FALSE;
		}
	}
#endif
	return R_TRUE;
}

R_API int r_socket_close (RSocket *s) {
	int ret = R_FALSE;
	if (!s) return R_FALSE;
	if (s->fd != -1) {
#if __WINDOWS__
		WSACleanup ();
		ret = closesocket (s->fd);
#else
		shutdown (s->fd, SHUT_RDWR);
		ret = close (s->fd);
#endif
	}
#if HAVE_LIB_SSL
	if (s->is_ssl && s->sfd)
		SSL_shutdown (s->sfd);
#endif
	return ret;
}

R_API int r_socket_free (RSocket *s) {
	int res = r_socket_close (s);
#if HAVE_LIB_SSL
	if (s->is_ssl) {
		if (s->sfd)
			SSL_free (s->sfd);
		if (s->ctx)
			SSL_CTX_free (s->ctx);
	}
#endif
	free (s);
	return res;
}

R_API int r_socket_listen (RSocket *s, const char *port, const char *certfile) {
	int optval = 1;
	struct sockaddr_in sa;
	struct linger linger = { 0 };

	if ((s->fd = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP))<0)
		return R_FALSE;
	linger.l_onoff = 1;
	linger.l_linger = 1;
	setsockopt (s->fd, SOL_SOCKET, SO_LINGER, (const char *)&linger, sizeof (linger));
	setsockopt(s->fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof optval);
	memset (&sa, 0, sizeof (sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = htonl (s->local? INADDR_LOOPBACK: INADDR_ANY);
	sa.sin_port = htons (atoi (port)); // WTF we should honor etc/services

	if (bind (s->fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		close (s->fd);
		return R_FALSE;
	}
#if __UNIX_
	signal (SIGPIPE, SIG_IGN);
#endif
	if (listen (s->fd, 1) < 0) {
		close (s->fd);
		return R_FALSE;
	}
#if HAVE_LIB_SSL
	if (s->is_ssl) {
		s->ctx = SSL_CTX_new (SSLv23_method ());
		if (s->ctx == NULL) {
			r_socket_free (s);
			return R_FALSE;
		}
		if (!SSL_CTX_use_certificate_chain_file (s->ctx, certfile)) {
			r_socket_free (s);
			return R_FALSE;
		}
		if (!SSL_CTX_use_PrivateKey_file (s->ctx, certfile, SSL_FILETYPE_PEM)) {
			r_socket_free (s);
			return R_FALSE;
		}
		SSL_CTX_set_verify_depth (s->ctx, 1);
	}
#endif
	return R_TRUE;
}

R_API RSocket *r_socket_accept(RSocket *s) {
	RSocket *sock;
	if (!s) return NULL;
	sock = R_NEW (RSocket);
	if (!sock) return NULL;
	sock->is_ssl = s->is_ssl;
	sock->fd = accept (s->fd, NULL, NULL);
	if (sock->fd == -1) {
		free (sock);
		return NULL;
	}
#if HAVE_LIB_SSL
	if (sock->is_ssl) {
		sock->sfd = NULL;
		sock->ctx = NULL;
		sock->bio = NULL;
		BIO *sbio = BIO_new_socket (sock->fd, BIO_NOCLOSE);
		sock->sfd = SSL_new (s->ctx);
		SSL_set_bio (sock->sfd, sbio, sbio);
		if (SSL_accept (sock->sfd) <= 0) {
			r_socket_free (sock);
			return NULL;
		}
		sock->bio = BIO_new (BIO_f_buffer ());
		sbio = BIO_new (BIO_f_ssl ());
		BIO_set_ssl (sbio, sock->sfd, BIO_CLOSE);
		BIO_push (sock->bio, sbio);
	}
#endif
	return sock;
}

R_API int r_socket_block_time (RSocket *s, int block, int sec) {
	struct timeval sv;
#if __UNIX__
	fcntl (s->fd, F_SETFL, O_NONBLOCK, !block);
#elif __WINDOWS__
	ioctlsocket (s->fd, FIONBIO, (u_long FAR*)&block);
#endif
	if (sec > 0) {
		sv.tv_sec = sec;
		sv.tv_usec = 0;
		if (setsockopt (s->fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&sv, sizeof (sv)) < 0)
			return R_FALSE;
	}
	return R_TRUE;
}

R_API int r_socket_flush(RSocket *s) {
#if HAVE_LIB_SSL
	if (s->is_ssl && s->bio)
		return BIO_flush(s->bio);
#endif
	return R_TRUE;
}

// XXX: rewrite it to use select //
/* waits secs until new data is received.     */
/* returns -1 on error, 0 is false, 1 is true */
R_API int r_socket_ready(RSocket *s, int secs, int usecs) {
#if __UNIX__
	struct pollfd fds[1];
	fds[0].fd = s->fd;
	fds[0].events = POLLIN|POLLPRI;
	fds[0].revents = POLLNVAL|POLLHUP|POLLERR;
	return poll((struct pollfd *)&fds, 1, usecs);
#elif __WINDOWS__
	fd_set rfds;
	struct timeval tv;
	if (s->fd==-1)
		return -1;
	FD_ZERO (&rfds);
	FD_SET (s->fd, &rfds);
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

/* Read/Write functions */
R_API int r_socket_write(RSocket *s, void *buf, int len) {
	int ret, delta = 0;
	for (;;) {
#if HAVE_LIB_SSL
		if (s->is_ssl)
			if (s->bio)
				ret = BIO_write (s->bio, buf+delta, len);
			else
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
	if (!s) return -1;
#if HAVE_LIB_SSL
	if (s->is_ssl)
		if (s->bio)
			return BIO_read (s->bio, buf, len);
		else
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

R_API RSocket *r_socket_new_from_fd (int fd) {
	RSocket *s = R_NEW0 (RSocket);
	s->fd = fd;
	return s;
}
