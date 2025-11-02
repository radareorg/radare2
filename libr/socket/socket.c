/* radare - LGPL - Copyright 2006-2025 - pancake */

/* must be included first because of winsock2.h and windows.h */
#include <r_socket.h>
#include <r_types.h>
#include <r_util.h>
#include <errno.h>

#if __linux__
#include "i/isotp.h"
#endif

#if EMSCRIPTEN || __wasi__ || defined(__serenity__) || defined(__MINGW32__)
#define NETWORK_DISABLED 1
#else
#define NETWORK_DISABLED 0
#endif

R_LIB_VERSION(r_socket);

#if NETWORK_DISABLED
/* no network */
R_API RSocket *r_socket_new(bool is_ssl) {
	return NULL;
}
R_API bool r_socket_is_connected(RSocket *s) {
	return false;
}
R_API bool r_socket_connect(RSocket *s, const char *host, const char *port, int proto, unsigned int timeout) {
	return false;
}
R_API bool r_socket_spawn(RSocket *s, const char *cmd, unsigned int timeout) {
	return -1;
}
R_API bool r_socket_close_fd(RSocket *s) {
	return false;
}
R_API bool r_socket_close(RSocket *s) {
	return false;
}
R_API void r_socket_free(RSocket *s) {
}
R_API int r_socket_port_by_name(const char *name) {
	return -1;
}
R_API bool r_socket_listen(RSocket *s, const char *port, const char *certfile) {
	return false;
}
R_API RSocket *r_socket_accept(RSocket *s) {
	return NULL;
}
R_API RSocket *r_socket_accept_timeout(RSocket *s, unsigned int timeout) {
	return NULL;
}
R_API bool r_socket_block_time(RSocket *s, bool block, int sec, int usec) {
	return false;
}
R_API int r_socket_flush(RSocket *s) {
	return -1;
}
R_API int r_socket_ready(RSocket *s, int secs, int usecs) {
	return -1;
}
R_API char *r_socket_tostring(RSocket *s) {
	return NULL;
}
R_API int r_socket_write(RSocket *s, const void *buf, int len) {
	return -1;
}
R_API int r_socket_puts(RSocket *s, char *buf) {
	return -1;
}
R_API void r_socket_printf(RSocket *s, const char *fmt, ...) {
	/* nothing here */
}
R_API int r_socket_read(RSocket *s, unsigned char *buf, int len) {
	return -1;
}
R_API int r_socket_read_block(RSocket *s, unsigned char *buf, int len) {
	return -1;
}
R_API int r_socket_gets(RSocket *s, char *buf,	int size) {
	return -1;
}
R_API RSocket *r_socket_new_from_fd(int fd) {
	return NULL;
}
R_API ut8* r_socket_slurp(RSocket *s, int *len) {
	return NULL;
}
#else

R_API bool r_socket_is_connected(RSocket *s) {
	if (!r_sandbox_check (R_SANDBOX_GRAIN_SOCKET)) {
		return false;
	}
#if R2__WINDOWS__
	char buf[2];
	r_socket_block_time (s, false, 0, 0);
#ifdef _MSC_VER
	int ret = recv (s->fd, (char*)&buf, 1, MSG_PEEK);
#else
	ssize_t ret = recv (s->fd, (char*)&buf, 1, MSG_PEEK);
#endif
	r_socket_block_time (s, true, 0, 0);
	return ret == 1;
#else
	int error = 0;
	socklen_t len = sizeof (error);
	int ret = getsockopt (s->fd, SOL_SOCKET, SO_ERROR, &error, &len);
	if (ret != 0) {
		r_sys_perror ("getsockopt");
		return false;
	}
	return (error == 0);
#endif
}

#if R2__UNIX__
static bool __connect_unix(RSocket *s, const char *file) {
	struct sockaddr_un addr;
	int sock = socket (PF_UNIX, SOCK_STREAM, 0);
	if (sock < 0) {
		return false;
	}
	// TODO: set socket options
	addr.sun_family = AF_UNIX;
	strncpy (addr.sun_path, file, sizeof (addr.sun_path) - 1);

	if (connect (sock, (struct sockaddr *)&addr, sizeof (addr)) == -1) {
		close (sock);
		return false;
	}
	s->fd = sock;
	s->is_ssl = false;
	return true;
}

static bool __listen_unix(RSocket *s, const char *file) {
	struct sockaddr_un unix_name;
	int sock = socket (PF_UNIX, SOCK_STREAM, 0);
	if (sock < 0) {
		return false;
	}
	// TODO: set socket options
	unix_name.sun_family = AF_UNIX;
	strncpy (unix_name.sun_path, file, sizeof (unix_name.sun_path)-1);

	/* just to make sure there is no other socket file */
	unlink (unix_name.sun_path);

	if (bind (sock, (struct sockaddr *) &unix_name, sizeof (unix_name)) < 0) {
		close (sock);
		return false;
	}
	r_sys_signal (SIGPIPE, SIG_IGN);

	/* change permissions */
	if (chmod (unix_name.sun_path, 0777) != 0) {
		close (sock);
		return false;
	}
	if (listen (sock, 1)) {
		close (sock);
		return false;
	}
	s->fd = sock;
	return true;
}
#endif

R_API RSocket *r_socket_new(bool is_ssl) {
	RSocket *s = R_NEW0 (RSocket);
	s->is_ssl = is_ssl;
	s->port = 0;
#if __UNIX_
	r_sys_signal (SIGPIPE, SIG_IGN);
#endif
	s->local = 0;
	s->fd = R_INVALID_SOCKET;
#if HAVE_LIB_SSL
	if (is_ssl) {
		s->sfd = NULL;
		s->ctx = NULL;
		s->bio = NULL;
#if OPENSSL_VERSION_NUMBER < 0x1010000fL
		if (!SSL_library_init ()) {
			r_socket_free (s);
			return NULL;
		}
		SSL_load_error_strings ();
#endif
	}
#endif
	return s;
}

R_API bool r_socket_spawn(RSocket *s, const char *cmd, unsigned int timeout) {
	if (!r_sandbox_check (R_SANDBOX_GRAIN_EXEC)) {
		return false;
	}
	// XXX TODO: dont use sockets, we can achieve the same with pipes
	const int port = 2000 + r_num_rand (2000);
	int childPid = r_sys_fork ();
	if (childPid == 0) {
		char *a = r_str_replace (strdup (cmd), "\\", "\\\\", true);
		int res = r_sys_cmdf ("rarun2 system=\"%s\" listen=%d", a, port);
		free (a);
#if 0
		// TODO: use the api
		char *profile = r_str_newf (
				"system=%s\n"
				"listen=%d\n", cmd, port);
		RRunProfile *rp = r_run_new (profile);
		if (!r_run_start (rp)) {
			R_LOG_ERROR ("r_run_start failed");
		}
		r_run_free (rp);
		free (profile);
#endif
		if (res != 0) {
			R_LOG_ERROR ("rarun2 has failed");
			exit (1);
		}
		R_LOG_ERROR ("r_socket_spawn: %s is dead", cmd);
		exit (0);
	}
	r_sys_sleep (1); // wait for the process to start listening.. <- thats a bottleneck
	r_sys_usleep (timeout);

	r_strf_var (aport, 32, "%d", port);
	// redirect stdin/stdout/stderr
	bool sock = r_socket_connect (s, "127.0.0.1", aport, R_SOCKET_PROTO_TCP, 2000);
	if (!sock) {
		return false;
	}
#if R2__UNIX__
	// unnecessary naps
	// r_sys_sleep (2);
	// r_sys_usleep (timeout);

	int status = 0;
	int ret = waitpid (childPid, &status, WNOHANG | WUNTRACED);
	if (ret != 0) {
		r_socket_close (s);
		return false;
	}
#endif
	return true;
}

R_API bool r_socket_connect(RSocket *s, const char *host, const char *port, int proto, unsigned int timeout) {
	R_RETURN_VAL_IF_FAIL (s, false);
#if R2__WINDOWS__
#define gai_strerror gai_strerrorA
	WSADATA wsadata;

	if (WSAStartup (MAKEWORD (1, 1), &wsadata) == SOCKET_ERROR) {
		R_LOG_ERROR ("WSAStartup failed");
		return false;
	}
#endif
	int ret;
	struct addrinfo hints = {0};
	struct addrinfo *res, *rp;
	if (proto == R_SOCKET_PROTO_NONE) {
		proto = R_SOCKET_PROTO_DEFAULT;
	}
#if R2__UNIX__
	r_sys_signal (SIGPIPE, SIG_IGN);
#endif
	if (proto == R_SOCKET_PROTO_UNIX) {
#if R2__UNIX__
		if (!__connect_unix (s, host)) {
			return false;
		}
#endif
	} else if (proto == R_SOCKET_PROTO_CAN) {
#if __linux__
		// host: can interface name
		// port: src and dst can identifiers
		ut32 srcid = 0;
		ut32 dstid = 0;
		sscanf (port, "0x%x/0x%x", &srcid, &dstid);
		// s = socket(PF_CAN, SOCK_RAW, CAN_RAW);
		int fd = socket (PF_CAN, SOCK_DGRAM, CAN_ISOTP);
		if (fd == -1) {
			return false;
		}
		struct can_isotp_options opts = {
			.txpad_content = 0xcc,
			.rxpad_content = 0xcc,
			.frame_txtime = 0x1000,
		};
		if (setsockopt (fd, SOL_CAN_ISOTP, CAN_ISOTP_OPTS, &opts, sizeof (opts)) == -1) {
			close (fd);
			return false;
		}
		struct can_isotp_fc_options fcopts = {
			.stmin = 0xf3
		};
		if (setsockopt (fd, SOL_CAN_ISOTP, CAN_ISOTP_RECV_FC, &fcopts, sizeof (fcopts)) == -1) {
			close (fd);
			return false;
		}
		struct can_isotp_ll_options llopts = {
			.mtu = 8,
			.tx_dl = 8,
		};
		if (setsockopt (fd, SOL_CAN_ISOTP, CAN_ISOTP_LL_OPTS, &llopts, sizeof (llopts)) == -1) {
			close (fd);
			return false;
		}

		struct ifreq ifr;
		memset (&ifr, 0, sizeof (ifr));
		r_str_ncpy (ifr.ifr_name, host, sizeof (ifr.ifr_name));
		if (ioctl (fd, SIOCGIFINDEX, &ifr) == -1) {
			r_sys_perror ("ioctl");
			close (fd);
			return -1;
		}

		struct sockaddr_can addr = {0};
		addr.can_family = AF_CAN;
		addr.can_ifindex = ifr.ifr_ifindex;
		addr.can_addr.tp.rx_id = srcid | 0x80000000;
		addr.can_addr.tp.tx_id = dstid | 0x80000000;

		if (bind (fd, (struct sockaddr *)&addr, sizeof (addr)) < 0) {
			r_sys_perror ("bind");
			close (fd);
			return false;
		}
		s->fd = fd;
		s->is_ssl = false;
		return true;
#else
		R_LOG_ERROR ("Unsupported ISOTP socket protocol");
		return false;
#endif
	} else {
		hints.ai_family = AF_UNSPEC; /* Allow IPv4 or IPv6 */
		hints.ai_protocol = proto;
		int gai = getaddrinfo (host, port, &hints, &res);
		if (gai != 0) {
			R_LOG_ERROR ("getaddrinfo: %s (%s:%s)",
				gai_strerror (gai), host, port);
			return false;
		}
		for (rp = res; rp; rp = rp->ai_next) {
			int flag = 1;

			s->fd = socket (rp->ai_family, rp->ai_socktype, rp->ai_protocol);
			if (s->fd == -1) {
				r_sys_perror ("socket");
				continue;
			}

			switch (proto) {
			case R_SOCKET_PROTO_TCP:
				ret = setsockopt (s->fd, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof (flag));
				if (ret < 0) {
					r_sys_perror ("setsockopt");
					close (s->fd);
					s->fd = -1;
					continue;
				}
				r_socket_block_time (s, true, 1, 0);
				ret = connect (s->fd, rp->ai_addr, rp->ai_addrlen);
				break;
			case R_SOCKET_PROTO_UDP:
				memset (&s->sa, 0, sizeof (s->sa));
				s->sa.sin_family = AF_INET;
				s->sa.sin_addr.s_addr = htonl (s->local? INADDR_LOOPBACK: INADDR_ANY);
				s->port = r_socket_port_by_name (port);
				if (s->port < 1) {
					continue;
				}
				s->sa.sin_port = htons (s->port);
				if (bind (s->fd, (struct sockaddr *)&s->sa, sizeof (s->sa)) < 0) {
					r_sys_perror ("bind");
#ifdef R2__WINDOWS__
					closesocket (s->fd);
#else
					close (s->fd);
#endif
					continue;
				}
				ret = connect (s->fd, rp->ai_addr, rp->ai_addrlen);
				break;
			default:
				r_socket_block_time (s, true, 1, 0);
				ret = connect (s->fd, rp->ai_addr, rp->ai_addrlen);
				break;
			}

			if (ret == 0) {
				freeaddrinfo (res);
				return true;
			}
			if (errno == EINPROGRESS) {
				struct timeval tv = {timeout, 0};
				fd_set wfds;
				FD_ZERO (&wfds);
				FD_SET (s->fd, &wfds);

				if ((ret = select (s->fd + 1, NULL, &wfds, NULL, &tv)) != -1) {
					if (r_socket_is_connected (s)) {
						freeaddrinfo (res);
						goto success;
					}
				} else {
					r_sys_perror ("connect");
				}
			}
			r_socket_close (s);
		}
		freeaddrinfo (res);
		if (!rp) {
			// R_LOG_ERROR ("Could not resolve address '%s' or failed to connect", host);
			return false;
		}
	}
success:
#if HAVE_LIB_SSL
	if (s->is_ssl) {
		s->ctx = SSL_CTX_new (SSLv23_client_method ());
		if (!s->ctx) {
			r_socket_close (s);
			return false;
		}
		s->sfd = SSL_new (s->ctx);
		SSL_set_fd (s->sfd, s->fd);
		int ret = SSL_connect (s->sfd);
		if (ret != 1) {
			int error = SSL_get_error (s->sfd, ret);
			int tries = 10;
			while (tries && ret && (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE)) {
				struct timeval tv = {1, 0};
				fd_set rfds, wfds;
				FD_ZERO (&rfds);
				FD_ZERO (&wfds);
				if (error == SSL_ERROR_WANT_READ) {
					FD_SET (s->fd, &rfds);
				} else {
					FD_SET (s->fd, &wfds);
				}
				if ((ret = select (s->fd + 1, &rfds, &wfds, NULL, &tv)) < 1) {
					r_socket_close (s);
					return false;
				}
				ret = SSL_connect (s->sfd);
				if (ret == 1) {
					return true;
				}
				error = SSL_get_error (s->sfd, ret);
				tries--;
			}
			r_socket_close (s);
			return false;
		}
	}
#endif
	return true;
}

/* close the file descriptor associated with the RSocket s */
R_API bool r_socket_close_fd(RSocket *s) {
#ifdef _MSC_VER
	return s->fd != INVALID_SOCKET ? closesocket (s->fd) : false;
#else
	return s->fd != -1 ? close (s->fd) : false;
#endif
}

/* shutdown the socket and close the file descriptor */
R_API bool r_socket_close(RSocket *s) {
	int ret = false;
	if (!s) {
		return false;
	}
	if (s->fd != R_INVALID_SOCKET) {
#if R2__UNIX__
		shutdown (s->fd, SHUT_RDWR);
#endif
#if R2__WINDOWS__
		// https://msdn.microsoft.com/en-us/library/windows/desktop/ms740481(v=vs.85).aspx
		shutdown (s->fd, SD_SEND);
		if (r_socket_ready (s, 0, 250)) {
			do {
				char buf = 0;
				ret = recv (s->fd, &buf, 1, 0);
			} while (ret != 0 && ret != SOCKET_ERROR);
		}
		ret = closesocket (s->fd);
#else
		ret = close (s->fd);
#endif
		s->fd = R_INVALID_SOCKET;
	}
#if HAVE_LIB_SSL
	if (s->is_ssl && s->sfd) {
		SSL_free (s->sfd);
		s->sfd = NULL;
	}
#endif
	return ret;
}

/* shutdown the socket, close the file descriptor and free the RSocket */
R_API void r_socket_free(RSocket *s) {
	(void)r_socket_close (s);
#if HAVE_LIB_SSL
	if (s && s->is_ssl) {
		if (s->sfd) {
			SSL_free (s->sfd);
		}
		if (s->ctx) {
			SSL_CTX_free (s->ctx);
		}
	}
#endif
	free (s);
}

R_API int r_socket_port_by_name(const char *name) {
	struct servent *p = getservbyname (name, "tcp");
	return (p && p->s_port) ? ntohs (p->s_port) : r_num_get (NULL, name);
}

R_API bool r_socket_listen(RSocket *s, const char *port, const char *certfile) {
	int optval = 1;
	int ret;
	struct linger linger = {0};

	if (s->proto == R_SOCKET_PROTO_UNIX) {
#if R2__UNIX__
		return __listen_unix (s, port);
#endif
		return false;
	}
	if (!r_sandbox_check (R_SANDBOX_GRAIN_SOCKET)) {
		return false;
	}
#if R2__WINDOWS__
	WSADATA wsadata;
	if (WSAStartup (MAKEWORD (1, 1), &wsadata) == SOCKET_ERROR) {
		R_LOG_ERROR ("WSAStartup failed");
		return false;
	}
#endif
	if (s->proto == R_SOCKET_PROTO_NONE) {
		s->proto = R_SOCKET_PROTO_DEFAULT;
	}
	switch (s->proto) {
	case R_SOCKET_PROTO_TCP:
		if ((s->fd = socket (AF_INET, SOCK_STREAM, R_SOCKET_PROTO_TCP)) == R_INVALID_SOCKET) {
			return false;
		}
		break;
	case R_SOCKET_PROTO_UDP:
		if ((s->fd = socket (AF_INET, SOCK_DGRAM, R_SOCKET_PROTO_UDP)) == R_INVALID_SOCKET) {
			return false;
		}
		break;
	default:
		R_LOG_ERROR ("Invalid protocol for socket");
		return false;
	}

	linger.l_onoff = 1;
	linger.l_linger = 1;
	ret = setsockopt (s->fd, SOL_SOCKET, SO_LINGER, (void*)&linger, sizeof (linger));
	if (ret < 0) {
		return false;
	}
	{ // fix close after write bug //
	int x = 1500; // FORCE MTU
	ret = setsockopt (s->fd, SOL_SOCKET, SO_SNDBUF, (void*)&x, sizeof (int));
	if (ret < 0) {
		return false;
	}
	}
	ret = setsockopt (s->fd, SOL_SOCKET, SO_REUSEADDR, (void*)&optval, sizeof optval);
	if (ret < 0) {
		return false;
	}

	memset (&s->sa, 0, sizeof (s->sa));
	s->sa.sin_family = AF_INET;
	s->sa.sin_addr.s_addr = htonl (s->local? INADDR_LOOPBACK: INADDR_ANY);
	s->port = r_socket_port_by_name (port);
	if (s->port < 1) {
		return false;
	}
	s->sa.sin_port = htons (s->port); // TODO honor etc/services
	if (bind (s->fd, (struct sockaddr *)&s->sa, sizeof (s->sa)) < 0) {
		r_sys_perror ("bind");
#ifdef _MSC_VER
		closesocket (s->fd);
#else
		close (s->fd);
#endif
		return false;
	}
#if R2__UNIX__
	r_sys_signal (SIGPIPE, SIG_IGN);
#endif
	if (s->proto == R_SOCKET_PROTO_TCP) {
		if (listen (s->fd, 32) < 0) {
			r_sys_perror ("listen");
#ifdef _MSC_VER
			closesocket (s->fd);
#else
			close (s->fd);
#endif
			return false;
		}
	}
#if HAVE_LIB_SSL
	if (s->is_ssl) {
		s->ctx = SSL_CTX_new (SSLv23_method ());
		if (!s->ctx) {
			r_socket_free (s);
			return false;
		}
		if (!SSL_CTX_use_certificate_chain_file (s->ctx, certfile)) {
			r_socket_free (s);
			return false;
		}
		if (!SSL_CTX_use_PrivateKey_file (s->ctx, certfile, SSL_FILETYPE_PEM)) {
			r_socket_free (s);
			return false;
		}
		SSL_CTX_set_verify_depth (s->ctx, 1);
	}
#endif
	return true;
}

R_API RSocket *r_socket_accept(RSocket *s) {
	RSocket *sock;
	socklen_t salen = sizeof (s->sa);
	if (!s) {
		return NULL;
	}
	sock = R_NEW0 (RSocket);
	if (!sock) {
		return NULL;
	}
	// signal (SIGPIPE, SIG_DFL);
	sock->fd = accept (s->fd, (struct sockaddr *)&s->sa, &salen);
	if (sock->fd == R_INVALID_SOCKET) {
		// EINTR Is received when the terminal is resized
		if (errno != EWOULDBLOCK && errno != EINTR) {
			// not just a timeout
			r_sys_perror ("accept");
		}
		free (sock);
		return NULL;
	}
#if HAVE_LIB_SSL
	sock->is_ssl = s->is_ssl;
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
#else
	sock->is_ssl = 0;
#endif
	return sock;
}

R_API RSocket *r_socket_accept_timeout(RSocket *s, unsigned int timeout) {
	fd_set read_fds;
	fd_set except_fds;

	FD_ZERO (&read_fds);
	FD_SET (s->fd, &read_fds);

	FD_ZERO (&except_fds);
	FD_SET (s->fd, &except_fds);

	struct timeval t = {timeout, 0};

	int r = select (s->fd + 1, &read_fds, NULL, &except_fds, &t);
	if (r < 0) {
		r_sys_perror ("select");
	} else if (r > 0 && FD_ISSET (s->fd, &read_fds)) {
		return r_socket_accept (s);
	}

	return NULL;
}

// Only applies to read in UNIX
R_API bool r_socket_block_time(RSocket *s, bool block, int sec, int usec) {
#if R2__UNIX__
	int ret, flags;
#endif
	if (!s) {
		return false;
	}
#if R2__UNIX__
	flags = fcntl (s->fd, F_GETFL, 0);
	if (flags < 0) {
		return false;
	}
	ret = fcntl (s->fd, F_SETFL, block?
			(flags & ~O_NONBLOCK):
			(flags | O_NONBLOCK));
	if (ret < 0) {
		return false;
	}
#elif R2__WINDOWS__
	ioctlsocket (s->fd, FIONBIO, (u_long FAR*)&block);
#endif
	if (sec < 0) {
		sec = 0;
	}
	if (usec < 0) {
		usec = 0;
	}
	struct timeval tv = {sec, usec};
	if (setsockopt (s->fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof (tv)) < 0) {
		return false;
	}
	return true;
}

R_API int r_socket_flush(RSocket *s) {
#if HAVE_LIB_SSL
	if (s->is_ssl && s->bio) {
		return BIO_flush (s->bio);
	}
#endif
	return true;
}

/* waits secs until new data is received.	  */
/* returns -1 on error, 0 is false, 1 is true */
R_API int r_socket_ready(RSocket *s, int secs, int usecs) {
	fd_set rfds;
	if (secs < 0) {
		secs = 0;
	}
	if (usecs < 0) {
		usecs = 0;
	}
	if (s->fd == R_INVALID_SOCKET) {
		return -1;
	}
	FD_ZERO (&rfds);
	FD_SET (s->fd, &rfds);
	struct timeval tv = {secs, usecs};
	return select (s->fd + 1, &rfds, NULL, NULL, &tv);
}

R_API char *r_socket_tostring(RSocket *s) {
#if R2__WINDOWS__
	return r_str_newf ("fd%d", (int)(size_t)s->fd);
#elif R2__UNIX__
	char *str = NULL;
	struct sockaddr sa;
	socklen_t sl = sizeof (sa);
	memset (&sa, 0, sizeof (sa));
	if (!getpeername (s->fd, &sa, &sl)) {
		struct sockaddr_in *sain = (struct sockaddr_in*) &sa;
		ut8 *a = (ut8*) &(sain->sin_addr);
		str = r_str_newf ("%d.%d.%d.%d:%d",
			a[0], a[1], a[2], a[3], ntohs (sain->sin_port));
	} else {
		r_sys_perror ("getpeername");
	}
	return str;
#else
	return NULL;
#endif
}

/* Read/Write functions */
R_API int r_socket_write(RSocket *s, const void *buf, int len) {
	int ret, delta = 0;
#if R2__UNIX__
	// this is on non-linux only in theory..
	r_sys_signal (SIGPIPE, SIG_IGN);
#endif
	for (;;) {
		int b = 1500; //65536; // Use MTU 1500?
		if (b > len) {
			b = len;
		}
#if HAVE_LIB_SSL
		if (s->is_ssl) {
			if (s->bio) {
				ret = BIO_write (s->bio, buf+delta, b);
			} else {
				ret = SSL_write (s->sfd, buf + delta, b);
			}
		} else /* block */
#endif
		if (s->proto == R_SOCKET_PROTO_SERIAL) {
			ret = write (s->fd, (char *)buf + delta, b);
		} else {
#if __linux__
			ret = send (s->fd, (char *)buf + delta, b, MSG_NOSIGNAL);
#else
			ret = send (s->fd, (char *)buf + delta, b, 0);
#endif
		}
		//if (ret == 0) return -1;
		if (ret < 1) {
			break;
		}
		if (ret == len) {
			return len;
		}
		delta += ret;
		len -= ret;
	}
	return (ret == -1)? -1 : delta;
}

R_API int r_socket_puts(RSocket *s, char *buf) {
	return r_socket_write (s, buf, strlen (buf));
}

R_API void r_socket_printf(RSocket *s, const char *fmt, ...) {
	va_list ap, ap0;
	if (s->fd != R_INVALID_SOCKET) {
		va_start (ap, fmt);
		va_copy (ap0, ap);
		size_t len = vsnprintf (NULL, 0, fmt, ap0);
		char *buf = calloc (len + 1, 1);
		if (buf) {
			vsnprintf (buf, len + 1, fmt, ap);
			size_t left = len;
			size_t done = 0;
			while (left > 0) {
				int res = r_socket_write (s, buf + done, left);
				if (res < 1) {
					break;
				}
				if (res == left) {
					break;
				}
				left -= res;
				done += res;
			}
			free (buf);
		}
		va_end (ap);
	}
}

R_API int r_socket_read(RSocket *s, unsigned char *buf, int len) {
	if (!s) {
		return -1;
	}
#if HAVE_LIB_SSL
	if (s->is_ssl) {
		if (s->bio) {
			return BIO_read (s->bio, buf, len);
		}
		return SSL_read (s->sfd, buf, len);
	}
#endif
	if (s->proto == R_SOCKET_PROTO_SERIAL) {
		return read (s->fd, (char *)buf, len);
	}
	return recv (s->fd, (char *)buf, len, 0);
}

R_API int r_socket_read_block(RSocket *s, ut8 *buf, int len) {
	int ret = 0;
	for (ret = 0; ret < len; ) {
		int r = r_socket_read (s, buf + ret, len - ret);
		if (r == -1) {
#if HAVE_LIB_SSL
			if (s->is_ssl && SSL_get_error (s->sfd, r) == SSL_ERROR_WANT_READ) {
				if (r_socket_ready (s, 1, 0) == 1) {
					continue;
				}
			}
#endif
			return -1;
		}
		if (r < 1) {
			break;
		}
		ret += r;
	}
	return ret;
}

R_API int r_socket_gets(RSocket *s, char *buf,	int size) {
	int i = 0;
	int ret = 0;

	if (s->fd == R_INVALID_SOCKET) {
		return -1;
	}
	while (i < size) {
		ret = r_socket_read (s, (ut8 *)buf + i, 1);
		if (ret == 0) {
			if (i > 0) {
				return i;
			}
			return -1;
		}
		if (ret < 0) {
			r_socket_close (s);
			return i == 0? -1: i;
		}
		if (buf[i] == '\r' || buf[i] == '\n') {
			buf[i] = 0;
			break;
		}
		i += ret;
	}
	buf[i] = '\0';
	return i;
}

R_API RSocket *r_socket_new_from_fd(int fd) {
	RSocket *s = R_NEW0 (RSocket);
	if (s) {
		s->fd = fd;
		s->proto = R_SOCKET_PROTO_DEFAULT;
	}
	return s;
}

R_API ut8* r_socket_slurp(RSocket *s, int *len) {
	int blockSize = 4096;
	ut8 *ptr, *buf = malloc (blockSize);
	if (!buf) {
		return NULL;
	}
	int copied = 0;
	if (len) {
		*len = 0;
	}
	for (;;) {
		int rc = r_socket_read (s, buf + copied, blockSize);
		if (rc > 0) {
			copied += rc;
		}
		ptr = realloc (buf, copied + blockSize);
		if (!ptr) {
			break;
		}
		buf = ptr;
		if (rc < 1) {
			break;
		}
	}
	if (copied == 0) {
		R_FREE (buf);
	}
	if (len) {
		*len = copied;
	}
	return buf;
}

#endif // EMSCRIPTEN
