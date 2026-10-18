/* radare - LGPL - Copyright 2026 - pancake */

#define WASI_NET(name) __attribute__((import_module("r2net"), import_name(#name)))
extern int wasi_net_connect(const char *host, const char *port, int proto, int tls, int timeout) WASI_NET(connect);
extern int wasi_net_listen(const char *port, int local, int proto) WASI_NET(listen);
extern int wasi_net_accept(int fd) WASI_NET(accept);
extern int wasi_net_read(int fd, void *buf, int len) WASI_NET(read);
extern int wasi_net_write(int fd, const void *buf, int len) WASI_NET(write);
extern int wasi_net_close(int fd) WASI_NET(close);
extern int wasi_net_ready(int fd, int sec, int usec) WASI_NET(ready);
extern int wasi_net_block_time(int fd, int block, int sec, int usec) WASI_NET(block_time);
extern int wasi_net_peer(int fd, char *buf, int len) WASI_NET(peer);

static bool wasi_socket_allowed(RSocket *s) {
	return s && r_sandbox_check (R_SANDBOX_GRAIN_SOCKET)
		&& (r_sandbox_check (R_SANDBOX_GRAIN_NETWORK) || s->local);
}

static bool wasi_socket_local(const char *host, char *address, size_t size) {
	if (!strcmp (host, "localhost") || !strcmp (host, "::1")) {
		snprintf (address, size, "%s", !strcmp (host, "localhost")? "127.0.0.1": "::1");
		return true;
	}
	unsigned int a, b, c, d;
	char tail;
	if (sscanf (host, "%u.%u.%u.%u%c", &a, &b, &c, &d, &tail) == 4
		&& a == 127 && b < 256 && c < 256 && d < 256) {
		snprintf (address, size, "%u.%u.%u.%u", a, b, c, d);
		return true;
	}
	return false;
}

R_API RSocket *r_socket_new(bool is_ssl) {
	RSocket *s = R_NEW0 (RSocket);
	s->fd = R_INVALID_SOCKET;
	s->proto = R_SOCKET_PROTO_DEFAULT;
	s->is_ssl = is_ssl;
	return s;
}

R_API bool r_socket_is_connected(RSocket *s) {
	return wasi_socket_allowed (s) && s->fd != R_INVALID_SOCKET;
}

R_API bool r_socket_connect(RSocket *s, const char *host, const char *port, int proto, unsigned int timeout) {
	R_RETURN_VAL_IF_FAIL (s && host && port, false);
	char local_host[48];
	bool local = wasi_socket_local (host, local_host, sizeof (local_host));
	if (!r_sandbox_check (R_SANDBOX_GRAIN_SOCKET)
		|| (!r_sandbox_check (R_SANDBOX_GRAIN_NETWORK) && !local)) {
		return false;
	}
	// Do not rely on host DNS for the localhost sandbox exception.
	if (local) {
		host = local_host;
	}
	r_socket_close (s);
	s->local = local;
	s->proto = proto? proto: R_SOCKET_PROTO_DEFAULT;
	s->fd = wasi_net_connect (host, port, s->proto, s->is_ssl, timeout);
	return s->fd >= 0;
}

R_API bool r_socket_spawn(RSocket *s, const char *cmd, unsigned int timeout) {
	return false;
}

R_API bool r_socket_close_fd(RSocket *s) {
	return r_socket_close (s);
}

R_API bool r_socket_close(RSocket *s) {
	if (!s || s->fd < 0) {
		return false;
	}
	// Cleanup remains allowed after a sandbox policy is tightened.
	int ret = wasi_net_close (s->fd);
	s->fd = R_INVALID_SOCKET;
	return ret == 0;
}

R_API void r_socket_free(RSocket *s) {
	r_socket_close (s);
	free (s);
}

R_API int r_socket_port_by_name(const char *name) {
	char *end;
	long port = strtol (name, &end, 10);
	return end != name && !*end && port > 0 && port <= 65535? port: -1;
}

R_API bool r_socket_listen(RSocket *s, const char *port, const char *certfile) {
	if (!wasi_socket_allowed (s) || s->is_ssl || !port) {
		return false;
	}
	r_socket_close (s);
	s->fd = wasi_net_listen (port, s->local, s->proto);
	return s->fd >= 0;
}

R_API RSocket *r_socket_accept(RSocket *s) {
	if (!wasi_socket_allowed (s)) {
		return NULL;
	}
	int fd = wasi_net_accept (s->fd);
	if (fd < 0) {
		return NULL;
	}
	RSocket *client = r_socket_new_from_fd (fd);
	client->local = s->local;
	return client;
}

R_API RSocket *r_socket_accept_timeout(RSocket *s, unsigned int timeout) {
	return r_socket_ready (s, timeout, 0) == 1? r_socket_accept (s): NULL;
}

R_API bool r_socket_block_time(RSocket *s, bool block, int sec, int usec) {
	return wasi_socket_allowed (s) && wasi_net_block_time (s->fd, block, sec, usec) == 0;
}

R_API int r_socket_flush(RSocket *s) {
	return wasi_socket_allowed (s)? 1: -1;
}

R_API int r_socket_ready(RSocket *s, int secs, int usecs) {
	return wasi_socket_allowed (s)? wasi_net_ready (s->fd, secs, usecs): -1;
}

R_API char *r_socket_tostring(RSocket *s) {
	char buf[128];
	if (!wasi_socket_allowed (s) || wasi_net_peer (s->fd, buf, sizeof (buf)) < 0) {
		return NULL;
	}
	buf[sizeof (buf) - 1] = 0;
	return strdup (buf);
}

R_API int r_socket_write(RSocket *s, const void *buf, int len) {
	return wasi_socket_allowed (s) && len >= 0? wasi_net_write (s->fd, buf, len): -1;
}

R_API int r_socket_read(RSocket *s, unsigned char *buf, int len) {
	return wasi_socket_allowed (s) && len >= 0? wasi_net_read (s->fd, buf, len): -1;
}

R_API RSocket *r_socket_new_from_fd(int fd) {
	RSocket *s = r_socket_new (false);
	s->fd = fd;
	return s;
}
