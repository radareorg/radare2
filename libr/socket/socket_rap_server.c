/* radare - LGPL - Copyright 2014-2019 - pancake, condret */

#include <r_socket.h>
#include <r_util.h>

R_API RSocketRapServer *r_socket_rap_server_new(bool use_ssl, const char *port) {
	R_RETURN_VAL_IF_FAIL (port, NULL);
	RSocketRapServer *s = R_NEW0 (RSocketRapServer);
	if (s) {
		s->port = strdup (port);
		s->fd = r_socket_new (use_ssl);
		if (s->fd) {
			return s;
		}
		r_socket_free (s->fd);
		free (s->port);
		free (s);
	}
	return NULL;
}

R_API RSocketRapServer *r_socket_rap_server_create(const char *pathname) {
	R_RETURN_VAL_IF_FAIL (pathname, NULL);
	if (strlen (pathname) < 11) {
		return NULL;
	}
	if (strncmp (pathname, "rap", 3)) {
		return NULL;
	}
	bool is_ssl = (pathname[3] == 's');
	const char *port = &pathname[7 + is_ssl];
	return r_socket_rap_server_new (is_ssl, port);
}

R_API void r_socket_rap_server_free(RSocketRapServer *s) {
	if (s) {
		r_socket_free (s->fd);
		free (s);
	}
}

R_API bool r_socket_rap_server_listen(RSocketRapServer *s, const char *certfile) {
	R_RETURN_VAL_IF_FAIL (s && s->port && *s->port, false);
	return r_socket_listen (s->fd, s->port, certfile);
}

R_API RSocket* r_socket_rap_server_accept(RSocketRapServer *s) {
	R_RETURN_VAL_IF_FAIL (s && s->fd, NULL);
	return r_socket_accept (s->fd);
}

R_API bool r_socket_rap_server_continue(RSocketRapServer *s) {
	R_RETURN_VAL_IF_FAIL (s && s->fd, false);

	int i;
	char *ptr = NULL;

	if (!r_socket_is_connected (s->fd)) {
		return false;
	}
	r_socket_read_block (s->fd, s->buf, 1);
	switch (s->buf[0]) {
	case RAP_PACKET_OPEN:
		r_socket_read_block (s->fd, &s->buf[1], 2);
		{
		int len = (int)(ut8)s->buf[2];
		if (len > sizeof (s->buf) - 3) {
			R_LOG_ERROR ("rap: filename too long %d", len);
			r_socket_close (s->fd);
			return false;
		}
		r_socket_read_block (s->fd, &s->buf[3], len);
		s->buf[3 + len] = 0;
		int fd = s->open (s->user, (const char *)&s->buf[3], (int)s->buf[1], 0);
		s->buf[0] = RAP_PACKET_OPEN | RAP_PACKET_REPLY;
		eprintf ("REPLY BACK %d\n", fd);
		r_write_be32 (s->buf + 1, fd);
		}
		r_socket_write (s->fd, s->buf, 5);
		r_socket_flush (s->fd);
		break;
	case RAP_PACKET_READ:
		r_socket_read_block (s->fd, &s->buf[1], 4);
		i = r_read_be32 (&s->buf[1]);
		if (i > RAP_PACKET_MAX || i < 0) {
			i = RAP_PACKET_MAX;
		}
		s->read (s->user, &s->buf[5], i);
		s->buf[0] = RAP_PACKET_READ | RAP_PACKET_REPLY;
		r_socket_write (s->fd, s->buf, i + 5);
		r_socket_flush (s->fd);
		break;
	case RAP_PACKET_WRITE:
		r_socket_read_block (s->fd, s->buf + 1, 4);
		i = r_read_be32 (s->buf + 1);
		if (i > RAP_PACKET_MAX || i < 0) {
			i = RAP_PACKET_MAX;
		}
		r_socket_read_block (s->fd, s->buf + 5, i);
		r_write_be32 (s->buf + 1, s->write (s->user, s->buf + 5, i));
		s->buf[0] = RAP_PACKET_WRITE | RAP_PACKET_REPLY;
		r_socket_write (s->fd, s->buf, 5);
		r_socket_flush (s->fd);
		break;
	case RAP_PACKET_SEEK:
		{
		r_socket_read_block (s->fd, &s->buf[1], 9);
		int whence = s->buf[1];
		ut64 offset = r_read_be64 (s->buf + 2);
		offset = s->seek (s->user, offset, whence);
		/* prepare reply */
		s->buf[0] = RAP_PACKET_SEEK | RAP_PACKET_REPLY;
		r_write_be64 (s->buf + 1, offset);
		r_socket_write (s->fd, s->buf, 9);
		r_socket_flush (s->fd);
		}
		break;
	case RAP_PACKET_CMD:
		/* Read and validate command request length */
		r_socket_read_block (s->fd, &s->buf[1], 4);
		i = r_read_be32 (&s->buf[1]);
		if (i < 0 || i > RAP_PACKET_MAX) {
			R_LOG_ERROR ("rap: invalid cmd request length %d", i);
			r_socket_close (s->fd);
			return false;
		}
		if (r_socket_read_block (s->fd, &s->buf[5], i) > 0) {
			ptr = s->cmd (s->user, (const char *)s->buf + 5);
			i = (ptr)? strlen (ptr) + 1: 0;
			r_write_be32 (&s->buf[1], i);
			s->buf[0] = RAP_PACKET_CMD | RAP_PACKET_REPLY;
			r_socket_write (s->fd, s->buf, 5);
			if (i) {
				r_socket_write (s->fd, ptr, i);
			}
			r_socket_flush (s->fd);
			R_FREE (ptr);
		}
		break;
	case RAP_PACKET_CLOSE:
		r_socket_read_block (s->fd, &s->buf[1], 4);
		i = r_read_be32 (&s->buf[1]);
		s->close (s->user, i);
		s->buf[0] = RAP_PACKET_CLOSE | RAP_PACKET_REPLY;
		r_socket_write (s->fd, s->buf, 5);
		r_socket_flush (s->fd);
		break;
	default:
		eprintf ("unknown command 0x%02x\n", (ut8)(s->buf[0] & 0xff));
		r_socket_close (s->fd);
		return false;
	}
	return true;
}
