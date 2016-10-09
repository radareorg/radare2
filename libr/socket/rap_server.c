/* radare - LGPL - Copyright 2014-2016 - condret */

#include <r_socket.h>
#include <string.h>
#include <r_util.h>

R_API RSocketRapServer *r_socket_rap_server_new (int is_ssl, const char *port) {
	RSocketRapServer *rap_s;
	if (!port) {
		return NULL;
	}
	rap_s = R_NEW0 (RSocketRapServer);
	if (!rap_s) {
		return NULL;
	}
	rap_s->fd = r_socket_new (is_ssl);
	memcpy (rap_s->port, port, 4);
	if (rap_s->fd) {
		return rap_s;
	}
	free (rap_s);
	return NULL;
}

R_API RSocketRapServer *r_socket_rap_server_create (const char *pathname) {
	const char *port = NULL;
	int is_ssl;
	if (!pathname) {
		return NULL;
	}
	if (strlen (pathname) < 11) {
		return NULL;
	}
	if (strncmp (pathname, "rap", 3)) {
		return NULL;
	}
	is_ssl = (pathname[3] == 's');
	port = &pathname[7 + is_ssl];
	return r_socket_rap_server_new (is_ssl, port);
}

R_API void r_socket_rap_server_free (RSocketRapServer *rap_s) {
	if (rap_s) {
		r_socket_free (rap_s->fd);
	}
	free (rap_s);
}

R_API int r_socket_rap_server_listen (RSocketRapServer *rap_s, const char *certfile) {
	if (!rap_s || !*rap_s->port) {
		return false;
	}
	return r_socket_listen (rap_s->fd, rap_s->port, certfile);
}

R_API RSocket* r_socket_rap_server_accept (RSocketRapServer *rap_s) {
	if (!rap_s || !rap_s->fd) {
		eprintf ("error: r_socket_rap_server_accept\n");
		return NULL;
	}
	return r_socket_accept (rap_s->fd);
}

R_API bool r_socket_rap_server_continue (RSocketRapServer *rap_s) {
	int i, whence, ret = true;
	ut64 offset;
	char *ptr = NULL;
	if (!rap_s || !rap_s->fd) {
		return false;
	}
	if (!r_socket_is_connected (rap_s->fd)) {
		return false;
	}
	r_socket_read_block (rap_s->fd, rap_s->buf, 1);
	ret = rap_s->buf[0];
	switch (ret) {
	case RAP_RMT_OPEN:
		r_socket_read_block (rap_s->fd, &rap_s->buf[1], 2);
		r_socket_read_block (rap_s->fd, &rap_s->buf[3], (int)rap_s->buf[2]);
		rap_s->open (rap_s->user, (const char *)&rap_s->buf[3], (int)rap_s->buf[1], 0);
		rap_s->buf[0] = RAP_RMT_OPEN | RAP_RMT_REPLY;
		r_socket_write (rap_s->fd, rap_s->buf, 5);
		r_socket_flush (rap_s->fd);
		break;
	case RAP_RMT_READ:
		r_socket_read_block (rap_s->fd, &rap_s->buf[1], 4);
		i = r_read_be32 (&rap_s->buf[1]);
		if (i > RAP_RMT_MAX || i < 0) {
			i = RAP_RMT_MAX;
		}
		rap_s->read (rap_s->user, &rap_s->buf[5], i);
		rap_s->buf[0] = RAP_RMT_READ | RAP_RMT_REPLY;
		r_socket_write (rap_s->fd, rap_s->buf, i + 5);
		r_socket_flush (rap_s->fd);
		break;
	case RAP_RMT_WRITE:
		r_socket_read_block (rap_s->fd, rap_s->buf + 1, 4);
		i = r_read_be32 (rap_s->buf + 1);
		if (i > RAP_RMT_MAX || i < 0) {
			i = RAP_RMT_MAX;
		}
		r_socket_read_block (rap_s->fd, rap_s->buf + 5, i);
		int ret = rap_s->write (rap_s->user, rap_s->buf + 5, i);
		r_write_be32 (rap_s->buf + 1, ret);
		rap_s->buf[0] = RAP_RMT_WRITE | RAP_RMT_REPLY;
		r_socket_write (rap_s->fd, rap_s->buf, 5);
		r_socket_flush (rap_s->fd);
		break;
	case RAP_RMT_SEEK:
		r_socket_read_block (rap_s->fd, &rap_s->buf[1], 9);
		whence = rap_s->buf[1];
		offset = r_read_be64 (rap_s->buf + 2);
		offset = rap_s->seek (rap_s->user, offset, whence);
		/* prepare reply */
		rap_s->buf[0] = RAP_RMT_SEEK | RAP_RMT_REPLY;
		r_write_be64 (rap_s->buf + 1, offset);
		r_socket_write (rap_s->fd, rap_s->buf, 9);
		r_socket_flush (rap_s->fd);
		break;
	case RAP_RMT_CMD:
		r_socket_read_block (rap_s->fd, &rap_s->buf[1], 4);
		i = r_read_be32 (&rap_s->buf[1]);
		r_socket_read_block (rap_s->fd, &rap_s->buf[5], i);
		ptr = rap_s->cmd (rap_s->user, (const char *)&rap_s->buf[5]);
		i = (ptr)? strlen (ptr) + 1: 0;
		r_write_be32 (&rap_s->buf[1], i);
		rap_s->buf[0] = RAP_RMT_CMD | RAP_RMT_REPLY;
		r_socket_write (rap_s->fd, rap_s->buf, 5);
		if (i) {
			r_socket_write (rap_s->fd, ptr, i);
		}
		r_socket_flush (rap_s->fd);
		free (ptr);
		ptr = NULL;
		break;
	case RAP_RMT_CLOSE:
		r_socket_read_block (rap_s->fd, &rap_s->buf[1], 4);
		i = r_read_be32 (&rap_s->buf[1]);
		rap_s->close (rap_s->user, i);
		rap_s->buf[0] = RAP_RMT_CLOSE | RAP_RMT_REPLY;
		r_socket_write (rap_s->fd, rap_s->buf, 5);
		r_socket_flush (rap_s->fd);
		break;
	default:
		eprintf ("unknown command 0x%02x\n", (ut8)(rap_s->buf[0] & 0xff));
		r_socket_close (rap_s->fd);
		ret = false;
		break;
	}
	return ret;
}
