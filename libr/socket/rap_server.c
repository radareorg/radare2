/* radare - LGPL - Copyright 2014 - condret */

#include <r_socket.h>
#include <string.h>
#include <r_util.h>

R_API RSocketRapServer *r_socket_rap_server_new (int is_ssl, const char *port) {
	RSocketRapServer *rap_s;
	if (!port)
		return NULL;
	rap_s = R_NEW0 (RSocketRapServer);
	rap_s->fd = r_socket_new (is_ssl);
	memcpy (rap_s->port, port, 4);
	if (rap_s->fd)
		return rap_s;
	free (rap_s);
	return NULL;
}

R_API RSocketRapServer *r_socket_rap_server_create (const char *pathname) {
	const char *port = NULL;
	int is_ssl;
	if (!pathname)
		return NULL;
	if (strlen (pathname) < 11)
		return NULL;
	if (strncmp (pathname, "rap", 3))
		return NULL;
	is_ssl = (pathname[3] == 's');
	port = &pathname[7 + is_ssl];
	return r_socket_rap_server_new (is_ssl, port);
}

R_API void r_socket_rap_server_free (RSocketRapServer *rap_s) {
	if (rap_s)
		r_socket_free (rap_s->fd);
	free (rap_s);
}

R_API int r_socket_rap_server_listen (RSocketRapServer *rap_s, const char *certfile) {
	if (!rap_s || rap_s->port[0] == '\0')
		return R_FALSE;
	return r_socket_listen (rap_s->fd, rap_s->port, certfile);
}

R_API RSocket* r_socket_rap_server_accept (RSocketRapServer *rap_s) {
	if (!rap_s || !rap_s->fd) {
		eprintf ("error: r_socket_rap_server_accept\n");
		return NULL;
	}
	return r_socket_accept (rap_s->fd);
}

static inline int getEndian () {
	int e = 0;
	ut8 *n = (ut8 *)&e;
	*n = 0x1;
	return (e == 0x1);
}

R_API int r_socket_rap_server_continue (RSocketRapServer *rap_s) {
	int endian, i, ret;
	ut64 offset;
	char *ptr = NULL;
	if (!rap_s || !rap_s->fd)
		return R_FALSE;
	if (!r_socket_is_connected (rap_s->fd))
		return R_FALSE;
	r_socket_read_block (rap_s->fd, rap_s->buf, 1);
	endian = getEndian();
	ret = rap_s->buf[0];
	switch (rap_s->buf[0]) {
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
			r_mem_copyendian ((ut8*)&i, &rap_s->buf[1], 4, !endian);
			if (i > RAP_RMT_MAX || i < 0)
				i = RAP_RMT_MAX;
			rap_s->read (rap_s->user, &rap_s->buf[5], i);
			rap_s->buf[0] = RAP_RMT_READ | RAP_RMT_REPLY;
			r_socket_write (rap_s->fd, rap_s->buf, i + 5);
			r_socket_flush (rap_s->fd);
			break;
		case RAP_RMT_WRITE:
			r_socket_read_block (rap_s->fd, &rap_s->buf[1], 4);
			r_mem_copyendian ((ut8*)&i, &rap_s->buf[1], 4, !endian);
			if (i > RAP_RMT_MAX || i < 0)
				i = RAP_RMT_MAX;
			r_socket_read_block (rap_s->fd, &rap_s->buf[5], i);
			rap_s->write(rap_s->user, &rap_s->buf[5], i);
			rap_s->buf[0] = RAP_RMT_WRITE | RAP_RMT_REPLY;
			r_socket_write (rap_s->fd, rap_s->buf, 1);
			r_socket_flush (rap_s->fd);
			break;
		case RAP_RMT_SEEK:
			r_socket_read_block (rap_s->fd, &rap_s->buf[1], 9);
			i = rap_s->buf[1];
			r_mem_copyendian ((ut8*)&offset, &rap_s->buf[2], 8, !endian);
			rap_s->seek (rap_s->user, offset, i);
			rap_s->buf[0] = RAP_RMT_WRITE | RAP_RMT_REPLY;
			r_socket_write (rap_s->fd, rap_s->buf, 1);
			r_socket_flush (rap_s->fd);
			break;
		case RAP_RMT_SYSTEM:
			r_socket_read_block (rap_s->fd, &rap_s->buf[1], 4);
			r_mem_copyendian ((ut8 *)&i, &rap_s->buf[1], 4, !endian);
			r_socket_read_block (rap_s->fd, &rap_s->buf[5], i);
			ptr = rap_s->system (rap_s->user, (const char *)&rap_s->buf[5]);
			if (ptr)
				i = strlen (ptr) + 1;
			else	i = 0;
			r_mem_copyendian (&rap_s->buf[1], (ut8 *)&i, 4, !endian);
			rap_s->buf[0] = RAP_RMT_SYSTEM | RAP_RMT_REPLY;
			r_socket_write (rap_s->fd, rap_s->buf, 5);
			if (i)	r_socket_write (rap_s->fd, ptr, i);
			r_socket_flush (rap_s->fd);
			free (ptr);
			ptr = NULL;
			break;
		case RAP_RMT_CMD:
			r_socket_read_block (rap_s->fd, &rap_s->buf[1], 4);
			r_mem_copyendian ((ut8 *)&i, &rap_s->buf[1], 4, !endian);
			r_socket_read_block (rap_s->fd, &rap_s->buf[5], i);
			ptr = rap_s->cmd (rap_s->user, (const char *)&rap_s->buf[5]);
			if (ptr)
				i = strlen (ptr) + 1;
			else	i = 0;
			r_mem_copyendian (&rap_s->buf[1], (ut8 *)&i, 4, !endian);
			rap_s->buf[0] = RAP_RMT_CMD | RAP_RMT_REPLY;
			r_socket_write (rap_s->fd, rap_s->buf, 5);
			if (i)	r_socket_write (rap_s->fd, ptr, i);
			r_socket_flush (rap_s->fd);
			free (ptr);
			ptr = NULL;
			break;
		case RAP_RMT_CLOSE:
			r_socket_read_block (rap_s->fd, &rap_s->buf[1], 4);
			r_mem_copyendian ((ut8 *)&i, &rap_s->buf[1], 4, !endian);
			rap_s->close (rap_s->user, i);
			rap_s->buf[0] = RAP_RMT_CLOSE | RAP_RMT_REPLY;
			r_socket_write (rap_s->fd, rap_s->buf, 5);
			r_socket_flush (rap_s->fd);
			break;
		default:
			eprintf ("unknown command 0x%02x\n", \
				(unsigned int)(unsigned char)rap_s->buf[0]);
			r_socket_close (rap_s->fd);
			ret = -1;
			break;
	}
	return ret;
}
