#include <r_socket.h>
#include <string.h>


#define	RAP_BUF_FD	"/tmp/.out"
#define	RAP_BUF_FD_ERR	"Cannot open tmp-fd\n"

R_API RSocketRapServer *r_socket_rap_server_new (int is_ssl, const char *port)
{
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

R_API RSocketRapServer *r_socket_rap_server_create (char *pathname)
{
	char *port = NULL;
	int is_ssl;
	if (!pathname)
		return NULL;
	if (strlen (pathname) < 11)
		return NULL;
	if (strncmp (pathname, "rap", 3));
		return NULL;
	is_ssl = (pathname[3] == 's');
	port = &pathname[7 + is_ssl];
	return r_socket_rap_server_new (is_ssl, port);
}

R_API void r_socket_rap_server_free (RSocketRapServer *rap_s)
{
	if (rap_s)
		r_socket_free (rap_s->fd);
	free (rap_s);
}

R_API int r_socket_rap_server_listen (RSocketRapServer *rap_s, char *certfile)
{
	if (!rap_s || !rap_s->port)
		return R_FALSE;
	return r_socket_listen (rap_s->fd, rap_s->port, certfile);
}

R_API int r_socket_rap_server_accept (RSocketRapServer *rap_s)
{
	int ret = R_FALSE;
	ut8 *flg, *size;
	if (!rap_s || !rap_s->fd || !rap_s->open) {
		eprintf ("error: r_socket_rap_server_accept\n");
		return R_FALSE;
	}
	if (!r_socket_accept (rap_s->fd))
		return R_FALSE;
	ret = r_socket_read_block (rap_s->fd, rap_s->buf, 3);
	if (ret < 3)
		return R_FALSE;
	if (rap_s->buf[0] != RAP_RMT_OPEN)
		return R_FALSE;
	flg = &rap_s->buf[1];
	size = &rap_s->buf[2];
	ret = r_socket_read (rap_s->fd, &rap_s->buf[3], (int)*size);
	if (ret != (int)*size)
		return R_FALSE;
	ret = rap_s->open (rap_s->user, &rap_s->buf[3], (int)*flg, 0);
	rap_s->buf[0] = (RAP_RMT_REPLY|RAP_RMT_OPEN);
	r_socket_write (rap_s->fd, rap_s->buf, 1);
	r_socket_flush (rap_s->fd);
	return ret;
}

static inline int getEndian ()
{
	int e = 0;
	ut8 *n = (ut8 *)&e;
	*n = 0x1;
	return (e == 0x1);
}

R_API int r_socket_rap_server_continue (RSocketRapServer *rap_s)
{
	int endian, i, pipe_fd, ret;
	ut64 offset;
	if (	!rap_s || !rap_s->fd || !r_socket_is_connected (rap_s->fd) ||
		!(r_socket_read (rap_s->fd, rap_s->buf, 1) == 1))
		return R_FALSE;
	endian = getEndian();
	ret = rap_s->buf[0];
	switch (rap_s->buf[0]) {
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
			rap_s->buf[i+5] = '\0';
			fflush (stdout);
			pipe_fd = r_cons_pipe_open (RAP_BUF_FD, 1, 0);
			rap_s->system (rap_s->user, &rap_s->buf[5]);
			r_cons_pipe_close (pipe_fd);
			{
				FILE *fd = r_sandbox_fopen (RAP_BUF_FD, "r");
				char *out = NULL;
				i = 0;
				if (fd) {
					fseek (fd, 0, SEEK_END);
					i = ftell (fd);
					fclose (fd);
					out = r_file_slurp (RAP_BUF_FD, &i);
					out = realloc (out, i + 5);
				}
				if (out) {
					memmove (out+5, out, i);
					out[0] = RAP_RMT_SYSTEM | RAP_RMT_REPLY;
					r_mem_copyendian ((ut8 *)&out[1], (ut8 *)&i, 4, !endian);
					r_socket_write (rap_s->fd, out, i + 5);
					free (out);
					out = NULL;
				} else {
					i = strlen (RAP_BUF_FD_ERR);
					rap_s->buf[0] = RAP_RMT_SYSTEM | RAP_RMT_REPLY;
					r_mem_copyendian (&rap_s->buf[1], (ut8 *)&i, 4, !endian);
					strcpy (&rap_s->buf[5], RAP_BUF_FD_ERR);
					r_socket_write (rap_s->fd, rap_s->buf, i + 5);
				}
				r_socket_flush (rap_s->fd);
			}
			break;
		case RAP_RMT_CMD:
			r_socket_read_block (rap_s->fd, &rap_s->buf[1], 4);
			r_mem_copyendian ((ut8*)&i, &rap_s->buf[1], 4, !endian);
			r_socket_read_block (rap_s->fd, &rap_s->buf[5], i);
			rap_s->buf[i+5] = '\0';
			fflush (stdout);
			pipe_fd = r_cons_pipe_open (RAP_BUF_FD, 1, 0);
			rap_s->cmd (rap_s->user, &rap_s->buf[5]);
			r_cons_pipe_close (pipe_fd);
			{
				FILE *fd = r_sandbox_fopen (RAP_BUF_FD, "r");
				char *out = NULL;
				i = 0;
				if (fd) {
					fseek (fd, 0, SEEK_END);
					i = ftell (fd);
					fclose (fd);
					out = r_file_slurp (RAP_BUF_FD, &i);
					out = realloc (out, i + 5);
				}
				if (out) {
					memmove (out+5, out, i);
					out[0] = RAP_RMT_SYSTEM | RAP_RMT_REPLY;
					r_mem_copyendian ((ut8 *)&out[1], (ut8 *)&i, 4, !endian);
					r_socket_write (rap_s->fd, out, i + 5);
					free (out);
					out = NULL;
				} else {
					i = strlen (RAP_BUF_FD_ERR);
					rap_s->buf[0] = RAP_RMT_CMD | RAP_RMT_REPLY;
					r_mem_copyendian (&rap_s->buf[1], (ut8 *)&i, 4, !endian);
					strcpy (&rap_s->buf[5], RAP_BUF_FD_ERR);
					r_socket_write (rap_s->fd, rap_s->buf, i + 5);
				}
				r_socket_flush (rap_s->fd);
			}
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
			eprintf ("unknown command 0x%2hhx\n", rap_s->buf[0]);
			r_socket_close (rap_s->fd);
			ret = -1;
			break;
	}
	return ret;
}
