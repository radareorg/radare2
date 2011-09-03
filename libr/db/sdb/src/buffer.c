/* Public Domain */

#include "buffer.h"

void buffer_init(buffer *s, BufferOp op, int fd, char *buf, ut32 len) {
	s->x = buf;
	s->fd = fd;
	s->op = op;
	s->p = 0;
	s->n = len;
}

static int allwrite(BufferOp op, int fd, const char *buf, ut32 len) {
	int w;
	while (len) {
		if ((w = op (fd, buf, len)) != len)
			return 0;
		buf += w;
		len -= w;
	}
	return 1;
}

int buffer_flush(buffer *s) {
	int p = s->p;
	if (!p) return 1;
	s->p = 0;
	return allwrite (s->op, s->fd, s->x, p);
}

int buffer_putalign(buffer *s, const char *buf, ut32 len) {
	ut32 n;
	while (len > (n = s->n - s->p)) {
		byte_copy (s->x + s->p, n, buf);
		s->p += n; buf += n; len -= n;
		if (!buffer_flush (s)) return 0;
	}
	/* now len <= s->n - s->p */
	byte_copy (s->x + s->p, len, buf);
	s->p += len;
	return 1;
}

int buffer_putflush(buffer *s, const char *buf, ut32 len) {
	if (!buffer_flush (s)) return 0;
	return allwrite (s->op, s->fd, buf, len);
}
