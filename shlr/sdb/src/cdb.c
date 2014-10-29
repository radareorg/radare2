/* Public domain - author D. J. Bernstein, modified by pancake - 2014 */

#include <sys/types.h>
#include <sys/stat.h>
#include "cdb.h"

#if USE_MMAN
#include <sys/mman.h>
#endif

/* XXX: this code must be rewritten . too slow */
int cdb_getkvlen(int fd, ut32 *klen, ut32 *vlen) {
	ut8 buf[4];
	*klen = *vlen = 0;
	if (fd == -1 || read (fd, buf, 4) != 4)
		return 0;
	*klen = (ut32)buf[0];
	*vlen = (ut32)(buf[1] + ((ut32)buf[2]<<8) + ((ut32)buf[3]<<16));
	return 1;
}

void cdb_free(struct cdb *c) {
	if (!c->map) return;
#if USE_MMAN
	munmap (c->map, c->size);
#else
	free (c->map);
#endif
	c->map = NULL;
}

void cdb_findstart(struct cdb *c) {
	c->loop = 0;
}

void cdb_init(struct cdb *c, int fd) {
	struct stat st;
	c->map = NULL;
	c->fd = fd;
	cdb_findstart (c);
	if (fd != -1 && !fstat (fd, &st) && st.st_size>4 && st.st_size != (off_t)UT32_MAX) {
#if USE_MMAN
		char *x = mmap (0, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
#else
		char *x = malloc (st.st_size);
		if (!x) return;
		read (fd, x, st.st_size); // TODO: handle return value
#endif
		if (x + 1) {
			c->size = st.st_size;
			c->map = x;
		}
	}
}

int cdb_read(struct cdb *c, char *buf, ut32 len, ut32 pos) {
	if (c->map) {
		if ((pos > c->size) || (c->size - pos < len))
			return 0;
		memcpy (buf, c->map + pos, len);
		return 1;
	}
	if (!seek_set (c->fd, pos))
		return 0;
	while (len > 0) {
		ssize_t r = read (c->fd, buf, len);
		if (r != len) return 0;
		buf += r;
		len -= r;
	}
	return 1;
}

static int match(struct cdb *c, const char *key, ut32 len, ut32 pos) {
	char buf[32];
	const size_t szb = sizeof buf;
	while (len > 0) {
		int n = (szb>len)? len: szb;
		if (!cdb_read (c, buf, n, pos))
			return -1;
		if (memcmp (buf, key, n))
			return 0;
		pos += n;
		key += n;
		len -= n;
	}
	return 1;
}

int cdb_findnext(struct cdb *c, ut32 u, const char *key, unsigned int len) {
	char buf[8];
	ut32 pos;
	int m;

	c->hslots = 0;
	if (!c->loop) {
		if (!cdb_read (c, buf, 8, (u << 3) & 2047))
			return -1;
		ut32_unpack (buf + 4, &c->hslots);
		if (!c->hslots)
			return 0;
		ut32_unpack (buf, &c->hpos);
		c->khash = u;
		u = ((u>>8)%c->hslots)<<3;
		c->kpos = c->hpos + u;
	}
	while (c->loop < c->hslots) {
		if (!cdb_read (c, buf, 8, c->kpos))
			return 0;
		ut32_unpack (buf + 4, &pos);
		if (!pos) return 0;
		c->loop++;
		c->kpos += 8;
		if (c->kpos == c->hpos + (c->hslots << 3))
			c->kpos = c->hpos;
		ut32_unpack (buf, &u);
		if (u == c->khash) {
			if (!seek_set (c->fd, pos))
				return -1;
			if (!cdb_getkvlen (c->fd, &u, &c->dlen))
				return -1;
			if (u == 0)
				return -1;
			if (u == len) {
				if ((m = match (c, key, len, pos + KVLSZ))==-1)
					return 0;
				if (m == 1) {
					c->dpos = pos + KVLSZ + len;
					return 1;
				}
			}
		}
	}
	return 0;
}
