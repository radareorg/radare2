/* Public domain. */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include "cdb.h"

int getkvlen(int fd, ut32 *klen, ut32 *vlen) {
	char buf[4];
	if (read (fd, buf, 4) != 4)
		return 0;
	*klen = (ut32)buf[0];
	*vlen = (ut32)buf[1] + (buf[2]<<8) + (buf[3]<<16);
	return 1;
}

ut32 cdb_hashadd(ut32 h, ut8 c) {
	h += (h << 5);
	return h ^ c;
}

ut32 cdb_hash(const char *buf, ut32 len) {
	ut32 h = CDB_HASHSTART;
	while (len--)
		h = cdb_hashadd (h, *buf++);
	return h;
}

void cdb_free(struct cdb *c) {
	if (!c->map) return;
	munmap (c->map, c->size);
	c->map = NULL;
}

void cdb_findstart(struct cdb *c) {
	c->loop = 0;
}

void cdb_init(struct cdb *c, int fd) {
	struct stat st;
	c->map = NULL;
	cdb_findstart (c);
	c->fd = fd;
	if (!fstat (fd, &st) && st.st_size != UT32_MAX) {
		char *x = mmap (0, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
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
		byte_copy (buf, len, c->map + pos);
		return 1;
	}
	if (!seek_set (c->fd, pos))
		return 0;
	while (len > 0) {
		int r = read (c->fd, buf, len);
		if (r!=len) return 0;
		buf += r;
		len -= r;
	}
	return 1;
}

static int match(struct cdb *c, const char *key, ut32 len, ut32 pos) {
	char buf[32];
	const int szb = sizeof buf;
	while (len > 0) {
		int n = (szb>len)? len: szb;
		if (!cdb_read (c, buf, n, pos))
			return -1;
		if (byte_diff (buf, n, key))
			return 0;
		pos += n;
		key += n;
		len -= n;
	}
	return 1;
}

int cdb_findnext(struct cdb *c, ut32 u, const char *key,unsigned int len) {
	char buf[8];
	ut32 pos;

	if (!c->loop) {
		if (!cdb_read (c, buf, 8, (u << 3) & 2047))
			return -1;
		ut32_unpack (buf + 4, &c->hslots);
		if (!c->hslots) {
			return 0;
		}
		ut32_unpack (buf, &c->hpos);
		c->khash = u;
		u >>= 8;
		u %= c->hslots;
		u <<= 3;
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
			if (!getkvlen (c->fd, &u, &c->dlen))
				return -1;
			if (u == len) {
				int m = match (c, key, len, pos + KVLSZ);
				if (m == -1)
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
