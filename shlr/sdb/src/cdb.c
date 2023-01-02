/* Public domain - author D. J. Bernstein, modified by pancake - 2014-2016 */

#include <sys/stat.h>
#include "sdb/cdb.h"
#include "sdb/heap.h"
#if USE_MMAN
#include <sys/mman.h>
#endif

/* XXX: this code must be rewritten . too slow */
bool cdb_getkvlen(struct cdb *c, ut32 *klen, ut32 *vlen, ut32 pos) {
	ut8 buf[4] = { 0 };
	*klen = *vlen = 0;
	if (!cdb_read (c, (char *)buf, sizeof (buf), pos)) {
		return false;
	}
	*klen = (ut32)buf[0];
	*vlen = (ut32)(buf[1] | ((ut32)buf[2] << 8) | ((ut32)buf[3] << 16));
	if (*vlen > CDB_MAX_VALUE) {
		*vlen = CDB_MAX_VALUE; // untaint value for coverity
		return false;
	}
	return true;
}

void cdb_free(struct cdb *c) {
	if (!c->map) {
		return;
	}
#if USE_MMAN
	(void)munmap (c->map, c->size);
#else
	sdb_gh_free (c->map);
#endif
	c->map = NULL;
}

void cdb_findstart(struct cdb *c) {
	c->loop = 0;
#if !USE_MMAN
	if (c->fd != -1) {
		lseek (c->fd, 0, SEEK_SET);
	}
#endif
}

bool cdb_init(struct cdb *c, int fd) {
	struct stat st;
	if (fd != c->fd && c->fd != -1) {
		close (c->fd);
	}
	c->fd = fd;
	cdb_findstart (c);
	if (fd != -1 && !fstat (fd, &st) && st.st_size > 4 && st.st_size != (off_t)UT64_MAX) {
#if USE_MMAN
		char *x = (char *)mmap (0, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
		if (x == MAP_FAILED) {
			// eprintf ("Cannot mmap %d\n", (int)st.st_size);
			return false;
		}
		if (c->map) {
			munmap (c->map, c->size);
		}
#else
		char *x = sdb_gh_calloc (1, st.st_size);
		if (!x) {
			// eprintf ("Cannot malloc %d\n", (int)st.st_size);
			return false;
		}
		/* TODO: read by chunks instead of a big huge syscall */
		if (read (fd, x, st.st_size) != st.st_size) {
			/* handle read error */
		}
		sdb_gh_free (c->map);
#endif
		c->map = x;
		c->size = st.st_size;
		return true;
	}
	c->map = NULL;
	c->size = 0;
	return false;
}

bool cdb_read(struct cdb *c, char *buf, ut32 len, ut32 pos) {
	if (c->map) {
		if ((pos > c->size) || (c->size - pos < len)) {
			return false;
		}
		if (!buf) {
			return false;
		}
		memcpy (buf, c->map + pos, len);
		return true;
	}
	if (c->fd == -1 || !seek_set (c->fd, pos)) {
		return false;
	}
	while (len > 0) {
		int r = (int)read (c->fd, buf, len);
		if (r < 1 || (ut32)r != len) {
			return false;
		}
		buf += r;
		len -= r;
	}
	return true;
}

static int match(struct cdb *c, const char *key, ut32 len, ut32 pos) {
	char buf[32];
	const size_t szb = sizeof buf;
	while (len > 0) {
		int n = (szb > len)? len: szb;
		if (!cdb_read (c, buf, n, pos)) {
			return -1;
		}
		if (memcmp (buf, key, n)) {
			return 0;
		}
		pos += n;
		key += n;
		len -= n;
	}
	return 1;
}

int cdb_findnext(struct cdb *c, ut32 u, const char *key, ut32 len) {
	char buf[8];
	ut32 pos;
	int m;
	len++;
	if (c->fd == -1) {
		return -1;
	}
	c->hslots = 0;
	if (!c->loop) {
		const int bufsz = ((u + 1) & 0xFF) ? sizeof (buf) : sizeof (buf) / 2;
		if (!cdb_read (c, buf, bufsz, (u << 2) & 1023)) {
			return -1;
		}
		/* hslots = (hpos_next - hpos) / 8 */
		ut32_unpack (buf, &c->hpos);
		if (bufsz == sizeof (buf)) {
			ut32_unpack (buf + 4, &pos);
		} else {
			pos = c->size;
		}
		if (pos < c->hpos) {
			return -1;
		}
		c->hslots = (pos - c->hpos) / (2 * sizeof (ut32));
		if (!c->hslots) {
			return 0;
		}
		c->khash = u;
		u = ((u >> 8) % c->hslots) << 3;
		c->kpos = c->hpos + u;
	}
	while (c->loop < c->hslots) {
		if (!cdb_read (c, buf, sizeof (buf), c->kpos)) {
			return 0;
		}
		ut32_unpack (buf + 4, &pos);
		if (!pos) {
			return 0;
		}
		c->loop++;
		c->kpos += sizeof (buf);
		if (c->kpos == c->hpos + (c->hslots << 3)) {
			c->kpos = c->hpos;
		}
		ut32_unpack (buf, &u);
		if (u == c->khash) {
			if (!cdb_getkvlen (c, &u, &c->dlen, pos) || !u) {
				return -1;
			}
			if (u == len) {
				if ((m = match (c, key, len, pos + KVLSZ)) == -1) {
					return 0;
				}
				if (m == 1) {
					c->dpos = pos + KVLSZ + len;
					return 1;
				}
			}
		}
	}
	return 0;
}
