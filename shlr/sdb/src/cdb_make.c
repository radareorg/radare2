/* Public domain. */

#include <stdio.h>
#include <stdlib.h>
#include "sdb.h"
#include "cdb.h"
#include "cdb_make.h"

#define ALIGNMENT sizeof (void*)

char *cdb_alloc(ut32 n) {
#if __APPLE__ && !__POWERPC__
	void *ret = NULL;
	return posix_memalign (&ret, ALIGNMENT, n)? NULL: ret;
#elif __SDB_WINDOWS__ && !__CYGWIN__
	return _aligned_malloc (n, ALIGNMENT);
#else
	return malloc (n);
#endif
}

void cdb_alloc_free(void *x) {
#if __SDB_WINDOWS__ && !__CYGWIN__
	_aligned_free (x);
#else
	free (x);
#endif
}

int cdb_make_start(struct cdb_make *c, int fd) {
	int i;
	c->head = 0;
	c->split = 0;
	c->hash = 0;
	c->numentries = 0;
	c->fd = fd;
	c->pos = sizeof (c->final);
	buffer_init (&c->b, (BufferOp)write, fd, c->bspace, sizeof (c->bspace));
	c->memsize = 1;
	for (i = 0; i < 256; i++) {
		c->count[i] = 0;
	}
	return seek_set (fd, c->pos);
}

static inline int incpos(struct cdb_make *c, ut32 len) {
	ut32 newpos = c->pos + len;
	if (newpos < len) {
		return 0;
	}
	c->pos = newpos;
	return 1;
}

#define R_ANEW(x) (x*)cdb_alloc(sizeof(x))
int cdb_make_addend(struct cdb_make *c, ut32 keylen, ut32 datalen, ut32 h) {
	ut32 u;
	struct cdb_hplist *head = c->head;
	if (!head || (head->num >= CDB_HPLIST)) {
		if (!(head = R_ANEW (struct cdb_hplist))) {
			return 0;
		}
		head->num = 0;
		head->next = c->head;
		c->head = head;
	}
	head->hp[head->num].h = h;
	head->hp[head->num].p = c->pos;
	head->num++;
	c->numentries++;
	c->count[255 & h] ++;
	u = c->count[255 & h] * 2;
	if (u > c->memsize) {
		c->memsize = u;
	}
	return incpos (c, KVLSZ + keylen + datalen);
}

static int pack_kvlen(ut8 *buf, ut32 klen, ut32 vlen) {
	if (klen > SDB_MAX_KEY) {
		return 0; // 0xff = 254 chars+trailing zero
	}
	if (vlen >= SDB_MAX_VALUE) {
		return 0;
	}
	buf[0] = (ut8)klen;
	buf[1] = (ut8)((vlen      ) & 0xff);
	buf[2] = (ut8)((vlen >> 8 ) & 0xff);
	buf[3] = (ut8)((vlen >> 16) & 0xff);
	return 1;
}

int cdb_make_addbegin(struct cdb_make *c, ut32 keylen, ut32 datalen) {
	ut8 buf[KVLSZ];
	if (!pack_kvlen (buf, keylen, datalen)) {
		return 0;
	}
	return buffer_putalign (&c->b, (const char *)buf, KVLSZ);
}

int cdb_make_add(struct cdb_make *c, const char *key, ut32 keylen, const char *data, ut32 datalen) {
	/* add tailing \0 to allow mmap to work later */
	keylen++;
	datalen++;
	if (!cdb_make_addbegin (c, keylen, datalen)) {
		return 0;
	}
	if (!buffer_putalign (&c->b, key, keylen)) {
		return 0;
	}
	if (!buffer_putalign (&c->b, data, datalen)) {
		return 0;
	}
	return cdb_make_addend (c, keylen, datalen, sdb_hash (key));
}

int cdb_make_finish(struct cdb_make *c) {
	int i;
	char buf[8];
	struct cdb_hp *hp;
	struct cdb_hplist *x, *n;
	ut32 len, u, memsize, count, where;

	memsize = c->memsize + c->numentries;
	if (memsize > (UT32_MAX / sizeof (struct cdb_hp))) {
		return 0;
	}
	c->split = (struct cdb_hp *) cdb_alloc (memsize * sizeof (struct cdb_hp));
	if (!c->split) {
		return 0;
	}
	c->hash = c->split + c->numentries;

	for (u = i = 0; i<256; i++) {
		u += c->count[i]; /* bounded by numentries, so no overflow */
		c->start[i] = u;
	}

	for (x = c->head; x; x=x->next) {
		i = x->num;
		while (i--) {
			c->split[--c->start[255 & x->hp[i].h]] = x->hp[i];
		}
	}

	for (i = 0; i < 256; i++) {
		count = c->count[i];
		len = count << 1;
		ut32_pack (c->final + 4 * i, c->pos);
		for (u = 0; u<len; u++) {
			c->hash[u].h = c->hash[u].p = 0;
		}
		hp = c->split + c->start[i];
		for (u = 0; u < count; u++) {
			where = (hp->h >> 8) % len;
			while (c->hash[where].p) {
				if (++where == len) {
					where = 0;
				}
			}
			c->hash[where] = *hp++;
		}
		for (u = 0; u < len; u++) {
			ut32_pack (buf, c->hash[u].h);
			ut32_pack (buf + 4, c->hash[u].p);
			if (!buffer_putalign (&c->b, buf, 8)) {
				return 0;
			}
			if (!incpos (c, 8)) {
				return 0;
			}
		}
	}

	if (!buffer_flush (&c->b)) {
		return 0;
	}
	if (!seek_set (c->fd, 0)) {
		return 0;
	}
	// free childs
	for (x = c->head; x;) {
		n = x->next;
		cdb_alloc_free (x);
		x = n;
	}
	cdb_alloc_free (c->split);
	return buffer_putflush (&c->b, c->final, sizeof c->final);
}
