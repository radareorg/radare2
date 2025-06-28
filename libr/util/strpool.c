/* radare - LGPL - Copyright 2025 - pancake */

#include <r_util.h>

R_API RStrpool * R_NULLABLE r_strpool_new(void) {
	RStrpool *p = R_NEW0 (RStrpool);
	p->size = 128;
	p->isize = 16;
	p->str = malloc (p->size);
	p->idxs = calloc (sizeof (p->idxs[0]), p->isize);
	if (p->str && p->idxs) {
		p->str[0] = 0;
		p->bloom = r_bloom_new (1024, 2, NULL);
		if (!p->bloom) {
			free (p->str);
			free (p->idxs);
			R_FREE (p);
		}
	} else {
		free (p->idxs);
		free (p->str);
		R_FREE (p);
	}
	return p;
}

static char *strpool_alloc(RStrpool *p, int l) {
	R_RETURN_VAL_IF_FAIL (p, NULL);
	char *ret = p->str + p->len;
	if ((p->len + l) >= p->size) {
		ut64 osize = p->size;
		if (l >= R_STRPOOL_INC) {
			p->size += l + R_STRPOOL_INC;
		} else {
			p->size += R_STRPOOL_INC;
		}
		if (p->size < osize) {
			p->size = osize;
			return NULL;
		}
		ret = realloc (p->str, p->size);
		if (!ret) {
			free (p->str);
			p->str = NULL;
			return NULL;
		}
		p->str = ret;
		ret += p->len;
	}
	p->len += l;
	return ret;
}

static bool strpool_resize_count(RStrpool *p) {
	R_RETURN_VAL_IF_FAIL (p, false);
	if (p->count + 8 >= p->isize) {
		const size_t ns = p->isize + 32;
		ut32 *ni = realloc (p->idxs, (sizeof (int) * ns));
		if (ni) {
			p->idxs = ni;
			p->isize = ns;
		} else {
			return false;
		}
	}
	return true;
}

static int strpool_memcat(RStrpool *p, const char *s, int len) {
	char *ptr = strpool_alloc (p, len);
	if (!ptr) {
		return -1;
	}
	memcpy (ptr, s, len);
	return (size_t)(ptr - p->str);
}

R_API void r_strpool_empty(RStrpool *p) {
	p->size = 128;
	p->isize = 128;
	p->count = 0;
	p->len = 0;
	free (p->str);
	p->str = malloc (p->size);
	free (p->idxs);
	p->idxs = calloc (sizeof (p->idxs[0]), p->isize);
}

R_API void r_strpool_slice(RStrpool *p, int index) {
	char *pos = r_strpool_get_nth (p, index);
	if (pos) {
		p->count = index; // or index -1 ?
		// TODO: shrink string allocation too?
	}
}

R_API int r_strpool_add(RStrpool *p, const char *s) {
	R_RETURN_VAL_IF_FAIL (p && s, -1);
	if (!r_bloom_check (p->bloom, s, strlen (s))) {
		return r_strpool_append (p, s);
	}
	const int pos = r_strpool_get (p, s);
	if (pos >= 0) {
		return pos;
	}
	return r_strpool_append (p, s);
}

R_API int r_strpool_append(RStrpool *p, const char *s) {
	R_RETURN_VAL_IF_FAIL (p && s, -1);
	const int l = strlen (s) + 1;
	const int idx = strpool_memcat (p, s, l);
	if (idx < 0) {
		return -1;
	}
	r_bloom_add (p->bloom, s, l - 1);
	if (!strpool_resize_count (p)) {
		return -1;
	}
	int pos = p->count;
	p->idxs[p->count] = idx;
	p->count++;
	return pos;
}

R_API void r_strpool_free(RStrpool *p) {
	if (R_LIKELY (p)) {
		r_bloom_free (p->bloom);
		free (p->str);
		free (p->idxs);
		free (p);
	}
}

R_API char *r_strpool_get_at(RStrpool *p, int index) {
	R_RETURN_VAL_IF_FAIL (p && p->str && index >= 0, NULL);
	return (index < 0 || index >= p->len) ? NULL : p->str + index;
}

R_API char *r_strpool_get_nth(RStrpool *p, int index) {
	R_RETURN_VAL_IF_FAIL (p, NULL);
	if (index < 0 || index >= p->count) {
		return NULL;
	}
	return p->str + p->idxs[index];
}

R_API int r_strpool_get(RStrpool *p, const char *w) {
	int i;
	// XXX this is O(n) - must be optimized with an skiparray or hashtable
	for (i = 0; i < p->count; i++) {
		const char *v = r_strpool_get_nth (p, i);
		if (!strcmp (v, w)) {
			return i;
		}
	}
	return -1;
}
