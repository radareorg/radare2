/* radare - LGPL - Copyright 2025 - pancake */

#include <r_util.h>

R_API R_NULLABLE RUStrpool* r_ustrpool_new(void) {
	RUStrpool *p = R_NEW0 (RUStrpool);
	p->size = 128;
	p->isize = 16;
	p->str = malloc (p->size);
	p->idxs = calloc (sizeof (p->idxs[0]), p->isize);
	if (p->str) {
		p->str[0] = 0;
		p->bloom = r_bloom_new (1024, 2, NULL);
		if (!p->bloom) {
			free (p->str);
			R_FREE (p);
		}
	} else {
		R_FREE (p);
	}
	return p;
}

// must be internal imho
static char *strpool_alloc(RUStrpool *p, int l) {
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

static bool strpool_resize_count(RUStrpool *p) {
	if (p->count + 8 < p->isize) {
		const size_t ns = p->isize + 32;
		ut32 *ni = realloc (p->idxs, ns);
		if (ni) {
			p->idxs = ni;
			p->isize += ns;
		} else {
			return false;
		}
	}
	return true;
}

// must be internal imho, we store strings not bytes. must be always nul terminated. or just rename to append_n
static int strpool_memcat(RUStrpool *p, const char *s, int len) {
	char *ptr = strpool_alloc (p, len);
	if (!ptr) {
		return -1;
	}
	memcpy (ptr, s, len);
	return (size_t)(ptr - p->str);
}

R_API int r_ustrpool_add(RUStrpool *p, const char *s) {
	R_RETURN_VAL_IF_FAIL (p && s, -1);
	if (!r_bloom_check (p->bloom, s, strlen (s))) {
		return r_ustrpool_append (p, s);
	}
	const int pos = r_ustrpool_get (p, s);
	if (pos >= 0) {
		return pos;
	}
	return r_ustrpool_append (p, s);
}

R_API int r_ustrpool_append(RUStrpool *p, const char *s) {
	R_RETURN_VAL_IF_FAIL (p && s, -1);
	const int l = strlen (s) + 1;
	const int idx = strpool_memcat (p, s, l);
	r_bloom_add (p->bloom, s, l - 1);
	p->idxs[p->count] = idx;
	int pos = p->count;
	p->count++;
	strpool_resize_count (p);
	return pos;
}

R_API void r_ustrpool_free(RUStrpool *p) {
	if (R_LIKELY (p)) {
		r_bloom_free (p->bloom);
		free (p->str);
		free (p);
	}
}

R_API char *r_ustrpool_get_at(RUStrpool *p, int index) {
	R_RETURN_VAL_IF_FAIL (p && p->str && index >= 0, NULL);
	return (index < 0 || index >= p->len) ? NULL : p->str + index;
}

R_API char *r_ustrpool_get_nth(RUStrpool *p, int index) {
	R_RETURN_VAL_IF_FAIL (p, NULL);
	if (index < 0 || index >= p->count) {
		return NULL;
	}
	return p->str + p->idxs[index];
}

R_API int r_ustrpool_get(RUStrpool *p, const char *w) {
	int i;
	// XXX this is O(n) - must be optimized with an skiparray or hashtable
	for (i = 0; i < p->count; i++) {
		const char *v = r_ustrpool_get_nth (p, i);
		if (!strcmp (v, w)) {
			return i;
		}
	}
	return -1;
}
