/* radare - LGPL - Copyright 2025 - pancake */

#include <r_util.h>

// a scan beats hashing for this many strings
#define STRPOOL_LINEAR_MAX 16
// slots keep the position in the low 24 bits and a hash tag in the high 8
#define STRPOOL_POS_MASK 0xffffff
#define STRPOOL_TAG(h) (((h) >> 24) | 1)

// seeded, eight bytes per round
static ut32 strpool_hash(RStrpool *p, const char *s) {
	const size_t len = strlen (s);
	ut64 h = p->seed ^ (len * 0x9e3779b97f4a7c15ULL);
	size_t i;
	for (i = 0; i + 8 <= len; i += 8) {
		h = (h ^ r_read_le64 (s + i)) * 0xff51afd7ed558ccdULL;
		h ^= h >> 32;
	}
	ut64 tail = 0;
	memcpy (&tail, s + i, len - i);
	h = (h ^ tail) * 0xc4ceb9fe1a85ec53ULL;
	h ^= h >> 29;
	return (ut32)h;
}

static void strpool_index_put(RStrpool *p, int pos, ut32 h) {
	const ut32 tag = STRPOOL_TAG (h);
	const ut32 mask = p->index_size - 1;
	ut32 i = h & mask;
	while (p->index[i]) {
		const ut32 slot = p->index[i];
		if ((slot >> 24) == tag) {
			const int first = (slot & STRPOOL_POS_MASK) - 1;
			if (!strcmp (p->str + p->idxs[first], p->str + p->idxs[pos])) {
				return;
			}
		}
		i = (i + 1) & mask;
	}
	p->index[i] = (tag << 24) | (ut32)(pos + 1);
}

static int strpool_find(RStrpool *p, const char *w, ut32 h) {
	const ut32 tag = STRPOOL_TAG (h);
	const ut32 mask = p->index_size - 1;
	ut32 i;
	for (i = h & mask; p->index[i]; i = (i + 1) & mask) {
		const ut32 slot = p->index[i];
		if ((slot >> 24) == tag) {
			const int pos = (slot & STRPOOL_POS_MASK) - 1;
			if (!strcmp (p->str + p->idxs[pos], w)) {
				return pos;
			}
		}
	}
	return -1;
}

static int strpool_find_linear(RStrpool *p, const char *w) {
	int i;
	for (i = 0; i < p->count; i++) {
		if (!strcmp (p->str + p->idxs[i], w)) {
			return i;
		}
	}
	return -1;
}

// make room for count strings, false when the pool is small or too large to be indexed
static bool strpool_index_fit(RStrpool *p, int count) {
	if (count < STRPOOL_LINEAR_MAX || count >= STRPOOL_POS_MASK) {
		R_FREE (p->index);
		p->index_size = 0;
		return false;
	}
	if (p->index && (ut64)count * 4 < (ut64)p->index_size * 3) {
		return true;
	}
	ut32 size = 64;
	while ((ut64)count * 4 >= (ut64)size * 3) {
		size *= 2;
	}
	ut32 *index = calloc (size, sizeof (ut32));
	free (p->index);
	p->index = index;
	p->index_size = index? size: 0;
	if (!index) {
		return false;
	}
	int i;
	for (i = 0; i < p->count; i++) {
		strpool_index_put (p, i, strpool_hash (p, p->str + p->idxs[i]));
	}
	return true;
}

R_API RStrpool * R_NULLABLE r_strpool_new(void) {
	RStrpool *p = R_NEW0 (RStrpool);
	p->size = 128;
	p->isize = 16;
	p->str = malloc (p->size);
	p->idxs = calloc (sizeof (p->idxs[0]), p->isize);
	if (p->str && p->idxs) {
		p->str[0] = 0;
		p->last = UT32_MAX;
		p->seed = (ut32)(size_t)p ^ (ut32)r_time_now ();
	} else {
		free (p->idxs);
		free (p->str);
		R_FREE (p);
	}
	return p;
}

static char *strpool_alloc(RStrpool *p, size_t l) {
	R_RETURN_VAL_IF_FAIL (p, NULL);
	const ut64 len = (ut64)p->len + l;
	if (len >= (ut64)p->size) {
		// len and size are int offsets
		if (len >= ST32_MAX) {
			return NULL;
		}
		const ut64 size = R_MIN (R_MAX ((ut64)p->size * 2, len + R_STRPOOL_INC), ST32_MAX);
		char *str = realloc (p->str, size);
		if (!str) {
			return NULL;
		}
		p->str = str;
		p->size = size;
	}
	char *ret = p->str + p->len;
	p->len = len;
	return ret;
}

static bool strpool_resize_count(RStrpool *p) {
	R_RETURN_VAL_IF_FAIL (p, false);
	if (p->count + 8 >= p->isize) {
		const size_t ns = (size_t)p->isize * 2;
		ut32 *ni = r_array_resize (p->idxs, ns, sizeof (p->idxs[0]));
		if (ni) {
			p->idxs = ni;
			p->isize = ns;
		} else {
			return false;
		}
	}
	return true;
}

static int strpool_memcat(RStrpool *p, const char *s, size_t len) {
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
	p->last = UT32_MAX;
	free (p->str);
	p->str = malloc (p->size);
	free (p->idxs);
	p->idxs = calloc (sizeof (p->idxs[0]), p->isize);
	R_FREE (p->index);
}

R_API void r_strpool_slice(RStrpool *p, int index) {
	R_RETURN_IF_FAIL (p);
	char *pos = r_strpool_get_nth (p, index);
	if (pos) {
		p->count = index; // or index -1 ?
		p->last = UT32_MAX;
		// TODO: shrink string allocation too?
		R_FREE (p->index);
	}
}

R_API void r_strpool_slice_range(RStrpool *p, int idx_from, int idx_to) {
	R_RETURN_IF_FAIL (p);
	if (idx_from >= p->count || idx_from < 0) {
		return;
	}
	if (idx_to > p->count || idx_to < idx_from) {
		idx_to = p->count;
	}
	p->last = UT32_MAX;
	R_FREE (p->index);
	if (idx_from == 0) {
		// Just truncate from idx_to onwards
		p->count = idx_to;
		return;
	}
	int i, j;
	// Shift remaining items to the beginning
	for (i = idx_from, j = 0; i < idx_to; i++, j++) {
		p->idxs[j] = p->idxs[i];
	}
	p->count = j;
}

static int strpool_push(RStrpool *p, const char *s) {
	const size_t l = strlen (s) + 1;
	const int idx = strpool_memcat (p, s, l);
	if (idx < 0 || !strpool_resize_count (p)) {
		return -1;
	}
	p->idxs[p->count] = idx;
	return p->count++;
}

// dedup selects whether an existing copy is returned instead of appending
static int strpool_insert(RStrpool *p, const char *s, bool dedup) {
	if (!strpool_index_fit (p, p->count + 1)) {
		const int pos = dedup? strpool_find_linear (p, s): -1;
		return pos < 0? strpool_push (p, s): pos;
	}
	const ut32 h = strpool_hash (p, s);
	const int found = strpool_find (p, s, h);
	if (dedup && found >= 0) {
		return found;
	}
	const int pos = strpool_push (p, s);
	// appended duplicates keep resolving to the first position
	if (pos >= 0 && found < 0) {
		strpool_index_put (p, pos, h);
	}
	return pos;
}

R_API int r_strpool_add(RStrpool *p, const char *s) {
	R_RETURN_VAL_IF_FAIL (p && s, -1);
	if (p->last != UT32_MAX && !strcmp (p->str + p->idxs[p->last], s)) {
		return p->last;
	}
	const int pos = strpool_insert (p, s, true);
	p->last = (pos < 0)? UT32_MAX: (ut32)pos;
	return pos;
}

R_API int r_strpool_append(RStrpool *p, const char *s) {
	R_RETURN_VAL_IF_FAIL (p && s, -1);
	if (!p->index) {
		return strpool_push (p, s);
	}
	return strpool_insert (p, s, false);
}

R_API void r_strpool_free(RStrpool *p) {
	if (R_LIKELY (p)) {
		free (p->index);
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

// drop the index while no strings are added, the next lookup builds it again
R_API void r_strpool_lock(RStrpool *p) {
	R_RETURN_IF_FAIL (p);
	R_FREE (p->index);
	p->index_size = 0;
}

R_API int r_strpool_get(RStrpool *p, const char *w) {
	R_RETURN_VAL_IF_FAIL (p && w, -1);
	if (strpool_index_fit (p, p->count)) {
		return strpool_find (p, w, strpool_hash (p, w));
	}
	return strpool_find_linear (p, w);
}
