/* radare - LGPL - Copyright 2026 - pancake */

#include <r_util.h>

R_API RStrsStore *r_strs_store_new(ut32 capacity) {
	RStrsStore *ss = R_NEW0 (RStrsStore);
	ut32 ecap = capacity? capacity: 16;
	ut32 bcap = ecap * 16;
	ss->base = malloc (bcap);
	ss->entries = malloc (ecap * sizeof (RStrsEntry));
	if (!ss->base || !ss->entries) {
		r_strs_store_free (ss);
		return NULL;
	}
	ss->base_cap = bcap;
	ss->cap = ecap;
	return ss;
}

R_API int r_strs_store_add(RStrsStore *ss, const char *s, int len) {
	R_RETURN_VAL_IF_FAIL (ss && s && !ss->borrowed_base, -1);
	if (len < 0) {
		len = strlen (s);
	}
	ut32 need;
	if (r_add_overflow (ss->base_len, (ut32)len, &need)) {
		return -1;
	}
	if (need > ss->base_cap) {
		ut32 nc;
		if (r_mul_overflow (need, (ut32)2, &nc)) {
			return -1;
		}
		char *nb = realloc (ss->base, nc);
		if (!nb) {
			return -1;
		}
		ss->base = nb;
		ss->base_cap = nc;
	}
	if (ss->count >= ss->cap) {
		ut32 nc;
		if (r_mul_overflow (ss->cap, (ut32)2, &nc)) {
			return -1;
		}
		RStrsEntry *ne = realloc (ss->entries, nc * sizeof (RStrsEntry));
		if (!ne) {
			return -1;
		}
		ss->entries = ne;
		ss->cap = nc;
	}
	memcpy (ss->base + ss->base_len, s, len);
	ut32 idx = ss->count++;
	ss->entries[idx] = (RStrsEntry){ ss->base_len, (ut32)len };
	ss->base_len += len;
	return (int)idx;
}

R_API void r_strs_store_seal(RStrsStore *ss) {
	R_RETURN_IF_FAIL (ss);
	if (!ss->borrowed_base && ss->base_cap > ss->base_len && ss->base_len > 0) {
		char *nb = realloc (ss->base, ss->base_len);
		if (nb) {
			ss->base = nb;
			ss->base_cap = ss->base_len;
		}
	}
	if (ss->cap > ss->count && ss->count > 0) {
		RStrsEntry *ne = realloc (ss->entries, ss->count * sizeof (RStrsEntry));
		if (ne) {
			ss->entries = ne;
			ss->cap = ss->count;
		}
	}
}

R_API void r_strs_store_free(RStrsStore *ss) {
	if (ss) {
		if (!ss->borrowed_base) {
			free (ss->base);
		}
		free (ss->entries);
		free (ss);
	}
}

R_API RStrsStore *r_strs_store_from_entries(const char *buf, ut32 buf_len, const RStrsEntry *entries, ut32 count) {
	R_RETURN_VAL_IF_FAIL (buf && entries, NULL);
	RStrsStore *ss = R_NEW0 (RStrsStore);
	ss->base = r_mem_dup (buf, buf_len? buf_len: 1);
	ss->entries = r_mem_dup (entries, count? count * sizeof (RStrsEntry): sizeof (RStrsEntry));
	if (!ss->base || !ss->entries) {
		r_strs_store_free (ss);
		return NULL;
	}
	ss->base_len = ss->base_cap = buf_len;
	ss->count = ss->cap = count;
	return ss;
}

R_API RStrsStore *r_strs_store_from_utf16le(const ut8 *src, ut32 src_len, const RStrsEntry *src_entries, ut32 count) {
	R_RETURN_VAL_IF_FAIL (src && src_entries, NULL);
	/* worst case: each UTF-16 code unit (2 bytes) → 3 UTF-8 bytes */
	ut64 max64 = (ut64)(src_len / 2) * 3;
	if (max64 > UT32_MAX) {
		return NULL;
	}
	ut32 max_utf8 = (ut32)max64;
	RStrsStore *ss = r_strs_store_new (count);
	if (!ss) {
		return NULL;
	}
	/* ensure base buffer fits worst case */
	if (max_utf8 > ss->base_cap) {
		char *nb = realloc (ss->base, max_utf8);
		if (!nb) {
			r_strs_store_free (ss);
			return NULL;
		}
		ss->base = nb;
		ss->base_cap = max_utf8;
	}
	ut32 i, pos = 0;
	for (i = 0; i < count; i++) {
		ut32 soff = src_entries[i].off;
		ut32 slen = src_entries[i].len;
		if (soff > src_len) {
			soff = src_len;
			slen = 0;
		} else if (slen > src_len - soff) {
			slen = src_len - soff;
		}
		int n = r_str_utf16_to_utf8 ((ut8 *)ss->base + pos,
			ss->base_cap - pos, src + soff, slen, true);
		ut32 utf8_len = (n > 0)? (ut32)n: 0;
		ss->entries[i] = (RStrsEntry){ pos, utf8_len };
		pos += utf8_len;
	}
	ss->base_len = pos;
	ss->count = count;
	r_strs_store_seal (ss);
	return ss;
}

R_API RStrsStore *r_strs_store_split(const char *s, int len, const char *seps, bool trim) {
	R_RETURN_VAL_IF_FAIL (s && seps, NULL);
	if (len < 0) {
		len = strlen (s);
	}
	ut32 slen = (ut32)len;
	/* pre-count tokens: (number of separators) + 1 */
	ut32 tokens = 1;
	ut32 i;
	for (i = 0; i < slen; i++) {
		if (strchr (seps, s[i])) {
			tokens++;
		}
	}
	RStrsStore *ss = R_NEW0 (RStrsStore);
	ss->entries = malloc (tokens * sizeof (RStrsEntry));
	if (!ss->entries) {
		free (ss);
		return NULL;
	}
	ss->base = (char *)s;
	ss->base_len = ss->base_cap = slen;
	ss->cap = tokens;
	ss->borrowed_base = true;
	ut32 start = 0, idx = 0;
	for (i = 0; i <= slen; i++) {
		if (i < slen && !strchr (seps, s[i])) {
			continue;
		}
		ut32 off = start;
		ut32 tlen = i - start;
		if (trim) {
			while (tlen > 0 && isspace ((unsigned char)s[off])) {
				off++;
				tlen--;
			}
			while (tlen > 0 && isspace ((unsigned char)s[off + tlen - 1])) {
				tlen--;
			}
		}
		ss->entries[idx++] = (RStrsEntry){ off, tlen };
		start = i + 1;
	}
	ss->count = idx;
	return ss;
}
