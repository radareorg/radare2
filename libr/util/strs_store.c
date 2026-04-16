/* radare - LGPL - Copyright 2026 - pancake */

#include <r_util.h>

#define STORE_BASE_INIT 256
#define STORE_ENTRIES_INIT 16

R_API RStrsStore *r_strs_store_new(void) {
	RStrsStore *ss = R_NEW0 (RStrsStore);
	if (R_LIKELY (ss)) {
		ss->base = malloc (STORE_BASE_INIT);
		ss->entries = malloc (STORE_ENTRIES_INIT * sizeof (RStrsEntry));
		if (ss->base && ss->entries) {
			ss->base_cap = STORE_BASE_INIT;
			ss->cap = STORE_ENTRIES_INIT;
		} else {
			free (ss->base);
			free (ss->entries);
			R_FREE (ss);
		}
	}
	return ss;
}

R_API int r_strs_store_add(RStrsStore *ss, const char *s, int len) {
	R_RETURN_VAL_IF_FAIL (ss && s, -1);
	if (len < 0) {
		len = strlen (s);
	}
	if (ss->base_len + len > ss->base_cap) {
		ut32 need = ss->base_len + len;
		ut32 nc = ss->base_cap;
		while (nc < need) {
			nc *= 2;
		}
		char *nb = realloc (ss->base, nc);
		if (!nb) {
			return -1;
		}
		ss->base = nb;
		ss->base_cap = nc;
	}
	if (ss->count >= ss->cap) {
		ut32 nc = ss->cap * 2;
		RStrsEntry *ne = realloc (ss->entries, nc * sizeof (RStrsEntry));
		if (!ne) {
			return -1;
		}
		ss->entries = ne;
		ss->cap = nc;
	}
	memcpy (ss->base + ss->base_len, s, len);
	RStrsEntry e = { ss->base_len, (ut32)len };
	ut32 idx = ss->count;
	ss->entries[idx] = e;
	ss->base_len += len;
	ss->count++;
	return (int)idx;
}

R_API void r_strs_store_seal(RStrsStore *ss) {
	R_RETURN_IF_FAIL (ss);
	if (ss->base_cap > ss->base_len) {
		char *nb = realloc (ss->base, ss->base_len? ss->base_len: 1);
		if (nb) {
			ss->base = nb;
			ss->base_cap = ss->base_len;
		}
	}
	if (ss->cap > ss->count) {
		RStrsEntry *ne = realloc (ss->entries, ss->count? ss->count * sizeof (RStrsEntry): sizeof (RStrsEntry));
		if (ne) {
			ss->entries = ne;
			ss->cap = ss->count;
		}
	}
}

R_API void r_strs_store_free(RStrsStore *ss) {
	if (ss) {
		free (ss->base);
		free (ss->entries);
		free (ss);
	}
}

R_API RStrsStore *r_strs_store_from_entries(const char *buf, ut32 buf_len, const RStrsEntry *entries, ut32 count) {
	R_RETURN_VAL_IF_FAIL (buf && entries, NULL);
	RStrsStore *ss = R_NEW0 (RStrsStore);
	if (!ss) {
		return NULL;
	}
	ss->base = malloc (buf_len? buf_len: 1);
	ss->entries = malloc (count? count * sizeof (RStrsEntry): sizeof (RStrsEntry));
	if (!ss->base || !ss->entries) {
		free (ss->base);
		free (ss->entries);
		free (ss);
		return NULL;
	}
	memcpy (ss->base, buf, buf_len);
	memcpy (ss->entries, entries, count * sizeof (RStrsEntry));
	ss->base_len = buf_len;
	ss->base_cap = buf_len;
	ss->count = count;
	ss->cap = count;
	return ss;
}

/* UTF-16LE helpers (static) */

static size_t utf16le_to_utf8_len(const ut8 *src, size_t code_units) {
	size_t len = 0;
	size_t i;
	for (i = 0; i < code_units; i++) {
		ut16 c = src[i * 2] | ((ut16)src[i * 2 + 1] << 8);
		if (c < 0x80) {
			len++;
		} else if (c < 0x800) {
			len += 2;
		} else if (c >= 0xD800 && c <= 0xDBFF && i + 1 < code_units) {
			ut16 c2 = src[(i + 1) * 2] | ((ut16)src[(i + 1) * 2 + 1] << 8);
			if (c2 >= 0xDC00 && c2 <= 0xDFFF) {
				len += 4;
				i++;
			} else {
				len += 3;
			}
		} else {
			len += 3;
		}
	}
	return len;
}

static size_t utf16le_to_utf8_write(const ut8 *src, size_t code_units, char *dst) {
	size_t pos = 0;
	size_t i;
	for (i = 0; i < code_units; i++) {
		ut16 c = src[i * 2] | ((ut16)src[i * 2 + 1] << 8);
		if (c < 0x80) {
			dst[pos++] = (char)c;
		} else if (c < 0x800) {
			dst[pos++] = (char)(0xC0 | (c >> 6));
			dst[pos++] = (char)(0x80 | (c & 0x3F));
		} else if (c >= 0xD800 && c <= 0xDBFF && i + 1 < code_units) {
			ut16 c2 = src[(i + 1) * 2] | ((ut16)src[(i + 1) * 2 + 1] << 8);
			if (c2 >= 0xDC00 && c2 <= 0xDFFF) {
				ut32 cp = 0x10000 + ((ut32)(c - 0xD800) << 10) + (c2 - 0xDC00);
				dst[pos++] = (char)(0xF0 | (cp >> 18));
				dst[pos++] = (char)(0x80 | ((cp >> 12) & 0x3F));
				dst[pos++] = (char)(0x80 | ((cp >> 6) & 0x3F));
				dst[pos++] = (char)(0x80 | (cp & 0x3F));
				i++;
			} else {
				dst[pos++] = (char)0xEF;
				dst[pos++] = (char)0xBF;
				dst[pos++] = (char)0xBD;
			}
		} else if (c >= 0xDC00 && c <= 0xDFFF) {
			dst[pos++] = (char)0xEF;
			dst[pos++] = (char)0xBF;
			dst[pos++] = (char)0xBD;
		} else {
			dst[pos++] = (char)(0xE0 | (c >> 12));
			dst[pos++] = (char)(0x80 | ((c >> 6) & 0x3F));
			dst[pos++] = (char)(0x80 | (c & 0x3F));
		}
	}
	return pos;
}

R_API RStrsStore *r_strs_store_from_utf16le(const ut8 *src, ut32 src_len, const RStrsEntry *src_entries, ut32 count) {
	R_RETURN_VAL_IF_FAIL (src && src_entries, NULL);
	ut32 i;
	ut32 total = 0;
	for (i = 0; i < count; i++) {
		ut32 soff = src_entries[i].off;
		ut32 slen = src_entries[i].len;
		if (soff + slen > src_len) {
			slen = (soff < src_len)? src_len - soff: 0;
		}
		total += (ut32)utf16le_to_utf8_len (src + soff, slen / 2);
	}
	RStrsStore *ss = R_NEW0 (RStrsStore);
	if (!ss) {
		return NULL;
	}
	ss->base = malloc (total? total: 1);
	ss->entries = malloc (count? count * sizeof (RStrsEntry): sizeof (RStrsEntry));
	if (!ss->base || !ss->entries) {
		free (ss->base);
		free (ss->entries);
		free (ss);
		return NULL;
	}
	ut32 pos = 0;
	for (i = 0; i < count; i++) {
		ut32 soff = src_entries[i].off;
		ut32 slen = src_entries[i].len;
		if (soff + slen > src_len) {
			slen = (soff < src_len)? src_len - soff: 0;
		}
		ut32 utf8_len = (ut32)utf16le_to_utf8_write (src + soff, slen / 2, ss->base + pos);
		RStrsEntry e = { pos, utf8_len };
		ss->entries[i] = e;
		pos += utf8_len;
	}
	ss->base_len = pos;
	ss->base_cap = total;
	ss->count = count;
	ss->cap = count;
	return ss;
}
