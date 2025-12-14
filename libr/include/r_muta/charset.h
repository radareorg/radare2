/* radare - MIT - Copyright 2025 - pancake */

#ifndef R2_MUTA_CHARSET_H
#define R2_MUTA_CHARSET_H

#include <r_muta.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#define R_MUTA_CHARSET_MAX_BYTES 8

typedef struct {
	const char *utf8;
	ut8 bytes[R_MUTA_CHARSET_MAX_BYTES];
	ut8 byte_count;
} RMutaCharsetMap;

static inline const ut8 *r_muta_charset_lookup_encode(
	const RMutaCharsetMap *table, const char *utf8, int *out_len) {
	if (!table || !utf8 || !out_len) {
		return NULL;
	}
	for (; table->utf8; table++) {
		if (!strcmp (table->utf8, utf8)) {
			*out_len = (int)table->byte_count;
			return table->bytes;
		}
	}
	return NULL;
}

static inline const char *r_muta_charset_lookup_decode(
	const RMutaCharsetMap *table, const ut8 *bytes, int bytes_len, int *consumed) {
	int best_len = 0;
	const char *best = NULL;
	if (consumed) {
		*consumed = 0;
	}
	if (!table || !bytes || bytes_len < 1 || !consumed) {
		return NULL;
	}
	for (; table->utf8; table++) {
		const int clen = (int)table->byte_count;
		if (clen < 1 || clen > bytes_len || clen > R_MUTA_CHARSET_MAX_BYTES) {
			continue;
		}
		if (!memcmp (table->bytes, bytes, clen)) {
			if (clen > best_len) {
				best_len = clen;
				best = table->utf8;
			}
		}
	}
	*consumed = best_len;
	return best;
}

typedef int (*RMutaCharsetParserFn)(const char *str, const char *end,
	char *token, int token_max);

R_API int r_muta_charset_parse_default(const char *str, const char *end,
	char *token, int token_max);

R_API ut8 *r_muta_charset_decode(const ut8 *in, int in_len, int *out_len,
	const RMutaCharsetMap *table, const char *unknown_fmt);

R_API ut8 *r_muta_charset_encode(const ut8 *in, int in_len, int *out_len,
	const RMutaCharsetMap *table, RMutaCharsetParserFn parser);

R_API ut8 *r_muta_charset_encode_ex(const ut8 *in, int in_len, int *out_len,
	const RMutaCharsetMap *table, RMutaCharsetParserFn parser, ut8 unknown_byte);

R_API bool r_muta_charset_stub_update(RMutaSession *cj, const ut8 *b, int l);
R_API bool r_muta_charset_stub_end(RMutaSession *cj, const ut8 *b, int l);

#ifdef __cplusplus
}
#endif

#endif
