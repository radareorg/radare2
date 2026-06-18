/* radare - LGPL - Copyright 2026 - pancake */

#include <limits.h>
#include <r_util.h>
#include <r_util/r_json.h>

static inline bool isvalid_jwtchar (char ch) {
	return isalnum (ch) || ch == '-' || ch == '_';
}

static bool jwt_segment_is_valid(const char *segment, size_t len) {
	bool pad = false;
	size_t i;
	for (i = 0; i < len; i++) {
		const char ch = segment[i];
		if (ch == '=') {
			pad = true;
			continue;
		}
		if (pad || !isvalid_jwtchar (ch)) {
			return false;
		}
	}
	return len > 0;
}

static ut8 *jwt_b64url_decode(const char *segment, size_t len, int *out_len) {
	if (out_len) {
		*out_len = 0;
	}
	if (!jwt_segment_is_valid (segment, len) || (len % 4) == 1) {
		return NULL;
	}
	const size_t padding = (4 - (len % 4)) % 4;
	size_t normalized_len = 0;
	if (r_add_overflow (len, padding, &normalized_len)
			|| normalized_len > (size_t)INT_MAX) {
		return NULL;
	}
	size_t normalized_size = 0;
	if (r_add_overflow (normalized_len, (size_t)1, &normalized_size)) {
		return NULL;
	}
	char *normalized = malloc (normalized_size);
	if (!normalized) {
		return NULL;
	}
	memcpy (normalized, segment, len);
	if (padding > 0) {
		memset (normalized + len, '=', padding);
	}
	normalized[normalized_len] = 0;

	size_t decoded_size = 0;
	if (r_mul_overflow (normalized_len / 4, (size_t)3, &decoded_size)
			|| r_add_overflow (decoded_size, (size_t)1, &decoded_size)
			|| decoded_size > (size_t)INT_MAX) {
		free (normalized);
		return NULL;
	}
	ut8 *decoded = malloc (decoded_size);
	if (!decoded) {
		free (normalized);
		return NULL;
	}
	const int decoded_len = r_base64_decode (decoded, normalized, (int)normalized_len, true);
	free (normalized);
	if (decoded_len < 0) {
		free (decoded);
		return NULL;
	}
	decoded[decoded_len] = 0;
	if (out_len) {
		*out_len = decoded_len;
	}
	return decoded;
}

static bool jwt_append_json_part(RStrBuf *sb, const char *segment, size_t len) {
	int decoded_len = 0;
	ut8 *decoded = jwt_b64url_decode (segment, len, &decoded_len);
	if (!decoded) {
		return false;
	}
	if (decoded_len <= 0 || strlen ((const char *)decoded) != (size_t)decoded_len) {
		free (decoded);
		return false;
	}
	RJson *json = r_json_parsedup ((const char *)decoded);
	if (!json) {
		free (decoded);
		return false;
	}
	const bool ok = json->type == R_JSON_OBJECT
		&& r_strbuf_append_n (sb, (const char *)decoded, decoded_len);
	r_json_free (json);
	free (decoded);
	return ok;
}

R_API char *r_str_jwtdec(const char *token) {
	R_RETURN_VAL_IF_FAIL (token, NULL);
	token = r_str_trim_head_ro (token);
	size_t len = strlen (token);
	while (len > 0 && IS_WHITECHAR (token[len - 1])) {
		len--;
	}
	if (len == 0) {
		return NULL;
	}

	const char *dot = memchr (token, '.', len);
	if (!dot) {
		return NULL;
	}
	const size_t header_len = dot - token;
	const char *payload = dot + 1;
	const size_t rest_len = len - header_len - 1;
	const char *dot2 = memchr (payload, '.', rest_len);
	if (!dot2) {
		return NULL;
	}
	const size_t payload_len = dot2 - payload;

	RStrBuf *sb = r_strbuf_new ("");
	if (!sb) {
		return NULL;
	}
	if (!jwt_append_json_part (sb, token, header_len)
			|| !r_strbuf_append (sb, "\n")
			|| !jwt_append_json_part (sb, payload, payload_len)) {
		r_strbuf_free (sb);
		return NULL;
	}
	return r_strbuf_drain (sb);
}
