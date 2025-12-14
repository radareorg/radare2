/* radare - LGPL - Copyright 2025 - pancake */

#include <r_muta/charset.h>
#include <r_util.h>

#include <stdio.h>
#include <string.h>

R_API int r_muta_charset_parse_default(const char *str, const char *end, char *token, int token_max) {
	R_RETURN_VAL_IF_FAIL (str && end && token, 0);
	R_RETURN_VAL_IF_FAIL (token_max > 1, 0);
	R_RETURN_VAL_IF_FAIL (str <= end, 0);

	if (str >= end) {
		return 0;
	}

	const int left = (int) (end - str);
	if (left < 1) {
		return 0;
	}

	if (str[0] == '<') {
		const void *tendp = memchr (str + 1, '>', left - 1);
		if (tendp) {
			const char *tend = (const char *)tendp;
			int tlen = (int) (tend - str) + 1;
			if (tlen > 0 && tlen < token_max) {
				memcpy (token, str, tlen);
				token[tlen] = 0;
				return tlen;
			}
		}
	}

	if (str[0] == '[') {
		const void *tendp = memchr (str + 1, ']', left - 1);
		if (tendp) {
			const char *tend = (const char *)tendp;
			int tlen = (int) (tend - str) + 1;
			if (tlen > 0 && tlen < token_max) {
				memcpy (token, str, tlen);
				token[tlen] = 0;
				return tlen;
			}
		}
	}

	if (left > 1 && str[0] == '\\') {
		int consumed = 2;
		switch (str[1]) {
		case 's':
			token[0] = ' ';
			break;
		case 't':
			token[0] = '\t';
			break;
		case 'n':
			token[0] = '\n';
			break;
		case 'r':
			token[0] = '\r';
			break;
		case '\\':
			token[0] = '\\';
			break;
		default:
			consumed = 1;
			token[0] = '\\';
			break;
		}
		token[1] = 0;
		return consumed;
	}

	if (left > 1 && str[0] == '\'') {
		switch (str[1]) {
		case 'r':
		case 'd':
		case 'l':
		case 's':
			if (token_max > 2) {
				token[0] = '\'';
				token[1] = str[1];
				token[2] = 0;
				return 2;
			}
			break;
		}
	}

	size_t ulen = r_str_utf8_charsize (str);
	if (ulen < 1) {
		ulen = 1;
	}
	if ((int)ulen > left) {
		ulen = (size_t)left;
	}
	if ((int)ulen >= token_max) {
		ulen = (size_t) (token_max - 1);
	}
	memcpy (token, str, ulen);
	token[ulen] = 0;
	return (int)ulen;
}

static bool r_muta_charset_outgrow(ut8 **out, int *outcap, int need) {
	if (need <= *outcap) {
		return true;
	}
	int cap = *outcap;
	while (need > cap) {
		cap = cap? cap * 2: 64;
	}
	ut8 *tmpbuf = realloc (*out, cap);
	if (!tmpbuf) {
		free (*out);
		*out = NULL;
		*outcap = 0;
		return false;
	}
	*out = tmpbuf;
	*outcap = cap;
	return true;
}

R_API ut8 *r_muta_charset_decode(const ut8 *in, int in_len, int *out_len, const RMutaCharsetMap *table, const char *unknown_fmt) {
	R_RETURN_VAL_IF_FAIL (out_len, NULL);
	*out_len = 0;
	R_RETURN_VAL_IF_FAIL (in && in_len >= 0 && table, NULL);

	const ut8 *ptr = in;
	const ut8 *end = in + in_len;
	ut8 *out = NULL;
	int outcap = 0;
	int outpos = 0;

	while (ptr < end) {
		int consumed = 0;
		const char *decoded = r_muta_charset_lookup_decode (table, ptr, (int) (end - ptr), &consumed);
		const char *text = NULL;
		int len = 0;

		if (decoded && consumed > 0) {
			text = decoded;
			len = (int)strlen (decoded);
		} else if (unknown_fmt) {
			static char tmp[32];
			ut8 b = *ptr;
			len = snprintf (tmp, sizeof (tmp), unknown_fmt, b);
			if (len > 0 && len < (int)sizeof (tmp)) {
				text = tmp;
			}
			consumed = 1;
		} else {
			consumed = 1;
		}

		ptr += (consumed > 0)? consumed: 1;

		if (!text || len <= 0) {
			continue;
		}

		if (!r_muta_charset_outgrow (&out, &outcap, outpos + len)) {
			*out_len = 0;
			return NULL;
		}

		memcpy (out + outpos, text, len);
		outpos += len;
	}

	*out_len = outpos;
	return out;
}

R_API ut8 *r_muta_charset_encode_ex(const ut8 *in, int in_len, int *out_len, const RMutaCharsetMap *table, RMutaCharsetParserFn parser, ut8 unknown_byte) {
	R_RETURN_VAL_IF_FAIL (out_len, NULL);
	*out_len = 0;
	R_RETURN_VAL_IF_FAIL (in && in_len >= 0 && table && parser, NULL);

	const char *str = (const char *)in;
	const char *end = str + in_len;
	ut8 *out = NULL;
	int outcap = 0;
	int outpos = 0;

	while (str < end) {
		if (!*str) {
			break;
		}
		char tok[128] = { 0 };
		int consumed = parser (str, end, tok, (int)sizeof (tok));
		if (consumed < 1) {
			break;
		}

		int byte_len = 0;
		const ut8 *bytes = r_muta_charset_lookup_encode (table, tok, &byte_len);
		if (!bytes || byte_len < 1) {
			ut8 q = unknown_byte;
			if (!r_muta_charset_outgrow (&out, &outcap, outpos + 1)) {
				*out_len = 0;
				return NULL;
			}
			out[outpos++] = q;
		} else {
			if (!r_muta_charset_outgrow (&out, &outcap, outpos + byte_len)) {
				*out_len = 0;
				return NULL;
			}
			memcpy (out + outpos, bytes, byte_len);
			outpos += byte_len;
		}

		str += consumed;
	}

	*out_len = outpos;
	return out;
}

R_API ut8 *r_muta_charset_encode(const ut8 *in, int in_len, int *out_len, const RMutaCharsetMap *table, RMutaCharsetParserFn parser) {
	return r_muta_charset_encode_ex (in, in_len, out_len, table, parser, '?');
}

R_API bool r_muta_charset_stub_update(RMutaSession *cj, const ut8 *b, int l) {
	R_RETURN_VAL_IF_FAIL (cj && b && l >= 0, false);
	r_muta_session_append (cj, b, l);
	return true;
}

R_API bool r_muta_charset_stub_end(RMutaSession *cj, const ut8 *b, int l) {
	return r_muta_charset_stub_update (cj, b, l);
}

R_API bool r_muta_charset_tr_update(RMutaSession *cj, const ut8 *buf, int len, const ut8 tr[256]) {
	int i;
	if (!cj || !buf || len < 0 || !tr) {
		return false;
	}
	for (i = 0; i < len; i++) {
		ut8 out = tr[buf[i]];
		r_muta_session_append (cj, &out, 1);
	}
	return true;
}
