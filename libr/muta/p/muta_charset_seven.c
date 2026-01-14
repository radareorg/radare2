/* radare - MIT - Copyright 2026 - pancake */

#include <r_muta.h>
#include <r_muta/charset.h>

static int decode(RMutaSession *ms, const ut8 *in, int len, ut8 **out, int *consumed) {
	if (len < 2) {
		return 0;
	}

	char buf[3] = { 0 };
	int i, shift = 0;
	ut8 ch1, ch2 = '\0';

	char *dest = malloc ((len / 2) * 8 / 7 + 2);
	if (!dest) {
		return 0;
	}

	int out_len = 0;
	int processed = 0;

	for (i = 0; i < len; i += 2) {
		if (i + 1 >= len) {
			break;
		}
		buf[0] = in[i];
		buf[1] = in[i + 1];
		buf[2] = 0;
		ch1 = strtol (buf, NULL, 16);
		int j = out_len;
		dest[j++] = ((ch1 &(0x7F >> shift)) << shift) | ch2;
		dest[j++] = '\0';
		ch2 = ch1 >> (7 - shift);
		shift++;
		if (shift == 7) {
			dest[j++] = ch2;
			dest[j++] = '\0';
			ch2 = 0;
			shift = 0;
		}
		out_len = j;
		processed += 2;
	}

	*out = (ut8 *)dest;
	*consumed = processed;
	return out_len;
}

static bool encode(RMutaSession *ms, const ut8 *buf, int len) {
	if (!ms || !buf || len < 0) {
		return false;
	}

	int i, shift = 0;
	ut8 ch1, ch2;
	RStrBuf *sb = r_strbuf_new ("");
	if (!sb) {
		return false;
	}
	const ut8 *src = buf;
	for (i = 0; i < len; i++) {
		ch1 = src[i] & 0x7F;
		ch1 = ch1 >> shift;
		if (i + 1 < len) {
			ch2 = src[i + 1] & 0x7F;
			ch2 = ch2 << (7 - shift);
			ch1 = ch1 | ch2;
		}
		r_strbuf_appendf (sb, "%x", (ch1 >> 4));
		r_strbuf_appendf (sb, "%x", (ch1 & 0x0F));
		shift++;
		if (shift == 7) {
			shift = 0;
			i++;
		}
	}
	char *result = r_strbuf_drain (sb);
	r_muta_session_append (ms, (const ut8 *)result, strlen (result));
	free (result);
	return true;
}

static bool update(RMutaSession *ms, const ut8 *buf, int len) {
	if (!ms || !buf || len < 0) {
		return false;
	}

	switch (ms->dir) {
	case R_MUTA_OP_ENCRYPT:
		return encode (ms, buf, len);
	case R_MUTA_OP_DECRYPT:
		{
			ut8 *out = NULL;
			int consumed = 0;
			int out_len = decode (ms, buf, len, &out, &consumed);
		if (out && out_len > 0) {
				r_muta_session_append (ms, out, out_len);
				free (out);
				return true;
			}
			free (out);
			return false;
		}
	}
	return false;
}

static bool end(RMutaSession *ms, const ut8 *buf, int len) {
	return update (ms, buf, len);
}

RMutaPlugin r_muta_plugin_charset_seven = {
	.meta = {
		.name = "seven",
		.license = "LGPL",
		.desc = "7-bit character set encoding/decoding",
	},
	.type = R_MUTA_TYPE_CHARSET,
	.implements = "7bit",
	.update = update,
	.end = end,
	.decode = decode
};

#ifndef R2_PLUGIN_INCORE
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_MUTA,
	.data = &r_muta_plugin_charset_seven
};
#endif
