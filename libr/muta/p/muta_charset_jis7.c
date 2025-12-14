/* radare - MIT - Charset JIS7 (radare2 legacy) */
#include <r_muta.h>
#include <r_muta/charset.h>
#include <r_util.h>

static const RMutaCharsetMap jis7_table[] = {
	{ "ァ", { 0x21, 0x21 }, 2 },
	{ "ア", { 0x21, 0x22 }, 2 },
	{ NULL, { 0 }, 0 }
};

static bool check(const char *algo) {
	return !strcmp (algo, "jis7");
}

static int decode(RMutaSession *cj, const ut8 *in, int len, ut8 **out, int *consumed) {
	const char *s = NULL;
	int clen = 0;
	R_RETURN_VAL_IF_FAIL (cj && in && out && consumed, 0);
	if (len < 1) {
		return 0;
	}
	s = r_muta_charset_lookup_decode (jis7_table, in, len, &clen);
	if (s && clen > 0) {
		*consumed = clen;
	} else if (IS_PRINTABLE (in[0])) {
		char *cpy = malloc (2);
		if (!cpy) {
			return 0;
		}
		cpy[0] = (char)in[0];
		cpy[1] = 0;
		*out = (ut8*)cpy;
		*consumed = 1;
		return 1;
	} else {
		s = "?";
		*consumed = 1;
	}
	char *cpy = strdup (s);
	if (!cpy) {
		return 0;
	}
	*out = (ut8*)cpy;
	return (int)strlen (cpy);
}

static bool update(RMutaSession *cj, const ut8 *b, int l) {
	if (!cj || !b || l < 0) {
		return false;
	}
	if (cj->dir == R_CRYPTO_DIR_DECRYPT) {
		int i = 0;
		while (i < l) {
			ut8 *out = NULL;
			int consumed = 0;
			int olen = decode (cj, b + i, l - i, &out, &consumed);
			if (olen > 0 && out) {
				r_muta_session_append (cj, out, olen);
				free (out);
			} else {
				r_muta_session_append (cj, (const ut8 *)"?", 1);
			}
			if (consumed < 1) {
				consumed = 1;
			}
			i += consumed;
		}
	} else {
		r_muta_session_append (cj, b, l);
	}
	return true;
}

static bool end(RMutaSession *cj, const ut8 *b, int l) {
	return update (cj, b, l);
}

RMutaPlugin r_muta_plugin_charset_jis7 = {
	.meta = { .name = "jis7", .license = "MIT", .desc = "JIS 7-bit Roman (ASCII-like)" },
	.type = R_MUTA_TYPE_CHARSET,
	.check = check,
	.decode = decode,
	.update = update,
	.end = end
};
#ifndef R2_PLUGIN_INCORE
RLibStruct radare_plugin = { .type = R_LIB_TYPE_MUTA, .data = &r_muta_plugin_charset_jis7 };
#endif

