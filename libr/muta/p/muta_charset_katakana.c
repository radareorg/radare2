/* radare - LGPL - Copyright 2025 - pancake */
/* Charset Katakana (half-width mapping) */

#include <r_muta.h>
#include <r_muta/charset.h>
#include <r_util.h>

/* Map ASCII digraphs to single Katakana glyphs: "ra"->ラ, "da"->ダ, "re"->レ */
// clang-format off
static const RMutaCharsetMap katakana_table[] = {
	{ "ラ", { 'r', 'a' }, 2 }, { "ラ", { 'r', 'A' }, 2 }, { "ラ", { 'R', 'a' }, 2 }, { "ラ", { 'R', 'A' }, 2 },
	{ "ダ", { 'd', 'a' }, 2 }, { "ダ", { 'd', 'A' }, 2 }, { "ダ", { 'D', 'a' }, 2 }, { "ダ", { 'D', 'A' }, 2 },
	{ "レ", { 'r', 'e' }, 2 }, { "レ", { 'r', 'E' }, 2 }, { "レ", { 'R', 'e' }, 2 }, { "レ", { 'R', 'E' }, 2 },
	{ NULL, { 0 }, 0 }
};
// clang-format on

static int decode(RMutaSession *cj, const ut8 *in, int len, ut8 **out, int *consumed) {
	const char *s = NULL;
	int clen = 0;
	R_RETURN_VAL_IF_FAIL (cj && in && out && consumed, 0);
	if (len < 1) {
		return 0;
	}
	s = r_muta_charset_lookup_decode (katakana_table, in, len, &clen);
	if (s && clen > 0) {
		char *cpy = strdup (s);
		if (!cpy) {
			return 0;
		}
		*out = (ut8 *)cpy;
		*consumed = clen;
		return (int)strlen (cpy);
	}
	*consumed = 1;
	if (IS_PRINTABLE (in[0])) {
		char *cpy = malloc (2);
		if (!cpy) {
			return 0;
		}
		cpy[0] = (char)in[0];
		cpy[1] = 0;
		*out = (ut8 *)cpy;
		return 1;
	}
	/* Drop non-printable bytes (so trailing zeros don't emit '? '). */
	return 0;
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
			}
			if (consumed < 1) {
				consumed = 1;
			}
			i += consumed;
		}
	} else {
		/* Encoding back to ASCII: drop multibyte, keep ASCII */
		int i;
		for (i = 0; i < l; i++) {
			r_muta_session_append (cj, &b[i], 1);
		}
	}
	return true;
}

static bool end(RMutaSession *cj, const ut8 *b, int l) {
	return update (cj, b, l);
}

RMutaPlugin r_muta_plugin_charset_katakana = {
	.meta = { .name = "katakana", .license = "MIT", .desc = "Katakana mapping (legacy-compatible)" },
	.type = R_MUTA_TYPE_CHARSET,
	.implements = "katakana",
		.decode = decode,
	.update = update,
	.end = end
};
#ifndef R2_PLUGIN_INCORE
RLibStruct radare_plugin = { .type = R_LIB_TYPE_MUTA, .data = &r_muta_plugin_charset_katakana };
#endif
