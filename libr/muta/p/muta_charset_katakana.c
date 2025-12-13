/* radare - MIT - Charset Katakana (half-width mapping used in r2 charsets) */
#include <r_muta.h>
#include <r_util.h>

/* Map ASCII digraphs to single Katakana glyphs: "ra"->ラ, "da"->ダ, "re"->レ */
typedef struct {
	const char *in2;
	const char *out;
} KDMap;
static const KDMap kdmap[] = {
	{ "ra", "ラ" }, { "rA", "ラ" }, { "Ra", "ラ" }, { "RA", "ラ" },
	{ "da", "ダ" }, { "dA", "ダ" }, { "Da", "ダ" }, { "DA", "ダ" },
	{ "re", "レ" }, { "rE", "レ" }, { "Re", "レ" }, { "RE", "レ" },
	{ NULL, NULL }
};

static bool check(const char *algo) {
	return !strcmp (algo, "katakana");
}

static int decode(RMutaSession *cj, const ut8 *in, int len, ut8 **out, int *consumed) {
	R_RETURN_VAL_IF_FAIL (cj && in && out && consumed, 0);
	if (len < 1) {
		return 0;
	}
	*consumed = 1;
	if (len > 1) {
		char two[3] = { (char)in[0], (char)in[1], 0 };
		const KDMap *m;
		for (m = kdmap; m->in2; m++) {
			if (!strcmp (m->in2, two)) {
				char *cpy = strdup (m->out);
				if (!cpy) {
					return 0;
				}
				*out = (ut8*)cpy;
				*consumed = 2;
				return (int)strlen (cpy);
			}
		}
	}
	if (IS_PRINTABLE (in[0])) {
		char *cpy = malloc (2);
		if (!cpy) {
			return 0;
		}
		cpy[0] = (char)in[0];
		cpy[1] = 0;
		*out = (ut8*)cpy;
		return 1;
	}
	/* Drop non-printable bytes (so trailing zeros don't emit '?'). */
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
	.check = check,
	.decode = decode,
	.update = update,
	.end = end
};
#ifndef R2_PLUGIN_INCORE
RLibStruct radare_plugin = { .type = R_LIB_TYPE_MUTA, .data = &r_muta_plugin_charset_katakana };
#endif
