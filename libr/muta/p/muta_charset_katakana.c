/* radare - MIT - Charset Katakana (half-width mapping used in r2 charsets) */
#include <r_muta.h>

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
static bool update(RMutaSession *cj, const ut8 *b, int l) {
	if (!cj || !b || l < 0) {
		return false;
	}
	if (cj->dir == R_CRYPTO_DIR_DECRYPT) {
		RStrBuf *sb = r_strbuf_new ("");
		for (int i = 0; i < l;) {
			if (i + 1 < l) {
				char two[3] = { (char)b[i], (char)b[i + 1], 0 };
				bool matched = false;
				for (const KDMap *m = kdmap; m->in2; m++) {
					if (!strcmp (m->in2, two)) {
						r_strbuf_append (sb, m->out);
						i += 2;
						matched = true;
						break;
					}
				}
				if (matched) {
					continue;
				}
			}
			// Not matched: drop ASCII letters; keep non-ASCII as-is
			if (b[i] & 0x80) {
				char ch[2] = { (char)b[i], 0 };
				r_strbuf_append (sb, ch);
			}
			i++;
		}
		const char *out = r_strbuf_get (sb);
		r_muta_session_append (cj, (const ut8 *)out, (int)strlen (out));
		r_strbuf_free (sb);
	} else {
		/* Encoding back to ASCII: drop multibyte, keep ASCII */
		for (int i = 0; i < l; i++) {
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
	.update = update,
	.end = end
};
#ifndef R2_PLUGIN_INCORE
RLibStruct radare_plugin = { .type = R_LIB_TYPE_MUTA, .data = &r_muta_plugin_charset_katakana };
#endif
