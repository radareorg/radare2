/* radare - MIT - Charset JIS 7-bit Roman (ASCII-compatible subset) */
#include <r_muta.h>

/* For now, treat as ASCII for single-byte range; full JIS encodings with escape sequences
 *(ISO-2022-JP) are out-of-scope for this minimal plugin. */
static bool check(const char *algo) {
	return !strcmp (algo, "jis7");
}
static bool update(RMutaSession *cj, const ut8 *b, int l) {
	if (!cj || !b || l < 0) {
		return false;
	}
	/* Pass through printable ASCII, replace control/unknown with '?' on decrypt */
	if (cj->dir == R_CRYPTO_DIR_DECRYPT) {
		for (int i = 0; i < l; i++) {
			ut8 ch = b[i];
			if (ch < 0x20 && ch != '\n' && ch != '\t') {
				ch = '?';
			}
			r_muta_session_append (cj, &ch, 1);
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
	.update = update,
	.end = end
};
#ifndef R2_PLUGIN_INCORE
RLibStruct radare_plugin = { .type = R_LIB_TYPE_MUTA, .data = &r_muta_plugin_charset_jis7 };
#endif
