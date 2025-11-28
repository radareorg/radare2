/* radare - MIT - Charset arabic_iso (stub) */
#include <r_muta.h>
static bool check(const char *algo) {
	return !strcmp (algo, "arabic_iso");
}
static bool update(RMutaSession *cj, const ut8 *b, int l) {
	if (!cj || !b || l < 0) {
		return false;
	}
	if (cj->dir == R_CRYPTO_DIR_DECRYPT) {
		r_muta_session_append (cj, b, l);
	} else {
		r_muta_session_append (cj, b, l);
	}
	return true;
}
static bool end(RMutaSession *cj, const ut8 *b, int l) {
	return update (cj, b, l);
}
RMutaPlugin r_muta_plugin_charset_arabic_iso = {
	.meta = { .name = "arabic_iso", .license = "MIT", .desc = "arabic ISO stub" },
	.type = R_MUTA_TYPE_CHARSET,
	.check = check,
	.update = update,
	.end = end
};
#ifndef R2_PLUGIN_INCORE
RLibStruct radare_plugin = { .type = R_LIB_TYPE_MUTA, .data = &r_muta_plugin_charset_arabic_iso };
#endif
