/* radare - MIT - Charset ascii_ansi (stub) */
#include <r_muta.h>
static bool check(const char *algo) {
	return !strcmp (algo, "ascii_ansi");
}
static bool update(RMutaSession *cj, const ut8 *b, int l) {
	if (!cj || !b || l < 0) {
		return false;
	}
	r_muta_session_append (cj, b, l);
	return true;
}
static bool end(RMutaSession *cj, const ut8 *b, int l) {
	return update (cj, b, l);
}
RMutaPlugin r_muta_plugin_charset_ascii_ansi = {
	.meta = { .name = "ascii_ansi", .license = "MIT", .desc = "ASCII ANSI stub" },
	.type = R_MUTA_TYPE_CHARSET,
	.check = check,
	.update = update,
	.end = end
};
#ifndef R2_PLUGIN_INCORE
RLibStruct radare_plugin = { .type = R_LIB_TYPE_MUTA, .data = &r_muta_plugin_charset_ascii_ansi };
#endif
