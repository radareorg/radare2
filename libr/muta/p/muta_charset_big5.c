/* radare - MIT - Charset big5 (stub) */
#include <r_muta.h>
#include <r_muta/charset.h>
static bool check(const char *algo) {
	return !strcmp (algo, "big5");
}
RMutaPlugin r_muta_plugin_charset_big5 = {
	.meta = { .name = "big5", .license = "MIT", .desc = "Big5 stub" },
	.type = R_MUTA_TYPE_CHARSET,
	.check = check,
	.update = r_muta_charset_stub_update,
	.end = r_muta_charset_stub_end
};
#ifndef R2_PLUGIN_INCORE
RLibStruct radare_plugin = { .type = R_LIB_TYPE_MUTA, .data = &r_muta_plugin_charset_big5 };
#endif
