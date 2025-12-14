/* radare - MIT - Charset ascii_ansi (stub) */
#include <r_muta.h>
#include <r_muta/charset.h>
static bool check(const char *algo) {
	return !strcmp (algo, "ascii_ansi");
}
RMutaPlugin r_muta_plugin_charset_ascii_ansi = {
	.meta = { .name = "ascii_ansi", .license = "MIT", .desc = "ASCII ANSI stub" },
	.type = R_MUTA_TYPE_CHARSET,
	.check = check,
	.update = r_muta_charset_stub_update,
	.end = r_muta_charset_stub_end
};
#ifndef R2_PLUGIN_INCORE
RLibStruct radare_plugin = { .type = R_LIB_TYPE_MUTA, .data = &r_muta_plugin_charset_ascii_ansi };
#endif
