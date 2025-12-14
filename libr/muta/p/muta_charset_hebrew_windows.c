/* radare - MIT - Charset hebrew_windows (stub) */
#include <r_muta.h>
#include <r_muta/charset.h>
static bool check(const char *algo) {
	return !strcmp (algo, "hebrew_windows");
}
RMutaPlugin r_muta_plugin_charset_hebrew_windows = {
	.meta = { .name = "hebrew_windows", .license = "MIT", .desc = "Hebrew Windows stub" },
	.type = R_MUTA_TYPE_CHARSET,
	.check = check,
	.update = r_muta_charset_stub_update,
	.end = r_muta_charset_stub_end
};
#ifndef R2_PLUGIN_INCORE
RLibStruct radare_plugin = { .type = R_LIB_TYPE_MUTA, .data = &r_muta_plugin_charset_hebrew_windows };
#endif
