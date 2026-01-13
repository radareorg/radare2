/* radare - MIT - Charset ascii_ansi (stub) */
#include <r_muta.h>
#include <r_muta/charset.h>
RMutaPlugin r_muta_plugin_charset_ascii_ansi = {
	.meta = { .name = "ascii.ansi", .license = "MIT", .desc = "ASCII ANSI stub" },
	.type = R_MUTA_TYPE_CHARSET,
	.implements = "ascii.ansi",
	.update = r_muta_charset_stub_update,
	.end = r_muta_charset_stub_end
};
#ifndef R2_PLUGIN_INCORE
RLibStruct radare_plugin = { .type = R_LIB_TYPE_MUTA, .data = &r_muta_plugin_charset_ascii_ansi };
#endif
