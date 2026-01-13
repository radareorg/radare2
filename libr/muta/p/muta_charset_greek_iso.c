/* radare - MIT - Charset greek_iso (stub) */
#include <r_muta.h>
#include <r_muta/charset.h>
RMutaPlugin r_muta_plugin_charset_greek_iso = {
	.meta = { .name = "greek.iso", .license = "MIT", .desc = "Greek ISO stub" },
	.type = R_MUTA_TYPE_CHARSET,
	.implements = "greek.iso",
	.update = r_muta_charset_stub_update,
	.end = r_muta_charset_stub_end
};
#ifndef R2_PLUGIN_INCORE
RLibStruct radare_plugin = { .type = R_LIB_TYPE_MUTA, .data = &r_muta_plugin_charset_greek_iso };
#endif
