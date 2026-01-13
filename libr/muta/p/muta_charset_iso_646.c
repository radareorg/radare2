/* radare - LGPL - Copyright 2025 - pancake */
/* Charset ISO 646 (IRV, close to ASCII) */
#include <r_muta.h>
#include <r_muta/charset.h>

static inline bool iso646_is_visible(ut8 b) {
	if (b == '\n' || b == '\t') {
		return true;
	}
	return b >= 0x20 && b <= 0x7e;
}

static bool update(RMutaSession *cj, const ut8 *buf, int len) {
	int i;
	if (!cj || !buf || len < 0) {
		return false;
	}
	switch (cj->dir) {
	case R_CRYPTO_DIR_DECRYPT:
		for (i = 0; i < len; i++) {
			if (iso646_is_visible (buf[i])) {
				r_muta_session_append (cj, &buf[i], 1);
			} else {
				r_muta_session_append (cj, (const ut8 *)".", 1);
			}
		}
		break;
	case R_CRYPTO_DIR_ENCRYPT:
		for (i = 0; i < len; i++) {
			ut8 out = '?';
			if (buf[i] == '\n' || buf[i] == '\t') {
				out = buf[i];
			} else if (buf[i] >= 0x20 && buf[i] <= 0x7e) {
				out = buf[i];
			}
			r_muta_session_append (cj, &out, 1);
		}
		break;
	}
	return true;
}

static bool end(RMutaSession *cj, const ut8 *b, int l) {
	return update (cj, b, l);
}

RMutaPlugin r_muta_plugin_charset_iso_646 = {
	.meta = { .name = "iso_646", .license = "MIT", .desc = "ISO 646 (IRV)" },
	.type = R_MUTA_TYPE_CHARSET,
	.implements = "iso_646",
	.update = update,
	.end = end
};
#ifndef R2_PLUGIN_INCORE
RLibStruct radare_plugin = { .type = R_LIB_TYPE_MUTA, .data = &r_muta_plugin_charset_iso_646 };
#endif
