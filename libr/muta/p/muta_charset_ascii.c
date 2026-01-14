/* radare - MIT - Copyright 2025 - pancake */

#include <r_muta.h>
#include <r_muta/charset.h>

static bool is_visible(const char c) {
	return ((c == '\n' || c == '\t') || (c >= 0x20 && c <= 0x7e));
}

static bool update(RMutaSession *ms, const ut8 *buf, int len) {
	int i;
	if (!ms || !buf || len < 0) {
		return false;
	}
	switch (ms->dir) {
	case R_MUTA_OP_ENCRYPT:
		for (i = 0; i < len; i++) {
			ut8 out = is_visible (buf[i])? buf[i]: '?';
			r_muta_session_append (ms, &out, 1);
		}
		break;
	case R_MUTA_OP_DECRYPT:
		for (i = 0; i < len; i++) {
			if (is_visible (buf[i])) {
				r_muta_session_append (ms, &buf[i], 1);
			} else {
				char tmp[5] = { 0 };
				snprintf (tmp, sizeof (tmp), "\\x%02x", buf[i]);
				r_muta_session_append (ms, (const ut8 *)tmp, 4);
			}
		}
		break;
	}
	return true;
}

static int decode(RMutaSession *ms, const ut8 *in, int len, ut8 **out, int *consumed) {
	R_RETURN_VAL_IF_FAIL (ms && in && out && consumed, 0);
	if (len < 1) {
		return 0;
	}
	*consumed = 1;
	if (!is_visible (in[0])) {
		*out = NULL;
		return 0;
	}
	char *cpy = malloc (2);
	cpy[0] = (char)in[0];
	cpy[1] = 0;
	*out = (ut8 *)cpy;
	return 1;
}

static bool end(RMutaSession *ms, const ut8 *buf, int len) {
	return update (ms, buf, len);
}

RMutaPlugin r_muta_plugin_charset_ascii = {
	.meta = {
		.name = "ascii",
		.license = "MIT",
		.desc = "ASCII character set encoding/decoding",
	},
	.type = R_MUTA_TYPE_CHARSET,
	.implements = "ascii",
	.update = update,
	.end = end,
	.decode = decode
};

#ifndef R2_PLUGIN_INCORE
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_MUTA,
	.data = &r_muta_plugin_charset_ascii
};
#endif
