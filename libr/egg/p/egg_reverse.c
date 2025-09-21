/* radare - LGPL - Copyright 2013-2025 - pancake */

#include <r_egg.h>
#include "sc/out/decrypt.inc.c"

static const ut8 armle_osx_reverse[] =
#include "sc/out/armle-osx-reverse.c"
;

static const ut8 x86_freebsd_reverse[] =
#include "sc/out/x86-freebsd-reverse.c"
;

static RBuffer *build(REgg *egg) {
	RBuffer *buf = r_buf_new ();
	size_t sc_len = 0;
	const ut8 *sc = NULL;
	int cd = 0;
	char *port = r_egg_option_get (egg, "port");
	//TODO: char *udp = r_egg_option_get (egg, "udp");
	switch (egg->os) {
	case R_EGG_OS_OSX:
	case R_EGG_OS_DARWIN:
		switch (egg->arch) {
		case R_SYS_ARCH_ARM:
			sc = (const ut8*)armle_osx_reverse;
			sc_len = sizeof (armle_osx_reverse) - 1;
			cd = 7+36;
			break;
		}
		break;
	case R_EGG_OS_FREEBSD:
		switch (egg->arch) {
		case R_SYS_ARCH_X86:
			switch (egg->bits) {
			case 32:
				sc = x86_freebsd_reverse;
				sc_len = sizeof (x86_freebsd_reverse) - 1;
				break;
			default: R_LOG_ERROR ("Unsupported");
			}
			break;
		}
		break;
	default:
		R_LOG_ERROR ("unsupported os %x", egg->os);
		break;
	}
	if (sc) {
		ut8 *dec = sc_decrypt (sc, sc_len ? sc_len: strlen ((const char *)sc));
		if (dec) {
			r_buf_set_bytes (buf, dec, sc_len ? sc_len: strlen ((const char *)sc));
			free (dec);
			if (R_STR_ISNOTEMPTY (port)) {
				if (cd) {
					ut8 nport = atoi (port);
					r_buf_write_at (buf, cd, (const ut8*)&nport, 1);
				} else {
					R_LOG_WARN ("Cannot set port");
				}
			}
		} else {
			R_LOG_ERROR ("Cannot pull shellcode");
			r_buf_free (buf);
			buf = NULL;
		}
	}
	free (port);
	return buf;
}

//TODO: rename plugin to run
REggPlugin r_egg_plugin_reverse = {
	.meta = {
		.name = "reverse",
		.desc = "listen port=4444",
		.license = "MIT",
	},
	.type = R_EGG_PLUGIN_SHELLCODE,
	.build = (void *)build
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_EGG,
	.data = &r_egg_plugin_bind,
	.version = R2_VERSION
};
#endif
