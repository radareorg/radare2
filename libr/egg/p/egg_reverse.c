/* radare - LGPL - Copyright 2013-2025 - pancake */

#include <r_egg.h>

unsigned long armle_osx_reverse[] = {
#include "sc/src/armle-osx-reverse.c"
;

unsigned char x86_freebsd_reverse[] =
#include "sc/src/x86-freebsd-reverse.c"
;

static RBuffer *build(REgg *egg) {
	RBuffer *buf = r_buf_new ();
	int scsz = 0;
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
			scsz = sizeof (armle_osx_reverse);
			cd = 7+36;
			break;
		}
		break;
	case R_EGG_OS_FREEBSD:
		switch (egg->arch) {
		case R_SYS_ARCH_X86:
			switch (egg->bits) {
			case 32: sc = x86_freebsd_reverse; break;
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
		r_buf_set_bytes (buf, sc, scsz? scsz: strlen ((const char *)sc));
		if (R_STR_ISNOTEMPTY (port)) {
			if (cd) {
				ut8 nport = atoi (port);
				r_buf_write_at (buf, cd, (const ut8*)&nport, 1);
			} else {
				R_LOG_ERROR ("Cannot set port");
			}
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
