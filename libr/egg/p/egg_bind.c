/* radare - LGPL - Copyright 2013-2025 - pancake */

#include <r_egg.h>

#define SUPPORT_UDP 0

static ut8 x86_osx_bind4444[] =
#include "sc/x86-osx-bind4444.c"
;

static ut8 x86_solaris_bind4444[] =
#include "sc/x86-solaris-bind4444.c"
;

static ut8 x86_openbsd_bind6969[] =
#include "sc/x86-openbsd-bind6969.c"
;

static ut8 x86_linux_bind4444[] =
#include "sc/x86-linux-bind4444.c"
;

#if SUPPORT_UDP
static ut8 x86_linux_udp4444[] =
#include "sc/x86-linux-udp4444.c"
#endif


static ut8 arm_linux_bind[] =
#include "sc/arm-linux-bind.c"
;

static ut8 sparc_linux_bind4444[] =
#include "sc/sparc-linux-bind4444.c"
;

static ut8 x86_w32_tcp4444[] =
#include "sc/x86-w32-tcp4444.c"
;


static RBuffer *build(REgg *egg) {
	char *shell= NULL;
	RBuffer *buf = r_buf_new ();
	const ut8 *sc = NULL;
	int cd = 0;
	char *port = r_egg_option_get (egg, "port");
	//TODO: char *udp = r_egg_option_get (egg, "udp");
	switch (egg->os) {
	case R_EGG_OS_OSX:
	case R_EGG_OS_DARWIN:
		switch (egg->arch) {
		case R_SYS_ARCH_X86:
			sc = x86_osx_bind4444;
			break;
		}
		break;
	case R_EGG_OS_SOLARIS:
		switch (egg->arch) {
		case R_SYS_ARCH_X86:
			sc = x86_solaris_bind4444;
			break;
		}
		break;
	case R_EGG_OS_OPENBSD:
		switch (egg->arch) {
		case R_SYS_ARCH_X86:
			sc = (const ut8*)x86_openbsd_bind6969;
			break;
		}
		break;
	case R_EGG_OS_LINUX:
		switch (egg->arch) {
		case R_SYS_ARCH_X86:
			switch (egg->bits) {
			case 32: sc = x86_linux_bind4444; break;
			// TODO: support udpcase 32: sc = x86_linux_udp4444; break;
			}
			break;
		case R_SYS_ARCH_SPARC:
			sc = sparc_linux_bind4444;
			break;
		case R_SYS_ARCH_ARM:
			case 32: sc = arm_linux_bind; break;
			break;
		}
		break;
	case R_EGG_OS_WINDOWS:
		sc = x86_w32_tcp4444;
		break;
	default:
		R_LOG_ERROR ("unsupported os %x", egg->os);
		break;
	}
	if (sc) {
		r_buf_set_bytes (buf, sc, strlen ((const char *)sc));
		if (R_STR_ISNOTEMPTY (port)) {
			if (cd) {
				ut8 nport = atoi (port);
				r_buf_write_at (buf, cd, (const ut8*)&nport, 1);
			} else {
				R_LOG_ERROR ("Cannot set port");
			}
		}
	} else {
		R_LOG_ERROR ("Unsupported target");
	}
	free (shell);
	return buf;
}

//TODO: rename plugin to run
REggPlugin r_egg_plugin_bind = {
	.meta = {
		.name = "bind",
		.author = "pancake",
		.license = "MIT",
		.desc = "listen port=4444",
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
