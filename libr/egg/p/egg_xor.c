/* radare - LGPL - Copyright 2011-2012 - pancake */
/* based on @santitox patch */
#include <r_egg.h>

static RBuffer *build (REgg *egg) {
	RBuffer *buf, *sc;
	ut8 aux[32], nkey;
	int i;
	char *key = r_egg_option_get (egg, "key");

	if (!key || !*key) {
		eprintf ("Invalid key (null)\n");
		return R_FALSE;
	}
	nkey = r_num_math (NULL, key);
	if (nkey == 0) {
		eprintf ("Invalid key (%s)\n", key);
		return R_FALSE;
	}
	if (nkey != (nkey & 0xff)) {
		nkey &= 0xff;
		eprintf ("xor key wrapped to (%d)\n", nkey);
	}
	if (egg->bin->length > 240) { // XXX
		eprintf ("shellcode is too long :(\n");
		return NULL;
	}
	sc = egg->bin; // hack
	for (i = 0; i<sc->length; i++) {
		// eprintf ("%02x -> %02x\n", sc->buf[i], sc->buf[i] ^nkey);
		if ((sc->buf[i]^nkey)==0) {
			eprintf ("This xor key generates null bytes. Try again.\n");
			return NULL;
		}
	}
	buf = r_buf_new ();
	sc = r_buf_new ();

	// TODO: alphanumeric? :D
	// This is the x86-32/64 xor encoder
	r_buf_append_buf (sc, egg->bin);
	if (egg->arch == R_SYS_ARCH_X86) {
		#define STUBLEN 18
		ut8 stub[STUBLEN] =
			"\xe8\xff\xff\xff\xff" // call $$+4
			"\xc1" // ffc1 = inc ecx
			"\x5e" // pop esi
			"\x48\x83\xc6\x0d" // add rsi, xx ... 64bit
			// loop0:
			"\x30\x1e" // xor [esi], bl
			"\x48\xff\xc6" // inc rsi
			"\xe2\xf9"; // loop loop0
		// ecx = length
		aux[0] = 0x6a; // push length
		aux[1] = sc->length;
		aux[2] = 0x59; // pop ecx
		// ebx = key
		aux[3] = 0x6a; // push key
		aux[4] = nkey;
		aux[5] = 0x5b; // pop ebx
		r_buf_set_bytes (buf, aux, 6);

		r_buf_append_bytes (buf, stub, STUBLEN);

		for (i = 0; i<sc->length; i++) {
//			 eprintf ("%02x -> %02x\n", sc->buf[i], sc->buf[i] ^nkey);
			sc->buf[i]^=nkey;
		}
		r_buf_append_buf (buf, sc);
	}
	r_buf_free (sc);
	return buf;
}

//TODO: rename plugin to run
REggPlugin r_egg_plugin_xor = {
	.name = "xor",
	.type = R_EGG_PLUGIN_ENCODER,
	.desc = "xor encoder for shellcode",
	.build = (void *)build
};

#if 0
#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_EGG,
	.data = &r_egg_plugin_xor
};
#endif
#endif
