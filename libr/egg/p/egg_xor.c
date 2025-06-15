/* radare - LGPL - Copyright 2011-2025 - pancake */

#include <r_egg.h>

#define DEFAULT_XOR_KEY "0xFF"

/* based on @santitox patch */
static RBuffer *build(REgg *egg) {
	ut8 aux[32];
	const char *default_key = DEFAULT_XOR_KEY;
	char *key = r_egg_option_get (egg, "key");
	int i;

	if (R_STR_ISEMPTY (key)) {
		free (key);
		key = strdup (default_key);
		R_LOG_WARN ("XOR key not provided. Using (%s) as the key", key);
	}
	ut8 nkey = (ut8)r_num_math (NULL, key);
	if (nkey == 0) {
		R_LOG_ERROR ("Invalid key (%s)", key);
		free (key);
		return false;
	}
	if (nkey != (nkey & 0xff)) {
		nkey &= 0xff;
		R_LOG_INFO ("xor key wrapped to (%d)", nkey);
	}
	if (r_buf_size (egg->bin) > 240) { // XXX
		R_LOG_ERROR ("shellcode is too long :(");
		free (key);
		return NULL;
	}
	RBuffer *sc = egg->bin; // hack
	if (!r_buf_size (sc)) {
		R_LOG_ERROR ("No shellcode found!");
		free (key);
		return NULL;
	}

	for (i = 0; i < r_buf_size (sc); i++) {
		// eprintf ("%02x -> %02x\n", sc->buf[i], sc->buf[i] ^nkey);
		if ((r_buf_read8_at (sc, i) ^ nkey) == 0) {
			R_LOG_INFO ("This xor key generates null bytes. Try again");
			free (key);
			return NULL;
		}
	}
	RBuffer *buf = r_buf_new ();
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
		aux[1] = r_buf_size (sc);
		aux[2] = 0x59; // pop ecx
		// ebx = key
		aux[3] = 0x6a; // push key
		aux[4] = nkey;
		aux[5] = 0x5b; // pop ebx
		r_buf_set_bytes (buf, aux, 6);

		r_buf_append_bytes (buf, stub, STUBLEN);

		for (i = 0; i < r_buf_size (sc); i++) {
			ut8 v = r_buf_read8_at (sc, i) ^ nkey;
			r_buf_write_at (sc, i, &v, sizeof (v));
		}
		r_buf_append_buf (buf, sc);
	} else {
		R_LOG_ERROR ("Invalid arch for egg.xor which is x86-only for now");
		r_buf_free (buf);
		buf = NULL;
	}
	r_buf_free (sc);
	free (key);
	return buf;
}

//TODO: rename plugin to run
REggPlugin r_egg_plugin_xor = {
	.meta = {
		.name = "xor",
		.desc = "xor encoder for shellcode",
		.author = "pancake,santitox",
		.license = "MIT",
	},
	.type = R_EGG_PLUGIN_ENCODER,
	.build = (void *)build
};

#if 0
#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_EGG,
	.data = &r_egg_plugin_xor,
	.version = R2_VERSION
};
#endif
#endif
