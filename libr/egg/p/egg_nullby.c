/* radare - LGPL - Copyright 2025 - pancake */

#include <r_egg.h>

#define DEFAULT_NULLBY_KEY "0x41"

/* based on @santitox patch */
static RBuffer *build(REgg *egg) {
	ut8 nkey;
	const char *default_key = DEFAULT_NULLBY_KEY;
	char *key = r_egg_option_get (egg, "key");
	int i;

	if (R_STR_ISEMPTY (key)) {
		free (key);
		key = strdup (default_key);
		R_LOG_WARN ("Null byte not provided. Using (%s) as the key", key);
	}
	nkey = r_num_math (NULL, key);
	if (nkey == 0) {
		R_LOG_ERROR ("Invalid key (%s)", key);
		free (key);
		return false;
	}
	if (nkey != (nkey & 0xff)) {
		nkey &= 0xff;
		R_LOG_INFO ("xor key wrapped to (%d)", nkey);
	}
	if (r_buf_size (egg->bin) > 250) { // XXX
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

	bool hasnul = false;
	for (i = 0; i < r_buf_size (sc); i++) {
		// eprintf ("%02x -> %02x\n", sc->buf[i], sc->buf[i] ^nkey);
		if (r_buf_read8_at (sc, i) == 0) {
			hasnul = true;
		}
	}
	if (!hasnul) {
		R_LOG_WARN ("This shellcode contains no null bytes. the encoder is not needed");
	}
	RBuffer *buf = r_buf_new ();
	sc = r_buf_new ();

	// This is the x86-32/64 byte replacement encoder
	r_buf_append_buf (sc, egg->bin);
	if (egg->arch == R_SYS_ARCH_X86) {
		#define STUBLEN 0x1e
		ut8 stub[STUBLEN] =
			"\x30\xdb" // xor bl, bl
			"\x48\x31\xc9" // xor rcx, rcx
			"\xe8\xff\xff\xff\xff" // call $$+4
			"\xc1" // inc ecx // 1 byte hack for the call in the middle
			"\x5f" // pop rdi
			"\x48\x83\xc7\x14" // add rdi, 0x14 // payload size
			"\xb1\x80" // mov cl, 0x80 // size of payload 128 .. must be replaced
			"\x80\x3f\x41" // cmp byte [rdi], 0x41
			"\x75\x02" // jne .loop
			"\x88\x1f" // mov byte [rdi], bl
			"\xe2\xf7"; // loop 0x15 (cmp byte rdi..)
		size_t scsz = r_buf_size (sc);	
		if (scsz >= 0xff) {
			R_LOG_ERROR ("This encoder doesnt work for shellcodes larger than 255 bytes");
			return NULL;
		}
		stub[17] = scsz; // payload size
		stub[22] = nkey; // char to nullify

		r_buf_append_bytes (buf, stub, STUBLEN);

		for (i = 0; i < r_buf_size (sc); i++) {
			ut8 v = r_buf_read8_at (sc, i);
			if (v == 0) {
				v = nkey;
			}
			r_buf_write_at (sc, i, &v, sizeof (v));
		}
		r_buf_append_buf (buf, sc);
	}
	r_buf_free (sc);
	free (key);
	return buf;
}

//TODO: rename plugin to run
REggPlugin r_egg_plugin_nullby = {
	.meta = {
		.name = "nullby",
		.desc = "null byte encoder",
		.author = "pancake",
		.license = "MIT",
	},
	.type = R_EGG_PLUGIN_ENCODER,
	.build = (void *)build
};

#if 0
#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_EGG,
	.data = &r_egg_plugin_nullby,
	.version = R2_VERSION
};
#endif
#endif
