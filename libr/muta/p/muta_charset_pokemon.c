/* radare - MIT - Copyright 2025 - pancake */

#include <r_muta.h>
#include <r_muta/charset.h>

static const RMutaCharsetMap pokemon_table[] = {
	{ "<NULL>", { 0x00 }, 1 }, { "<PAGE>", { 0x49 }, 1 }, { "<PKMN>", { 0x4a }, 1 }, { "<pkmn>", { 0x4a }, 1 }, { "<CONT>", { 0x55 }, 1 },
	{ "<SCROLL>", { 0x4c }, 1 }, { "<NEXT>", { 0x4e }, 1 }, { "<LINE>", { 0x4f }, 1 }, { "<PARA>", { 0x51 }, 1 }, { "<PLAYER>", { 0x52 }, 1 },
	{ "<RIVAL>", { 0x53 }, 1 }, { "<DONE>", { 0x57 }, 1 }, { "<PROMPT>", { 0x58 }, 1 }, { "<TARGET>", { 0x59 }, 1 }, { "<USER>", { 0x5a }, 1 },
	{ "<PC>", { 0x5b }, 1 }, { "<TM>", { 0x5c }, 1 }, { "<TRAINER>", { 0x5d }, 1 }, { "<ROCKET>", { 0x5e }, 1 }, { "<DEXDEND>", { 0x5f }, 1 },
	{ "<BOLD_A>", { 0x60 }, 1 }, { "<BOLD_B>", { 0x61 }, 1 }, { "<BOLD_C>", { 0x62 }, 1 }, { "<BOLD_D>", { 0x63 }, 1 }, { "<BOLD_E>", { 0x64 }, 1 },
	{ "<BOLD_F>", { 0x65 }, 1 }, { "<BOLD_G>", { 0x66 }, 1 }, { "<BOLD_H>", { 0x67 }, 1 }, { "<BOLD_I>", { 0x68 }, 1 }, { "<BOLD_V>", { 0x69 }, 1 },
	{ "<BOLD_S>", { 0x6a }, 1 }, { "<BOLD_L>", { 0x6b }, 1 }, { "<BOLD_M>", { 0x6c }, 1 }, { "<COLON>", { 0x6d }, 1 },
	{ "@", { 0x50 }, 1 }, { "#", { 0x54 }, 1 }, { "<……>", { 0x56 }, 1 }, { "-", { 0x7f }, 1 }, { "é", { 0xe0 }, 1 }, { "?", { 0xe6 }, 1 }, { "!", { 0xe7 }, 1 },
	{ "'r", { 0xe4 }, 1 }, { "'d", { 0xbb }, 1 }, { "'l", { 0xbc }, 1 }, { "'s", { 0xbd }, 1 },
	/* Letters */
	{ "A", { 0x80 }, 1 }, { "B", { 0x81 }, 1 }, { "C", { 0x82 }, 1 }, { "D", { 0x83 }, 1 }, { "E", { 0x84 }, 1 }, { "F", { 0x85 }, 1 }, { "G", { 0x86 }, 1 }, { "H", { 0x87 }, 1 },
	{ "I", { 0x88 }, 1 }, { "J", { 0x89 }, 1 }, { "K", { 0x8a }, 1 }, { "L", { 0x8b }, 1 }, { "M", { 0x8c }, 1 }, { "N", { 0x8d }, 1 }, { "O", { 0x8e }, 1 }, { "P", { 0x8f }, 1 },
	{ "Q", { 0x90 }, 1 }, { "R", { 0x91 }, 1 }, { "S", { 0x92 }, 1 }, { "T", { 0x93 }, 1 }, { "U", { 0x94 }, 1 }, { "V", { 0x95 }, 1 }, { "W", { 0x96 }, 1 }, { "X", { 0x97 }, 1 },
	{ "Y", { 0x98 }, 1 }, { "Z", { 0x99 }, 1 },
	{ "a", { 0xa0 }, 1 }, { "b", { 0xa1 }, 1 }, { "c", { 0xa2 }, 1 }, { "d", { 0xa3 }, 1 }, { "e", { 0xa4 }, 1 }, { "f", { 0xa5 }, 1 }, { "g", { 0xa6 }, 1 }, { "h", { 0xa7 }, 1 },
	{ "i", { 0xa8 }, 1 }, { "j", { 0xa9 }, 1 }, { "k", { 0xaa }, 1 }, { "l", { 0xab }, 1 }, { "m", { 0xac }, 1 }, { "n", { 0xad }, 1 }, { "o", { 0xae }, 1 }, { "p", { 0xaf }, 1 },
	{ "q", { 0xb0 }, 1 }, { "r", { 0xb1 }, 1 }, { "s", { 0xb2 }, 1 }, { "t", { 0xb3 }, 1 }, { "u", { 0xb4 }, 1 }, { "v", { 0xb5 }, 1 }, { "w", { 0xb6 }, 1 }, { "x", { 0xb7 }, 1 },
	{ "y", { 0xb8 }, 1 }, { "z", { 0xb9 }, 1 },
	{ "(", { 0x9a }, 1 }, { ")", { 0x9b }, 1 }, { ":", { 0x9c }, 1 }, { ";", { 0x9d }, 1 }, { "[", { 0x9e }, 1 }, { "]", { 0x9f }, 1 },
	{ "0", { 0xf6 }, 1 }, { "1", { 0xf7 }, 1 }, { "2", { 0xf8 }, 1 }, { "3", { 0xf9 }, 1 }, { "4", { 0xfa }, 1 }, { "5", { 0xfb }, 1 }, { "6", { 0xfc }, 1 },
	{ "7", { 0xfd }, 1 }, { "8", { 0xfe }, 1 }, { "9", { 0xff }, 1 },
	{ NULL, { 0 }, 0 }
};

static bool check(const char *algo) {
	return !strcmp (algo, "pokemon");
}

static bool update(RMutaSession *cj, const ut8 *buf, int len) {
	int olen = 0;
	ut8 *obuf = NULL;
	if (!cj || !buf || len < 0) {
		return false;
	}
	switch (cj->dir) {
	case R_CRYPTO_DIR_ENCRYPT:
		obuf = r_muta_charset_encode (buf, len, &olen, pokemon_table, r_muta_charset_parse_default);
		break;
	case R_CRYPTO_DIR_DECRYPT:
		obuf = r_muta_charset_decode (buf, len, &olen, pokemon_table, "\\x%02x");
		break;
	}
	if (!obuf) {
		return false;
	}
	if (olen > 0) {
		r_muta_session_append (cj, obuf, olen);
	}
	free (obuf);
	return true;
}

static bool end(RMutaSession *cj, const ut8 *buf, int len) {
	return update (cj, buf, len);
}

RMutaPlugin r_muta_plugin_charset_pokemon = {
	.meta = {
		.name = "pokemon",
		.license = "MIT",
		.desc = "Transcode from/to Pokémon charset used in Gen 1 games",
	},
	.type = R_MUTA_TYPE_CHARSET,
	.check = check,
	.update = update,
	.end = end
};

#ifndef R2_PLUGIN_INCORE
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_MUTA,
	.data = &r_muta_plugin_charset_pokemon
};
#endif

