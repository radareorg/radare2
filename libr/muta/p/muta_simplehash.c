/* radare - LGPL - Copyright 2024-2026 - pancake */

#include <r_lib.h>
#include <r_muta.h>
#include <r_hash.h>
#include <r_endian.h>

typedef struct {
	const char *name;
	int digest_size;
} SimpleHashAlgorithm;

static const SimpleHashAlgorithm simplehash_algorithms[] = {
	{ "xorpair", 2 },
	{ "parity", 1 },
	{ "hamdist", 1 },
	{ "pcprint", 1 },
	{ "mod255", 1 },
	{ "adler32", 4 },
	{ "luhn", 1 },
	{ "elf", 4 },
};

static const SimpleHashAlgorithm *simplehash_find(const char *algo) {
	const size_t amount = sizeof (simplehash_algorithms) / sizeof (simplehash_algorithms[0]);
	size_t i;
	for (i = 0; i < amount; i++) {
		if (!strcmp (algo, simplehash_algorithms[i].name)) {
			return &simplehash_algorithms[i];
		}
	}
	return NULL;
}

static bool simplehash_check(const char *algo) {
	return simplehash_find (algo) != NULL;
}

static unsigned long elf_hash(const unsigned char *name) {
	unsigned long h = 0, g;
	while (*name) {
		h = (h << 4) + *name++;
		g = h & 0xf0000000;
		if (g) {
			h ^= g >> 24;
		}
		h &= ~g;
	}
	return h;
}

static bool simplehash_update(RMutaSession *ms, const ut8 *buf, int len) {
	const SimpleHashAlgorithm *algo = ms->subtype? simplehash_find (ms->subtype): NULL;
	if (!algo) {
		return false;
	}
	ut8 digest[8] = { 0 };
	if (!strcmp (algo->name, "xorpair")) {
		ut16 res = r_hash_xorpair (buf, len);
		r_write_be16 (digest, res);
	} else if (!strcmp (algo->name, "parity")) {
		digest[0] = r_hash_parity (buf, len);
	} else if (!strcmp (algo->name, "hamdist")) {
		digest[0] = r_hash_hamdist (buf, len);
	} else if (!strcmp (algo->name, "pcprint")) {
		digest[0] = r_hash_pcprint (buf, len);
	} else if (!strcmp (algo->name, "mod255")) {
		digest[0] = r_hash_mod255 (buf, len);
	} else if (!strcmp (algo->name, "adler32")) {
		ut32 res = r_hash_adler32 (buf, len);
		r_write_be32 (digest, res);
	} else if (!strcmp (algo->name, "luhn")) {
		digest[0] = (ut8)r_hash_luhn (buf, len);
	} else if (!strcmp (algo->name, "elf")) {
		ut8 *s = (ut8 *)r_str_ndup ((const char *)buf, len);
		ut32 res = (ut32)elf_hash (s);
		free (s);
		r_write_be32 (digest, res);
	} else {
		return false;
	}
	r_muta_session_append (ms, digest, algo->digest_size);
	return true;
}

RMutaPlugin r_muta_plugin_simplehash = {
	.meta = {
		.name = "simplehash",
		.desc = "Simple hash algorithms (xorpair, parity, hamdist, pcprint, mod255, adler32, luhn, elf)",
		.author = "pancake",
		.license = "LGPL-3.0-only",
	},
	.type = R_MUTA_TYPE_HASH,
	.implements = "xorpair,parity,hamdist,pcprint,mod255,adler32,luhn,elf",
	.check = simplehash_check,
	.update = simplehash_update,
	.end = simplehash_update
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_CRYPTO,
	.data = &r_muta_plugin_simplehash,
	.version = R2_VERSION
};
#endif
