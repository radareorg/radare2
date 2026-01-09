/* radare - LGPL - Copyright 2024-2026 - pancake */

#include <r_lib.h>
#include <r_muta.h>
#include <r_hash.h>
#include <r_endian.h>

typedef struct {
	const char *name;
	int digest_size;
} FletcherAlgorithm;

static const FletcherAlgorithm fletcher_algorithms[] = {
	{ "fletcher8",  1 },
	{ "fletcher16", 2 },
	{ "fletcher32", 4 },
	{ "fletcher64", 8 },
};

static const FletcherAlgorithm *fletcher_find(const char *algo) {
	const size_t amount = sizeof (fletcher_algorithms) / sizeof (fletcher_algorithms[0]);
	size_t i;
	for (i = 0; i < amount; i++) {
		if (!strcmp (algo, fletcher_algorithms[i].name)) {
			return &fletcher_algorithms[i];
		}
	}
	return NULL;
}

static bool fletcher_check(const char *algo) {
	return fletcher_find (algo) != NULL;
}

static bool fletcher_update(RMutaSession *cj, const ut8 *buf, int len) {
	R_RETURN_VAL_IF_FAIL (cj && buf, false);
	const FletcherAlgorithm *algo = cj->subtype ? fletcher_find (cj->subtype) : NULL;
	if (!algo) {
		return false;
	}
	ut8 digest[8] = {0};
	switch (algo->digest_size) {
	case 1:
		r_write_be8 (digest, r_hash_fletcher8 (buf, len));
		break;
	case 2:
		r_write_be16 (digest, r_hash_fletcher16 (buf, len));
		break;
	case 4:
		r_write_be32 (digest, r_hash_fletcher32 (buf, len));
		break;
	case 8:
		r_write_be64 (digest, r_hash_fletcher64 (buf, len));
		break;
	}
	r_muta_session_append (cj, digest, algo->digest_size);
	return true;
}

RMutaPlugin r_muta_plugin_fletcher = {
	.meta = {
		.name = "fletcher",
		.desc = "Fletcher hash algorithms",
		.author = "pancake",
		.license = "MIT",
	},
	.type = R_MUTA_TYPE_HASH,
	.implements = "fletcher8,fletcher16,fletcher32,fletcher64",
	.check = fletcher_check,
	.update = fletcher_update,
	.end = fletcher_update
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_CRYPTO,
	.data = &r_muta_plugin_fletcher,
	.version = R2_VERSION
};
#endif
