/* radare - LGPL - Copyright 2024-2026 - pancake */

#include <r_lib.h>
#include <r_muta.h>
#include <r_hash.h>
#include <r_endian.h>

typedef struct {
	const char *name;
	enum CRC_PRESETS preset;
	int digest_size;
} CrcAlgorithm;

static const CrcAlgorithm crc_algorithms[] = {
	{ "crc8smbus",    CRC_PRESET_8_SMBUS,       1 },
	{ "crc15can",     CRC_PRESET_15_CAN,        2 },
	{ "crc16",        CRC_PRESET_16,            2 },
	{ "crc16hdlc",    CRC_PRESET_16_HDLC,       2 },
	{ "crc16usb",     CRC_PRESET_16_USB,        2 },
	{ "crc16citt",    CRC_PRESET_16_CITT,       2 },
	{ "crc24",        CRC_PRESET_24,            3 },
	{ "crc32",        CRC_PRESET_32,            4 },
	{ "crc32c",       CRC_PRESET_32C,           4 },
	{ "crc32ecma267", CRC_PRESET_32_ECMA_267,   4 },
	{ "crc32bzip2",   CRC_PRESET_CRC32_BZIP2,   4 },
	{ "crc32d",       CRC_PRESET_CRC32D,        4 },
	{ "crc32mpeg2",   CRC_PRESET_CRC32_MPEG2,   4 },
	{ "crc32posix",   CRC_PRESET_CRC32_POSIX,   4 },
	{ "crc32q",       CRC_PRESET_CRC32Q,        4 },
	{ "crc32jamcrc",  CRC_PRESET_CRC32_JAMCRC,  4 },
	{ "crc32xfer",    CRC_PRESET_CRC32_XFER,    4 },
	{ "crc64",        CRC_PRESET_CRC64,         8 },
	{ "crc64ecma",    CRC_PRESET_CRC64_ECMA182, 8 },
	{ "crc64we",      CRC_PRESET_CRC64_WE,      8 },
	{ "crc64xz",      CRC_PRESET_CRC64_XZ,      8 },
	{ "crc64iso",     CRC_PRESET_CRC64_ISO,     8 },
};

static const CrcAlgorithm *crc_find(const char *algo) {
	const size_t amount = sizeof (crc_algorithms) / sizeof (crc_algorithms[0]);
	size_t i;
	for (i = 0; i < amount; i++) {
		if (!strcmp (algo, crc_algorithms[i].name)) {
			return &crc_algorithms[i];
		}
	}
	return NULL;
}

static bool crc_check(const char *algo) {
	return crc_find (algo) != NULL;
}

static bool crc_update(RMutaSession *cj, const ut8 *buf, int len) {
	R_RETURN_VAL_IF_FAIL (cj && buf, false);
	const CrcAlgorithm *algo = cj->subtype ? crc_find (cj->subtype) : NULL;
	if (!algo) {
		return false;
	}
	utcrc result = r_hash_crc_preset (buf, len, algo->preset);
	ut8 digest[8];
	switch (algo->digest_size) {
	case 1: digest[0] = (ut8)result; break;
	case 2: r_write_be16 (digest, (ut16)result); break;
	case 3: r_write_be24 (digest, (ut32)result); break;
	case 4: r_write_be32 (digest, (ut32)result); break;
	case 8: r_write_be64 (digest, (ut64)result); break;
	}
	r_muta_session_append (cj, digest, algo->digest_size);
	return true;
}

RMutaPlugin r_muta_plugin_crc = {
	.meta = {
		.name = "crc",
		.desc = "CRC8/CRC15/CRC16/CRC24/CRC32/CRC64 hash algorithms",
		.author = "pancake",
		.license = "MIT",
	},
	.type = R_MUTA_TYPE_HASH,
	.implements = "crc8smbus,crc15can,crc16,crc16hdlc,crc16usb,crc16citt,crc24,crc32,crc32c,crc32ecma267,crc32bzip2,crc32d,crc32mpeg2,crc32posix,crc32q,crc32jamcrc,crc32xfer,crc64,crc64ecma,crc64we,crc64xz,crc64iso",
	.check = crc_check,
	.update = crc_update,
	.end = crc_update
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_CRYPTO,
	.data = &r_muta_plugin_crc,
	.version = R2_VERSION
};
#endif
