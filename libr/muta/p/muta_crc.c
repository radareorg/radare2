/* radare - LGPL - Copyright 2024-2026 - pancake */

#include <r_lib.h>
#include <r_muta.h>
#include <r_hash.h>
#include <r_endian.h>

static bool crc_check(const char *algo) {
	return !strcmp (algo, "crc8smbus") ||
		!strcmp (algo, "crc15can") ||
		!strcmp (algo, "crc16") ||
		!strcmp (algo, "crc16hdlc") ||
		!strcmp (algo, "crc16usb") ||
		!strcmp (algo, "crc16citt") ||
		!strcmp (algo, "crc24") ||
		!strcmp (algo, "crc32") ||
		!strcmp (algo, "crc32c") ||
		!strcmp (algo, "crc32ecma267") ||
		!strcmp (algo, "crc32bzip2") ||
		!strcmp (algo, "crc32d") ||
		!strcmp (algo, "crc32mpeg2") ||
		!strcmp (algo, "crc32posix") ||
		!strcmp (algo, "crc32q") ||
		!strcmp (algo, "crc32jamcrc") ||
		!strcmp (algo, "crc32xfer") ||
		!strcmp (algo, "crc64") ||
		!strcmp (algo, "crc64ecma") ||
		!strcmp (algo, "crc64we") ||
		!strcmp (algo, "crc64xz") ||
		!strcmp (algo, "crc64iso");
}

static bool crc_update(RMutaSession *cj, const ut8 *buf, int len) {
	R_RETURN_VAL_IF_FAIL (cj && buf, false);
	enum CRC_PRESETS preset = 0;
	if (cj->subtype) {
		if (!strcmp (cj->subtype, "crc8smbus")) {
			preset = CRC_PRESET_8_SMBUS;
		} else if (!strcmp (cj->subtype, "crc15can")) {
			preset = CRC_PRESET_15_CAN;
		} else if (!strcmp (cj->subtype, "crc16")) {
			preset = CRC_PRESET_16;
		} else if (!strcmp (cj->subtype, "crc16hdlc")) {
			preset = CRC_PRESET_16_HDLC;
		} else if (!strcmp (cj->subtype, "crc16usb")) {
			preset = CRC_PRESET_16_USB;
		} else if (!strcmp (cj->subtype, "crc16citt")) {
			preset = CRC_PRESET_16_CITT;
		} else if (!strcmp (cj->subtype, "crc24")) {
			preset = CRC_PRESET_24;
		} else if (!strcmp (cj->subtype, "crc32")) {
			preset = CRC_PRESET_32;
		} else if (!strcmp (cj->subtype, "crc32c")) {
			preset = CRC_PRESET_32C;
		} else if (!strcmp (cj->subtype, "crc32ecma267")) {
			preset = CRC_PRESET_32_ECMA_267;
		} else if (!strcmp (cj->subtype, "crc32bzip2")) {
			preset = CRC_PRESET_CRC32_BZIP2;
		} else if (!strcmp (cj->subtype, "crc32d")) {
			preset = CRC_PRESET_CRC32D;
		} else if (!strcmp (cj->subtype, "crc32mpeg2")) {
			preset = CRC_PRESET_CRC32_MPEG2;
		} else if (!strcmp (cj->subtype, "crc32posix")) {
			preset = CRC_PRESET_CRC32_POSIX;
		} else if (!strcmp (cj->subtype, "crc32q")) {
			preset = CRC_PRESET_CRC32Q;
		} else if (!strcmp (cj->subtype, "crc32jamcrc")) {
			preset = CRC_PRESET_CRC32_JAMCRC;
		} else if (!strcmp (cj->subtype, "crc32xfer")) {
			preset = CRC_PRESET_CRC32_XFER;
		} else if (!strcmp (cj->subtype, "crc64")) {
			preset = CRC_PRESET_CRC64;
		} else if (!strcmp (cj->subtype, "crc64ecma")) {
			preset = CRC_PRESET_CRC64_ECMA182;
		} else if (!strcmp (cj->subtype, "crc64we")) {
			preset = CRC_PRESET_CRC64_WE;
		} else if (!strcmp (cj->subtype, "crc64xz")) {
			preset = CRC_PRESET_CRC64_XZ;
		} else if (!strcmp (cj->subtype, "crc64iso")) {
			preset = CRC_PRESET_CRC64_ISO;
		}
	}
	if (!preset) {
		return false;
	}
	utcrc result = r_hash_crc_preset (buf, len, preset);
	int digest_size = r_hash_size (r_hash_name_to_bits (cj->subtype));
	ut8 digest[8]; // max crc64 is 8 bytes
	if (digest_size == 1) {
		digest[0] = (ut8)result;
	} else if (digest_size == 2) {
		r_write_be16 (digest, (ut16)result);
	} else if (digest_size == 3) {
		r_write_be24 (digest, (ut32)result);
	} else if (digest_size == 4) {
		r_write_be32 (digest, (ut32)result);
	} else if (digest_size == 8) {
		r_write_be64 (digest, (ut64)result);
	}
	r_muta_session_append (cj, digest, digest_size);
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