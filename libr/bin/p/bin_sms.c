/* radare - LGPL - Copyright 2015-2022 - shengdi */

#include <r_bin.h>

typedef struct gen_hdr {
	ut8 HeaderID[8];
	ut8 ReservedWord[2];
	ut16 CheckSum;
	ut8 ProductCode[2];
	ut8 Version; //Low 4 bits version, Top 4 bits ProductCode
	ut8 RegionRomSize; //Low 4 bits RomSize, Top 4 bits Region
} SMS_Header;

static ut32 get_buffer(RBinFile *bf, RBuffer *b) {
	ut32 *off, offs[] = { 0x2000, 0x4000, 0x8000, 0x9000, 0 };
	ut8 signature[8];
	for (off = (ut32*)&offs; *off; off++) {
		r_buf_read_at (b, *off - 16, (ut8*)&signature, 8);
		if (!strncmp ((const char *)signature, "TMR SEGA", 8)) {
			return *off - 16;
		}
		if (*off == 0x8000) {
			if (!strncmp ((const char *)signature, "SDSC", 4)) {
				return *off - 16;
			}
		}
	}
	return UT32_MAX;
}

static int sms_rom_kilobytes(ut8 size_code) {
	switch (size_code & 0xf) {
	case 0xa: return 8;
	case 0xb: return 16;
	case 0xc: return 32;
	case 0xd: return 48;
	case 0xe: return 64;
	case 0xf: return 128;
	case 0x0: return 256;
	case 0x1: return 512;
	case 0x2: return 1024;
	}
	return 0;
}

static bool check(RBinFile *bf, RBuffer *b) {
	ut32 res = get_buffer (bf, b);
	return res != UT32_MAX;
}

static bool load(RBinFile *bf, RBuffer *buf, ut64 loadaddr) {
	return check (bf, buf);
}

static RBinInfo *info(RBinFile *bf) {
	RBinInfo *ret = R_NEW0 (RBinInfo);
	if (!ret || !bf || !bf->buf) {
		free (ret);
		return NULL;
	}
	ret->file = strdup (bf->file);
	ret->type = strdup ("ROM");
	ret->machine = strdup ("SEGA MasterSystem");
	ret->os = strdup ("sms");
	ret->arch = strdup ("z80");
	ret->has_va = 1;
	ret->bits = 8;
	ut32 cb = get_buffer (bf, bf->buf);
	if (cb == UT32_MAX) {
		R_LOG_ERROR ("Cannot find magic SEGA copyright");
		free (ret);
		return NULL;
	}
	SMS_Header hdr = {{0}};
	r_buf_read_at (bf->buf, cb, (ut8*)&hdr, sizeof (hdr));
	hdr.CheckSum = r_read_le16 (&hdr.CheckSum);

	R_LOG_INFO ("Checksum: 0x%04x", (ut32)hdr.CheckSum); // use endian safe apis here
	R_LOG_INFO ("ProductCode: %02d%02X%02X", (hdr.Version >> 4), hdr.ProductCode[1],
		hdr.ProductCode[0]);
	switch (hdr.RegionRomSize >> 4) {
	case 3:
		R_LOG_INFO ("Console: Sega Master System");
		R_LOG_INFO ("Region: Japan");
		break;
	case 4:
		R_LOG_INFO ("Console: Sega Master System");
		R_LOG_INFO ("Region: Export");
		break;
	case 5:
		R_LOG_INFO ("Console: Game Gear");
		R_LOG_INFO ("Region: Japan");
		break;
	case 6:
		R_LOG_INFO ("Console: Game Gear");
		R_LOG_INFO ("Region: Export");
		break;
	case 7:
		R_LOG_INFO ("Console: Game Gear");
		R_LOG_INFO ("Region: International");
		break;
	}
	R_LOG_INFO ("RomSize: %dKB", sms_rom_kilobytes (hdr.RegionRomSize));
	return ret;
}

// the checksum is the sum of the rom bytes declared by the header, skipping the header itself
static int checksum(RBinFile *bf, RStrBuf *report, bool fix) {
	const ut64 hdr = get_buffer (bf, bf->buf);
	ut64 size = 0;
	const ut8 *data = r_buf_data (bf->buf, &size);
	if (!data || hdr == UT32_MAX || hdr + sizeof (SMS_Header) > size || memcmp (data + hdr, "TMR SEGA", 8)) {
		return -1;
	}
	const ut64 declared = sms_rom_kilobytes (data[hdr + r_offsetof (SMS_Header, RegionRomSize)]) * 1024ULL;
	const ut64 rom_size = (declared && declared < size)? declared: size;
	ut16 sum = 0;
	ut64 i;
	for (i = 0; i < rom_size; i++) {
		if (i < hdr || i >= hdr + sizeof (SMS_Header)) {
			sum += data[i];
		}
	}
	ut8 computed[2];
	r_write_le16 (computed, sum);
	const ut64 paddr = hdr + r_offsetof (SMS_Header, CheckSum);
	return !r_bin_wr_checksum_update (bf->buf, report, "sms", paddr, computed, sizeof (computed), fix);
}

static RBinWrite r_bin_write_sms = {
	.checksum = &checksum,
};

RBinPlugin r_bin_plugin_sms = {
	.meta = {
		.name = "sms",
		.author = "pancake",
		.desc = "SEGA MasterSystem/GameGear",
		.license = "LGPL-3.0-only",
	},
	.load = &load,
	.check = &check,
	.info = &info,
	.write = &r_bin_write_sms,
	.minstrlen = 10,
	.strfilter = 'U'
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_sms,
	.version = R2_VERSION
};
#endif
