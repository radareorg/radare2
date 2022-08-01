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

static R_TH_LOCAL ut32 cb = 0;

static bool check_buffer(RBinFile *bf, RBuffer *b) {
	ut32 *off, offs[] = { 0x2000, 0x4000, 0x8000, 0x9000, 0 };
	ut8 signature[8];
	for (off = (ut32*)&offs; *off; off++) {
		r_buf_read_at (b, *off - 16, (ut8*)&signature, 8);
		if (!strncmp ((const char *)signature, "TMR SEGA", 8)) {
			cb = *off - 16;
			return true; // int)(*off - 16);
		}
		if (*off == 0x8000) {
			if (!strncmp ((const char *)signature, "SDSC", 4)) {
				cb = *off - 16;
				return true; // (int)(*off - 16);
			}
		}
	}
	return false;
}

static bool load_buffer(RBinFile *bf, void **bin_obj, RBuffer *buf, ut64 loadaddr, Sdb *sdb) {
	return check_buffer (bf, buf);
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
	if (!check_buffer (bf, bf->buf)) {
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
	int romsize = 0;
	switch (hdr.RegionRomSize & 0xf) {
	case 0xa: romsize = 8; break;
	case 0xb: romsize = 16; break;
	case 0xc: romsize = 32; break;
	case 0xd: romsize = 48; break;
	case 0xe: romsize = 64; break;
	case 0xf: romsize = 128; break;
	case 0x0: romsize = 256; break;
	case 0x1: romsize = 512; break;
	case 0x2: romsize = 1024; break;
	}
	R_LOG_INFO ("RomSize: %dKB", romsize);
	return ret;
}

RBinPlugin r_bin_plugin_sms = {
	.name = "sms",
	.desc = "SEGA MasterSystem/GameGear",
	.license = "LGPL3",
	.load_buffer = &load_buffer,
	.check_buffer = &check_buffer,
	.info = &info,
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
