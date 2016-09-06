/* radare - LGPL - Copyright 2015-2016 - shengdi */

#include <r_bin.h>

typedef struct gen_hdr {
	ut8 HeaderID[8];
	ut8 ReservedWord[2];
	ut16 CheckSum;
	ut8 ProductCode[2];
	ut8 Version; //Low 4 bits version, Top 4 bits ProductCode
	ut8 RegionRomSize; //Low 4 bits RomSize, Top 4 bits Region
} SMS_Header;

static int check(RBinFile *arch);
static int check_bytes(const ut8 *buf, ut64 length);

static void * load_bytes(RBinFile *arch, const ut8 *buf, ut64 sz, ut64 loadaddr, Sdb *sdb){
	check_bytes (buf, sz);
	return R_NOTNULL;
}

static int check(RBinFile *arch) {
	const ut8 *bytes = arch ? r_buf_buffer (arch->buf) : NULL;
	ut64 sz = arch ? r_buf_size (arch->buf): 0;
	return check_bytes (bytes, sz);
}

#define CMP8(o,x) strncmp((const char*)bs+o,x,8)
#define CMP4(o,x) strncmp((const char*)bs+o,x,4)
static int check_bytes(const ut8 *bs, ut64 length) {
	if (length > 0x2000 && !CMP8(0x1ff0, "TMR SEGA")) {
		return true;
	}
	if (length > 0x4000 && !CMP8(0x3ff0, "TMR SEGA")) {
		return true;
	}
	if (length > 0x8000 && !CMP8(0x7ff0, "TMR SEGA")) {
		return true;
	}
	if (length > 0x9000 && !CMP8(0x8ff0, "TMR SEGA")) {
		return true;
	}
	if (length > 0x8000 && !CMP4(0x7fe0, "SDSC")) {
		return true;
	}
	return false;
}

static RBinInfo* info(RBinFile *arch) {
	const char *bs;
	SMS_Header *hdr = NULL;
	RBinInfo *ret = R_NEW0 (RBinInfo);
	if (!ret || !arch || !arch->buf) {
		free (ret);
		return NULL;
	}
	ret->file = strdup (arch->file);
	ret->type = strdup ("ROM");
	ret->machine = strdup ("SEGA MasterSystem");
	ret->os = strdup ("sms");
	ret->arch = strdup ("z80");
	ret->has_va = 1;
	ret->bits = 8;
	bs = (const char*)arch->buf->buf;
	// TODO: figure out sections/symbols for this format and move this there
	//       also add SDSC headers..and find entry
	if (!CMP8(0x1ff0, "TMR SEGA")) {
		hdr = (SMS_Header*)(bs + 0x1ff0);
	} else if (!CMP8(0x3ff0, "TMR SEGA")) {
		hdr = (SMS_Header*)(bs + 0x3ff0);
	} else if (!CMP8(0x7ff0, "TMR SEGA")) {
		hdr = (SMS_Header*)(bs + 0x7ff0);
	} else if (!CMP8(0x8ff0, "TMR SEGA")) {
		hdr = (SMS_Header*)(bs + 0x8ff0);
	} else {
		eprintf ("Cannot find magic SEGA copyright\n");
		free (ret);
		return NULL;
	}

	eprintf ("Checksum: 0x%04x\n", (ut32)hdr->CheckSum);
	eprintf ("ProductCode: %02d%02X%02X\n", (hdr->Version >> 4), hdr->ProductCode[1],
			hdr->ProductCode[0]);
	switch (hdr->RegionRomSize >> 4) {
	case 3:
		eprintf ("Console: Sega Master System\n");
		eprintf ("Region: Japan\n");
		break;
	case 4:
		eprintf ("Console: Sega Master System\n");
		eprintf ("Region: Export\n");
		break;
	case 5:
		eprintf ("Console: Game Gear\n");
		eprintf ("Region: Japan\n");
		break;
	case 6:
		eprintf ("Console: Game Gear\n");
		eprintf ("Region: Export\n");
		break;
	case 7:
		eprintf ("Console: Game Gear\n");
		eprintf ("Region: International\n");
		break;
	}
	int romsize = 0;
	switch (hdr->RegionRomSize & 0xf) {
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
	eprintf ("RomSize: %dKB\n", romsize);
	return ret;
}


struct r_bin_plugin_t r_bin_plugin_sms = {
	.name = "sms",
	.desc = "SEGA MasterSystem/GameGear",
	.license = "LGPL3",
	.load_bytes = &load_bytes,
	.check = &check,
	.check_bytes = &check_bytes,
	.info = &info,
	.minstrlen = 10,
	.strfilter = 'U'
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_sms,
	.version = R2_VERSION
};
#endif

