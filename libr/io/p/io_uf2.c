/* radare - LGPL - Copyright 2024 - aviciano */

#include <r_io.h>

// Little endian is used, as most microcontrollers are little endian.
// https://github.com/Microsoft/uf2
// https://github.com/raspberrypi/picotool/issues/8

#define UF2_MAGIC_START0 0x0A324655UL // "UF2\n"
#define UF2_MAGIC_START1 0x9E5D5157UL // Randomly selected
#define UF2_MAGIC_END 0x0AB16F30UL    // Ditto

enum UF2_Flags {
	NOT_MAIN_FLASH = 0x1 << 0,
	FILE_CONTAINER = 0x1 << 12,
	FAMILY_ID      = 0x1 << 13,
	MD5_CHECKSUM   = 0x1 << 14,
	EXTENSION_TAGS = 0x1 << 15,
};


#define ETAG_DESCRIPTION 0x650d9d // description of device for which the firmware file is destined (UTF8)
#define ETAG_FW_VERSION  0x9fc7bc // version of firmware file - UTF8 semver string
#define ETAG_PAGE_SIZE   0x0be9f7 // page size of target device (32 bit unsigned number)
#define ETAG_FW_CHECKSUM 0xb46db0 // SHA-2 checksum of firmware (can be of various size)
#define ETAG_DEVICE_ID   0xc8a729 // device type identifier - a refinement of familyID meant to identify a kind of device (eg., a toaster with specific pinout and heating unit), not only MCU; 32 or 64 bit number; can be hash of 0x650d9d

typedef struct {
	// 32 byte header
	ut32 magicStart0; // First magic number, 0x0A324655 ("UF2\n")
	ut32 magicStart1; // Second magic number, 0x9E5D5157
	ut32 flags;
	ut32 targetAddr;  // Address in flash where the data should be written
	ut32 payloadSize; // Number of bytes used in data (often 256)
	ut32 blockNo;     // Sequential block number; starts at 0
	ut32 numBlocks;   // Total number of blocks in file
	ut32 fileSize;    // File size or board family ID or zero

	// raw data
	// ut8 data[476];    // Data, padded with zeros
	ut8 *data;        // Data, padded with zeros

	// store magic also at the end to limit damage from partial block reads
	ut32 magicEnd;    // Final magic number, 0x0AB16F30
} UF2_Block;

#if 0
static void dump(UF2_Block *block) {
	eprintf ("===========[BLOCK]===========\n");
	eprintf ("- magicStart0 : 0x%08x\n", block->magicStart0); // First magic number, 0x0A324655 ("UF2\n")
	eprintf ("- magicStart1 : 0x%08x\n", block->magicStart1); // Second magic number, 0x9E5D5157
	eprintf ("- flags       : 0x%08x (", block->flags);
	eprintf ("%s", (block->flags & NOT_MAIN_FLASH) == 0 ? "" : " NOT_MAIN_FLASH");
	eprintf ("%s", (block->flags & FILE_CONTAINER) == 0 ? "" : " FILE_CONTAINER");
	eprintf ("%s", (block->flags & FAMILY_ID     ) == 0 ? "" : " FAMILY_ID");
	eprintf ("%s", (block->flags & MD5_CHECKSUM  ) == 0 ? "" : " MD5_CHECKSUM");
	eprintf ("%s", (block->flags & EXTENSION_TAGS) == 0 ? "" : " EXTENSION_TAGS");
	eprintf (" )\n");
	eprintf ("- targetAddr  : 0x%08x\n", block->targetAddr);  // Address in flash where the data should be written
	eprintf ("- payloadSize : %u\n", block->payloadSize); // Number of bytes used in data (often 256)
	eprintf ("- blockNo     : %u\n", block->blockNo);     // Sequential block number; starts at 0
	eprintf ("- numBlocks   : %u\n", block->numBlocks);   // Total number of blocks in file
	if ((block->flags & FAMILY_ID) == 0) {
		eprintf ("- fileSize    : %u\n", block->fileSize);    // File size or board family ID or zero
	} else {
		eprintf ("- familyID    : 0x%08x\n", block->fileSize);    // File size or board family ID or zero
	}
	eprintf ("- data        : \n");        // Raw Data, padded with zeros 476
	int i = 0;
	while (i < block->payloadSize) {
		eprintf ("%02x ", block->data[i++] & 0xff);
		if (i % 16 == 0) {
			eprintf("\n");
		}
	}
	if (i % 16 != 0) {
		eprintf("\n");
	}
	eprintf ("- magicEnd    : 0x%08x\n", block->magicEnd);    // Final magic number, 0x0AB16F30
	eprintf ("\n");
}
#endif

typedef struct {
	ut32 id;
	char *name;
	char *desc;
	char *arch;
	char *cpu;
	st16 bits;
} UF2_Family;

// FAMILY_IDs from https://github.com/microsoft/uf2/blob/master/utils/uf2families.json
static UF2_Family uf2families[] = {
	{ 0x00ff6919, "STM32L4", "ST STM32L4xx", "arm", "cortex", 32 }, // Arm Cortex-M4 32-bit
	{ 0x04240bdf, "STM32L5", "ST STM32L5xx", "arm", "cortex", 32 }, // Arm Cortex-M33 32-bit
	{ 0x06d1097b, "STM32F411xC", "ST STM32F411xC", "arm", "cortex", 32 }, // Arm Cortex-M4 32-bit
	{ 0x11de784a, "M0SENSE", "M0SENSE BL702", "riscv", NULL, 32 }, // RISC-V 32-bit
	{ 0x16573617, "ATMEGA32", "Microchip (Atmel) ATmega32", "avr", NULL, 8 }, // AVR 8-bit
	{ 0x1851780a, "SAML21", "Microchip (Atmel) SAML21", "arm", "cortex", 32 }, // Arm Cortex-M0+ 32-bit
	{ 0x1b57745f, "NRF52", "Nordic NRF52", "arm", "cortex", 32 }, // Arm Cortex-M4 32-bit
	{ 0x1c5f21b0, "ESP32", "ESP32", "xtensa", NULL, 32 }, // Xtensa LX6 32-bit
	{ 0x1e1f432d, "STM32L1", "ST STM32L1xx", "arm", "cortex", 32 }, // Arm Cortex-M3 32-bit
	{ 0x202e3a91, "STM32L0", "ST STM32L0xx", "arm", "cortex", 32 }, // Arm Cortex-M0+ 32-bit
	{ 0x21460ff0, "STM32WL", "ST STM32WLxx", "arm", "cortex", 32 }, // Arm Cortex 32-bit
	{ 0x22e0d6fc, "RTL8710B", "Realtek AmebaZ RTL8710B", "arm", "cortex", 32 }, // Arm Cortex-M3 32-bit
	{ 0x2abc77ec, "LPC55", "NXP LPC55xx", "arm", "cortex", 32 }, // Arm Cortex-M33 32-bit
	{ 0x2b88d29c, "ESP32C2", "ESP32-C2", "riscv", NULL, 32 }, // RISC-V 32-bit
	{ 0x2dc309c5, "STM32F411xE", "ST STM32F411xE", "arm", "cortex", 32 }, // Arm Cortex-M4 32-bit
	{ 0x300f5633, "STM32G0", "ST STM32G0xx", "arm", "cortex", 32 }, // Arm Cortex-M0+ 32-bit
	{ 0x31d228c6, "GD32F350", "GD32F350", "arm", "cortex", 32 }, // Arm Cortex-M4 32-bit
	{ 0x332726f6, "ESP32H2", "ESP32-H2", "riscv", NULL, 32 }, // RISC-V 32-bit
	{ 0x3379CFE2, "RTL8720D", "Realtek AmebaD RTL8720D", "arm", "cortex", 32 }, // Arm Cortex-M4 32-bit
	{ 0x3d308e94, "ESP32P4", "ESP32-P4", "riscv", NULL, 32 }, // RISC-V 32-bit
	{ 0x4b684d71, "MaixPlay-U4", "Sipeed MaixPlay-U4(BL618)", "riscv", NULL, 32 }, // RISC-V 32-bit
	{ 0x4c71240a, "STM32G4", "ST STM32G4xx", "arm", "cortex", 32 }, // Arm Cortex-M4 32-bit
	{ 0x4e8f1c5d, "STM32H5", "ST STM32H5xx", "arm", "cortex", 32 }, // Arm Cortex-M33 32-bit
	{ 0x4f6ace52, "CSK4", "LISTENAI CSK300x/400x", NULL, NULL, -1 },
	{ 0x4fb2d5bd, "MIMXRT10XX", "NXP i.MX RT10XX", "arm", "cortex", 32 }, // Arm Cortex-M7 32-bit
	{ 0x51e903a8, "XR809", "Xradiotech 809", "arm", "cortex", 32 }, // Arm Cortex-M4 32-bit
	{ 0x53b80f00, "STM32F7", "ST STM32F7xx", "arm", "cortex", 32 }, // Arm Cortex-M7 32-bit
	{ 0x540ddf62, "ESP32C6", "ESP32-C6", "riscv", NULL, 32 }, // RISC-V 32-bit
	{ 0x55114460, "SAMD51", "Microchip (Atmel) SAMD51", "arm", "cortex", 32 }, // Arm Cortex-M4F 32-bit
	{ 0x57755a57, "STM32F4", "ST STM32F4xx", "arm", "cortex", 32 }, // Arm Cortex-M4 32-bit
	{ 0x5a18069b, "FX2", "Cypress FX2", NULL, NULL, -1 }, // 8051 8-bit
	{ 0x5d1a0a2e, "STM32F2", "ST STM32F2xx", "arm", "cortex", 32 }, // Arm Cortex-M3 32-bit
	{ 0x5ee21072, "STM32F1", "ST STM32F103", "arm", "cortex", 32 }, // Arm Cortex-M3 32-bit
	{ 0x621e937a, "NRF52833", "Nordic NRF52833", "arm", "cortex", 32 }, // Arm Cortex-M4 32-bit
	{ 0x647824b6, "STM32F0", "ST STM32F0xx", "arm", "cortex", 32 }, // Arm Cortex-M0 32-bit
	{ 0x675a40b0, "BK7231U", "Beken 7231U/7231T", "arm", NULL, 32 }, // ARM968E-S (ARMv5TE) 32-bit
	{ 0x68ed2b88, "SAMD21", "Microchip (Atmel) SAMD21", "arm", "cortex", 32 }, // Arm Cortex-M0+ 32-bit
	{ 0x699b62ec, "CH32V", "WCH CH32V2xx and CH32V3xx", "riscv", NULL, 32 }, // RISC-V 32-bit
	{ 0x6a82cc42, "BK7251", "Beken 7251/7252", NULL, NULL, -1 },
	{ 0x6b846188, "STM32F3", "ST STM32F3xx", "arm", "cortex", 32 }, // Arm Cortex-M4 32-bit
	{ 0x6d0922fa, "STM32F407", "ST STM32F407", "arm", "cortex", 32 }, // Arm Cortex-M4 32-bit
	{ 0x6db66082, "STM32H7", "ST STM32H7xx", "arm", "cortex", 32 }, // Arm Cortex-M7 32-bit
	{ 0x6e7348a8, "CSK6", "LISTENAI CSK60xx", NULL, NULL, -1 },
	{ 0x6f752678, "NRF52832xxAB", "Nordic NRF52832xxAB", "arm", "cortex", 32 }, // Arm Cortex-M4 32-bit
	{ 0x70d16653, "STM32WB", "ST STM32WBxx", "arm", "cortex", 32 }, // Arm Cortex-M4 32-bit + Arm Cortex-M0+ 32-bit
	{ 0x72721d4e, "NRF52832xxAA", "Nordic NRF52832xxAA", "arm", "cortex", 32 }, // Arm Cortex-M4 32-bit
	{ 0x77d850c4, "ESP32C61", "ESP32-C61", "riscv", NULL, 32 }, // RISC-V 32-bit
	{ 0x7b3ef230, "BK7231N", "Beken 7231N", NULL, NULL, -1 },
	{ 0x7be8976d, "RA4M1", "Renesas RA4M1", "arm", "cortex", 32 }, // Arm Cortex-M4 32-bit
	{ 0x7eab61ed, "ESP8266", "ESP8266", "xtensa", NULL, 32 }, // L106 32-bit
	{ 0x7f83e793, "KL32L2", "NXP KL32L2x", "arm", "cortex", 32 }, // Arm Cortex-M0+ 32-bit
	{ 0x820d9a5f, "NRF52820", "Nordic NRF52820_xxAA", "arm", "cortex", 32 }, // Arm Cortex-M4 32-bit
	{ 0x8fb060fe, "STM32F407VG", "ST STM32F407VG", "arm", "cortex", 32 }, // Arm Cortex-M4 32-bit
	{ 0x9517422f, "RZA1LU", "Renesas RZ/A1LU (R7S7210xx)", "arm", "cortex", 32 }, // Arm Cortex-A9 32-bit
	{ 0x9af03e33, "GD32VF103", "GigaDevice GD32VF103", "riscv", NULL, 32 }, // RISC-V 32-bit
	{ 0x9e0baa8a, "ESP32H4", "ESP32-H4", "riscv", NULL, 32 }, // RISC-V 32-bit
	{ 0x9fffd543, "RTL8710A", "Realtek Ameba1 RTL8710A", "arm", "cortex", 32 }, // Arm Cortex-M3 32-bit
	{ 0xa0c97b8e, "AT32F415", "ArteryTek AT32F415", "arm", "cortex", 32 }, // Arm Cortex-M4 32-bit
	{ 0xada52840, "NRF52840", "Nordic NRF52840", "arm", "cortex", 32 }, // Arm Cortex-M4 32-bit
	{ 0xb6dd00af, "ESP32H21", "ESP32-H21", "riscv", NULL, 32 }, // RISC-V 32-bit
	{ 0xbfdd4eee, "ESP32S2", "ESP32-S2", "xtensa", NULL, 32 }, // Xtensa LX7 32-bit
	{ 0xc47e5767, "ESP32S3", "ESP32-S3", "xtensa", NULL, 32 }, // Xtensa LX7 32-bit
	{ 0xd42ba06c, "ESP32C3", "ESP32-C3", "riscv", NULL, 32 }, // RISC-V 32-bit
	{ 0xde1270b7, "BL602", "Boufallo 602", "riscv", NULL, 32 }, // RISC-V 32-bit
	{ 0xe08f7564, "RTL8720C", "Realtek AmebaZ2 RTL8720C", "arm", "cortex", 32 }, // Arm Cortex-M4 32-bit
	{ 0xe48bff56, "RP2040", "Raspberry Pi RP2040", "arm", "cortex", 32 }, // Arm Cortex-M0+ 32-bit
	{ 0xe48bff57, "RP2XXX_ABSOLUTE", "Raspberry Pi Microcontrollers: Absolute (unpartitioned) download", NULL, NULL, -1 },
	{ 0xe48bff58, "RP2XXX_DATA", "Raspberry Pi Microcontrollers: Data partition download", NULL, NULL, -1 },
	{ 0xe48bff59, "RP2350_ARM_S", "Raspberry Pi RP2350, Secure Arm image", "arm", "cortex", 32 }, // Arm Cortex-M33 32-bit
	{ 0xe48bff5a, "RP2350_RISCV", "Raspberry Pi RP2350, RISC-V image", "riscv", NULL, 32 }, // Hazard3 RISC-V 32-bit
	{ 0xe48bff5b, "RP2350_ARM_NS", "Raspberry Pi RP2350, Non-secure Arm image", "arm", "cortex", 32 }, // Arm Cortex-M33 32-bit
	{ 0xf71c0343, "ESP32C5", "ESP32-C5", "riscv", NULL, 32 }, // RISC-V 32-bit
};

static int binary_search(UF2_Family *A, ut32 key, int imin, int imax) {
	int imid;

	// continually narrow search until just one element remains
	while (imin < imax) {
		R_LOG_DEBUG ("uf2: binary search %08x [%d, %d]", key, imin, imax);
		imid = (imin + imax) / 2;
		if (A[imid].id < key) {
			imin = imid + 1;
		} else {
			imax = imid;
		}
	}

	// At exit of while:
	//   if A[] is empty, then imax < imin
	//   otherwise imax == imin

	// deferred test for equality
	if ((imax == imin) && (A[imin].id == key)) {
		return imin;
	}
	return -1;
}

static void process_family_id(RIO *io, ut32 family_id) {
	const int n = sizeof (uf2families) / sizeof (uf2families[0]);
	const int idx = binary_search (uf2families, family_id,  0, n - 1);
	if (idx < 0) {
		R_LOG_WARN ("uf2: FAMILY_ID: 0x%08x => Unknown", family_id);
		return;
	}

	const UF2_Family family = uf2families[idx];
	R_LOG_DEBUG ("uf2: FAMILY_ID: 0x%08x => { name:%s, desc:%s, arch:%s, cpu:%s, bits:%d }",
			family_id, family.name, family.desc, family.arch, family.cpu, family.bits);

	if (family.arch != NULL) {
		io->coreb.cmdf (io->coreb.core, "e asm.arch=%s", family.arch);
	}

	if (family.cpu != NULL) {
		io->coreb.cmdf (io->coreb.core, "'e asm.cpu=%s", family.cpu);
	}

	if (family.bits >= 0) {
		io->coreb.cmdf (io->coreb.core, "'e asm.bits=%d", family.bits);
	}
}

static inline int pad(int offset, int n) {
	if (n < 1) {
		return 0;
	}
	return (offset % n != 0
		? (offset / n + 1)
		: (offset / n)) * n;
}

static bool uf2_read(RIO *io, RBuffer *rbuf, char *buf) {
	const bool has_debug = r_sys_getenv_asbool ("R2_DEBUG");
	ut32 family_id = 0;

	UF2_Block block;
	do {
		block.magicStart0 = *(ut32 *)(buf + 0x00); // First magic number, 0x0A324655 ("UF2\n")
		block.magicStart1 = *(ut32 *)(buf + 0x04); // Second magic number, 0x9E5D5157
		block.flags       = *(ut32 *)(buf + 0x08);
		block.targetAddr  = *(ut32 *)(buf + 0x0c); // Address in flash where the data should be written
		block.payloadSize = *(ut32 *)(buf + 0x10); // Number of bytes used in data (often 256)
		block.blockNo     = *(ut32 *)(buf + 0x14); // Sequential block number; starts at 0
		block.numBlocks   = *(ut32 *)(buf + 0x18); // Total number of blocks in file
		block.fileSize    = *(ut32 *)(buf + 0x1c); // File size or board family ID or zero
		block.data        = (ut8 *)(buf + 0x20); // Raw Data, padded with zeros [476]
		block.magicEnd    = *(ut32 *)(buf + 0x1fc); // Final magic number, 0x0AB16F30
		buf += 512;

		// dump (&block);

		if (block.magicStart0 != UF2_MAGIC_START0) {
			R_LOG_ERROR ("uf2: Invalid magic start 0 @ block %d", block.blockNo);
			return false;
		}

		if (block.magicStart1 != UF2_MAGIC_START1) {
			R_LOG_ERROR ("uf2: Invalid magic start 1 @ block %d", block.blockNo);
			return false;
		}

		if (block.magicEnd != UF2_MAGIC_END) {
			R_LOG_ERROR ("uf2: Invalid magic end @ block %d", block.blockNo);
			return false;
		}

		if ((block.flags & NOT_MAIN_FLASH) != 0) {
			R_LOG_WARN ("uf2: Found NOT_MAIN_FLASH flag @ block #%d, skiping", block.blockNo);
			// this block should be skipped when writing the device flash;
			// it can be used to store "comments" in the file, typically embedded source code
			// or debug info that does not fit on the device flash
			continue;
		}

		if ((block.flags & FILE_CONTAINER) != 0) {
			// It is also possible to use the UF2 format as a container for one or more
			// regular files (akin to a TAR file, or ZIP archive without compression).
			// This is useful when the embedded device being flashed sports a file system.
			// The field fileSize holds the file size of the current file,
			// and the field targetAddr holds the offset in current file.
			// The file name is stored at &data[payloadSize] and terminated with a 0x00.
			const char *file_name = (const char *)(block.data + block.payloadSize);
			R_LOG_WARN ("uf2: Found FILE_CONTAINER flag @ block #%d, TODO"
					"{ file_name: \"%s\", chunk: %d, total_size: %d, offset: %d }", block.blockNo,
					file_name, block.payloadSize, block.fileSize, block.targetAddr);
			continue;
		}

		if ((block.flags & FAMILY_ID) != 0) {
			// R_LOG_DEBUG ("uf2: Found FAMILY_ID flag @ block #%d", block.blockNo);
			bool new_family_id = family_id != block.fileSize;
			if (new_family_id) {
				if (family_id != 0) {
					R_LOG_WARN ("uf2: FAMILY_ID 0x%08x changed", block.fileSize);
				}
				family_id =  block.fileSize;
				process_family_id (io, family_id);
			}
		}

		if ((block.flags & MD5_CHECKSUM) != 0) {
			R_LOG_WARN ("uf2: Found MD5_CHECKSUM flag @ block #%d, TODO", block.blockNo);
			// the last 24 bytes of data[] hold the following structure:
			// Offset | Size | Value
			// 0      | 4    | Start address of region
			// 4      | 4    | Length of region in bytes
			// 8      | 16   | MD5 checksum in binary format
		}

		if ((block.flags & EXTENSION_TAGS) != 0) {
			// Extension tags can, but don't have to, be repeated in all blocks.
			R_LOG_WARN ("uf2: Found EXTENSION_TAGS flag @ block #%d", block.blockNo);
			ut16 offset = block.payloadSize;
			while (offset < 476) {
				ut32 tag_sz = *(ut32 *)(block.data + offset);
				ut32 tag = (tag_sz >> 8) & 0xffffff;
				ut8 size = (ut8)(tag_sz & 0xff);
				switch (tag) {
				case ETAG_FW_VERSION:
				case ETAG_FW_CHECKSUM:
				case ETAG_DESCRIPTION:
				case ETAG_DEVICE_ID:
				case ETAG_PAGE_SIZE:
				default:
					R_LOG_WARN ("uf2: Unknown EXTENSION TAG 0x%04x, TODO", tag);
					// TODO dump size
					break;
				}
				// Every tag starts at 4 byte boundary
				offset += pad (size, 4);
			}
		}

		if (r_buf_write_at (rbuf, block.targetAddr, block.data, block.payloadSize) != block.payloadSize) {
			R_LOG_ERROR ("uf2: Sparse buffer problem, giving up");
			return false;
		}

		if (has_debug) {
			R_LOG_DEBUG ("uf2: Block #%02d (%d bytes @ 0x%08x)", block.blockNo, block.payloadSize, block.targetAddr);
		}

		r_strf_var (comment, 64,  "CC uf2 block #%02d (%d bytes)", block.blockNo, block.payloadSize);
		io->coreb.callAt (io->coreb.core, block.targetAddr, comment);

	} while (block.blockNo < block.numBlocks - 1);

	return true;
}

typedef struct {
	int fd;
	RBuffer *rbuf;
} Ruf2;

extern RIOPlugin r_io_plugin_uf2;

static bool __check(RIO *io, const char *pathname, bool many) {
	return r_str_startswith (pathname, "uf2://");
}

static RIODesc *__open(RIO *io, const char *pathname, int rw, int mode) {
	if (!__check (io, pathname, false)) {
		return NULL;
	}

	char *buf = r_file_slurp (pathname + 6, NULL);
	if (!buf) {
		return NULL;
	}

	Ruf2 *mal = R_NEW0 (Ruf2);
	if (!mal) {
		free (buf);
		return NULL;
	}

	mal->rbuf = r_buf_new_sparse (io->Oxff);
	if (!mal->rbuf) {
		free (buf);
		free (mal);
		return NULL;
	}

	if (!uf2_read (io, mal->rbuf, buf)) {
		R_LOG_ERROR ("uf2: Failed to read UF2 file");
		free (buf);
		r_buf_free (mal->rbuf);
		free (mal);
		return NULL;
	}

	free (buf);
	return r_io_desc_new (io, &r_io_plugin_uf2, pathname, rw, mode, mal);
}


static int __read(RIO *io, RIODesc *desc, ut8 *buf, int count) {
	if (!desc || !desc->data || (count <= 0)) {
		return -1;
	}
	Ruf2 *mal = desc->data;
	memset (buf, io->Oxff, count);
	int r = r_buf_read_at (mal->rbuf, io->off, buf, count);
	if (r >= 0) {
		r_buf_seek (mal->rbuf, r, R_BUF_CUR);
	}
	return r;
}

static bool __close(RIODesc *desc) {
	if (!desc || !desc->data) {
		return false;
	}
	Ruf2 *mal = desc->data;
	r_buf_free (mal->rbuf);
	free (mal);
	desc->data = NULL;
	return true;
}

static ut64 __lseek(RIO *io, RIODesc *desc, ut64 offset, int whence) {
	if (!desc || !desc->data) {
		return -1;
	}
	Ruf2 *mal = desc->data;
	io->off = r_buf_seek (mal->rbuf, offset, whence);
	return io->off;
}

static int __write(RIO *io, RIODesc *desc, const ut8 *buf, int count) {
	// TODO
	return -1;
}

static bool __resize(RIO *io, RIODesc *desc, ut64 size) {
	if (!desc) {
		return false;
	}
	Ruf2 *mal = desc->data;
	if (!mal) {
		return false;
	}
	return r_buf_resize (mal->rbuf, size);
}

static char *__system(RIO *io, RIODesc *fd, const char *cmd) {
	// TODO
	return NULL;
}

RIOPlugin r_io_plugin_uf2 = {
	.meta = {
		.name = "uf2",
		.desc = "Open UF2 files",
		.license = "LGPL-3.0-only",
		.author = "aviciano"
	},
	.uris = "uf2://",
	.open = __open,
	.close = __close,
	.read = __read,
	.check = __check,
	.seek = __lseek,
	.write = __write,
	.resize = __resize,
	.system = __system,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_uf2,
	.version = R2_VERSION
};
#endif

