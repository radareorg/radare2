/* radare2 - LGPL 3 - Copyright 2018 - lowlyw */

/*
 * info comes from here.
 * https://github.com/mikeryan/n64dev
 * http://en64.shoutwiki.com/wiki/N64_Memory
 */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>
#include <r_io.h>
#include <r_cons.h>

#define N64_ROM_START 0x1000

// starting at 0
/*
0000h              (1 byte): initial PI_BSB_DOM1_LAT_REG value (0x80)
0001h              (1 byte): initial PI_BSB_DOM1_PGS_REG value (0x37)
0002h              (1 byte): initial PI_BSB_DOM1_PWD_REG value (0x12)
0003h              (1 byte): initial PI_BSB_DOM1_PGS_REG value (0x40)
0004h - 0007h     (1 dword): ClockRate
0008h - 000Bh     (1 dword): Program Counter (PC)
000Ch - 000Fh     (1 dword): Release
0010h - 0013h     (1 dword): CRC1
0014h - 0017h     (1 dword): CRC2
0018h - 001Fh    (2 dwords): Unknown (0x0000000000000000)
0020h - 0033h    (20 bytes): Image name
                             Padded with 0x00 or spaces (0x20)
0034h - 0037h     (1 dword): Unknown (0x00000000)
0038h - 003Bh     (1 dword): Manufacturer ID
                             0x0000004E = Nintendo ('N')
003Ch - 003Dh      (1 word): Cartridge ID
003Eh - 003Fh      (1 word): Country code
                             0x4400 = Germany ('D')
                             0x4500 = USA ('E')
                             0x4A00 = Japan ('J')
                             0x5000 = Europe ('P')
                             0x5500 = Australia ('U')
0040h - 0FFFh (1008 dwords): Boot code
*/
typedef struct {
	ut8 x1; /* initial PI_BSB_DOM1_LAT_REG value */
	ut8 x2; /* initial PI_BSB_DOM1_PGS_REG value */
	ut8 x3; /* initial PI_BSB_DOM1_PWD_REG value */
	ut8 x4; /* initial PI_BSB_DOM1_RLS_REG value */
	ut32 ClockRate;
	ut32 BootAddress;
	ut32 Release;
	ut32 CRC1;
	ut32 CRC2;
	ut64 UNK1;
	char Name[20];
	ut32 UNK2;
	ut16 UNK3;
	ut8 UNK4;
	ut8 ManufacturerID; // 0x0000004E ('N') ?
	ut16 CartridgeID;
	char CountryCode;
	ut8 UNK5;
	// BOOT CODE?
} N64Header;

static N64Header n64_header;

static ut64 baddr(RBinFile *bf) {
	return (ut64) r_read_be32(&n64_header.BootAddress);
}

static bool check_bytes (const ut8 *buf, ut64 length) {
	ut32 magic = 0x80371240;
	if (length < N64_ROM_START) {
		return false;
	}
	return magic == r_read_be32 (buf);
}

static bool load_bytes(RBinFile *bf, void **bin_obj, const ut8 *buf, ut64 sz, ut64 loadaddr, Sdb *sdb) {
	if (check_bytes (r_buf_buffer (bf->buf), sz)) {
		*bin_obj = memcpy (&n64_header, buf, sizeof (N64Header));
		return true;
	}
	return false;
}

static bool load(RBinFile *bf) {
	const ut8 *bytes = bf ? r_buf_buffer (bf->buf) : NULL;
	ut64 sz = bf ? r_buf_size (bf->buf) : 0;
	if (!bf || !bf->o) {
		return false;
	}
	load_bytes (bf, &bf->o->bin_obj, bytes, sz, bf->o->loadaddr, bf->sdb);
	return check_bytes (bytes, sz);
}

static int destroy(RBinFile *bf) {
	return true;
}

static RList *entries(RBinFile *bf) {
	RList /*<RBinAddr>*/ *ret = r_list_newf (free);
	if (!ret) {
		return NULL;
	}
	RBinAddr *ptr = R_NEW0 (RBinAddr);
	if (ptr) {
		ptr->paddr = N64_ROM_START;
		ptr->vaddr = baddr (bf);
		r_list_append (ret, ptr);
	}
	return ret;
}

static RList *sections(RBinFile *bf) {
	RList /*<RBinSection>*/ *ret = r_list_new ();
	if (!ret) {
		return NULL;
	}
	RBinSection *text = R_NEW0 (RBinSection);
	if (!text) {
		r_list_free (ret);
		return NULL;
	}
	strncpy (text->name, "text", R_BIN_SIZEOF_STRINGS);
	text->size = bf->buf->length - N64_ROM_START;
	text->vsize = text->size;
	text->paddr = N64_ROM_START;
	text->vaddr = baddr (bf);
	text->perm = R_PERM_RX;
	text->add = true;
	r_list_append (ret, text);
	return ret;
}

static ut64 boffset(RBinFile *bf) {
	return 0LL;
}

static RBinInfo *info(RBinFile *bf) {
	char GameName[21] = {0};
	RBinInfo *ret = R_NEW0 (RBinInfo);
	if (!ret) {
		return NULL;
	}
	memcpy (GameName, n64_header.Name, sizeof (n64_header.Name));
	ret->file = r_str_newf ("%s (%c)", GameName, n64_header.CountryCode);
	ret->os = strdup ("n64");
	ret->arch = strdup ("mips");
	ret->machine = strdup ("Nintendo 64");
	ret->type = strdup ("ROM");
	ret->bits = 32;
	ret->has_va = true;
	ret->big_endian = true;
	return ret;
}

#if !R_BIN_Z64

RBinPlugin r_bin_plugin_z64 = {
	.name = "z64",
	.desc = "Nintendo 64 binaries big endian r_bin plugin",
	.license = "LGPL3",
	.load = &load,
	.load_bytes = &load_bytes,
	.destroy = &destroy,
	.check_bytes = &check_bytes,
	.baddr = baddr,
	.boffset = &boffset,
	.entries = &entries,
	.sections = &sections,
	.info = &info
};

#ifndef CORELIB
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_z64,
	.version = R2_VERSION
};
#endif
#endif
