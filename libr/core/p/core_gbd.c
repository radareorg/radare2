#include <r_core.h>
#include <r_io.h>
#include <r_anal.h>
#include <r_util.h>
#include <r_bin.h>

const ut8 gb_license_bytes[]={
	0xce, 0xed, 0x66, 0x66, 0xcc, 0x0d, 0x00, 0x0b, 0x03, 0x73, 0x00,
	0x83, 0x00, 0x0c, 0x00, 0x0d, 0x00, 0x08, 0x11, 0x1f, 0x88, 0x89,
	0x00, 0x0e, 0xdc, 0xcc, 0x6e, 0xe6, 0xdd, 0xdd, 0xd9, 0x99, 0xbb,
	0xbb, 0x67, 0x63, 0x6e, 0x0e, 0xec, 0xcc, 0xdd, 0xdc, 0x99, 0x9f,
	0xbb, 0xb9, 0x33, 0x3e
};

// RBin is trash, so I reimplement things here
static bool is_gb_rom (RIO *io) {
	ut8 license_buf[sizeof (gb_license_bytes)];
	if (r_io_nread_at (io, 0x104, license_buf, sizeof (license_buf)) != sizeof (license_buf)) {
		return false;
	}
	return !memcmp (gb_license_bytes, license_buf, sizeof (license_buf));
}

typedef enum {
	GB_ROM
	,GB_ROM_MBC1
	,GB_ROM_MBC1_RAM
	,GB_ROM_MBC1_RAM_BAT
	,GB_ROM_MBC2		= 0x5
	,GB_ROM_MBC2_BAT
	,GB_ROM_RAM		= 0x8
	,GB_ROM_RAM_BAT
	,GB_ROM_MMM0		= 0xb
	,GB_ROM_MMM0_SRAM
	,GB_ROM_MMM0_SRAM_BAT
	,GB_ROM_MBC3_TIMER_BAT	= 0xf
	,GB_ROM_MBC3_TIMER_RAM_BAT
	,GB_ROM_MBC3
	,GB_ROM_MBC3_RAM
	,GB_ROM_MBC3_RAM_BAT
	,GB_ROM_MBC5		= 0x19
	,GB_ROM_MBC5_RAM
	,GB_ROM_MBC5_RAM_BAT
	,GB_ROM_MBC5_RMBL
	,GB_ROM_MBC5_RMBL_SRAM
	,GB_ROM_MBC5_RMBL_SRAM_BAT
	,GB_CAM
	,GB_TAMA5		= 0xfd
	,GB_HUC3
	,GB_HUC1
} RMBCType;

static RMBCType get_mbc_type (RIO *io) {
	ut8 mbc_type;
	r_io_read_at (io, 0x147, &mbc_type, 1);
	return (RMBCType)mbc_type;
}

// tries to figure out blocksize of a bb starting at specified offset
static ut64 gbd_discover_bblen_at (RAnal *anal, ut64 addr, ut64 base, ut8 *rombank) {
	if (!anal || !rombank || (addr - base > 0x3fff)) {
		return 0;
	}
	RAnalOp op;
	r_anal_op_init (&op);
	ut64 bb_len = 0;
	do {
		r_anal_op_fini (&op);
		r_anal_op_init (&op);
		const ut64 off = addr - base + bb_len;
		if (off > 0x3fff) {
			break;
		}
		const int len = r_anal_op (anal, &op, addr + bb_len, &rombank[off], 0x4000 - off, R_ANAL_OP_MASK_BASIC);
		if (len < 1) {
			break;
		}
		bb_len += len;
	} while (!op.eob);
	r_anal_op_fini (&op);
	return bb_len;
}

static void gbd_anal_mbc3_rom (RCore *core) {
	eprintf ("Start analyzing mbc3 rom\n");
	RBinAddr *gb_main = r_bin_get_sym (core->bin, R_BIN_SYM_MAIN);
	if (!gb_main) {
		eprintf ("Couldn't find main (TODO: implement entrypoint analysis)\n");
		return;
	}
	ut8 rombank0[0x4000];
	if (r_io_nread_at (core->io, 0x0, rombank0, 0x4000) != 0x4000) {
		eprintf ("Couldn't slurp rombank0 entirely\n");
		return;
	}
	ut64 bb_len = gbd_discover_bblen_at (core->anal, gb_main->vaddr, 0x0ULL, rombank0);
	if (bb_len) {
		eprintf ("Found block at 0x%04"PFMT64x"\n", gb_main->vaddr);
		r_core_cmdf (core, "pD %"PFMT64d" @ 0x%"PFMT64x"", bb_len, gb_main->vaddr);
	}
}

static int gbd_call (void *user, const char *input) {
	RCore *core = (RCore *) user;
	if (strncmp (input, "gbd", 3)) {
		return false;
	}
	if (!is_gb_rom (core->io)) {
		eprintf ("not a gb rom\n");
		return true;
	}
	if (strcmp (core->anal->cur->name, "gb")) {
		eprintf ("wrong anal arch selected (%s)\n", core->anal->cur->name);
		return true;
	}
	RMBCType mbc = get_mbc_type (core->io);
	switch (mbc) {
	case GB_ROM:
	case GB_ROM_RAM:
	case GB_ROM_RAM_BAT:
		eprintf ("no rombanks here, nothing todo\n");
		break;
	case GB_ROM_MBC3_TIMER_BAT:
	case GB_ROM_MBC3_TIMER_RAM_BAT:
	case GB_ROM_MBC3:
	case GB_ROM_MBC3_RAM:
	case GB_ROM_MBC3_RAM_BAT:
		gbd_anal_mbc3_rom (core);
		break;
	default:
		eprintf ("mbc type is 0x%02x\n", mbc);
	}
	return true;
}

// PLUGIN Definition Info
RCorePlugin r_core_plugin_gbd = {
	.name = "gbd",
	.desc = "Gameboy bankswitch discovery",
	.license = "LGPL3",
	.call = gbd_call,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_CORE,
	.data = &r_core_plugin_gbd,
	.version = R2_VERSION
};
#endif
