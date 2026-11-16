/* radare - LGPL3 - 2017-2019 - usrshare */

#include <r_bin.h>
#include <r_lib.h>
#include "sfc/sfc_specs.h"
#include <r_endian.h>

typedef struct {
	sfc_int_hdr hdr;
	ut64 hdr_paddr;
	ut64 rom_paddr; // 0x200 when a copier header precedes the rom
	bool is_hirom;
} SfcLayout;

static bool sfc_read_header(RBuffer *b, ut64 paddr, sfc_int_hdr *hdr) {
	if (r_buf_read_at (b, paddr, (ut8 *)hdr, SFC_HDR_SIZE) != SFC_HDR_SIZE) {
		return false;
	}
	return r_read_le16 (&hdr->comp_check) == (ut16)~r_read_le16 (&hdr->checksum);
}

// the low nibble of the map mode is 1 for HiROM and 5 for ExHiROM, LoROM, S-DD1 and SA-1 use 0, 2 and 3
static bool sfc_map_mode_is_hirom(const sfc_int_hdr *hdr) {
	const ut8 mode = hdr->rom_setup & 0xf;
	return mode == 1 || mode == 5;
}

static bool sfc_layout(RBuffer *b, SfcLayout *layout) {
	const ut64 length = r_buf_size (b);
	// copiers prepend 512 bytes to a rom that is otherwise a multiple of 1KB
	const ut64 rom_paddr = (length % 0x400 == 0x200)? 0x200: 0;
	if (length < rom_paddr + LOROM_PAGE_SIZE) {
		return false;
	}
	sfc_int_hdr lorom, hirom;
	const bool has_lorom = sfc_read_header (b, rom_paddr + LOROM_HDR_LOC, &lorom);
	const bool has_hirom = sfc_read_header (b, rom_paddr + HIROM_HDR_LOC, &hirom);
	if (!has_lorom && !has_hirom) {
		return false;
	}
	// when both locations look valid, trust the one whose map mode agrees with it
	const bool is_hirom = has_hirom && (!has_lorom || sfc_map_mode_is_hirom (&hirom));
	layout->hdr = is_hirom? hirom: lorom;
	layout->hdr_paddr = rom_paddr + (is_hirom? HIROM_HDR_LOC: LOROM_HDR_LOC);
	layout->rom_paddr = rom_paddr;
	layout->is_hirom = is_hirom;
	return true;
}

static bool check(RBinFile *bf, RBuffer *b) {
	SfcLayout layout;
	return sfc_layout (b, &layout);
}

static bool load(RBinFile *bf, RBuffer *b, ut64 loadaddr) {
	return check (bf, b);
}

static RBinInfo *info(RBinFile *bf) {
	SfcLayout layout;
	if (!sfc_layout (bf->buf, &layout)) {
		R_LOG_ERROR ("Unable to read SFC/SNES header");
		return NULL;
	}
	RBinInfo *ret = R_NEW0 (RBinInfo);
	ret->file = strdup (bf->file);
	ret->type = strdup ("ROM");
	ret->machine = strdup ("Super NES / Super Famicom");
	ret->os = strdup ("snes");
	ret->arch = strdup ("snes");
	ret->bits = 16;
	ret->has_va = 1;
	return ret;
}

static void addrom(RBinFile *bf, const char *name, int i, ut64 paddr, ut64 vaddr, ut32 size) {
	RBinSection *ptr = RVecRBinSection_emplace_back (&bf->bo->sections_vec);
	ptr->name = r_str_newf ("%s_%02x", name, i);
	ptr->paddr = paddr;
	ptr->vaddr = vaddr;
	ptr->size = ptr->vsize = size;
	ptr->perm = R_PERM_RX;
	ptr->add = true;
}

#if 0
static void addsym(RList *ret, const char *name, ut64 addr, ut32 size) {
	RBinSymbol *ptr = R_NEW0 (RBinSymbol);
	ptr->name = strdup (r_str_get (name));
	ptr->paddr = ptr->vaddr = addr;
	ptr->size = size;
	ptr->ordinal = 0;
	r_list_append (ret, ptr);
}
#endif

static bool sections_vec(RBinFile *bf) {
	SfcLayout layout;
	if (!sfc_layout (bf->buf, &layout)) {
		R_LOG_ERROR ("Unable to read SFC/SNES header");
		return false;
	}
	const int hdroffset = layout.rom_paddr;
	const bool is_hirom = layout.is_hirom;
	int i;
	RVecRBinSection_clear (&bf->bo->sections_vec);
	if (is_hirom) {
		for (i = 0; i < ((bf->size - hdroffset) / 0x8000) ; i++) {
			// XXX check integer overflow here
			addrom (bf, "ROM", i, hdroffset + i * 0x8000, 0x400000 + (i * 0x8000), 0x8000);
			if (i % 2) {
				addrom (bf, "ROM_MIRROR", i, hdroffset + i * 0x8000, i * 0x8000, 0x8000);
			}
		}

	} else {
		for (i = 0; i < ((bf->size - hdroffset)/ 0x8000) ; i++) {
			addrom (bf, "ROM", i, hdroffset + i * 0x8000, 0x8000 + (i * 0x10000), 0x8000);
		}
	}
	return true;
}

static RList *mem(RBinFile *bf) {
	RList *ret = r_list_newf (free);
	if (!ret) {
		return NULL;
	}

	RBinMem *m = R_NEW0 (RBinMem);
	m->name = strdup ("LOWRAM");
	m->addr = LOWRAM_START_ADDRESS;
	m->size = LOWRAM_SIZE;
	m->perms = r_str_rwx ("rwx");
	m->mirrors = r_list_new ();
	r_list_append (ret, m);

	RBinMem *mirror = R_NEW0 (RBinMem);
	mirror->name = strdup ("LOWRAM_MIRROR");
	mirror->addr = LOWRAM_MIRROR_START_ADDRESS;
	mirror->size = LOWRAM_MIRROR_SIZE;
	mirror->perms = r_str_rwx ("rwx");
	r_list_append (m->mirrors, mirror);

	m = R_NEW0 (RBinMem);
	m->name = strdup ("HIRAM");
	m->addr = HIRAM_START_ADDRESS;
	m->size = HIRAM_SIZE;
	m->perms = r_str_rwx ("rwx");
	r_list_append (ret, m);

	m = R_NEW0 (RBinMem);
	m->name = strdup ("EXTRAM");
	m->addr = EXTRAM_START_ADDRESS;
	m->size = EXTRAM_SIZE;
	m->perms = r_str_rwx ("rwx");
	r_list_append (ret, m);

	m = R_NEW0 (RBinMem);
	m->name = strdup ("PPU1_REG");
	m->addr = PPU1_REG_ADDRESS;
	m->size = PPU1_REG_SIZE;
	m->perms = r_str_rwx ("rwx");
	r_list_append (ret, m);

	m = R_NEW0 (RBinMem);
	m->name = strdup ("DSP_REG");
	m->addr = DSP_REG_ADDRESS;
	m->size = DSP_REG_SIZE;
	m->perms = r_str_rwx ("rwx");
	r_list_append (ret, m);

	m = R_NEW0 (RBinMem);
	m->name = strdup ("OLDJOY_REG");
	m->addr = OLDJOY_REG_ADDRESS;
	m->size = OLDJOY_REG_SIZE;
	m->perms = r_str_rwx ("rwx");
	r_list_append (ret, m);

	m = R_NEW0 (RBinMem);
	m->name = strdup ("PPU2_REG");
	m->addr = PPU2_REG_ADDRESS;
	m->size = PPU2_REG_SIZE;
	m->perms = r_str_rwx ("rwx");
	r_list_append (ret, m);
	return ret;
}

static RList* entries(RBinFile *bf) { //Should be 3 offsets pointed by NMI, RESET, IRQ after mapping && default = 1st CHR
	RList *ret;
	if (!(ret = r_list_new ())) {
		return NULL;
	}
	/*
	RBinAddr *ptr = NULL;
	ptr = R_NEW0 (RBinAddr);
	ptr->paddr = INES_HDR_SIZE;
	ptr->vaddr = ROM_START_ADDRESS;
	r_list_append (ret, ptr);
	*/
	return ret;
}

// sum every rom byte, counting the complement and checksum fields as ff ff 00 00
static ut16 sfc_rom_checksum(const ut8 *rom, ut64 size, ut64 hdr_offset) {
	// a rom that is not a power of two repeats its tail to fill the next one
	ut64 base = 1;
	while (base * 2 <= size) {
		base *= 2;
	}
	const ut64 tail = size - base;
	const ut64 repeats = tail? base / tail: 0;
	ut32 sum = 0;
	ut64 i;
	for (i = 0; i < base; i++) {
		sum += rom[i];
	}
	ut32 tail_sum = 0;
	for (i = base; i < size; i++) {
		tail_sum += rom[i];
	}
	const ut64 fields = hdr_offset + r_offsetof (sfc_int_hdr, comp_check);
	ut32 *fields_sum = fields < base? &sum: &tail_sum;
	for (i = fields; i < fields + 4; i++) {
		*fields_sum -= rom[i];
	}
	*fields_sum += 0xff * 2;
	return sum + tail_sum * repeats;
}

static int checksum(RBinFile *bf, RStrBuf *report, bool fix) {
	SfcLayout layout;
	ut64 size = 0;
	const ut8 *data = r_buf_data (bf->buf, &size);
	if (!data || !sfc_layout (bf->buf, &layout) || layout.hdr_paddr + SFC_HDR_SIZE > size) {
		return -1;
	}
	const ut16 sum = sfc_rom_checksum (data + layout.rom_paddr, size - layout.rom_paddr, layout.hdr_paddr - layout.rom_paddr);
	ut8 computed[4];
	r_write_le16 (computed, ~sum);
	r_write_le16 (computed + 2, sum);
	const ut64 paddr = layout.hdr_paddr + r_offsetof (sfc_int_hdr, comp_check);
	return !r_bin_wr_checksum_update (bf->buf, report, "sfc", paddr, computed, sizeof (computed), fix);
}

static RBinWrite r_bin_write_sfc = {
	.checksum = &checksum,
};

RBinPlugin r_bin_plugin_sfc = {
	.meta = {
		.name = "sfc",
		.desc = "Super NES / Super Famicom ROM",
		.author = "usrshare",
		.license = "LGPL-3.0-only",
	},
	.weak_guess = true,
	.load = &load,
	.check = &check,
	.entries = &entries,
	.sections_vec = &sections_vec,
	.info = &info,
	.mem = &mem,
	.write = &r_bin_write_sfc,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_sfc,
	.version = R2_VERSION
};
#endif
