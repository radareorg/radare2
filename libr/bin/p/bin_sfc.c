/* radare - LGPL3 - 2017-2019 - usrshare */

#include <r_bin.h>
#include <r_lib.h>
#include "sfc/sfc_specs.h"
#include <r_endian.h>

static bool check_buffer(RBuffer *b) {
	ut16 cksum1, cksum2;
	ut64 length = r_buf_size (b);
	// FIXME: this was commented out because it always evaluates to false.
	//        Need to be fixed by someone with SFC knowledge
	// if ((length & 0x8000) == 0x200) {
	// 	buf_hdr += 0x200;
	// }
	if (length < 0x8000) {
		return false;
	}
	//determine if ROM is headered, and add a 0x200 gap if so.
	cksum1 = r_buf_read_le16_at (b, 0x7fdc);
	cksum2 = r_buf_read_le16_at (b, 0x7fde);

	if (cksum1 == (ut16)~cksum2) {
		return true;
	}
	if (length < 0xffee) {
		return false;
	}
	cksum1 = r_buf_read_le16_at (b, 0xffdc);
	cksum2 = r_buf_read_le16_at (b, 0xffde);
	return (cksum1 == (ut16)~cksum2);
}

static bool load_buffer(RBinFile *bf, void **bin_obj, RBuffer *b, ut64 loadaddr, Sdb *sdb){
	return check_buffer (b);
}

static RBinInfo* info(RBinFile *bf) {
	sfc_int_hdr sfchdr = {{0}};
	RBinInfo *ret = NULL;
	int hdroffset = 0;
#if THIS_IS_ALWAYS_FALSE_WTF
	if ((bf->size & 0x8000) == 0x200) {
		hdroffset = 0x200;
	}
#endif
	int reat = r_buf_read_at (bf->buf, 0x7FC0 + hdroffset,
		(ut8*)&sfchdr, SFC_HDR_SIZE);
	if (reat != SFC_HDR_SIZE) {
		eprintf ("Unable to read SFC/SNES header\n");
		return NULL;
	}

	if ( (sfchdr.comp_check != (ut16)~(sfchdr.checksum)) || ((sfchdr.rom_setup & 0x1) != 0) ){

		// if the fixed 0x33 byte or the LoROM indication are not found, then let's try interpreting the ROM as HiROM

		reat = r_buf_read_at (bf->buf, 0xFFC0 + hdroffset, (ut8*)&sfchdr, SFC_HDR_SIZE);
		if (reat != SFC_HDR_SIZE) {
			eprintf ("Unable to read SFC/SNES header\n");
			return NULL;
		}

		if ( (sfchdr.comp_check != (ut16)~(sfchdr.checksum)) || ((sfchdr.rom_setup & 0x1) != 1) ) {

			eprintf ("Cannot determine if this is a LoROM or HiROM file\n");
			return NULL;
		}
	}

	if (!(ret = R_NEW0 (RBinInfo))) {
		return NULL;
	}
	ret->file = strdup (bf->file);
	ret->type = strdup ("ROM");
	ret->machine = strdup ("Super NES / Super Famicom");
	ret->os = strdup ("snes");
	ret->arch = strdup ("snes");
	ret->bits = 16;
	ret->has_va = 1;
	return ret;
}

static void addrom(RList *ret, const char *name, int i, ut64 paddr, ut64 vaddr, ut32 size) {
	RBinSection *ptr = R_NEW0 (RBinSection);
	if (!ptr) {
		return;
	}
	ptr->name = r_str_newf ("%s_%02x", name, i);
	ptr->paddr = paddr;
	ptr->vaddr = vaddr;
	ptr->size = ptr->vsize = size;
	ptr->perm = R_PERM_RX;
	ptr->add = true;
	r_list_append (ret, ptr);
}

#if 0
static void addsym(RList *ret, const char *name, ut64 addr, ut32 size) {
	RBinSymbol *ptr = R_NEW0 (RBinSymbol);
	if (!ptr) {
		return;
	}
	ptr->name = strdup (r_str_get (name));
	ptr->paddr = ptr->vaddr = addr;
	ptr->size = size;
	ptr->ordinal = 0;
	r_list_append (ret, ptr);
}
#endif

static RList* symbols(RBinFile *bf) {
	return NULL;
}

static RList* sections(RBinFile *bf) {
	RList *ret = NULL;
	// RBinSection *ptr = NULL;
	int hdroffset = 0;
	bool is_hirom = false;
	int i = 0; //0x8000-long bank number for loops
#if THIS_IS_ALWAYS_FALSE_WTF
	if ((bf->size & 0x8000) == 0x200) {
		hdroffset = 0x200;
	}
#endif
	sfc_int_hdr sfchdr = {{0}};

	int reat = r_buf_read_at (bf->buf, 0x7FC0 + hdroffset, (ut8*)&sfchdr, SFC_HDR_SIZE);
	if (reat != SFC_HDR_SIZE) {
		eprintf ("Unable to read SFC/SNES header\n");
		return NULL;
	}

	if ( (sfchdr.comp_check != (ut16)~(sfchdr.checksum)) || ((sfchdr.rom_setup & 0x1) != 0) ){

		// if the fixed 0x33 byte or the LoROM indication are not found, then let's try interpreting the ROM as HiROM

		reat = r_buf_read_at (bf->buf, 0xFFC0 + hdroffset, (ut8*)&sfchdr, SFC_HDR_SIZE);
		if (reat != SFC_HDR_SIZE) {
			eprintf ("Unable to read SFC/SNES header\n");
			return NULL;
		}

		if ( (sfchdr.comp_check != (ut16)~(sfchdr.checksum)) || ((sfchdr.rom_setup & 0x1) != 1) ) {

			eprintf ("Cannot determine if this is a LoROM or HiROM file\n");
			return NULL;
		}
		is_hirom = true;
	}

	if (!(ret = r_list_new ())) {
		return NULL;
	}

	if (is_hirom) {
		for (i = 0; i < ((bf->size - hdroffset) / 0x8000) ; i++) {
			// XXX check integer overflow here
			addrom (ret, "ROM",i,hdroffset + i * 0x8000, 0x400000 + (i * 0x8000), 0x8000);
			if (i % 2) {
				addrom(ret, "ROM_MIRROR", i, hdroffset + i * 0x8000,(i * 0x8000), 0x8000);
			}
		}

	} else {
		for (i=0; i < ((bf->size - hdroffset)/ 0x8000) ; i++) {

			addrom(ret,"ROM",i,hdroffset + i*0x8000,0x8000 + (i*0x10000), 0x8000);
		}
	}
	return ret;
}

static RList *mem (RBinFile *bf) {
	RList *ret;
	RBinMem *m;
	RBinMem *m_bak;
	if (!(ret = r_list_new ())) {
		return NULL;
	}
	ret->free = free;
	if (!(m = R_NEW0 (RBinMem))) {
		r_list_free (ret);
		return NULL;
	}
	m->name = strdup ("LOWRAM");
	m->addr = LOWRAM_START_ADDRESS;
	m->size = LOWRAM_SIZE;
	m->perms = r_str_rwx ("rwx");
	r_list_append (ret, m);

	if (!(m = R_NEW0 (RBinMem))) {
		return ret;
	}
	m->mirrors = r_list_new ();
	m->name = strdup ("LOWRAM_MIRROR");
	m->addr = LOWRAM_MIRROR_START_ADDRESS;
	m->size = LOWRAM_MIRROR_SIZE;
	m->perms = r_str_rwx ("rwx");
	r_list_append (m->mirrors, m);
	m_bak = m;
	if (!(m = R_NEW0 (RBinMem))) {
		r_list_free (m_bak->mirrors);
		return ret;
	}
	m->name = strdup ("HIRAM");
	m->addr = HIRAM_START_ADDRESS;
	m->size = HIRAM_SIZE;
	m->perms = r_str_rwx ("rwx");
	r_list_append (ret, m);
	if (!(m = R_NEW0 (RBinMem))) {
		return ret;
	}
	m->name = strdup ("EXTRAM");
	m->addr = EXTRAM_START_ADDRESS;
	m->size = EXTRAM_SIZE;
	m->perms = r_str_rwx ("rwx");
	r_list_append (ret, m);
	if (!(m = R_NEW0 (RBinMem))) {
		return ret;
	}
	m->name = strdup ("PPU1_REG");
	m->addr = PPU1_REG_ADDRESS;
	m->size = PPU1_REG_SIZE;
	m->perms = r_str_rwx ("rwx");
	r_list_append (ret, m);
	if (!(m = R_NEW0 (RBinMem))) {
		r_list_free (ret);
		return NULL;
	}
	m->name = strdup ("DSP_REG");
	m->addr = DSP_REG_ADDRESS;
	m->size = DSP_REG_SIZE;
	m->perms = r_str_rwx ("rwx");
	r_list_append (ret, m);
	if (!(m = R_NEW0 (RBinMem))) {
		r_list_free (ret);
		return NULL;
	}
	m->name = strdup ("OLDJOY_REG");
	m->addr = OLDJOY_REG_ADDRESS;
	m->size = OLDJOY_REG_SIZE;
	m->perms = r_str_rwx ("rwx");
	r_list_append (ret, m);
	if (!(m = R_NEW0 (RBinMem))) {
		r_list_free (ret);
		return NULL;
	}
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
	if (!(ptr = R_NEW0 (RBinAddr))) {
		return ret;
	}
	ptr->paddr = INES_HDR_SIZE;
	ptr->vaddr = ROM_START_ADDRESS;
	r_list_append (ret, ptr);
	*/
	return ret;
}

RBinPlugin r_bin_plugin_sfc = {
	.name = "sfc",
	.desc = "Super NES / Super Famicom ROM file",
	.license = "LGPL3",
	.load_buffer = &load_buffer,
	.check_buffer = &check_buffer,
	.entries = &entries,
	.sections = sections,
	.symbols = &symbols,
	.info = &info,
	.mem = &mem,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_sfc,
	.version = R2_VERSION
};
#endif
