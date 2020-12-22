/* radare - LGPL3 - 2015-2019 - maijin */

#include <r_bin.h>
#include <r_lib.h>
#include "nes/nes_specs.h"


static bool check_buffer(RBuffer *b) {
	if (r_buf_size (b) > 4) {
		ut8 buf[4];
		r_buf_read_at (b, 0, buf, sizeof (buf));
		return (!memcmp (buf, INES_MAGIC, sizeof (buf)));
	}
	return false;
}

static bool load_buffer(RBinFile *bf, void **bin_obj, RBuffer *buf, ut64 loadaddr, Sdb *sdb) {
	return check_buffer (buf);
}

static RBinInfo *info(RBinFile *bf) {
	RBinInfo *ret = NULL;
	ines_hdr ihdr;
	memset (&ihdr, 0, INES_HDR_SIZE);
	int reat = r_buf_read_at (bf->buf, 0, (ut8*)&ihdr, INES_HDR_SIZE);
	if (reat != INES_HDR_SIZE) {
		eprintf ("Truncated Header\n");
		return NULL;
	}
	if (!(ret = R_NEW0 (RBinInfo))) {
		return NULL;
	}
	ret->file = strdup (bf->file);
	ret->type = strdup ("ROM");
	ret->machine = strdup ("Nintendo NES");
	ret->os = strdup ("nes");
	ret->arch = strdup ("6502");
	ret->bits = 8;
	ret->has_va = 1;
	return ret;
}

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

static RList* symbols(RBinFile *bf) {
	RList *ret = NULL;
	if (!(ret = r_list_newf (free))) {
		return NULL;
	}
	addsym (ret, "NMI_VECTOR_START_ADDRESS", NMI_VECTOR_START_ADDRESS,2);
	addsym (ret, "RESET_VECTOR_START_ADDRESS", RESET_VECTOR_START_ADDRESS,2);
	addsym (ret, "IRQ_VECTOR_START_ADDRESS", IRQ_VECTOR_START_ADDRESS,2);
	addsym (ret, "PPU_CTRL_REG1", PPU_CTRL_REG1,0x1);
	addsym (ret, "PPU_CTRL_REG2", PPU_CTRL_REG2,0x1);
	addsym (ret, "PPU_STATUS", PPU_STATUS,0x1);
	addsym (ret, "PPU_SPR_ADDR", PPU_SPR_ADDR,0x1);
	addsym (ret, "PPU_SPR_DATA", PPU_SPR_DATA,0x1);
	addsym (ret, "PPU_SCROLL_REG", PPU_SCROLL_REG,0x1);
	addsym (ret, "PPU_ADDRESS", PPU_ADDRESS,0x1);
	addsym (ret, "PPU_DATA", PPU_DATA,0x1);
	addsym (ret, "SND_REGISTER", SND_REGISTER,0x15);
	addsym (ret, "SND_SQUARE1_REG", SND_SQUARE1_REG,0x4);
	addsym (ret, "SND_SQUARE2_REG", SND_SQUARE2_REG,0x4);
	addsym (ret, "SND_TRIANGLE_REG", SND_TRIANGLE_REG,0x4);
	addsym (ret, "SND_NOISE_REG", SND_NOISE_REG,0x2);
	addsym (ret, "SND_DELTA_REG", SND_DELTA_REG,0x4);
	addsym (ret, "SND_MASTERCTRL_REG", SND_MASTERCTRL_REG,0x5);
	addsym (ret, "SPR_DMA", SPR_DMA,0x2);
	addsym (ret, "JOYPAD_PORT", JOYPAD_PORT,0x1);
	addsym (ret, "JOYPAD_PORT1", JOYPAD_PORT1,0x1);
	addsym (ret, "JOYPAD_PORT2", JOYPAD_PORT2,0x1);
	return ret;
}

static RList* sections(RBinFile *bf) {
	RList *ret = NULL;
	RBinSection *ptr = NULL;
	ines_hdr ihdr;
	memset (&ihdr, 0, INES_HDR_SIZE);
	int reat = r_buf_read_at (bf->buf, 0, (ut8*)&ihdr, INES_HDR_SIZE);
	if (reat != INES_HDR_SIZE) {
		eprintf ("Truncated Header\n");
		return NULL;
	}
	if (!(ret = r_list_new ())) {
		return NULL;
	}
	if (!(ptr = R_NEW0 (RBinSection))) {
		return ret;
	}
	ptr->name = strdup ("ROM");
	ptr->paddr = INES_HDR_SIZE;
	ptr->size = ihdr.prg_page_count_16k * PRG_PAGE_SIZE;
	ptr->vaddr = ROM_START_ADDRESS;
	ptr->vsize = ROM_SIZE;
	ptr->perm = R_PERM_RX;
	ptr->add = true;
	r_list_append (ret, ptr);
	if (ROM_START_ADDRESS + ptr->size <= ROM_MIRROR_ADDRESS) {
		// not a 256bit ROM, mapper 0 mirrors the complete ROM in this case
		if (!(ptr = R_NEW0 (RBinSection))) {
			return ret;
		}
		ptr->name = strdup ("ROM_MIRROR");
		ptr->paddr = INES_HDR_SIZE;
		ptr->size = ihdr.prg_page_count_16k * PRG_PAGE_SIZE;
		ptr->vaddr = ROM_MIRROR_ADDRESS;
		ptr->vsize = ROM_MIRROR_SIZE;
		ptr->perm = R_PERM_RX;
		ptr->add = true;
		r_list_append (ret, ptr);
	}
	return ret;
}

static RList *mem(RBinFile *bf) {
	RList *ret;
	RBinMem *m, *n;
	if (!(ret = r_list_new ())) {
		return NULL;
	}
	ret->free = free;
	if (!(m = R_NEW0 (RBinMem))) {
		r_list_free (ret);
		return NULL;
	}
	m->name = strdup ("RAM");
	m->addr = RAM_START_ADDRESS;
	m->size = RAM_SIZE;
	m->perms = r_str_rwx ("rwx");
	r_list_append (ret, m);
	if (!(n = R_NEW0 (RBinMem))) {
		return ret;
	}
	m->mirrors = r_list_new ();
	n->name = strdup ("RAM_MIRROR_2");
	n->addr = RAM_MIRROR_2_ADDRESS;
	n->size = RAM_MIRROR_2_SIZE;
	n->perms = r_str_rwx ("rwx");
	r_list_append (m->mirrors, n);
	if (!(n = R_NEW0 (RBinMem))) {
		r_list_free (m->mirrors);
		m->mirrors = NULL;
		return ret;
	}
	n->name = strdup ("RAM_MIRROR_3");
	n->addr = RAM_MIRROR_3_ADDRESS;
	n->size = RAM_MIRROR_3_SIZE;
	n->perms = r_str_rwx ("rwx");
	r_list_append (m->mirrors, n);
	if (!(m = R_NEW0 (RBinMem))) {
		r_list_free (ret);
		return NULL;
	}
	m->name = strdup ("PPU_REG");
	m->addr = PPU_REG_ADDRESS;
	m->size = PPU_REG_SIZE;
	m->perms = r_str_rwx ("rwx");
	r_list_append (ret, m);
	m->mirrors = r_list_new ();
	int i;
	for (i = 1; i < 1024; i++) {
		if (!(n = R_NEW0 (RBinMem))) {
			r_list_free (m->mirrors);
			m->mirrors = NULL;
			return ret;
		}
		n->name = r_str_newf ("PPU_REG_MIRROR_%d", i);
		n->addr = PPU_REG_ADDRESS+i*PPU_REG_SIZE;
		n->size = PPU_REG_SIZE;
		n->perms = r_str_rwx ("rwx");
		r_list_append (m->mirrors, n);
	}
	if (!(m = R_NEW0 (RBinMem))) {
		r_list_free (ret);
		return NULL;
	}
	m->name = strdup ("APU_AND_IOREGS");
	m->addr = APU_AND_IOREGS_START_ADDRESS;
	m->size = APU_AND_IOREGS_SIZE;
	m->perms = r_str_rwx ("rwx");
	r_list_append (ret, m);
	if (!(m = R_NEW0 (RBinMem))) {
		r_list_free (ret);
		return NULL;
	}
	m->name = strdup ("SRAM");
	m->addr = SRAM_START_ADDRESS;
	m->size = SRAM_SIZE;
	m->perms = r_str_rwx ("rwx");
	r_list_append (ret, m);
	return ret;
}

static RList* entries(RBinFile *bf) { //Should be 3 offsets pointed by NMI, RESET, IRQ after mapping && default = 1st CHR
	RList *ret;
	RBinAddr *ptr = NULL;
	if (!(ret = r_list_new ())) {
		return NULL;
	}
	if (!(ptr = R_NEW0 (RBinAddr))) {
		return ret;
	}
	ptr->paddr = INES_HDR_SIZE;
	ptr->vaddr = ROM_START_ADDRESS;
	r_list_append (ret, ptr);
	return ret;
}

static ut64 baddr(RBinFile *bf) {
	// having this we make r2 -B work, otherwise it doesnt works :??
	return 0;
}

RBinPlugin r_bin_plugin_nes = {
	.name = "nes",
	.desc = "NES",
	.license = "MIT",
	.load_buffer = &load_buffer,
	.baddr = &baddr,
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
	.data = &r_bin_plugin_nes,
	.version = R2_VERSION
};
#endif
