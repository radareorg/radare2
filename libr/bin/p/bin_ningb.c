/* radare - LGPL - 2013-2023 - condret@runas-racer.com */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>
#include <string.h>
#include "../format/nin/nin.h"

static bool check(RBinFile *bf, RBuffer *b) {
	ut8 lict[sizeof (lic)];
	if (r_buf_read_at (b, 0x104, lict, sizeof (lict)) == sizeof (lict)) {
		return !memcmp (lict, lic, sizeof (lict));
	}
	return false;
}

static bool load(RBinFile *bf, RBuffer *buf, ut64 loadaddr) {
	return check (bf, buf);
}

static ut64 baddr(RBinFile *bf) {
	return 0LL;
}

static RBinAddr* binsym(RBinFile *bf, int type) {
	if (type != R_BIN_SYM_MAIN) {
		return NULL;
	}
	ut8 init_jmp[4];
	r_buf_read_at (bf->buf, 0x100, init_jmp, 4);
	if (init_jmp[1] == 0xc3) {
		RBinAddr *ret = R_NEW0 (RBinAddr);
		ret->paddr = ret->vaddr = init_jmp[3] * 0x100 + init_jmp[2];
		return ret;
	}
	return NULL;
}

static RList* entries(RBinFile *bf) {
	RList *ret = r_list_newf (free);
	if (!ret) {
		return NULL;
	}
	RBinAddr *ptr = R_NEW0 (RBinAddr);
	ptr->paddr = ptr->vaddr = ptr->hpaddr = 0x100;
	r_list_append (ret, ptr);
	return ret;
}

static RList* sections(RBinFile *bf) {
	ut8 bank;
	int i;
	RList *ret;

	if (!bf) {
		return NULL;
	}

	ret = r_list_new ();
	if (!ret) {
		return NULL;
	}

	r_buf_read_at (bf->buf, 0x148, &bank, 1);
	bank = gb_get_rombanks(bank);
#ifdef _MSC_VER
	RBinSection **rombank = (RBinSection**) malloc (sizeof (RBinSection*) * bank);
#else
	RBinSection *rombank[bank];
#endif

	if (!bf->buf) {
		free (ret);
#ifdef _MSC_VER
		free (rombank);
#endif
		return NULL;
	}

	ret->free = free;

	rombank[0] = R_NEW0 (RBinSection);
	rombank[0]->name = strdup ("rombank00");
	rombank[0]->paddr = 0;
	rombank[0]->size = 0x4000;
	rombank[0]->vsize = 0x4000;
	rombank[0]->vaddr = 0;
	rombank[0]->perm = r_str_rwx ("rx");
	rombank[0]->add = true;

	r_list_append (ret, rombank[0]);

	for (i = 1; i < bank; i++) {
		rombank[i] = R_NEW0 (RBinSection);
		rombank[i]->name = r_str_newf ("rombank%02x", i);
		rombank[i]->paddr = i*0x4000;
		rombank[i]->vaddr = i*0x10000-0xc000;			//spaaaaaaaaaaaaaaaace!!!
		rombank[i]->size = rombank[i]->vsize = 0x4000;
		rombank[i]->perm = r_str_rwx ("rx");
		rombank[i]->add = true;
		r_list_append (ret,rombank[i]);
	}
#ifdef _MSC_VER
	free (rombank);
#endif
	return ret;
}

static void gb_addsym(RList *ret, const char *name, ut64 addr, int ordinal) {
	RBinSymbol *sym = R_NEW0 (RBinSymbol);
	sym->name = r_bin_name_new (name);
	sym->paddr = sym->vaddr = addr;
	sym->size = 1;
	sym->ordinal = ordinal;
	r_list_append (ret, sym);
}

static RList* symbols(RBinFile *bf) {
	RList *ret = r_list_newf ((RListFree)r_bin_symbol_free);
	if (!ret) {
		return NULL;
	}
	int i;
	for (i = 0; i < 8; i++) {
		char name[16];
		snprintf (name, sizeof (name), "rst_%i", i * 8);
		gb_addsym (ret, name, i * 8, i);
	}
	gb_addsym (ret, "Interrupt_Vblank", 64, 8);
	gb_addsym (ret, "Interrupt_LCDC-Status", 72, 9);
	gb_addsym (ret, "Interrupt_Timer-Overflow", 80, 10);
	gb_addsym (ret, "Interrupt_Serial-Transfere", 88, 11);
	gb_addsym (ret, "Interrupt_Joypad", 96, 12);
	return ret;
}

static RBinInfo* info(RBinFile *bf) {
	ut8 rom_header[76];
	RBinInfo *ret = R_NEW0 (RBinInfo);
	r_buf_read_at (bf->buf, 0x104, rom_header, 76);
	ret->file = r_str_ndup ((const char*)&rom_header[48], 16);
	ret->type = malloc (128);
	ret->type[0] = 0;
	gb_get_gbtype (ret->type, rom_header[66], rom_header[63]);
	gb_add_cardtype (ret->type, rom_header[67]); // XXX
	ret->machine = strdup ("Gameboy");
	ret->os = strdup ("any");
	ret->arch = strdup ("gb");
	ret->has_va = true;
	ret->bits = 16;
	ret->big_endian = 0;
	ret->dbg_info = 0;
	return ret;
}

RList *mem (RBinFile *bf) {
	RList *ret = r_list_newf (free);
	if (!ret) {
		return NULL;
	}

	RBinMem *m = R_NEW0 (RBinMem);
	m->name = strdup ("fastram");
	m->addr = 0xff80LL;
	m->size = 0x80;
	m->perms = r_str_rwx ("rwx");
	r_list_append (ret, m);

	m = R_NEW0 (RBinMem);
	m->name = strdup ("ioports");
	m->addr = 0xff00LL;
	m->size = 0x4c;
	m->perms = r_str_rwx ("rwx");
	r_list_append (ret, m);

	m = R_NEW0 (RBinMem);
	m->name = strdup ("oam");
	m->addr = 0xfe00LL;
	m->size = 0xa0;
	m->perms = r_str_rwx ("rwx");
	r_list_append (ret, m);

	m = R_NEW0 (RBinMem);
	m->name = strdup ("videoram");
	m->addr = 0x8000LL;
	m->size = 0x2000;
	m->perms = r_str_rwx ("rwx");
	r_list_append (ret, m);

	m = R_NEW0 (RBinMem);
	m->name = strdup ("iram");
	m->addr = 0xc000LL;
	m->size = 0x2000;
	m->perms = r_str_rwx ("rwx");
	m->mirrors = r_list_new ();
	r_list_append (ret, m);

	RBinMem *n = R_NEW0 (RBinMem);
	n->name = strdup ("iram_echo");
	n->addr = 0xe000LL;
	n->size = 0x1e00;
	n->perms = r_str_rwx ("rx");
	r_list_append (m->mirrors, n);

	return ret;
}

RBinPlugin r_bin_plugin_ningb = {
	.meta = {
		.name = "ningb",
		.author = "condret",
		.desc = "Nintendo GameBoy ROM",
		.license = "LGPL-3.0-only",
	},
	.load = &load,
	.check = &check,
	.baddr = &baddr,
	.binsym = &binsym,
	.entries = &entries,
	.sections = &sections,
	.symbols = &symbols,
	.info = &info,
	.mem = &mem,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_ningb,
	.version = R2_VERSION
};
#endif
