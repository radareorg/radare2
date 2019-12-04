/* radare - LGPL - 2013 - 2017 - condret@runas-racer.com */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>
#include <string.h>
#include "../format/nin/nin.h"

static bool check_buffer(RBuffer *b) {
	ut8 lict[sizeof (lic)];
	if (r_buf_read_at (b, 0x104, lict, sizeof (lict)) == sizeof (lict)) {
		return !memcmp (lict, lic, sizeof (lict));
	}
	return false;
}

static bool load_buffer(RBinFile *bf, void **bin_obj, RBuffer *buf, ut64 loadaddr, Sdb *sdb) {
	return check_buffer (buf);
}

static ut64 baddr(RBinFile *bf) {
	return 0LL;
}

static RBinAddr* binsym(RBinFile *bf, int type) {
	if (type == R_BIN_SYM_MAIN && bf && bf->buf) {
		ut8 init_jmp[4];
		RBinAddr *ret = R_NEW0 (RBinAddr);
		if (!ret) {
			return NULL;
		}
		r_buf_read_at (bf->buf, 0x100, init_jmp, 4);
		if (init_jmp[1] == 0xc3) {
			ret->paddr = ret->vaddr = init_jmp[3]*0x100 + init_jmp[2];
			return ret;
		}
		free (ret);
	}
	return NULL;
}

static RList* entries(RBinFile *bf) {
	RList *ret = r_list_new ();
	RBinAddr *ptr = NULL;

	if (bf && bf->buf != NULL) {
		if (!ret) {
			return NULL;
		}
		ret->free = free;
		if (!(ptr = R_NEW0 (RBinAddr))) {
			return ret;
		}
		ptr->paddr = ptr->vaddr = ptr->hpaddr = 0x100;
		r_list_append (ret, ptr);
	}
	return ret;
}

static RList* sections(RBinFile *bf){
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

static RList* symbols(RBinFile *bf) {
	RList *ret = NULL;
	RBinSymbol *ptr[13];
	int i;
	if (!(ret = r_list_new ())) {
		return NULL;
	}
	ret->free = free;

	for (i = 0; i < 8; i++) {
		if (!(ptr[i] = R_NEW0 (RBinSymbol))) {
			ret->free (ret);
			return NULL;
		}
		ptr[i]->name = r_str_newf ("rst_%i", i*8);
		ptr[i]->paddr = ptr[i]->vaddr = i*8;
		ptr[i]->size = 1;
		ptr[i]->ordinal = i;
		r_list_append (ret, ptr[i]);
	}

	if (!(ptr[8] = R_NEW0 (RBinSymbol))) {
		return ret;
	}

	ptr[8]->name = strdup ("Interrupt_Vblank");
	ptr[8]->paddr = ptr[8]->vaddr = 64;
	ptr[8]->size = 1;
	ptr[8]->ordinal = 8;
	r_list_append (ret, ptr[8]);

	if (!(ptr[9] = R_NEW0 (RBinSymbol))) {
		return ret;
	}

	ptr[9]->name = strdup ("Interrupt_LCDC-Status");
	ptr[9]->paddr = ptr[9]->vaddr = 72;
	ptr[9]->size = 1;
	ptr[9]->ordinal = 9;
	r_list_append (ret, ptr[9]);

	if (!(ptr[10] = R_NEW0 (RBinSymbol))) {
		return ret;
	}

	ptr[10]->name = strdup ("Interrupt_Timer-Overflow");
	ptr[10]->paddr = ptr[10]->vaddr = 80;
	ptr[10]->size = 1;
	ptr[10]->ordinal = 10;
	r_list_append (ret, ptr[10]);

	if (!(ptr[11] = R_NEW0 (RBinSymbol))) {
		return ret;
	}

	ptr[11]->name = strdup ("Interrupt_Serial-Transfere");
	ptr[11]->paddr = ptr[11]->vaddr = 88;
	ptr[11]->size = 1;
	ptr[11]->ordinal = 11;
	r_list_append (ret, ptr[11]);

	if (!(ptr[12] = R_NEW0 (RBinSymbol))) {
		return ret;
	}

	ptr[12]->name = strdup ("Interrupt_Joypad");
	ptr[12]->paddr = ptr[12]->vaddr = 96;
	ptr[12]->size = 1;
	ptr[12]->ordinal = 12;
	r_list_append (ret, ptr[12]);

	return ret;
}

static RBinInfo* info(RBinFile *bf) {
	ut8 rom_header[76];
	RBinInfo *ret = R_NEW0 (RBinInfo);
	if (!ret || !bf || !bf->buf) {
		free (ret);
		return NULL;
	}
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
	m->name = strdup ("fastram");
	m->addr = 0xff80LL;
	m->size = 0x80;
	m->perms = r_str_rwx ("rwx");
	r_list_append (ret, m);

	if (!(m = R_NEW0 (RBinMem))) {
		return ret;
	}
	m->name = strdup ("ioports");
	m->addr = 0xff00LL;
	m->size = 0x4c;
	m->perms = r_str_rwx ("rwx");
	r_list_append (ret, m);

	if (!(m = R_NEW0 (RBinMem))) {
		return ret;
	}
	m->name = strdup ("oam");
	m->addr = 0xfe00LL;
	m->size = 0xa0;
	m->perms = r_str_rwx ("rwx");
	r_list_append (ret, m);

	if (!(m = R_NEW0 (RBinMem))) {
		return ret;
	}
	m->name = strdup ("videoram");
	m->addr = 0x8000LL;
	m->size = 0x2000;
	m->perms = r_str_rwx ("rwx");
	r_list_append (ret, m);

	if (!(m = R_NEW0 (RBinMem))) {
		return ret;
	}
	m->name = strdup ("iram");
	m->addr = 0xc000LL;
	m->size = 0x2000;
	m->perms = r_str_rwx ("rwx");
	r_list_append (ret, m);
	if (!(m->mirrors = r_list_new ())) {
		return ret;
	}
	if (!(n = R_NEW0 (RBinMem))) {
		r_list_free (m->mirrors);
		m->mirrors = NULL;
		return ret;
	}
	n->name = strdup ("iram_echo");
	n->addr = 0xe000LL;
	n->size = 0x1e00;
	n->perms = r_str_rwx ("rx");
	r_list_append (m->mirrors, n);

	return ret;
}

RBinPlugin r_bin_plugin_ningb = {
	.name = "ningb",
	.desc = "Gameboy format r_bin plugin",
	.license = "LGPL3",
	.load_buffer = &load_buffer,
	.check_buffer = &check_buffer,
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
