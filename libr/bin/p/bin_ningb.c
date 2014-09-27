/* radare - LGPL - 2013 - 2014 - condret@runas-racer.com */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>
#include <string.h>
#include "../format/nin/nin.h"

static int check(RBinFile *arch);
static int check_bytes(const ut8 *buf, ut64 length);

static Sdb* get_sdb (RBinObject *o) {
	if (!o) return NULL;
	//struct r_bin_[NAME]_obj_t *bin = (struct r_bin_r_bin_[NAME]_obj_t *) o->bin_obj;
	//if (bin->kv) return kv;
	return NULL;
}

static void * load_bytes(const ut8 *buf, ut64 sz, ut64 loadaddr, Sdb *sdb){
	return R_NOTNULL;
}

static int check(RBinFile *arch) {
	const ut8 *bytes = arch ? r_buf_buffer (arch->buf) : NULL;
	ut64 sz = arch ? r_buf_size (arch->buf): 0;
	return check_bytes (bytes, sz);

}

static int check_bytes(const ut8 *buf, ut64 length) {
	ut8 lict[48];
	if (!buf || length < (0x104+48))
		return 0;
	memcpy (lict, buf+0x104, 48);
	return (!memcmp (lict, lic, 48))? 1: 0;
}

static int load(RBinFile *arch) {
	const ut8 *bytes = arch ? r_buf_buffer (arch->buf) : NULL;
	ut64 sz = arch ? r_buf_size (arch->buf): 0;
	if (!arch || !arch->o) return R_FALSE;
	arch->o->bin_obj = load_bytes (bytes, sz, arch->o->loadaddr, arch->sdb);
	return check_bytes (bytes, sz);
}

static int destroy(RBinFile *arch) {
	r_buf_free (arch->buf);
	arch->buf = NULL;
	return R_TRUE;
}

static ut64 baddr(RBinFile *arch) {
	return 0LL;
}

static RBinAddr* binsym(RBinFile *arch, int type)
{
	if (type == R_BIN_SYM_MAIN && arch && arch->buf) {
		ut8 init_jmp[4];
		RBinAddr *ret = R_NEW0 (RBinAddr);
		if (!ret) return NULL;
		r_buf_read_at (arch->buf, 0x100, init_jmp, 4);
		if (init_jmp[1] == 0xc3) {
			ret->paddr = ret->vaddr = init_jmp[3]*0x100 + init_jmp[2];
			return ret;
		}
		free (ret);
	}
	return NULL;
}

static RList* entries(RBinFile *arch)
{
	RList *ret = r_list_new ();
	RBinAddr *ptr = NULL;

	if (arch && arch->buf != NULL) {
		if (!ret)
			return NULL;
		ret->free = free;
		if (!(ptr = R_NEW0 (RBinAddr)))
			return ret;
		ptr->paddr = ptr->vaddr = 0x100;
		r_list_append (ret, ptr);
	}
	return ret;
}

static RList* sections(RBinFile *arch){
	ut8 bank;
	int i;
	RList *ret;

	if (!arch)
		return NULL;

	ret = r_list_new();
	if (!ret )
		return NULL;

	r_buf_read_at (arch->buf, 0x148, &bank, 1);
	bank = gb_get_rombanks(bank);
	RBinSection *rombank[bank];

	if (!arch->buf) {
		free (ret);
		return NULL;
	}

	ret->free = free;

	rombank[0] = R_NEW0 (RBinSection);
	strncpy (rombank[0]->name, "rombank00", R_BIN_SIZEOF_STRINGS);
	rombank[0]->paddr = 0;
	rombank[0]->size = 0x4000;
	rombank[0]->vsize = 0x4000;
	rombank[0]->vaddr = 0;
	rombank[0]->srwx = r_str_rwx ("rx");

	r_list_append (ret, rombank[0]);

	for (i = 1; i < bank; i++) {
		rombank[i] = R_NEW0 (RBinSection);
		sprintf (rombank[i]->name,"rombank%02x",i);
		rombank[i]->paddr = i*0x4000;
		rombank[i]->vaddr = i*0x10000-0xc000;			//spaaaaaaaaaaaaaaaace!!!
		rombank[i]->size = rombank[i]->vsize = 0x4000;
		rombank[i]->srwx=r_str_rwx ("rx");
		r_list_append (ret,rombank[i]);
	}
	return ret;
}

static RList* symbols(RBinFile *arch)
{
	RList *ret = NULL;
	RBinSymbol *ptr[13];
	int i;
	if (!(ret = r_list_new()))
		return NULL;
	ret->free = free;

	for (i = 0; i < 8; i++) {
		if (!(ptr[i] = R_NEW (RBinSymbol))) {
			ret->free (ret);
			return NULL;
		}
		snprintf (ptr[i]->name, R_BIN_SIZEOF_STRINGS, "rst_%i", i*8);
		ptr[i]->paddr = ptr[i]->vaddr = i*8;
		ptr[i]->size = 1;
		ptr[i]->ordinal = i;
		r_list_append (ret, ptr[i]);
	}

	if (!(ptr[8] = R_NEW (RBinSymbol)))
		return ret;

	strncpy (ptr[8]->name, "Interrupt_Vblank", R_BIN_SIZEOF_STRINGS);
	ptr[8]->paddr = ptr[8]->vaddr = 64;
	ptr[8]->size = 1;
	ptr[8]->ordinal = 8;
	r_list_append (ret, ptr[8]);

	if (!(ptr[9] = R_NEW (RBinSymbol)))
		return ret;

	strncpy (ptr[9]->name, "Interrupt_LCDC-Status", R_BIN_SIZEOF_STRINGS);
	ptr[9]->paddr = ptr[9]->vaddr = 72;
	ptr[9]->size = 1;
	ptr[9]->ordinal = 9;
	r_list_append (ret, ptr[9]);

	if (!(ptr[10] = R_NEW (RBinSymbol)))
		return ret;

	strncpy(ptr[10]->name, "Interrupt_Timer-Overflow", R_BIN_SIZEOF_STRINGS);
	ptr[10]->paddr = ptr[10]->vaddr = 80;
	ptr[10]->size = 1;
	ptr[10]->ordinal = 10;
	r_list_append (ret, ptr[10]);

	if (!(ptr[11] = R_NEW (RBinSymbol)))
		return ret;

	strncpy(ptr[11]->name, "Interrupt_Serial-Transfere", R_BIN_SIZEOF_STRINGS);
	ptr[11]->paddr = ptr[11]->vaddr = 88;
	ptr[11]->size = 1;
	ptr[11]->ordinal = 11;
	r_list_append (ret, ptr[11]);

	if (!(ptr[12] = R_NEW (RBinSymbol)))
		return ret;

	strncpy (ptr[12]->name, "Interrupt_Joypad", R_BIN_SIZEOF_STRINGS);
	ptr[12]->paddr = ptr[12]->vaddr = 96;
	ptr[12]->size = 1;
	ptr[12]->ordinal = 12;
	r_list_append (ret, ptr[12]);

	return ret;
}

static RBinInfo* info(RBinFile *arch) {
	ut8 rom_header[76];
	RBinInfo *ret = R_NEW0 (RBinInfo);

	if (!ret)
		return NULL;

	if (!arch || !arch->buf) {
		free (ret);
		return NULL;
	}

	ret->lang = NULL;
	r_buf_read_at (arch->buf,0x104,rom_header,76);
	strncpy (ret->file, (const char*)&rom_header[48], 16);
	gb_get_gbtype (ret->type,rom_header[66],rom_header[63]);
	gb_add_cardtype (ret->type,rom_header[67]);			// XXX
	strncpy (ret->machine, "Gameboy", sizeof (ret->machine)-1);
	strncpy (ret->os, "any", sizeof (ret->os)-1);
	strcpy (ret->arch, "gb");
	ret->has_va = 1;
	ret->bits = 8;
	ret->big_endian = 0;
	ret->dbg_info = 0;
	return ret;
}

struct r_bin_plugin_t r_bin_plugin_ningb = {
	.name = "ningb",
	.desc = "Gameboy format r_bin plugin",
	.license = "LGPL3",
	.init = NULL,
	.fini = NULL,
	.get_sdb = &get_sdb,
	.load = &load,
	.load_bytes = &load_bytes,
	.destroy = &destroy,
	.check = &check,
	.check_bytes = &check_bytes,
	.baddr = &baddr,
	.boffset = NULL,
	.binsym = &binsym,
	.entries = &entries,
	.sections = &sections,
	.symbols = &symbols,
	.imports = NULL,
	.strings = NULL,
	.info = &info,
	.fields = NULL,
	.libs = NULL,
	.relocs = NULL,
	.dbginfo = NULL,
	.create = NULL,
	.write = NULL,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_ningb
};
#endif
