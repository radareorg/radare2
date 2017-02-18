/* radare - LGPL - Copyright 2009-2016 - nibble, pancake */

#include <stdio.h>
#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>
#include <r_io.h>
#include <r_cons.h>
#include "elf/elf.h"

//TODO: implement r_bin_symbol_dup() and r_bin_symbol_free ?
static void setsymord(ELFOBJ* eobj, ut32 ord, RBinSymbol *ptr) {
	if (!eobj->symbols_by_ord || ord >= eobj->symbols_by_ord_size) {
		return;
	}
	free (eobj->symbols_by_ord[ord]);
	eobj->symbols_by_ord[ord] = r_mem_dup (ptr, sizeof (RBinSymbol));
}

static inline bool setimpord(ELFOBJ* eobj, ut32 ord, RBinImport *ptr) {
	if (!eobj->imports_by_ord || ord >= eobj->imports_by_ord_size) {
		return false;
	}
	if (eobj->imports_by_ord[ord]) {
		free (eobj->imports_by_ord[ord]->name);
		free (eobj->imports_by_ord[ord]);
	}
	eobj->imports_by_ord[ord] = r_mem_dup (ptr, sizeof (RBinImport));
	eobj->imports_by_ord[ord]->name = strdup (ptr->name);
	return true;
}

static Sdb* get_sdb(RBinObject *o) {
	if (o && o->bin_obj) {
		struct Elf_(r_bin_elf_obj_t) *bin = (struct Elf_(r_bin_elf_obj_t) *) o->bin_obj;
		return bin->kv;
	}
	return NULL;
}

static void * load_bytes(RBinFile *arch, const ut8 *buf, ut64 sz, ut64 loadaddr, Sdb *sdb){
	struct Elf_(r_bin_elf_obj_t) *res;
	char *elf_type;
	RBuffer *tbuf;

	if (!buf || !sz || sz == UT64_MAX) {
		return NULL;
	}
	tbuf = r_buf_new ();
	r_buf_set_bytes (tbuf, buf, sz);
	res = Elf_(r_bin_elf_new_buf) (tbuf, arch->rbin->verbose);
	if (res) {
		sdb_ns_set (sdb, "info", res->kv);
	}

	elf_type = Elf_(r_bin_elf_get_file_type (res));
	if (elf_type && !strncmp (elf_type, "CORE", 4)) {
		int len = 0;
		ut8 *regs = Elf_(r_bin_elf_grab_regstate)(res, &len);
		if (regs && len > 0) {
			char *hexregs = r_hex_bin2strdup (regs, len);
			eprintf ("arw %s\n", hexregs);
			free (hexregs);
		}
		free (regs);
	}
	free (elf_type);
	r_buf_free (tbuf);
	return res;
}

/* TODO: must return bool */
static int load(RBinFile *arch) {
	const ut8 *bytes = arch ? r_buf_buffer (arch->buf) : NULL;
	ut64 sz = arch ? r_buf_size (arch->buf): 0;
	if (!arch || !arch->o) {
		return false;
	}
	arch->o->bin_obj = load_bytes (arch, bytes, sz, arch->o->loadaddr, arch->sdb);
	return arch->o->bin_obj != NULL;
}

static int destroy(RBinFile *arch) {
	int i;
	ELFOBJ* eobj = arch->o->bin_obj;
	if (eobj && eobj->imports_by_ord) {
		for (i = 0; i < eobj->imports_by_ord_size; i++) {
			RBinImport *imp = eobj->imports_by_ord[i];
			if (imp) {
				free (imp->name);
				free (imp);
				eobj->imports_by_ord[i] = NULL;
			}
		}
		R_FREE (eobj->imports_by_ord);
	}
	//static int r_bin_object_set_items(RBinFile *binfile, RBinObject *o) {
	Elf_(r_bin_elf_free) ((struct Elf_(r_bin_elf_obj_t)*)arch->o->bin_obj);
	return true;
}

static ut64 baddr(RBinFile *arch) {
	return Elf_(r_bin_elf_get_baddr) (arch->o->bin_obj);
}

static ut64 boffset(RBinFile *arch) {
	return Elf_(r_bin_elf_get_boffset) (arch->o->bin_obj);
}

static RBinAddr* binsym(RBinFile *arch, int sym) {
	struct Elf_(r_bin_elf_obj_t)* obj = arch->o->bin_obj;
	RBinAddr *ret = NULL;
	ut64 addr = 0LL;

	switch (sym) {
	case R_BIN_SYM_ENTRY:
		addr = Elf_(r_bin_elf_get_entry_offset) (arch->o->bin_obj);
		break;
	case R_BIN_SYM_MAIN:
		addr = Elf_(r_bin_elf_get_main_offset) (arch->o->bin_obj);
		break;
	case R_BIN_SYM_INIT:
		addr = Elf_(r_bin_elf_get_init_offset) (arch->o->bin_obj);
		break;
	case R_BIN_SYM_FINI:
		addr = Elf_(r_bin_elf_get_fini_offset) (arch->o->bin_obj);
		break;
	}
	if (addr && addr != UT64_MAX && (ret = R_NEW0 (RBinAddr))) {
		struct Elf_(r_bin_elf_obj_t) *bin = arch->o->bin_obj;
		bool is_arm = bin->ehdr.e_machine == EM_ARM;
		ret->paddr = addr;
		ret->vaddr = Elf_(r_bin_elf_p2v) (obj, addr);
		if (is_arm && addr & 1) {
			ret->bits = 16;
			//ret->vaddr --; // noes
		}
	}
	return ret;
}

static RList* entries(RBinFile *arch) {
	struct Elf_(r_bin_elf_obj_t)* obj;
	RBinAddr *ptr = NULL;
	RList *ret;

	if (!arch || !arch->o || !arch->o->bin_obj) {
		return NULL;
	}
	obj = arch->o->bin_obj;
	if (!(ret = r_list_new ())) {
		return NULL;
	}
	ret->free = free;
	if (!(ptr = R_NEW0 (RBinAddr))) {
		return ret;
	}
	ptr->paddr = Elf_(r_bin_elf_get_entry_offset) (obj);
	ptr->vaddr = Elf_(r_bin_elf_p2v) (obj, ptr->paddr);
	ptr->haddr = 0x18;

	if (obj->ehdr.e_machine == EM_ARM) {
		int bin_bits = Elf_(r_bin_elf_get_bits) (obj);
		if (bin_bits != 64) {
			ptr->bits = 32;
			if (ptr->vaddr & 1) {
				ptr->vaddr--;
				ptr->bits = 16;
			}
			if (ptr->paddr & 1) {
				ptr->paddr--;
				ptr->bits = 16;
			}
		}
	}
	r_list_append (ret, ptr);
	return ret;
}

static RList* sections(RBinFile *arch) {
	struct Elf_(r_bin_elf_obj_t)* obj = arch && arch->o ? arch->o->bin_obj : NULL;
	struct r_bin_elf_section_t *section = NULL;
	int i, num, found_load = 0;
	Elf_(Phdr)* phdr = NULL;
	RBinSection *ptr = NULL;
	RList *ret = NULL;

	if (!obj || !(ret = r_list_newf (free))) {
		return NULL;
	}
	//there is not leak in section since they are cached by elf.c
	//and freed within Elf_(r_bin_elf_free)
	if ((section = Elf_(r_bin_elf_get_sections) (obj))) {
		for (i = 0; !section[i].last; i++) {
			if (!(ptr = R_NEW0 (RBinSection))) {
				break;
			}
			strncpy (ptr->name, (char*)section[i].name, R_BIN_SIZEOF_STRINGS);
			if (strstr (ptr->name, "data") && !strstr (ptr->name, "rel")) {
				ptr->is_data = true;
			}
			ptr->size = section[i].size;
			ptr->vsize = section[i].size;
			ptr->paddr = section[i].offset;
			ptr->vaddr = section[i].rva;
			ptr->add = true;
			ptr->srwx = 0;
			if (R_BIN_ELF_SCN_IS_EXECUTABLE (section[i].flags)) {
				ptr->srwx |= R_BIN_SCN_EXECUTABLE;
			}
			if (R_BIN_ELF_SCN_IS_WRITABLE (section[i].flags)) {
				ptr->srwx |= R_BIN_SCN_WRITABLE;
			}
			if (R_BIN_ELF_SCN_IS_READABLE (section[i].flags)) {
				ptr->srwx |= R_BIN_SCN_READABLE;
				if (obj->ehdr.e_type == ET_REL) {
					ptr->srwx |= R_BIN_SCN_MAP;
				}
			}
			r_list_append (ret, ptr);
		}
	}

	// program headers is another section
	num = obj->ehdr.e_phnum;
	phdr = obj->phdr;
	if (phdr) {
		int n = 0;
		for (i = 0; i < num; i++) {
			if (!(ptr = R_NEW0 (RBinSection))) {
				return ret;
			}
			ptr->add = false;
			ptr->size = phdr[i].p_filesz;
			ptr->vsize = phdr[i].p_memsz;
			ptr->paddr = phdr[i].p_offset;
			ptr->vaddr = phdr[i].p_vaddr;
			ptr->srwx = phdr[i].p_flags | R_BIN_SCN_MAP;
			switch (phdr[i].p_type) {
			case PT_DYNAMIC:
				strncpy (ptr->name, "DYNAMIC", R_BIN_SIZEOF_STRINGS);
				break;
			case PT_LOAD:
				snprintf (ptr->name, R_BIN_SIZEOF_STRINGS, "LOAD%d", n++);
				found_load = 1;
				ptr->add = true;
				break;
			case PT_INTERP:
				strncpy (ptr->name, "INTERP", R_BIN_SIZEOF_STRINGS);
				break;
			case PT_GNU_STACK:
				strncpy (ptr->name, "GNU_STACK", R_BIN_SIZEOF_STRINGS);
				break;
			case PT_GNU_RELRO:
				strncpy (ptr->name, "GNU_RELRO", R_BIN_SIZEOF_STRINGS);
				break;
			case PT_GNU_EH_FRAME:
				strncpy (ptr->name, "GNU_EH_FRAME", R_BIN_SIZEOF_STRINGS);
				break;
			case PT_PHDR:
				strncpy (ptr->name, "PHDR", R_BIN_SIZEOF_STRINGS);
				break;
			case PT_TLS:
				strncpy (ptr->name, "TLS", R_BIN_SIZEOF_STRINGS);
				break;
			case PT_NOTE:
				strncpy (ptr->name, "NOTE", R_BIN_SIZEOF_STRINGS);
				break;
			default:
				strncpy (ptr->name, "UNKNOWN", R_BIN_SIZEOF_STRINGS);
				break;
			}
			ptr->name[R_BIN_SIZEOF_STRINGS - 1] = '\0';
			r_list_append (ret, ptr);
		}
	}

	if (r_list_empty (ret)) {
		if (!arch->size) {
			struct Elf_(r_bin_elf_obj_t) *bin = arch->o->bin_obj;
			arch->size = bin? bin->size: 0x9999;
		}
		if (found_load == 0) {
			if (!(ptr = R_NEW0 (RBinSection))) {
				return ret;
			}
			sprintf (ptr->name, "uphdr");
			ptr->size = arch->size;
			ptr->vsize = arch->size;
			ptr->paddr = 0;
			ptr->vaddr = 0x10000;
			ptr->add = true;
			ptr->srwx = R_BIN_SCN_READABLE | R_BIN_SCN_WRITABLE |
				R_BIN_SCN_EXECUTABLE | R_BIN_SCN_MAP;
			r_list_append (ret, ptr);
		}
	}
	// add entry for ehdr
	ptr = R_NEW0 (RBinSection);
	if (ptr) {
		ut64 ehdr_size = sizeof (obj->ehdr);
		if (arch->size < ehdr_size) {
			ehdr_size = arch->size;
		}
		sprintf (ptr->name, "ehdr");
		ptr->paddr = 0;
		ptr->vaddr = obj->baddr;
		ptr->size = ehdr_size;
		ptr->vsize = ehdr_size;
		ptr->add = true;
		if (obj->ehdr.e_type == ET_REL) {
			ptr->add = true;
		}
		ptr->srwx = R_BIN_SCN_READABLE | R_BIN_SCN_WRITABLE | R_BIN_SCN_MAP;
		r_list_append (ret, ptr);
	}
	return ret;
}


static void _set_arm_thumb_bits(struct Elf_(r_bin_elf_obj_t) *bin, RBinSymbol **sym) {
	int bin_bits = Elf_(r_bin_elf_get_bits) (bin);
	RBinSymbol *ptr = *sym;
	if (ptr->name[0] == '$' && !ptr->name[2]) {
		switch (ptr->name[1]) {
		case 'a' : //arm
			ptr->bits = 32;
			break;
		case 't': //thumb
			ptr->bits = 16;
			if (ptr->vaddr & 1) {
				ptr->vaddr--;
			}
			if (ptr->paddr & 1) {
				ptr->paddr--;
			}
			break;
		case 'd': //data
			break;
		default:
			goto arm_symbol;
		}
	} else {
arm_symbol:
		ptr->bits = bin_bits;
		if (bin_bits != 64) {
			ptr->bits = 32;
			if (ptr->vaddr & 1) {
				ptr->vaddr--;
				ptr->bits = 16;
			}
			if (ptr->paddr & 1) {
				ptr->paddr--;
				ptr->bits = 16;
			}
		}
	}
}

static RBinInfo* info(RBinFile *arch);

static RList* symbols(RBinFile *arch) {
	struct Elf_(r_bin_elf_obj_t) *bin;
	struct r_bin_elf_symbol_t *symbol = NULL;
	RBinSymbol *ptr = NULL;
	RList *ret = NULL;
	int i;

	if (!arch || !arch->o || !arch->o->bin_obj) {
		return NULL;
	}

	bin = arch->o->bin_obj;
	ret = r_list_newf (free);
	if (!ret) {
		return NULL;
	}
	if (!(symbol = Elf_(r_bin_elf_get_symbols) (bin))) {
		return ret;
	}
	for (i = 0; !symbol[i].last; i++) {
		ut64 paddr = symbol[i].offset;
		ut64 vaddr = Elf_(r_bin_elf_p2v) (bin, paddr);
		if (!(ptr = R_NEW0 (RBinSymbol))) {
			break;
		}
		ptr->name = strdup (symbol[i].name);
		ptr->forwarder = r_str_const ("NONE");
		ptr->bind = r_str_const (symbol[i].bind);
		ptr->type = r_str_const (symbol[i].type);
		ptr->paddr = paddr;
		ptr->vaddr = vaddr;
		ptr->size = symbol[i].size;
		ptr->ordinal = symbol[i].ordinal;
		setsymord (bin, ptr->ordinal, ptr);
		if (bin->ehdr.e_machine == EM_ARM) {
			_set_arm_thumb_bits (bin, &ptr);
		}
		r_list_append (ret, ptr);
	}
	if (!(symbol = Elf_(r_bin_elf_get_imports) (bin))) {
		return ret;
	}
	for (i = 0; !symbol[i].last; i++) {
		ut64 paddr = symbol[i].offset;
		ut64 vaddr = Elf_(r_bin_elf_p2v) (bin, paddr);
		if (!symbol[i].size) {
			continue;
		}
		if (!(ptr = R_NEW0 (RBinSymbol))) {
			break;
		}
		// TODO(eddyb) make a better distinction between imports and other symbols.
		//snprintf (ptr->name, R_BIN_SIZEOF_STRINGS-1, "imp.%s", symbol[i].name);
		ptr->name = r_str_newf ("imp.%s", symbol[i].name);
		ptr->forwarder = r_str_const ("NONE");
		//strncpy (ptr->forwarder, "NONE", R_BIN_SIZEOF_STRINGS);
		ptr->bind = r_str_const (symbol[i].bind);
		ptr->type = r_str_const (symbol[i].type);
		ptr->paddr = paddr;
		ptr->vaddr = vaddr;
		ptr->size = symbol[i].size;
		ptr->ordinal = symbol[i].ordinal;
		setsymord (bin, ptr->ordinal, ptr);
		/* detect thumb */
		if (bin->ehdr.e_machine == EM_ARM) {
			_set_arm_thumb_bits (bin, &ptr);
		}
		r_list_append (ret, ptr);
	}
	return ret;
}

static RList* imports(RBinFile *arch) {
	struct Elf_(r_bin_elf_obj_t) *bin = NULL;
	RBinElfSymbol *import = NULL;
	RBinImport *ptr = NULL;
	RList *ret = NULL;
	int i;

	if (!arch || !arch->o || !arch->o->bin_obj) {
		return NULL;
	}
	bin = arch->o->bin_obj;
	if (!(ret = r_list_newf (r_bin_import_free))) {
		return NULL;
	}
	if (!(import = Elf_(r_bin_elf_get_imports) (bin))) {
		r_list_free (ret);
		return NULL;
	}
	for (i = 0; !import[i].last; i++) {
		if (!(ptr = R_NEW0 (RBinImport))) {
			break;
		}
		ptr->name = strdup (import[i].name);
		ptr->bind = r_str_const (import[i].bind);
		ptr->type = r_str_const (import[i].type);
		ptr->ordinal = import[i].ordinal;
		(void)setimpord (bin, ptr->ordinal, ptr);
		r_list_append (ret, ptr);
	}
	return ret;
}

static RList* libs(RBinFile *arch) {
	struct r_bin_elf_lib_t *libs = NULL;
	RList *ret = NULL;
	char *ptr = NULL;
	int i;

	if (!arch || !arch->o || !arch->o->bin_obj)
		return NULL;
	if (!(ret = r_list_newf (free)))
		return NULL;
	if (!(libs = Elf_(r_bin_elf_get_libs) (arch->o->bin_obj)))
		return ret;
	for (i = 0; !libs[i].last; i++) {
		ptr = strdup (libs[i].name);
		r_list_append (ret, ptr);
	}
	free (libs);
	return ret;
}

static RBinReloc *reloc_convert(struct Elf_(r_bin_elf_obj_t) *bin, RBinElfReloc *rel, ut64 GOT) {
	RBinReloc *r = NULL;
	ut64 B, P;

	if (!bin || !rel) {
		return NULL;
	}
	B = bin->baddr;
	P = B + rel->rva;
	if (!(r = R_NEW0 (RBinReloc))) {
		return r;
	}
	r->import = NULL;
	r->symbol = NULL;
	r->is_ifunc = false;
	r->addend = rel->addend;
	if (rel->sym) {
		if (rel->sym < bin->imports_by_ord_size && bin->imports_by_ord[rel->sym]) {
			r->import = bin->imports_by_ord[rel->sym];
		} else if (rel->sym < bin->symbols_by_ord_size && bin->symbols_by_ord[rel->sym]) {
			r->symbol = bin->symbols_by_ord[rel->sym];
		}
	}
	r->vaddr = rel->rva;
	r->paddr = rel->offset;

	#define SET(T) r->type = R_BIN_RELOC_ ## T; r->additive = 0; return r
	#define ADD(T, A) r->type = R_BIN_RELOC_ ## T; r->addend += A; r->additive = !rel->is_rela; return r

	switch (bin->ehdr.e_machine) {
	case EM_386: switch (rel->type) {
		case R_386_NONE:     break; // malloc then free. meh. then again, there's no real world use for _NONE.
		case R_386_32:       ADD(32, 0);
		case R_386_PC32:     ADD(32,-P);
		case R_386_GLOB_DAT: SET(32);
		case R_386_JMP_SLOT: SET(32);
		case R_386_RELATIVE: ADD(32, B);
		case R_386_GOTOFF:   ADD(32,-GOT);
		case R_386_GOTPC:    ADD(32, GOT-P);
		case R_386_16:       ADD(16, 0);
		case R_386_PC16:     ADD(16,-P);
		case R_386_8:        ADD(8,  0);
		case R_386_PC8:      ADD(8, -P);
		case R_386_COPY:     ADD(64, 0); // XXX: copy symbol at runtime
		case R_386_IRELATIVE: r->is_ifunc = true; SET(32);
		default: break; //eprintf("TODO(eddyb): uninmplemented ELF/x86 reloc type %i\n", rel->type);
		}
		break;
	case EM_X86_64: switch (rel->type) {
		case R_X86_64_NONE:	break; // malloc then free. meh. then again, there's no real world use for _NONE.
		case R_X86_64_64:	ADD(64, 0);
		case R_X86_64_PLT32:	ADD(32,-P /* +L */);
		case R_X86_64_GOT32:	ADD(32, GOT);
		case R_X86_64_PC32:	ADD(32,-P);
		case R_X86_64_GLOB_DAT: r->vaddr -= rel->sto; SET(64);
		case R_X86_64_JUMP_SLOT: r->vaddr -= rel->sto; SET(64);
		case R_X86_64_RELATIVE:	ADD(64, B);
		case R_X86_64_32:	ADD(32, 0);
		case R_X86_64_32S:	ADD(32, 0);
		case R_X86_64_16:	ADD(16, 0);
		case R_X86_64_PC16:	ADD(16,-P);
		case R_X86_64_8:	ADD(8,  0);
		case R_X86_64_PC8:	ADD(8, -P);
		case R_X86_64_GOTPCREL:	ADD(64, GOT-P);
		case R_X86_64_COPY:	ADD(64, 0); // XXX: copy symbol at runtime
		case R_X86_64_IRELATIVE: r->is_ifunc = true; SET(64);
		default: break; ////eprintf("TODO(eddyb): uninmplemented ELF/x64 reloc type %i\n", rel->type);
		}
		break;
	case EM_ARM: switch (rel->type) {
		case R_ARM_NONE:	break; // malloc then free. meh. then again, there's no real world use for _NONE.
		case R_ARM_ABS32:	ADD(32, 0);
		case R_ARM_REL32:	ADD(32,-P);
		case R_ARM_ABS16:	ADD(16, 0);
		case R_ARM_ABS8:	ADD(8,  0);
		case R_ARM_SBREL32:	ADD(32, -B);
		case R_ARM_GLOB_DAT:	ADD(32, 0);
		case R_ARM_JUMP_SLOT:	ADD(32, 0);
		case R_ARM_RELATIVE:	ADD(32, B);
		case R_ARM_GOTOFF:	ADD(32,-GOT);
		default: ADD(32,GOT); break; // reg relocations
		 ////eprintf("TODO(eddyb): uninmplemented ELF/ARM reloc type %i\n", rel->type);
		}
		break;
	default: break;
	}

	#undef SET
	#undef ADD

	free(r);
	return 0;
}

static RList* relocs(RBinFile *arch) {
	RList *ret = NULL;
	RBinReloc *ptr = NULL;
	RBinElfReloc *relocs = NULL;
	struct Elf_(r_bin_elf_obj_t) *bin = NULL;
	ut64 got_addr;
	int i;
	if (!arch || !arch->o || !arch->o->bin_obj) {
		return NULL;
	}
	bin = arch->o->bin_obj;
	if (!(ret = r_list_new ())) {
		return NULL;
	}
	ret->free = free;
	/* FIXME: This is a _temporary_ fix/workaround to prevent a use-after-
	 * free detected by ASan that would corrupt the relocation names */
	r_list_free (imports (arch));
	if ((got_addr = Elf_(r_bin_elf_get_section_addr) (bin, ".got")) == -1) {
		got_addr = Elf_(r_bin_elf_get_section_addr) (bin, ".got.plt");
		if (got_addr == -1) {
			got_addr = 0;
		}
	}
	if (got_addr < 1 && bin->ehdr.e_type == ET_REL) {
		got_addr = Elf_(r_bin_elf_get_section_addr) (bin, ".got.r2");
		if (got_addr == -1) {
			got_addr = 0;
		}
	}
	if (arch->o) {
		if (!(relocs = Elf_(r_bin_elf_get_relocs) (bin))) {
			return ret;
		}
		for (i = 0; !relocs[i].last; i++) {
			if (!(ptr = reloc_convert (bin, &relocs[i], got_addr))) {
				continue;
			}
			r_list_append (ret, ptr);
		}
		free (relocs);
	}
	return ret;
}

#define write_into_reloc() \
	do { \
		ut8 *buf = malloc (strlen (s) + 1); \
		if (!buf) break; \
		int len = r_hex_str2bin (s, buf); \
		iob->write_at (iob->io, rel->rva, buf, len); \
		free (buf); \
	} while (0) \

static void __patch_reloc (RIOBind *iob, RBinElfReloc *rel, ut64 vaddr) {
	static int times = 0;
	char s[64];
	times++;
	switch (rel->type) {
	case R_X86_64_PC32: //R_386_PC32 both have the same value
		{
			ut64 num = vaddr - (rel->rva + 4);
			num  = ((num << 8) & 0xFF00FF00 ) | ((num >> 8) & 0xFF00FF);
			//if s is equal to 0x42d we should get 0x042d that is why %04
			snprintf (s, sizeof (s), "%04"PFMT64x, num);
			write_into_reloc();
		}
		break;
	case R_X86_64_32S:
		{
			st32 num = r_swap_st32(vaddr);
			snprintf (s, sizeof (s), "%08x", num);
			write_into_reloc();
		}
		break;
	case R_X86_64_64: //R_386_32
		{
			ut64 num = r_swap_ut64(vaddr);
			snprintf (s, sizeof (s), "%08"PFMT64x, num);
			write_into_reloc ();
		}
		break;
	default:
		//eprintf ("relocation %d not handle at this time\n", rel->type);
		break;
	}
}

static RList* patch_relocs(RBin *b) {
	RList *ret = NULL;
	RBinReloc *ptr = NULL;
	RIO *io = NULL;
	RBinObject *obj = NULL;
	struct Elf_(r_bin_elf_obj_t) *bin = NULL;
	RIOSection *g = NULL, *s = NULL;
	SdbListIter *iter;
	RBinElfReloc *relcs = NULL;
	int i;
	ut64 n_off, n_vaddr, vaddr, size, sym_addr = 0, offset = 0;
	if (!b)
		return NULL;
	io = b->iob.get_io(&b->iob);
	if (!io || !io->desc)
		return NULL;
	obj = r_bin_cur_object (b);
	if (!obj) {
	   	return NULL;
	}
	bin = obj->bin_obj;
	if (bin->ehdr.e_type != ET_REL) {
		return NULL;
	}
	if (!io->cached) {
	   	eprintf ("Warning: run r2 with -e io.cache=true to fix relocations in disassembly\n");	//wat?
		return relocs (r_bin_cur (b));
	}
	ls_foreach (io->sections, iter, s) {
		if (s->addr > offset) {
			offset = s->addr;
			g = s;
		}
	}
	if (!g) {
		return NULL;
	}
	n_off = g->addr + g->size;
	n_vaddr = g->vaddr + g->vsize;
	//reserve at least that space
	size = bin->reloc_num * 4;
	if (!b->iob.section_add (io, n_off, n_vaddr, size, size, R_BIN_SCN_READABLE|R_BIN_SCN_MAP, ".got.r2", 0, io->desc->fd)) {		//XXX binid is wrong
		return NULL;
	}
	if (!(relcs = Elf_(r_bin_elf_get_relocs) (bin))) {
		return NULL;
	}
	if (!(ret = r_list_newf ((RListFree)free))) {
		free (relcs);
		return NULL;
	}
	vaddr = n_vaddr;
	for (i = 0; !relcs[i].last; i++) {
		if (relcs[i].sym) {
			if (relcs[i].sym < bin->imports_by_ord_size && bin->imports_by_ord[relcs[i].sym]) {
				sym_addr = 0;
			} else if (relcs[i].sym < bin->symbols_by_ord_size && bin->symbols_by_ord[relcs[i].sym]) {
				sym_addr = bin->symbols_by_ord[relcs[i].sym]->vaddr;
			}
		}
		__patch_reloc (&b->iob, &relcs[i], sym_addr ? sym_addr : vaddr);
		if (!(ptr = reloc_convert (bin, &relcs[i], n_vaddr))) {
			continue;
		}
		ptr->vaddr = sym_addr ? sym_addr : vaddr;
		if (!sym_addr) {
			vaddr += 4;
		}
		r_list_append (ret, ptr);
		sym_addr = 0;
	}
	free (relcs);
	return ret;
}

static int has_canary(RBinFile *arch) {
	int ret = 0;
	RList* imports_list = imports (arch);
	RListIter *iter;
	RBinImport *import;
	if (imports_list) {
		r_list_foreach (imports_list, iter, import) {
			if (!strcmp (import->name, "__stack_chk_fail") ) {
				ret = 1;
				break;
			}
		}
		imports_list->free = r_bin_import_free;
		r_list_free (imports_list);
	}
	return ret;
}

static RBinInfo* info(RBinFile *arch) {
	RBinInfo *ret = NULL;
	char *str;

	if (!(ret = R_NEW0 (RBinInfo))) {
		return NULL;
	}
	ret->lang = "c";
	ret->file = arch->file
		? strdup (arch->file)
		: NULL;
	if ((str = Elf_(r_bin_elf_get_rpath)(arch->o->bin_obj))) {
		ret->rpath = strdup (str);
		free (str);
	} else ret->rpath = strdup ("NONE");
	if (!(str = Elf_(r_bin_elf_get_file_type) (arch->o->bin_obj))) {
		free (ret);
		return NULL;
	}
	ret->type = str;
	ret->has_pi = (strstr (str, "DYN"))? 1: 0;
	ret->has_canary = has_canary (arch);
	if (!(str = Elf_(r_bin_elf_get_elf_class) (arch->o->bin_obj))) {
		free (ret);
		return NULL;
	}
	ret->bclass = str;
	if (!(str = Elf_(r_bin_elf_get_osabi_name) (arch->o->bin_obj))) {
		free (ret);
		return NULL;
	}
	ret->os = str;
	if (!(str = Elf_(r_bin_elf_get_osabi_name) (arch->o->bin_obj))) {
		free (ret);
		return NULL;
	}
	ret->subsystem = str;
	if (!(str = Elf_(r_bin_elf_get_machine_name) (arch->o->bin_obj))) {
		free (ret);
		return NULL;
	}
	ret->machine = str;
	if (!(str = Elf_(r_bin_elf_get_arch) (arch->o->bin_obj))) {
		free (ret);
		return NULL;
	}
	ret->arch = str;
	ret->rclass = strdup ("elf");
	ret->bits = Elf_(r_bin_elf_get_bits) (arch->o->bin_obj);
	if (!strcmp (ret->arch, "avr")) {
		ret->bits = 16;
	}
	ret->big_endian = Elf_(r_bin_elf_is_big_endian) (arch->o->bin_obj);
	ret->has_va = Elf_(r_bin_elf_has_va) (arch->o->bin_obj);
	ret->has_nx = Elf_(r_bin_elf_has_nx) (arch->o->bin_obj);
	ret->intrp = Elf_(r_bin_elf_intrp) (arch->o->bin_obj);
	ret->dbg_info = 0;
	if (!Elf_(r_bin_elf_get_stripped) (arch->o->bin_obj)) {
		ret->dbg_info |= R_BIN_DBG_LINENUMS | R_BIN_DBG_SYMS | R_BIN_DBG_RELOCS;
	} else {
		ret->dbg_info |= R_BIN_DBG_STRIPPED;
	}
	if (Elf_(r_bin_elf_get_static) (arch->o->bin_obj)) {
		ret->dbg_info |= R_BIN_DBG_STATIC;
	}
	return ret;
}

static RList* fields(RBinFile *arch) {
	RList *ret = NULL;
	RBinField *ptr = NULL;
	struct r_bin_elf_field_t *field = NULL;
	int i;

	if (!(ret = r_list_new ())) {
		return NULL;
	}
	ret->free = free;
	if (!(field = Elf_(r_bin_elf_get_fields) (arch->o->bin_obj))) {
		return ret;
	}
	for (i = 0; !field[i].last; i++) {
		if (!(ptr = R_NEW0 (RBinField))) {
			break;
		}
		ptr->name = strdup (field[i].name);
		ptr->vaddr = field[i].offset;
		ptr->paddr = field[i].offset;
		r_list_append (ret, ptr);
	}
	free (field);
	return ret;
}

static ut64 size(RBinFile *arch) {
	ut64 off = 0;
	ut64 len = 0;
	if (!arch->o->sections) {
		RListIter *iter;
		RBinSection *section;
		arch->o->sections = sections (arch);
		r_list_foreach (arch->o->sections, iter, section) {
			if (section->paddr > off) {
				off = section->paddr;
				len = section->size;
			}
		}
	}
	return off+len;
}

#if !R_BIN_ELF64 && !R_BIN_CGC

static int check_bytes(const ut8 *buf, ut64 length) {
	return buf && length > 4 && memcmp (buf, ELFMAG, SELFMAG) == 0
		&& buf[4] != 2;
}

static int check(RBinFile *arch) {
	const ut8 *bytes = arch ? r_buf_buffer (arch->buf) : NULL;
	ut64 sz = arch ? r_buf_size (arch->buf): 0;
	return check_bytes (bytes, sz);
}

extern struct r_bin_dbginfo_t r_bin_dbginfo_elf;
extern struct r_bin_write_t r_bin_write_elf;

static RBuffer* create(RBin* bin, const ut8 *code, int codelen, const ut8 *data, int datalen) {
	ut32 filesize, code_va, code_pa, phoff;
	ut32 p_start, p_phoff, p_phdr;
	ut32 p_ehdrsz, p_phdrsz;
	ut16 ehdrsz, phdrsz;
	ut32 p_vaddr, p_paddr, p_fs, p_fs2;
	ut32 baddr;
	int is_arm = 0;
	RBuffer *buf = r_buf_new ();
	if (bin && bin->cur && bin->cur->o && bin->cur->o->info) {
		is_arm = !strcmp (bin->cur->o->info->arch, "arm");
	}
	// XXX: hardcoded
	if (is_arm) {
		baddr = 0x40000;
	} else {
		baddr = 0x8048000;
	}

#define B(x,y) r_buf_append_bytes(buf,(const ut8*)x,y)
#define D(x) r_buf_append_ut32(buf,x)
#define H(x) r_buf_append_ut16(buf,x)
#define Z(x) r_buf_append_nbytes(buf,x)
#define W(x,y,z) r_buf_write_at(buf,x,(const ut8*)y,z)
#define WZ(x,y) p_tmp=buf->length;Z(x);W(p_tmp,y,strlen(y))

	B ("\x7F" "ELF" "\x01\x01\x01\x00", 8);
	Z (8);
	H (2); // ET_EXEC
	if (is_arm) {
		H (40); // e_machne = EM_ARM
	} else {
		H (3); // e_machne = EM_I386
	}

	D (1);
	p_start = buf->length;
	D (-1); // _start
	p_phoff = buf->length;
	D (-1); // phoff -- program headers offset
	D (0);  // shoff -- section headers offset
	D (0);  // flags
	p_ehdrsz = buf->length;
	H (-1); // ehdrsz
	p_phdrsz = buf->length;
	H (-1); // phdrsz
	H (1);
	H (0);
	H (0);
	H (0);
	// phdr:
	p_phdr = buf->length;
	D (1);
	D (0);
	p_vaddr = buf->length;
	D (-1); // vaddr = $$
	p_paddr = buf->length;
	D (-1); // paddr = $$
	p_fs = buf->length;
	D (-1); // filesize
	p_fs2 = buf->length;
	D (-1); // filesize
	D (5); // flags
	D (0x1000); // align

	ehdrsz = p_phdr;
	phdrsz = buf->length - p_phdr;
	code_pa = buf->length;
	code_va = code_pa + baddr;
	phoff = 0x34;//p_phdr ;
	filesize = code_pa + codelen + datalen;

	W (p_start, &code_va, 4);
	W (p_phoff, &phoff, 4);
	W (p_ehdrsz, &ehdrsz, 2);
	W (p_phdrsz, &phdrsz, 2);

	code_va = baddr; // hack
	W (p_vaddr, &code_va, 4);
	code_pa = baddr; // hack
	W (p_paddr, &code_pa, 4);

	W (p_fs, &filesize, 4);
	W (p_fs2, &filesize, 4);

	B (code, codelen);

	if (data && datalen > 0) {
		//ut32 data_section = buf->length;
		eprintf ("Warning: DATA section not support for ELF yet\n");
		B (data, datalen);
	}
	return buf;
}

RBinPlugin r_bin_plugin_elf = {
	.name = "elf",
	.desc = "ELF format r_bin plugin",
	.license = "LGPL3",
	.get_sdb = &get_sdb,
	.load = &load,
	.load_bytes = &load_bytes,
	.destroy = &destroy,
	.check = &check,
	.check_bytes = &check_bytes,
	.baddr = &baddr,
	.boffset = &boffset,
	.binsym = &binsym,
	.entries = &entries,
	.sections = &sections,
	.symbols = &symbols,
	.minstrlen = 4,
	.imports = &imports,
	.info = &info,
	.fields = &fields,
	.size = &size,
	.libs = &libs,
	.relocs = &relocs,
	.patch_relocs = &patch_relocs,
	.dbginfo = &r_bin_dbginfo_elf,
	.create = &create,
	.write = &r_bin_write_elf,
};

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_elf,
	.version = R2_VERSION
};
#endif
#endif
