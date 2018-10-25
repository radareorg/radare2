/* radare - LGPL - Copyright 2009-2018 - nibble, pancake */

#include <stdio.h>
#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>
#include <r_io.h>
#include <r_cons.h>
#include "elf/elf.h"

static RBinInfo* info(RBinFile *bf);

//TODO: implement r_bin_symbol_dup() and r_bin_symbol_free ?

static int get_file_type(RBinFile *bf) {
	struct Elf_(r_bin_elf_obj_t) *obj = bf->o->bin_obj;
	char *type = Elf_(r_bin_elf_get_file_type (obj));
	int res = type? ((!strncmp (type, "CORE", 4)) ? R_BIN_TYPE_CORE : R_BIN_TYPE_DEFAULT) : -1;
	free (type);
	return res;
}

static RList *maps(RBinFile *bf) {
	if (bf && bf->o) {
		return Elf_(r_bin_elf_get_maps)(bf->o->bin_obj);
	}
	return NULL;
}

static char* regstate(RBinFile *bf) {
	struct Elf_(r_bin_elf_obj_t) *obj = bf->o->bin_obj;
	if (obj->ehdr.e_machine != EM_AARCH64 &&
		obj->ehdr.e_machine != EM_ARM &&
		obj->ehdr.e_machine != EM_386 &&
		obj->ehdr.e_machine != EM_X86_64) {
		eprintf ("Cannot retrieve regstate on: %s (not yet supported)\n",
					Elf_(r_bin_elf_get_machine_name)(obj));
		return NULL;
	}

	int len = 0;
	ut8 *regs = Elf_(r_bin_elf_grab_regstate) (obj, &len);
	char *hexregs = (regs && len > 0) ? r_hex_bin2strdup (regs, len) : NULL;

	free (regs);
	return hexregs;
}

static void setsymord(ELFOBJ* eobj, ut32 ord, RBinSymbol *ptr) {
	if (!eobj->symbols_by_ord || ord >= eobj->symbols_by_ord_size) {
		return;
	}
	r_bin_symbol_free (eobj->symbols_by_ord[ord]);
	eobj->symbols_by_ord[ord] = r_bin_symbol_clone (ptr);
}

static void setimpord(ELFOBJ* eobj, ut32 ord, RBinImport *ptr) {
	if (!eobj->imports_by_ord || ord >= eobj->imports_by_ord_size) {
		return;
	}
	r_bin_import_free (eobj->imports_by_ord[ord]);
	eobj->imports_by_ord[ord] = r_bin_import_clone (ptr);
}

static Sdb* get_sdb(RBinFile *bf) {
	RBinObject *o = bf->o;
	if (o && o->bin_obj) {
		struct Elf_(r_bin_elf_obj_t) *bin = (struct Elf_(r_bin_elf_obj_t) *) o->bin_obj;
		return bin->kv;
	}
	return NULL;
}

static void * load_buffer(RBinFile *bf, RBuffer *buf, ut64 loadaddr, Sdb *sdb) {
	struct Elf_(r_bin_elf_obj_t) *res;
	if (!buf) {
		return NULL;
	}
	res = Elf_(r_bin_elf_new_buf) (buf, bf->rbin->verbose);
	if (res) {
		sdb_ns_set (sdb, "info", res->kv);
	}
	return res;
}

static bool load_bytes(RBinFile *bf, void **bin_obj, const ut8 *buf, ut64 sz, ut64 loadaddr, Sdb *sdb) {
	struct Elf_(r_bin_elf_obj_t) *res;
	if (!buf || !sz || sz == UT64_MAX) {
		return false;
	}
	RBuffer *tbuf = r_buf_new ();
	// NOOOEES must use io!
	r_buf_set_bytes (tbuf, buf, sz);
	res = Elf_(r_bin_elf_new_buf) (tbuf, bf->rbin->verbose);
	if (res) {
		sdb_ns_set (sdb, "info", res->kv);
	}
	r_buf_free (tbuf);
	*bin_obj = res;
	return true;
}

static bool load(RBinFile *bf) {
	const ut8 *bytes = bf ? r_buf_buffer (bf->buf) : NULL;
	ut64 sz = bf ? r_buf_size (bf->buf): 0;
	if (!bf || !bf->o) {
		return false;
	}
	return load_bytes (bf, &bf->o->bin_obj, bytes, sz, bf->o->loadaddr, bf->sdb);
}

static int destroy(RBinFile *bf) {
	int i;
	ELFOBJ* eobj = bf->o->bin_obj;
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
	Elf_(r_bin_elf_free) ((struct Elf_(r_bin_elf_obj_t)*)bf->o->bin_obj);
	return true;
}

static ut64 baddr(RBinFile *bf) {
	return Elf_(r_bin_elf_get_baddr) (bf->o->bin_obj);
}

static ut64 boffset(RBinFile *bf) {
	return Elf_(r_bin_elf_get_boffset) (bf->o->bin_obj);
}

static RBinAddr* binsym(RBinFile *bf, int sym) {
	struct Elf_(r_bin_elf_obj_t)* obj = bf->o->bin_obj;
	RBinAddr *ret = NULL;
	ut64 addr = 0LL;

	switch (sym) {
	case R_BIN_SYM_ENTRY:
		addr = Elf_(r_bin_elf_get_entry_offset) (bf->o->bin_obj);
		break;
	case R_BIN_SYM_MAIN:
		addr = Elf_(r_bin_elf_get_main_offset) (bf->o->bin_obj);
		break;
	case R_BIN_SYM_INIT:
		addr = Elf_(r_bin_elf_get_init_offset) (bf->o->bin_obj);
		break;
	case R_BIN_SYM_FINI:
		addr = Elf_(r_bin_elf_get_fini_offset) (bf->o->bin_obj);
		break;
	}
	if (addr && addr != UT64_MAX && (ret = R_NEW0 (RBinAddr))) {
		struct Elf_(r_bin_elf_obj_t) *bin = bf->o->bin_obj;
		bool is_arm = bin->ehdr.e_machine == EM_ARM;
		ret->paddr = addr;
		ret->vaddr = Elf_(r_bin_elf_p2v) (obj, addr);
		if (is_arm && addr & 1) {
			ret->bits = 16;
			ret->vaddr--;
			ret->paddr--;
		}
	}
	return ret;
}

static RList* sections(RBinFile *bf) {
	struct Elf_(r_bin_elf_obj_t)* obj = (bf && bf->o)? bf->o->bin_obj : NULL;
	struct r_bin_elf_section_t *section = NULL;
	int i, num, found_load = 0;
	Elf_(Phdr)* phdr = NULL;
	RBinSection *ptr = NULL;
	RList *ret = NULL;

	if (!obj || !(ret = r_list_newf ((RListFree)r_bin_section_free))) {
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
			if (strstr (ptr->name, "data") && !strstr (ptr->name, "rel") && !strstr (ptr->name, "pydata")) {
				ptr->is_data = true;
			}
			ptr->size = section[i].type != SHT_NOBITS ? section[i].size : 0;
			ptr->vsize = section[i].size;
			ptr->paddr = section[i].offset;
			ptr->vaddr = section[i].rva;
			ptr->add = !obj->phdr; // Load sections if there is no PHDR
			ptr->perm = 0;
			if (R_BIN_ELF_SCN_IS_EXECUTABLE (section[i].flags)) {
				ptr->perm |= R_PERM_X;
			}
			if (R_BIN_ELF_SCN_IS_WRITABLE (section[i].flags)) {
				ptr->perm |= R_PERM_W;
			}
			if (R_BIN_ELF_SCN_IS_READABLE (section[i].flags)) {
				ptr->perm |= R_PERM_R;
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
			ptr->perm = phdr[i].p_flags;
			ptr->is_segment = true;
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
		if (!bf->size) {
			struct Elf_(r_bin_elf_obj_t) *bin = bf->o->bin_obj;
			bf->size = bin? bin->size: 0x9999;
		}
		if (found_load == 0) {
			if (!(ptr = R_NEW0 (RBinSection))) {
				return ret;
			}
			sprintf (ptr->name, "uphdr");
			ptr->size = bf->size;
			ptr->vsize = bf->size;
			ptr->paddr = 0;
			ptr->vaddr = 0x10000;
			ptr->add = true;
			ptr->perm = R_PERM_RWX;
			r_list_append (ret, ptr);
		}
	}
	// add entry for ehdr
	ptr = R_NEW0 (RBinSection);
	if (ptr) {
		ut64 ehdr_size = sizeof (obj->ehdr);
		if (bf->size < ehdr_size) {
			ehdr_size = bf->size;
		}
		sprintf (ptr->name, "ehdr");
		ptr->paddr = 0;
		ptr->vaddr = obj->baddr;
		ptr->size = ehdr_size;
		ptr->vsize = ehdr_size;
		ptr->add = false;
		if (obj->ehdr.e_type == ET_REL) {
			ptr->add = true;
		}
		ptr->perm = R_PERM_RW;
		ptr->is_segment = true;
		r_list_append (ret, ptr);
	}
	return ret;
}

static RBinAddr* newEntry(RBinFile *bf, ut64 hpaddr, ut64 hvaddr, ut64 vaddr, int type, int bits) {
	struct Elf_(r_bin_elf_obj_t)* obj;
	RBinAddr *ptr;

	if (!bf || !bf->o || !bf->o->bin_obj) {
		return NULL;
	}
	obj = bf->o->bin_obj;
	ptr = R_NEW0 (RBinAddr);
	if (ptr) {
		ptr->paddr = Elf_(r_bin_elf_v2p) (obj, vaddr);
		ptr->vaddr = vaddr;
		ptr->hpaddr = hpaddr;
		ptr->hvaddr = hvaddr;
		ptr->bits = bits;
		ptr->type = type;
		//realign due to thumb
		if (bits == 16 && ptr->vaddr & 1) {
			ptr->paddr--;
			ptr->vaddr--;
		}
	}
	return ptr;
}

static void process_constructors (RBinFile *bf, RList *ret, int bits) {
	RList *secs = sections (bf);
	RListIter *iter;
	RBinSection *sec;
	int i, type;
	r_list_foreach (secs, iter, sec) {
		type = -1;
		if (!strcmp (sec->name, ".fini_array")) {
			type = R_BIN_ENTRY_TYPE_FINI;
		} else if (!strcmp (sec->name, ".init_array")) {
			type = R_BIN_ENTRY_TYPE_INIT;
		} else if (!strcmp (sec->name, ".preinit_array")) {
			type = R_BIN_ENTRY_TYPE_PREINIT;
		}
		if (type != -1) {
			ut8 *buf = calloc (sec->size, 1);
			if (!buf) {
				continue;
			}
			(void)r_buf_read_at (bf->buf, sec->paddr, buf, sec->size);
			if (bits == 32) {
				for (i = 0; (i + 3) < sec->size; i += 4) {
					ut32 addr32 = r_read_le32 (buf + i);
					if (addr32) {
						RBinAddr *ba = newEntry (bf, sec->paddr + i, sec->vaddr + i,
						                         (ut64)addr32, type, bits);
						r_list_append (ret, ba);
					}
				}
			} else {
				for (i = 0; (i + 7) < sec->size; i += 8) {
					ut64 addr64 = r_read_le64 (buf + i);
					if (addr64) {
						RBinAddr *ba = newEntry (bf, sec->paddr + i, sec->vaddr + i,
						                         addr64, type, bits);
						r_list_append (ret, ba);
					}
				}
			}
			free (buf);
		}
	}
	r_list_free (secs);
}

static RList* entries(RBinFile *bf) {
	struct Elf_(r_bin_elf_obj_t)* obj;
	RBinAddr *ptr = NULL;
	struct r_bin_elf_symbol_t *symbol;
	RList *ret;
	int i;

	if (!bf || !bf->o || !bf->o->bin_obj) {
		return NULL;
	}
	obj = bf->o->bin_obj;
	if (!(ret = r_list_newf ((RListFree)free))) {
		return NULL;
	}
	if (!(ptr = R_NEW0 (RBinAddr))) {
		return ret;
	}
	ptr->paddr = Elf_(r_bin_elf_get_entry_offset) (obj);
	ptr->vaddr = Elf_(r_bin_elf_p2v) (obj, ptr->paddr);
	ptr->hpaddr = 0x18;  // e_entry offset in ELF header
	ptr->hvaddr = UT64_MAX;
	if (bf->o->sections) {
		RListIter *iter;
		RBinSection *section;
		r_list_foreach_prev (bf->o->sections, iter, section) {
			if (!strcmp (section->name, "ehdr")) {
				ptr->hvaddr = section->vaddr + ptr->hpaddr;
				break;
			}
		}
	}
	if (ptr->hvaddr == UT64_MAX) {
		Elf_(r_bin_elf_p2v_new) (obj, ptr->hpaddr);
	}

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

	// add entrypoint for jni libraries
	// NOTE: this is slow, we shouldnt find for java constructors here
	if (!(symbol = Elf_(r_bin_elf_get_symbols) (obj))) {
		return ret;
	}
	for (i = 0; !symbol[i].last; i++) {
		if (!strncmp (symbol[i].name, "Java", 4)) {
			if (r_str_endswith (symbol[i].name, "_init")) {
				if (!(ptr = R_NEW0 (RBinAddr))) {
					return ret;
				}
				ptr->paddr = symbol[i].offset;
				ptr->vaddr = Elf_(r_bin_elf_p2v) (obj, ptr->paddr);
				ptr->hpaddr = UT64_MAX;
				ptr->type = R_BIN_ENTRY_TYPE_INIT;
				r_list_append (ret, ptr);
				break;
			}
		}
	}
	int bin_bits = Elf_(r_bin_elf_get_bits) (bf->o->bin_obj);
	process_constructors (bf, ret, bin_bits < 32 ? 32: bin_bits);
	return ret;
}

static void _set_arm_thumb_bits(struct Elf_(r_bin_elf_obj_t) *bin, RBinSymbol **sym) {
	int bin_bits = Elf_(r_bin_elf_get_bits) (bin);
	RBinSymbol *ptr = *sym;
	int len = strlen (ptr->name);
	if (ptr->name[0] == '$' && (len >= 2 && !ptr->name[2])) {
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
			if (ptr->paddr != UT64_MAX) {
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
}

static RBinSymbol *convert_symbol(struct Elf_(r_bin_elf_obj_t) *bin,
				  struct r_bin_elf_symbol_t *symbol,
				  const char *namefmt) {
	ut64 paddr, vaddr;
	RBinSymbol *ptr = NULL;
	if (symbol->is_value) {
		paddr = UT64_MAX;
		vaddr = symbol->offset;
	} else {
		paddr = symbol->offset;
		vaddr = Elf_(r_bin_elf_p2v_new) (bin, paddr);
	}

	if (!(ptr = R_NEW0 (RBinSymbol))) {
		return NULL;
	}
	ptr->name = symbol->name[0] ? r_str_newf (namefmt, &symbol->name[0]) : strdup ("");
	ptr->forwarder = r_str_const ("NONE");
	ptr->bind = r_str_const (symbol->bind);
	ptr->type = r_str_const (symbol->type);
	ptr->paddr = paddr;
	ptr->vaddr = vaddr;
	ptr->size = symbol->size;
	ptr->ordinal = symbol->ordinal;
	// detect thumb
	if (bin->ehdr.e_machine == EM_ARM && *ptr->name) {
		_set_arm_thumb_bits (bin, &ptr);
	}

	return ptr;
}

static void insert_symbol(struct Elf_(r_bin_elf_obj_t) *bin,
			  RBinSymbol *ptr,
			  bool is_sht_null,
			  RList *ret) {
	// put the symbol in symbols_ord table
	setsymord (bin, ptr->ordinal, ptr);
	// add it to the list of symbols only if it doesn't point to SHT_NULL
	if (is_sht_null) {
		r_bin_symbol_free (ptr);
	} else {
		r_list_append (ret, ptr);
	}
}

static RList* symbols(RBinFile *bf) {
	struct Elf_(r_bin_elf_obj_t) *bin;
	struct r_bin_elf_symbol_t *symbol = NULL;
	RBinSymbol *ptr = NULL;
	RList *ret = NULL;
	int i;

	if (!bf|| !bf->o || !bf->o->bin_obj) {
		return NULL;
	}

	bin = bf->o->bin_obj;
	ret = r_list_newf (free);
	if (!ret) {
		return NULL;
	}

	// traverse symbols
	if (!(symbol = Elf_(r_bin_elf_get_symbols) (bin))) {
		return ret;
	}
	for (i = 0; !symbol[i].last; i++) {
		ptr = convert_symbol (bin, &symbol[i], "%s");
		if (!ptr) {
			break;
		}
		insert_symbol (bin, ptr, symbol[i].is_sht_null, ret);
	}

	// traverse imports
	if (!(symbol = Elf_(r_bin_elf_get_imports) (bin))) {
		return ret;
	}
	for (i = 0; !symbol[i].last; i++) {
		if (!symbol[i].size) {
			continue;
		}
		ptr = convert_symbol (bin, &symbol[i], "imp.%s");
		if (!ptr) {
			break;
		}
		// special case where there is not entry in the plt for the import
		if (ptr->vaddr == UT32_MAX) {
			ptr->paddr = 0;
			ptr->vaddr = 0;
		}
		insert_symbol (bin, ptr, symbol[i].is_sht_null, ret);
	}
	return ret;
}

static RList* imports(RBinFile *bf) {
	struct Elf_(r_bin_elf_obj_t) *bin = NULL;
	RBinElfSymbol *import = NULL;
	RBinImport *ptr = NULL;
	RList *ret = NULL;
	int i;

	if (!bf || !bf->o || !bf->o->bin_obj) {
		return NULL;
	}
	bin = bf->o->bin_obj;
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
		setimpord (bin, ptr->ordinal, ptr);
		r_list_append (ret, ptr);
	}
	return ret;
}

static RList* libs(RBinFile *bf) {
	struct r_bin_elf_lib_t *libs = NULL;
	RList *ret = NULL;
	char *ptr = NULL;
	int i;

	if (!bf || !bf->o || !bf->o->bin_obj) {
		return NULL;
	}
	if (!(ret = r_list_newf (free))) {
		return NULL;
	}
	if (!(libs = Elf_(r_bin_elf_get_libs) (bf->o->bin_obj))) {
		return ret;
	}
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
	P = rel->rva; // rva has taken baddr into account
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

	free (r);
	return 0;
}

static RList* relocs(RBinFile *bf) {
	RList *ret = NULL;
	RBinReloc *ptr = NULL;
	RBinElfReloc *relocs = NULL;
	struct Elf_(r_bin_elf_obj_t) *bin = NULL;
	ut64 got_addr;
	int i;
	if (!bf || !bf->o || !bf->o->bin_obj) {
		return NULL;
	}
	bin = bf->o->bin_obj;
	if (!(ret = r_list_newf (free))) {
		return NULL;
	}
	/* FIXME: This is a _temporary_ fix/workaround to prevent a use-after-
	 * free detected by ASan that would corrupt the relocation names */
	r_list_free (imports (bf));
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
	if (bf->o) {
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

static void _patch_reloc (ut16 e_machine, RIOBind *iob, RBinElfReloc *rel, ut64 S, ut64 B, ut64 L) {
	ut64 val;
	ut64 A = rel->addend, P = rel->rva;
	ut8 buf[8];
	switch (e_machine) {
	case EM_PPC64: {
		int low = 0, word = 0;
		switch (rel->type) {
		case R_PPC64_REL16_HA:
			word = 2;
			val = (S + A - P + 0x8000) >> 16;
			break;
		case R_PPC64_REL16_LO:
			word = 2;
			val = (S + A - P) & 0xffff;
			break;
		case R_PPC64_REL14:
			low = 14;
			val = (st64)(S + A - P) >> 2;
			break;
		case R_PPC64_REL24:
			low = 24;
			val = (st64)(S + A - P) >> 2;
			break;
		case R_PPC64_REL32:
			word = 4;
			val = S + A - P;
			break;
		default:
			break;
		}
		if (low) {
			// TODO big-endian
			switch (low) {
			case 14:
				val &= (1 << 14) - 1;
				iob->read_at (iob->io, rel->rva, buf, 2);
				r_write_le32 (buf, (r_read_le32 (buf) & ~((1<<16) - (1<<2))) | val << 2);
				iob->write_at (iob->io, rel->rva, buf, 2);
				break;
			case 24:
				val &= (1 << 24) - 1;
				iob->read_at (iob->io, rel->rva, buf, 4);
				r_write_le32 (buf, (r_read_le32 (buf) & ~((1<<26) - (1<<2))) | val << 2);
				iob->write_at (iob->io, rel->rva, buf, 4);
				break;
			}
		} else if (word) {
			// TODO big-endian
			switch (word) {
			case 2:
				r_write_le16 (buf, val);
				iob->write_at (iob->io, rel->rva, buf, 2);
				break;
			case 4:
				r_write_le32 (buf, val);
				iob->write_at (iob->io, rel->rva, buf, 4);
				break;
			}
		}
		break;
	}
	case EM_X86_64: {
		int word = 0;
		switch (rel->type) {
		case R_X86_64_8:
			word = 1;
			val = S + A;
			break;
		case R_X86_64_16:
			word = 2;
			val = S + A;
			break;
		case R_X86_64_32:
		case R_X86_64_32S:
			word = 4;
			val = S + A;
			break;
		case R_X86_64_64:
			word = 8;
			val = S + A;
			break;
		case R_X86_64_GLOB_DAT:
		case R_X86_64_JUMP_SLOT:
			word = 4;
			val = S;
			break;
		case R_X86_64_PC8:
			word = 1;
			val = S + A - P;
			break;
		case R_X86_64_PC16:
			word = 2;
			val = S + A - P;
			break;
		case R_X86_64_PC32:
			word = 4;
			val = S + A - P;
			break;
		case R_X86_64_PC64:
			word = 8;
			val = S + A - P;
			break;
		case R_X86_64_PLT32:
			word = 4;
			val = L + A - P;
			break;
		case R_X86_64_RELATIVE:
			word = 8;
			val = B + A;
			break;
		default:
			//eprintf ("relocation %d not handle at this time\n", rel->type);
			break;
		}
		switch (word) {
		case 0:
			break;
		case 1:
			buf[0] = val;
			iob->write_at (iob->io, rel->rva, buf, 1);
			break;
		case 2:
			r_write_le16 (buf, val);
			iob->write_at (iob->io, rel->rva, buf, 2);
			break;
		case 4:
			r_write_le32 (buf, val);
			iob->write_at (iob->io, rel->rva, buf, 4);
			break;
		case 8:
			r_write_le64 (buf, val);
			iob->write_at (iob->io, rel->rva, buf, 8);
			break;
		}
		break;
	}
	}
}

static bool ht_insert_intu64(SdbHt* ht, int key, ut64 value) {
	ut64 *mvalue = malloc (sizeof (ut64));
	if (!mvalue) {
		return false;
	}
	*mvalue = value;
	return ht_insert (ht, sdb_fmt ("%d", key), (void *)mvalue);
}

static ut64 ht_find_intu64(SdbHt* ht, int key, bool* found) {
	ut64 *mvalue = (ut64 *)ht_find (ht, sdb_fmt ("%d", key), found);
	return *found ? *mvalue : 0;
}

static void relocs_by_sym_free(HtKv *kv) {
	free (kv->key);
	free (kv->value);
}

static RList* patch_relocs(RBin *b) {
	RList *ret = NULL;
	RBinReloc *ptr = NULL;
	RIO *io = NULL;
	RBinObject *obj = NULL;
	struct Elf_(r_bin_elf_obj_t) *bin = NULL;
	RIOSection *g = NULL, *s = NULL;
	SdbHt *relocs_by_sym;
	SdbListIter *iter;
	RBinElfReloc *relcs = NULL;
	RBinInfo *info;
	int cdsz;
	int i;
	ut64 n_off, n_vaddr, vaddr, size, offset = 0;

	if (!b)
		return NULL;
	io = b->iob.io;
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
	   	eprintf ("Warning: run r2 with -e io.cache=true to fix relocations in disassembly\n");
		return relocs (r_bin_cur (b));
	}

	info = obj ? obj->info: NULL;
	cdsz = info? (info->bits == 64? 8: info->bits == 32? 4: info->bits == 16 ? 4: 0): 0;

	ls_foreach (io->sections, iter, s) {
		if (s->paddr > offset) {
			offset = s->paddr;
			g = s;
		}
	}
	if (!g) {
		return NULL;
	}
	n_off = g->paddr + g->size;
	n_vaddr = g->vaddr + g->vsize;
	//reserve at least that space
	size = bin->reloc_num * 4;
	if (!b->iob.section_add (io, n_off, n_vaddr, size, size, R_PERM_R, ".got.r2", 0, io->desc->fd)) {
		return NULL;
	}
	if (!(relcs = Elf_(r_bin_elf_get_relocs) (bin))) {
		return NULL;
	}
	if (!(ret = r_list_newf ((RListFree)free))) {
		free (relcs);
		return NULL;
	}
	if (!(relocs_by_sym = ht_new (NULL, relocs_by_sym_free, NULL))) {
		r_list_free (ret);
		free (relcs);
		return NULL;
	}
	vaddr = n_vaddr;
	for (i = 0; !relcs[i].last; i++) {
		ut64 sym_addr = 0;

		if (relcs[i].sym) {
			if (relcs[i].sym < bin->imports_by_ord_size && bin->imports_by_ord[relcs[i].sym]) {
				bool found;
				sym_addr = ht_find_intu64 (relocs_by_sym, relcs[i].sym, &found);
			} else if (relcs[i].sym < bin->symbols_by_ord_size && bin->symbols_by_ord[relcs[i].sym]) {
				sym_addr = bin->symbols_by_ord[relcs[i].sym]->vaddr;
			}
		}
		// TODO relocation types B, L
		_patch_reloc (bin->ehdr.e_machine, &b->iob, &relcs[i], sym_addr ? sym_addr : vaddr, 0, n_vaddr + size);
		if (!(ptr = reloc_convert (bin, &relcs[i], n_vaddr))) {
			continue;
		}

		if (sym_addr) {
			ptr->vaddr = sym_addr;
		} else {
			ptr->vaddr = vaddr;
			ht_insert_intu64 (relocs_by_sym, relcs[i].sym, vaddr);
			vaddr += cdsz;
		}
		r_list_append (ret, ptr);
	}
	ht_free (relocs_by_sym);
	free (relcs);
	return ret;
}

static void lookup_symbols(RBinFile *bf, RBinInfo *ret) {
	RList* symbols_list = symbols (bf);
	RListIter *iter;
	RBinSymbol *symbol;
	bool is_rust = false;
	if (symbols_list) {
		r_list_foreach (symbols_list, iter, symbol) {
			if (ret->has_canary == true && is_rust == true) {
				break;
			}
			if (!strcmp (symbol->name, "_NSConcreteGlobalBlock")) {
				ret->lang = !strcmp (ret->lang, "c++") ? "c++ blocks ext." : "c blocks ext.";
			}
			if (strstr (symbol->name, "__stack_chk_fail") || strstr (symbol->name, "__stack_smash_handler")) {
				ret->has_canary = true;
			}
			if (!strcmp (symbol->name, "__rust_oom")) {
				is_rust = true;
				ret->lang = "rust";
			}
		}
		symbols_list->free = r_bin_symbol_free;
		r_list_free (symbols_list);
	}
}

static void lookup_sections(RBinFile *bf, RBinInfo *ret) {
	RList* sections_list = sections (bf);
	RListIter *iter;
	RBinSection *section;
	bool is_go = false;
	ret->has_retguard = -1;
	r_list_foreach (sections_list, iter, section) {
		if (ret->has_retguard != -1 && is_go == true) {
			break;
		}
		if (strstr (section->name, "note.go.buildid") ||
		    strstr (section->name, ".gopclntab") ||
		    strstr (section->name, ".go_export")) {
			ret->lang = "go";
			is_go = true;
		}
		# define R_BIN_RANDOMDATA_RETGUARD_SZ 48
		if (!strcmp (section->name, ".openbsd.randomdata")) {
			// The retguard cookie adds 8 per return function inst.
			ret->has_retguard = (section->size >= R_BIN_RANDOMDATA_RETGUARD_SZ);
			break;
		}
	}
	r_list_free (sections_list);
}

static bool has_sanitizers(RBinFile *bf) {
	bool ret = false;
	RList* imports_list = imports (bf);
	RListIter *iter;
	RBinImport *import;
	r_list_foreach (imports_list, iter, import) {
		if (strstr (import->name, "__sanitizer") ||
		    strstr (import->name, "__ubsan")) {
			ret = true;
			break;
		}
	}
	r_list_free (imports_list);
	return ret;
}

static RBinInfo* info(RBinFile *bf) {
	RBinInfo *ret = NULL;
	char *str;

	if (!(ret = R_NEW0 (RBinInfo))) {
		return NULL;
	}
	ret->lang = r_bin_is_cxx (bf) ? "c++" : "c";
	ret->file = bf->file
		? strdup (bf->file)
		: NULL;
	void *obj = bf->o->bin_obj;
	if ((str = Elf_(r_bin_elf_get_rpath)(obj))) {
		ret->rpath = strdup (str);
		free (str);
	} else {
		ret->rpath = strdup ("NONE");
	}
	if (!(str = Elf_(r_bin_elf_get_file_type) (obj))) {
		free (ret);
		return NULL;
	}
	ret->type = str;
	ret->has_pi = (strstr (str, "DYN"))? 1: 0;
	ret->has_lit = true;
	ret->has_sanitizers = has_sanitizers (bf);
	if (!(str = Elf_(r_bin_elf_get_elf_class) (obj))) {
		free (ret);
		return NULL;
	}
	ret->bclass = str;
	if (!(str = Elf_(r_bin_elf_get_osabi_name) (obj))) {
		free (ret);
		return NULL;
	}
	ret->os = str;
	if (!(str = Elf_(r_bin_elf_get_osabi_name) (obj))) {
		free (ret);
		return NULL;
	}
	ret->subsystem = str;
	if (!(str = Elf_(r_bin_elf_get_machine_name) (obj))) {
		free (ret);
		return NULL;
	}
	ret->machine = str;
	if (!(str = Elf_(r_bin_elf_get_arch) (obj))) {
		free (ret);
		return NULL;
	}
	ret->arch = str;
	ret->rclass = strdup ("elf");
	ret->bits = Elf_(r_bin_elf_get_bits) (obj);
	if (!strcmp (ret->arch, "avr")) {
		ret->bits = 16;
	}
	ret->big_endian = Elf_(r_bin_elf_is_big_endian) (obj);
	ret->has_va = Elf_(r_bin_elf_has_va) (obj);
	ret->has_nx = Elf_(r_bin_elf_has_nx) (obj);
	ret->intrp = Elf_(r_bin_elf_intrp) (obj);
	ret->dbg_info = 0;
	if (!Elf_(r_bin_elf_get_stripped) (obj)) {
		ret->dbg_info |= R_BIN_DBG_LINENUMS | R_BIN_DBG_SYMS | R_BIN_DBG_RELOCS;
	} else {
		ret->dbg_info |= R_BIN_DBG_STRIPPED;
	}
	if (Elf_(r_bin_elf_get_static) (obj)) {
		ret->dbg_info |= R_BIN_DBG_STATIC;
	}
	lookup_sections (bf, ret);
	lookup_symbols (bf, ret);
	return ret;
}

static RList* fields(RBinFile *bf) {
	int left = 0;
	RList *ret = NULL;
	const ut8 *buf = NULL;

	if (!(ret = r_list_new ())) {
		return NULL;
	}
	ret->free = free;

	if (!(buf = r_buf_get_at (bf->buf, 0, &left))) {
		RBinField *ptr = NULL;
		struct r_bin_elf_field_t *field = NULL;
		int i;

		if (!(field = Elf_(r_bin_elf_get_fields) (bf->o->bin_obj))) {
		return ret;
		}
		for (i = 0; !field[i].last; i++) {
			if (!(ptr = R_NEW0 (RBinField))) {
				break;
			}
			ptr->name = strdup (field[i].name);
			ptr->comment = NULL;
			ptr->vaddr = field[i].offset;
			ptr->paddr = field[i].offset;
			r_list_append (ret, ptr);
		}
		free (field);

	} else {
		#define ROW(nam,siz,val,fmt) \
			r_list_append (ret, r_bin_field_new (addr, addr, siz, nam, sdb_fmt ("0x%08x", val), fmt));
		if (left < sizeof (Elf_(Ehdr))) {
			return ret;
		}
		ut64 addr = 0;
		ROW ("ELF", 4, r_read_le32 (buf), "x"); addr+=0x10;
		ROW ("Type", 2, r_read_le16 (buf + addr), "x"); addr+=0x2;
		ROW ("Machine", 2, r_read_le16 (buf + addr), "x"); addr+=0x2;
		ROW ("Version", 4, r_read_le32 (buf + addr), "x"); addr+=0x4;

		if (r_read_le8 (buf + 0x04) == 1) {
			ROW ("Entry point", 4, r_read_le32 (buf + addr), "x"); addr+=0x4;
			ROW ("PhOff", 4, r_read_le32 (buf + addr), "x"); addr+=0x4;
			ROW ("ShOff", 4, r_read_le32 (buf + addr), "x");
		} else {
			ROW ("Entry point", 8, r_read_le64 (buf + addr), "x"); addr+=0x8;
			ROW ("PhOff", 8, r_read_le64 (buf + addr), "x"); addr+=0x8;
			ROW ("ShOff", 8, r_read_le64 (buf + addr), "x");
		}
	}

	return ret;
}

static ut64 size(RBinFile *bf) {
	ut64 off = 0;
	ut64 len = 0;
	if (!bf->o->sections) {
		RListIter *iter;
		RBinSection *section;
		bf->o->sections = sections (bf);
		r_list_foreach (bf->o->sections, iter, section) {
			if (section->paddr > off) {
				off = section->paddr;
				len = section->size;
			}
		}
	}
	return off + len;
}
