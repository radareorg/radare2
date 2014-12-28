/* radare - LGPL - Copyright 2009-2014 - nibble, pancake */

#include <stdio.h>
#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>
#include "elf/elf.h"

#define ELFOBJ struct Elf_(r_bin_elf_obj_t)
static int check(RBinFile *arch);
static int check_bytes(const ut8 *buf, ut64 length);

//TODO: implement r_bin_symbol_dup() and r_bin_symbol_free ?
static void setsymord (ELFOBJ* eobj, ut32 ord, RBinSymbol *ptr) {
	if (! eobj->symbols_by_ord || ord >= eobj->symbols_by_ord_size)
		return;
	free (eobj->symbols_by_ord[ord]);
	eobj->symbols_by_ord[ord] = r_mem_dup (ptr, sizeof (RBinSymbol));
}

static void setimpord (ELFOBJ* eobj, ut32 ord, RBinImport *ptr) {
	if (!eobj->imports_by_ord || ord >= eobj->imports_by_ord_size)
		return;
	free (eobj->imports_by_ord[ord]);
	eobj->imports_by_ord[ord] = r_mem_dup (ptr, sizeof (RBinImport));
}

static Sdb* get_sdb (RBinObject *o) {
	struct Elf_(r_bin_elf_obj_t) *bin;
	if (!o) return NULL;
	bin = (struct Elf_(r_bin_elf_obj_t) *) o->bin_obj;
	if (bin && bin->kv) return bin->kv;
	return NULL;
}

static void * load_bytes(const ut8 *buf, ut64 sz, ut64 loadaddr, Sdb *sdb){
	struct Elf_(r_bin_elf_obj_t) *res;
	RBuffer *tbuf;
	if (!buf || sz == 0 || sz == UT64_MAX)
		return NULL;
	tbuf = r_buf_new ();
	r_buf_set_bytes (tbuf, buf, sz);
	res = Elf_(r_bin_elf_new_buf) (tbuf);
	if (res)
		sdb_ns_set (sdb, "info", res->kv);
	r_buf_free (tbuf);
	return res;
}

static int load(RBinFile *arch) {
	const ut8 *bytes = arch ? r_buf_buffer (arch->buf) : NULL;
	ut64 sz = arch ? r_buf_size (arch->buf): 0;
 	if (!arch || !arch->o) return R_FALSE;
	arch->o->bin_obj = load_bytes (bytes, sz, 
		arch->o->loadaddr, arch->sdb);
	if (!(arch->o->bin_obj))
		return R_FALSE;
	return R_TRUE;
}

static int destroy(RBinFile *arch) {
	Elf_(r_bin_elf_free) ((struct Elf_(r_bin_elf_obj_t)*)arch->o->bin_obj);
	return R_TRUE;
}

static ut64 baddr(RBinFile *arch) {
	return Elf_(r_bin_elf_get_baddr) (arch->o->bin_obj);
}

static ut64 boffset(RBinFile *arch) {
	return Elf_(r_bin_elf_get_boffset) (arch->o->bin_obj);
}

static RBinAddr* binsym(RBinFile *arch, int sym) {
	struct Elf_(r_bin_elf_obj_t)* obj = arch->o->bin_obj;
	ut64 addr = 0LL;
	RBinAddr *ret = NULL;
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
	if (addr && (ret = R_NEW0 (RBinAddr))) {
		ret->paddr = addr;
		ret->vaddr = obj->baddr + addr;
	}
	return ret;
}

static RList* entries(RBinFile *arch) {
	RList *ret;
	RBinAddr *ptr = NULL;
	struct Elf_(r_bin_elf_obj_t)* obj = arch->o->bin_obj;

	if (!obj)
		return NULL;

	if (!(ret = r_list_new ()))
		return NULL;

	ret->free = free;
	if (!(ptr = R_NEW0 (RBinAddr)))
		return ret;
	ptr->paddr = Elf_(r_bin_elf_get_entry_offset) (arch->o->bin_obj);
	ptr->vaddr = obj->baddr + ptr->paddr;
	r_list_append (ret, ptr);
	return ret;
}

static RList* sections(RBinFile *arch) {
	RList *ret = NULL;
	RBinSection *ptr = NULL;
	struct r_bin_elf_section_t *section = NULL;
	int i, n, num, found_phdr = 0;
	struct Elf_(r_bin_elf_obj_t)* obj = arch && arch->o ? arch->o->bin_obj : NULL;
	Elf_(Phdr)* phdr = NULL;


	if (!obj || !(ret = r_list_new ()))
		return NULL;
	ret->free = free;
	if ((section = Elf_(r_bin_elf_get_sections) (obj))) {
		for (i = 0; !section[i].last; i++) {
			if (!section[i].size) continue;
			if (!(ptr = R_NEW0 (RBinSection)))
				break;
			strncpy (ptr->name, (char*)section[i].name, R_BIN_SIZEOF_STRINGS);
			ptr->size = section[i].size;
			ptr->vsize = section[i].size;
			ptr->paddr = section[i].offset;
			ptr->vaddr = section[i].rva;

			// HACK if (ptr->vaddr == 0) { ptr->vaddr = section[i].offset; }
			ptr->srwx = 0;
			if (R_BIN_ELF_SCN_IS_EXECUTABLE (section[i].flags))
				ptr->srwx |= R_BIN_SCN_EXECUTABLE;
			if (R_BIN_ELF_SCN_IS_WRITABLE (section[i].flags))
				ptr->srwx |= R_BIN_SCN_WRITABLE;
			if (R_BIN_ELF_SCN_IS_READABLE (section[i].flags))
				ptr->srwx |= R_BIN_SCN_READABLE;
			r_list_append (ret, ptr);
		}
		free (section); // TODO: use r_list_free here
	}

	// program headers is another section
	num = obj->ehdr.e_phnum;
	phdr = obj->phdr;
	for (i=n=0; i<num; i++) {
		if (phdr && phdr[i].p_type == 1) {
			found_phdr = 1;
			ut64 paddr = phdr[i].p_offset;
			ut64 vaddr = phdr[i].p_vaddr;
			int memsz = (int)phdr[i].p_memsz;
			int perms = phdr[i].p_flags;
			ut64 align = phdr[i].p_align;
			if (!align) align = 0x1000;
			memsz = (int)(size_t)R_PTR_ALIGN_NEXT ((size_t)memsz, (int)align);
			//vaddr -= obj->baddr; // yeah
			if (!(ptr = R_NEW0 (RBinSection)))
				return ret;
			sprintf (ptr->name, "phdr%d", n);
			ptr->size = memsz;
			ptr->vsize = memsz;
			ptr->paddr = paddr;
			ptr->vaddr = vaddr;
			ptr->srwx = perms;
			r_list_append (ret, ptr);
			n++;
		}
	}

	if (r_list_empty (ret)) {
		if (!arch->size) {
			struct Elf_(r_bin_elf_obj_t) *bin = arch->o->bin_obj;
			arch->size = bin? bin->size: 0x9999;
		}
		if (found_phdr == 0) {
			if (!(ptr = R_NEW0 (RBinSection)))
				return ret;
			sprintf (ptr->name, "uphdr");
			ptr->size = arch->size;
			ptr->vsize = arch->size;
			ptr->paddr = 0;
			ptr->vaddr = 0x10000;
			ptr->srwx = 7;
			r_list_append (ret, ptr);
		}
	}
	// add entry for ehdr
	ptr = R_NEW0 (RBinSection);
	if (ptr) {
		ut64 ehdr_size = sizeof (obj->ehdr);

		sprintf (ptr->name, "ehdr");
		ptr->paddr = 0;
		ptr->vaddr = obj->baddr;
		ptr->size = ehdr_size;
		ptr->vsize = ehdr_size;
		ptr->srwx = R_BIN_SCN_READABLE | R_BIN_SCN_WRITABLE;
		r_list_append (ret, ptr);
	}

	return ret;
}

static RBinInfo* info(RBinFile *arch);
static RList* symbols(RBinFile *arch) {
	int i;
	struct Elf_(r_bin_elf_obj_t) *bin;
	struct r_bin_elf_symbol_t *symbol = NULL;
	RBinSymbol *ptr = NULL;
	RList *ret = NULL;
	ut64 base = 0;
	if (!arch || !arch->o || !arch->o->bin_obj)
		return NULL;
	bin = arch->o->bin_obj;
	// has_va = Elf_(r_bin_elf_has_va) (bin);
	// if (!has_va) {
	if (arch && arch->o && arch->o->baddr==0LL) {
		// find base address for non-linked object (.o) //
		if (arch->o->sections) {
			RBinSection *s;
			RListIter *iter;
			r_list_foreach (arch->o->sections, iter, s) {
				if (s->srwx & R_BIN_SCN_EXECUTABLE) {
					base = s->paddr;
					break;
				}
			}
		}
	}

	if (!(ret = r_list_new ()))
		return NULL;
	ret->free = free;

	if (!(symbol = Elf_(r_bin_elf_get_symbols) (arch->o->bin_obj, R_BIN_ELF_SYMBOLS)))
		return ret;
	for (i = 0; !symbol[i].last; i++) {
		ut64 vaddr = r_bin_get_vaddr (NULL, //arch->o->bin_obj,
			arch->o->baddr, symbol[i].offset,
			symbol[i].offset+arch->o->baddr);
		ut64 paddr = symbol[i].offset;
		if (vaddr == UT64_MAX) {
			ut64 ba = baddr (arch);
			if (ba) {
				vaddr = paddr + ba;
			} else {
				// no base address, probably an object file
				vaddr = paddr + base;
			}
		}
		if (!(ptr = R_NEW0 (RBinSymbol)))
			break;
		strncpy (ptr->name, symbol[i].name, R_BIN_SIZEOF_STRINGS);
		strncpy (ptr->forwarder, "NONE", R_BIN_SIZEOF_STRINGS);
		strncpy (ptr->bind, symbol[i].bind, R_BIN_SIZEOF_STRINGS);
		strncpy (ptr->type, symbol[i].type, R_BIN_SIZEOF_STRINGS);
		ptr->paddr = paddr;
		ptr->vaddr = vaddr;
		ptr->size = symbol[i].size;
		ptr->ordinal = symbol[i].ordinal;
		setsymord (bin, ptr->ordinal, ptr);
		r_list_append (ret, ptr);
	}
	free (symbol);

	if (!(symbol = Elf_(r_bin_elf_get_symbols) (arch->o->bin_obj, R_BIN_ELF_IMPORTS)))
		return ret;
	for (i = 0; !symbol[i].last; i++) {
		ut64 paddr = symbol[i].offset;
		ut64 vaddr = r_bin_get_vaddr (NULL, baddr (arch), paddr, 
			symbol[i].offset+arch->o->baddr);
		if (vaddr == UT64_MAX) {
			ut64 ba = baddr (arch);
			if (ba) {
				vaddr = paddr + ba;
			} else {
				// no base address, probably an object file
				vaddr = paddr + base;
			}
		}
		if (!symbol[i].size)
			continue;
		if (!(ptr = R_NEW0 (RBinSymbol)))
			break;
		// TODO(eddyb) make a better distinction between imports and other symbols.
		snprintf (ptr->name, R_BIN_SIZEOF_STRINGS-1, "imp.%s", symbol[i].name);
		strncpy (ptr->forwarder, "NONE", R_BIN_SIZEOF_STRINGS);
		strncpy (ptr->bind, symbol[i].bind, R_BIN_SIZEOF_STRINGS);
		strncpy (ptr->type, symbol[i].type, R_BIN_SIZEOF_STRINGS);
		ptr->paddr = paddr;
		ptr->vaddr = vaddr; 
		ptr->size = symbol[i].size;
		ptr->ordinal = symbol[i].ordinal;
		setsymord (bin, ptr->ordinal, ptr);
		r_list_append (ret, ptr);
	}
	free (symbol);

	return ret;
}

static RList* imports(RBinFile *arch) {
	struct Elf_(r_bin_elf_obj_t) *bin = arch->o->bin_obj;
	struct r_bin_elf_symbol_t *import = NULL;
	RBinImport *ptr = NULL;
	RList *ret = NULL;
	int i;

	if (!(ret = r_list_new ()))
		return NULL;
	ret->free = free;
	if (!(import = Elf_(r_bin_elf_get_symbols) (arch->o->bin_obj, R_BIN_ELF_IMPORTS)))
		return ret;
	for (i = 0; !import[i].last; i++) {
		if (!(ptr = R_NEW0 (RBinImport)))
			break;
		strncpy (ptr->name, import[i].name, sizeof(ptr->name)-1);
		strncpy (ptr->bind, import[i].bind, sizeof(ptr->bind)-1);
		strncpy (ptr->type, import[i].type, sizeof(ptr->type)-1);
		ptr->ordinal = import[i].ordinal;
		setimpord (bin, ptr->ordinal, ptr);
		r_list_append (ret, ptr);
	}
	free (import);
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
	//char *str;

	if (!bin || !rel) return NULL;
	B = bin->baddr;
	P = B + rel->rva;
	if (!(r = R_NEW0 (RBinReloc)))
		return r;

	r->import = NULL;
	r->symbol = NULL;
	r->addend = rel->addend;
	if (rel->sym) {
		if (rel->sym < bin->imports_by_ord_size && bin->imports_by_ord[rel->sym])
			r->import = bin->imports_by_ord[rel->sym];
		else if (rel->sym < bin->symbols_by_ord_size && bin->symbols_by_ord[rel->sym])
			r->symbol = bin->symbols_by_ord[rel->sym];
	}
	r->vaddr = rel->rva;
	r->paddr = rel->offset;
	// if object file
	if (bin->ehdr.e_type == ET_REL) {
		ut64 text;
		if ((text = Elf_ (r_bin_elf_get_section_offset) (bin, ".text")) != -1) {
			r->vaddr += text;
		}
	}

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
		default: break; //eprintf("TODO(eddyb): uninmplemented ELF/x86 reloc type %i\n", rel->type);
		}
		break;
	case EM_X86_64: switch (rel->type) {
		case R_X86_64_NONE:	break; // malloc then free. meh. then again, there's no real world use for _NONE.
		case R_X86_64_64:	ADD(64, 0);
		case R_X86_64_PLT32:	ADD(32,-P /* +L */);
		case R_X86_64_GOT32:	ADD(32, GOT);
		case R_X86_64_PC32:	ADD(32,-P);
		case R_X86_64_GLOB_DAT:	SET(64);
		case R_X86_64_JUMP_SLOT:SET(64);
		case R_X86_64_RELATIVE:	ADD(64, B);
		case R_X86_64_32:	ADD(32, 0);
		case R_X86_64_32S:	ADD(32, 0);
		case R_X86_64_16:	ADD(16, 0);
		case R_X86_64_PC16:	ADD(16,-P);
		case R_X86_64_8:	ADD(8,  0);
		case R_X86_64_PC8:	ADD(8, -P);
		case R_X86_64_GOTPCREL:	ADD(64, GOT-P);
		case R_X86_64_COPY:	ADD(64, 0); // XXX: copy symbol at runtime
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
#if 0
		if (!(str = Elf_(r_bin_elf_get_machine_name) (bin)))
			break;
		eprintf("TODO(eddyb): uninmplemented ELF reloc_convert for %s\n", str);
		free(str);
#endif
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
	ut64 got_addr;
	int i;

	if (!(ret = r_list_new ()))
		return NULL;
	ret->free = free;
	/* FIXME: This is a _temporary_ fix/workaround to prevent a use-after-
	 * free detected by ASan that would corrupt the relocation names */
	r_list_free (imports (arch));

#if 1
	if ((got_addr = Elf_ (r_bin_elf_get_section_addr) (arch->o->bin_obj, ".got")) == -1) {
		got_addr = Elf_ (r_bin_elf_get_section_addr) (arch->o->bin_obj, ".got.plt");
		got_addr = 0;
	}

	if (arch->o) {
		if (!(relocs = Elf_(r_bin_elf_get_relocs) (arch->o->bin_obj)))
			return ret;
		for (i = 0; !relocs[i].last; i++) {
			if (!(ptr = reloc_convert (arch->o->bin_obj,
					&relocs[i], got_addr)))
				continue;
			r_list_append (ret, ptr);
		}
		free (relocs);
	}
#endif
	return ret;
}

static int has_canary(RBinFile *arch) {
	RList* imports_list = imports (arch);
	RListIter *iter;
	RBinImport *import;
	r_list_foreach (imports_list, iter, import) {
		if (!strcmp(import->name, "__stack_chk_fail") ) {
			r_list_free (imports_list);
			return 1;
		}
	}
	r_list_free (imports_list);
	return 0;
}

static RBinInfo* info(RBinFile *arch) {
	RBinInfo *ret = NULL;
	char *str;

	if (!(ret = R_NEW0 (RBinInfo)))
		return NULL;
	ret->lang = "c";
	if (arch->file)
		strncpy (ret->file, arch->file, R_BIN_SIZEOF_STRINGS);
	else *ret->file = 0;
	if ((str = Elf_(r_bin_elf_get_rpath)(arch->o->bin_obj))) {
		strncpy (ret->rpath, str, R_BIN_SIZEOF_STRINGS);
		free (str);
	} else strncpy (ret->rpath, "NONE", R_BIN_SIZEOF_STRINGS);
	if (!(str = Elf_(r_bin_elf_get_file_type) (arch->o->bin_obj))) {
		free (ret);
		return NULL;
	}
	strncpy (ret->type, str, R_BIN_SIZEOF_STRINGS);
	ret->has_pi = (strstr (str, "DYN"))? 1: 0;
	ret->has_canary = has_canary (arch);
	free (str);
	if (!(str = Elf_(r_bin_elf_get_elf_class) (arch->o->bin_obj))) {
		free (ret);
		return NULL;
	}
	strncpy (ret->bclass, str, R_BIN_SIZEOF_STRINGS);
	free (str);
	if (!(str = Elf_(r_bin_elf_get_osabi_name) (arch->o->bin_obj))) {
		free (ret);
		return NULL;
	}
	strncpy (ret->os, str, R_BIN_SIZEOF_STRINGS);
	free (str);
	if (!(str = Elf_(r_bin_elf_get_osabi_name) (arch->o->bin_obj))) {
		free (ret);
		return NULL;
	}
	strncpy (ret->subsystem, str, R_BIN_SIZEOF_STRINGS);
	free (str);
	if (!(str = Elf_(r_bin_elf_get_machine_name) (arch->o->bin_obj))) {
		free (ret);
		return NULL;
	}
	strncpy (ret->machine, str, R_BIN_SIZEOF_STRINGS);
	free (str);
	if (!(str = Elf_(r_bin_elf_get_arch) (arch->o->bin_obj))) {
		free (ret);
		return NULL;
	}
	strncpy (ret->arch, str, R_BIN_SIZEOF_STRINGS);
	free (str);
	strncpy (ret->rclass, "elf", R_BIN_SIZEOF_STRINGS);
	ret->bits = Elf_(r_bin_elf_get_bits) (arch->o->bin_obj);
	ret->big_endian = Elf_(r_bin_elf_is_big_endian) (arch->o->bin_obj);
	ret->has_va = Elf_(r_bin_elf_has_va) (arch->o->bin_obj);
	ret->has_nx = Elf_(r_bin_elf_has_nx) (arch->o->bin_obj);
	ret->dbg_info = 0;
	if (!Elf_(r_bin_elf_get_stripped) (arch->o->bin_obj))
		ret->dbg_info |= R_BIN_DBG_LINENUMS | R_BIN_DBG_SYMS | R_BIN_DBG_RELOCS;
	else  ret->dbg_info |= R_BIN_DBG_STRIPPED;
	if (Elf_(r_bin_elf_get_static) (arch->o->bin_obj))
		ret->dbg_info |= R_BIN_DBG_STATIC;
	return ret;
}

static RList* fields(RBinFile *arch) {
	RList *ret = NULL;
	RBinField *ptr = NULL;
	struct r_bin_elf_field_t *field = NULL;
	int i;

	if (!(ret = r_list_new ()))
		return NULL;
	ret->free = free;
	if (!(field = Elf_(r_bin_elf_get_fields) (arch->o->bin_obj)))
		return ret;
	for (i = 0; !field[i].last; i++) {
		if (!(ptr = R_NEW0 (RBinField)))
			break;
		strncpy (ptr->name, field[i].name, R_BIN_SIZEOF_STRINGS);
		ptr->vaddr = field[i].offset;
		ptr->paddr = field[i].offset;
		r_list_append (ret, ptr);
	}
	free (field);
	return ret;
}

static int size(RBinFile *arch) {
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

#if !R_BIN_ELF64

static int check(RBinFile *arch) {
	const ut8 *bytes = arch ? r_buf_buffer (arch->buf) : NULL;
	ut64 sz = arch ? r_buf_size (arch->buf): 0;
	return check_bytes (bytes, sz);

}

static int check_bytes(const ut8 *buf, ut64 length) {
	if (buf && length > 4 &&
		!memcmp (buf, "\x7F\x45\x4c\x46", 4) && buf[4] != 2)
		return R_TRUE;
	return R_FALSE;
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
	if (bin && bin->cur && bin->cur->o && bin->cur->o->info)
		is_arm = !strcmp (bin->cur->o->info->arch, "arm");
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
	if (is_arm)
		H (40); // e_machne = EM_ARM
	else
		H (3); // e_machne = EM_I386

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

	if (data && datalen>0) {
		//ut32 data_section = buf->length;
		eprintf ("Warning: DATA section not support for ELF yet\n");
		B (data, datalen);
	}
	return buf;
}


static ut64 get_elf_vaddr (RBinFile *arch, ut64 ba, ut64 pa, ut64 va) {
	//NOTE(aaSSfxxx): since RVA is vaddr - "official" image base, we just need to add imagebase to vaddr
// WHY? NO NEED TO HAVE PLUGIN SPECIFIC VADDR
	struct Elf_(r_bin_elf_obj_t)* obj = arch->o->bin_obj;
	return obj->baddr - obj->boffset + va - ba;

}

RBinPlugin r_bin_plugin_elf = {
	.name = "elf",
	.desc = "ELF format r_bin plugin",
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
	.boffset = &boffset,
	.binsym = &binsym,
	.entries = &entries,
	.sections = &sections,
	.symbols = &symbols,
	.minstrlen = 4,
	.imports = &imports,
	.strings = NULL,
	.info = &info,
	.fields = &fields,
	.size = &size,
	.libs = &libs,
	.relocs = &relocs,
	.dbginfo = &r_bin_dbginfo_elf,
	.create = &create,
	.write = &r_bin_write_elf,
	.get_vaddr = &get_elf_vaddr,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_elf
};
#endif
#endif
