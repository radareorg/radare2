/* radare - LGPL - Copyright 2009-2013 - nibble, pancake */

#include <stdio.h>
#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>
#include "elf/elf.h"

static int load(RBinArch *arch) {
	if (!(arch->bin_obj = Elf_(r_bin_elf_new_buf) (arch->buf)))
		return R_FALSE;
	return R_TRUE;
}

static int destroy(RBinArch *arch) {
	Elf_(r_bin_elf_free) ((struct Elf_(r_bin_elf_obj_t)*)arch->bin_obj);
	return R_TRUE;
}

static ut64 baddr(RBinArch *arch) {
	return Elf_(r_bin_elf_get_baddr) (arch->bin_obj);
}

static ut64 boffset(RBinArch *arch) {
	return Elf_(r_bin_elf_get_boffset) (arch->bin_obj);
}

static RBinAddr* binsym(RBinArch *arch, int sym) {
	ut64 addr = 0LL;
	RBinAddr *ret = NULL;
	switch (sym) {
	case R_BIN_SYM_ENTRY:
		addr = Elf_(r_bin_elf_get_entry_offset) (arch->bin_obj);
		break;
	case R_BIN_SYM_MAIN:
		addr = Elf_(r_bin_elf_get_main_offset) (arch->bin_obj);
		break;
	case R_BIN_SYM_INIT:
		addr = Elf_(r_bin_elf_get_init_offset) (arch->bin_obj);
		break;
	case R_BIN_SYM_FINI:
		addr = Elf_(r_bin_elf_get_fini_offset) (arch->bin_obj);
		break;
	}
	if (addr && (ret = R_NEW0 (RBinAddr)))
		ret->offset = ret->rva = addr;
	return ret;
}

static RList* entries(RBinArch *arch) {
	RList *ret;
	RBinAddr *ptr = NULL;

	if (!(ret = r_list_new ()))
		return NULL;
	ret->free = free;
	if (!(ptr = R_NEW (RBinAddr)))
		return ret;
	memset (ptr, '\0', sizeof (RBinAddr));
	ptr->offset = ptr->rva = Elf_(r_bin_elf_get_entry_offset) (arch->bin_obj);
	r_list_append (ret, ptr);
	return ret;
}

static RList* sections(RBinArch *arch) {
	RList *ret = NULL;
	RBinSection *ptr = NULL;
	struct r_bin_elf_section_t *section = NULL;
	int i;

	if (!(ret = r_list_new ()))
		return NULL;
	ret->free = free;
	if ((section = Elf_(r_bin_elf_get_sections) (arch->bin_obj))) {
		for (i = 0; !section[i].last; i++) {
			if (!section[i].size) continue;
			if (!(ptr = R_NEW0 (RBinSection)))
				break;
			strncpy (ptr->name, (char*)section[i].name, R_BIN_SIZEOF_STRINGS);
			ptr->size = section[i].size;
			ptr->vsize = section[i].size;
			ptr->offset = section[i].offset;
			ptr->rva = section[i].rva;
			// HACK
			if (ptr->rva == 0) ptr->rva = section[i].offset;
			ptr->srwx = 0;
			if (R_BIN_ELF_SCN_IS_EXECUTABLE (section[i].flags))
				ptr->srwx |= 1;
			if (R_BIN_ELF_SCN_IS_WRITABLE (section[i].flags))
				ptr->srwx |= 2;
			if (R_BIN_ELF_SCN_IS_READABLE (section[i].flags))
				ptr->srwx |= 4;
			r_list_append (ret, ptr);
		}
		free (section); // TODO: use r_list_free here
	}

	// program headers is another section
	if (r_list_empty (ret)) {
		int found = 0;
#define USE_PHDR 1
#if USE_PHDR
		struct Elf_(r_bin_elf_obj_t)* obj = arch->bin_obj;
		int i, n, num = obj->ehdr.e_phnum;
		Elf_(Phdr)* phdr = obj->phdr;
		for (i=n=0; i<num; i++) {
			if (phdr && phdr[i].p_type == 1) {
				found = 1;
				ut64 paddr = phdr[i].p_offset;
				ut64 vaddr = phdr[i].p_vaddr;
				int memsz = (int)phdr[i].p_memsz;
				int perms = phdr[i].p_flags;
				ut64 align = phdr[i].p_align;
				if (!align) align = 0x1000;
				memsz = (int)(size_t)R_PTR_ALIGN_NEXT ((size_t)memsz, align);
				vaddr -= obj->baddr; // yeah
				if (!(ptr = R_NEW0 (RBinSection)))
					return ret;
				sprintf (ptr->name, "phdr%d", n);
				ptr->size = memsz;
				ptr->vsize = memsz;
				ptr->offset = paddr;
				ptr->rva = vaddr;
				ptr->srwx = perms;
				r_list_append (ret, ptr);
				n++;
			}
		}
#endif
		if (!arch->size) {
			struct Elf_(r_bin_elf_obj_t) *bin = arch->bin_obj;
			arch->size = bin? bin->size: 0x9999;
		}
		if (found == 0) {
			if (!(ptr = R_NEW0 (RBinSection)))
				return ret;
			sprintf (ptr->name, "undefined");
			ptr->size = arch->size;
			ptr->vsize = arch->size;
			ptr->offset = 0;
			ptr->rva = 0;
			ptr->srwx = 7;
			r_list_append (ret, ptr);
		} 
	}
	return ret;
}

static RList* symbols(RBinArch *arch) {
	RList *ret = NULL;
	RBinSymbol *ptr = NULL;
	ut64 base = 0;
	struct r_bin_elf_symbol_t *symbol = NULL;
	struct Elf_(r_bin_elf_obj_t) *bin = arch->bin_obj;
	int i;

	int has_va = Elf_(r_bin_elf_has_va) (arch->bin_obj);
	if (!has_va) {
		// find base address for non-linked object (.o) //
		if (arch->o->sections) {
			RBinSection *s;
			RListIter *iter;
			r_list_foreach (arch->o->sections, iter, s) {
				if (s->srwx & 1) {
					base = s->offset;
					break;
				}
			}
		}
	}

	if (!(ret = r_list_new ()))
		return NULL;
	ret->free = free;

	if (!(symbol = Elf_(r_bin_elf_get_symbols) (arch->bin_obj, R_BIN_ELF_SYMBOLS)))
		return ret;
	for (i = 0; !symbol[i].last; i++) {
		if (!(ptr = R_NEW (RBinSymbol)))
			break;
		strncpy (ptr->name, symbol[i].name, R_BIN_SIZEOF_STRINGS);
		strncpy (ptr->forwarder, "NONE", R_BIN_SIZEOF_STRINGS);
		strncpy (ptr->bind, symbol[i].bind, R_BIN_SIZEOF_STRINGS);
		strncpy (ptr->type, symbol[i].type, R_BIN_SIZEOF_STRINGS);
		ptr->rva = symbol[i].offset + base;
		ptr->offset = symbol[i].offset + base;
		ptr->size = symbol[i].size;
		ptr->ordinal = symbol[i].ordinal;
		if(bin->symbols_by_ord && ptr->ordinal < bin->symbols_by_ord_size)
			bin->symbols_by_ord[ptr->ordinal] = ptr;
		r_list_append (ret, ptr);
	}
	free (symbol);

	if (!(symbol = Elf_(r_bin_elf_get_symbols) (arch->bin_obj, R_BIN_ELF_IMPORTS)))
		return ret;
	for (i = 0; !symbol[i].last; i++) {
		if (!symbol[i].size)
			continue;
		if (!(ptr = R_NEW (RBinSymbol)))
			break;
		// TODO(eddyb) make a better distinction between imports and other symbols.
		snprintf (ptr->name, R_BIN_SIZEOF_STRINGS, "imp.%s", symbol[i].name);
		strncpy (ptr->forwarder, "NONE", R_BIN_SIZEOF_STRINGS);
		strncpy (ptr->bind, symbol[i].bind, R_BIN_SIZEOF_STRINGS);
		strncpy (ptr->type, symbol[i].type, R_BIN_SIZEOF_STRINGS);
		ptr->rva = symbol[i].offset;
		ptr->offset = symbol[i].offset;
		ptr->size = symbol[i].size;
		ptr->ordinal = symbol[i].ordinal;
		if(bin->symbols_by_ord && ptr->ordinal < bin->symbols_by_ord_size)
			bin->symbols_by_ord[ptr->ordinal] = ptr;
		r_list_append (ret, ptr);
	}
	free (symbol);

	return ret;
}

static RList* imports(RBinArch *arch) {
	RList *ret = NULL;
	RBinImport *ptr = NULL;
	struct r_bin_elf_symbol_t *import = NULL;
	struct Elf_(r_bin_elf_obj_t) *bin = arch->bin_obj;
	int i;

	if (!(ret = r_list_new ()))
		return NULL;
	ret->free = free;
	if (!(import = Elf_(r_bin_elf_get_symbols) (arch->bin_obj, R_BIN_ELF_IMPORTS)))
		return ret;
	for (i = 0; !import[i].last; i++) {
		if (!(ptr = R_NEW (RBinImport)))
			break;
		strncpy (ptr->name, import[i].name, R_BIN_SIZEOF_STRINGS);
		strncpy (ptr->bind, import[i].bind, R_BIN_SIZEOF_STRINGS);
		strncpy (ptr->type, import[i].type, R_BIN_SIZEOF_STRINGS);
		ptr->ordinal = import[i].ordinal;
		if(bin->imports_by_ord && ptr->ordinal < bin->imports_by_ord_size)
			bin->imports_by_ord[ptr->ordinal] = ptr;
		r_list_append (ret, ptr);
	}
	free (import);
	return ret;
}

static RList* libs(RBinArch *arch) {
	RList *ret = NULL;
	char *ptr = NULL;
	struct r_bin_elf_lib_t *libs = NULL;
	int i;

	if (!(ret = r_list_new ()))
		return NULL;
	ret->free = free;
	if (!(libs = Elf_(r_bin_elf_get_libs) (arch->bin_obj)))
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
	ut64 B = bin->baddr, P = B + rel->rva;
	char *str;

	if (!(r = R_NEW (RBinReloc)))
		return r;

	r->import = NULL;
	r->addend = rel->addend;
	if (rel->sym) {
		if (rel->sym < bin->imports_by_ord_size && bin->imports_by_ord[rel->sym])
			r->import = bin->imports_by_ord[rel->sym];
		else if (rel->sym < bin->symbols_by_ord_size && bin->symbols_by_ord[rel->sym])
			r->addend += B + bin->symbols_by_ord[rel->sym]->rva;
	}
	r->rva = rel->rva;
	r->offset = rel->offset;

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
		default: eprintf("TODO(eddyb): uninmplemented ELF/x86 reloc type %i\n", rel->type);
		}
		break;
	case EM_X86_64: switch (rel->type) {
		case R_X86_64_NONE:		break; // malloc then free. meh. then again, there's no real world use for _NONE.
		case R_X86_64_64:		ADD(64, 0);
		case R_X86_64_PC32:		ADD(32,-P);
		case R_X86_64_GLOB_DAT:	SET(64);
		case R_X86_64_JUMP_SLOT:SET(64);
		case R_X86_64_RELATIVE:	ADD(64, B);
		case R_X86_64_32:		ADD(32, 0);
		case R_X86_64_32S:		ADD(32, 0);
		case R_X86_64_16:		ADD(16, 0);
		case R_X86_64_PC16:		ADD(16,-P);
		case R_X86_64_8:		ADD(8,  0);
		case R_X86_64_PC8:		ADD(8, -P);
		default: eprintf("TODO(eddyb): uninmplemented ELF/x64 reloc type %i\n", rel->type);
		}
		break;
	case EM_ARM: switch (rel->type) {
		case R_ARM_NONE:		break; // malloc then free. meh. then again, there's no real world use for _NONE.
		case R_ARM_ABS32:		ADD(32, 0);
		case R_ARM_REL32:		ADD(32,-P);
		case R_ARM_ABS16:		ADD(16, 0);
		case R_ARM_ABS8:		ADD(8,  0);
		case R_ARM_SBREL32:		ADD(32, -B);
		case R_ARM_GLOB_DAT:	ADD(32, 0);
		case R_ARM_JUMP_SLOT:	ADD(32, 0);
		case R_ARM_RELATIVE:	ADD(32, B);
		case R_ARM_GOTOFF:		ADD(32,-GOT);
		default: eprintf("TODO(eddyb): uninmplemented ELF/ARM reloc type %i\n", rel->type);
		}
		break;
	default:
		if (!(str = Elf_(r_bin_elf_get_machine_name) (bin)))
			break;
		eprintf("TODO(eddyb): uninmplemented ELF reloc_convert for %s\n", str);
		free(str);
	}

	#undef SET
	#undef ADD

	free(r);
	return 0;
}

static RList* relocs(RBinArch *arch) {
	RList *ret = NULL;
	RBinReloc *ptr = NULL;
	RBinElfReloc *relocs = NULL;
	ut64 got_addr;
	int i;

	if (!(ret = r_list_new ()))
		return NULL;
	ret->free = free;
	if ((got_addr = Elf_ (r_bin_elf_get_section_addr) (arch->bin_obj, ".got")) == -1 &&
		(got_addr = Elf_ (r_bin_elf_get_section_addr) (arch->bin_obj, ".got.plt")) == -1)
		return ret;
	if (!(relocs = Elf_(r_bin_elf_get_relocs) (arch->bin_obj)))
		return ret;
	for (i = 0; !relocs[i].last; i++) {
		if (!(ptr = reloc_convert(arch->bin_obj, &relocs[i], got_addr)))
			break;
		r_list_append (ret, ptr);
	}
	free (relocs);
	return ret;
}

static RBinInfo* info(RBinArch *arch) {
	RBinInfo *ret = NULL;
	char *str;

	if(!(ret = R_NEW0 (RBinInfo)))
		return NULL;
	ret->lang = "c";
	strncpy (ret->file, arch->file, R_BIN_SIZEOF_STRINGS);
	if ((str = Elf_(r_bin_elf_get_rpath)(arch->bin_obj))) {
		strncpy (ret->rpath, str, R_BIN_SIZEOF_STRINGS);
		free (str);
	} else strncpy (ret->rpath, "NONE", R_BIN_SIZEOF_STRINGS);
	if (!(str = Elf_(r_bin_elf_get_file_type) (arch->bin_obj)))
		return NULL;
	strncpy (ret->type, str, R_BIN_SIZEOF_STRINGS);
	ret->has_pi = (strstr (str, "DYN"))? 1: 0;
	free (str);
	if (!(str = Elf_(r_bin_elf_get_elf_class) (arch->bin_obj)))
		return NULL;
	strncpy (ret->bclass, str, R_BIN_SIZEOF_STRINGS);
	free (str);
	if (!(str = Elf_(r_bin_elf_get_osabi_name) (arch->bin_obj)))
		return NULL;
	strncpy (ret->os, str, R_BIN_SIZEOF_STRINGS);
	free (str);
	if (!(str = Elf_(r_bin_elf_get_osabi_name) (arch->bin_obj)))
		return NULL;
	strncpy (ret->subsystem, str, R_BIN_SIZEOF_STRINGS);
	free (str);
	if (!(str = Elf_(r_bin_elf_get_machine_name) (arch->bin_obj)))
		return NULL;
	strncpy (ret->machine, str, R_BIN_SIZEOF_STRINGS);
	free (str);
	if (!(str = Elf_(r_bin_elf_get_arch) (arch->bin_obj)))
		return NULL;
	strncpy (ret->arch, str, R_BIN_SIZEOF_STRINGS);
	free (str);
	strncpy (ret->rclass, "elf", R_BIN_SIZEOF_STRINGS);
	ret->bits = Elf_(r_bin_elf_get_bits) (arch->bin_obj);
	ret->big_endian = Elf_(r_bin_elf_is_big_endian) (arch->bin_obj);
	ret->has_va = Elf_(r_bin_elf_has_va) (arch->bin_obj);
	ret->dbg_info = 0;
	if (!Elf_(r_bin_elf_get_stripped) (arch->bin_obj))
		ret->dbg_info |= 0x04 | 0x08 | 0x10;
	else  ret->dbg_info |= 0x01;
	if (Elf_(r_bin_elf_get_static) (arch->bin_obj))
		ret->dbg_info |= 0x02;
	return ret;
}

static RList* fields(RBinArch *arch) {
	RList *ret = NULL;
	RBinField *ptr = NULL;
	struct r_bin_elf_field_t *field = NULL;
	int i;
	
	if (!(ret = r_list_new ()))
		return NULL;
	ret->free = free;
	if (!(field = Elf_(r_bin_elf_get_fields) (arch->bin_obj)))
		return ret;
	for (i = 0; !field[i].last; i++) {
		if (!(ptr = R_NEW (RBinField)))
			break;
		strncpy (ptr->name, field[i].name, R_BIN_SIZEOF_STRINGS);
		ptr->rva = field[i].offset;
		ptr->offset = field[i].offset;
		r_list_append (ret, ptr);
	}
	free (field);
	return ret;
}

#if !R_BIN_ELF64
static int check(RBinArch *arch) {
	if (arch && arch->buf && arch->buf->buf)
	//if (!memcmp (arch->buf->buf, "\x7F\x45\x4c\x46\x01", 5))
	if (!memcmp (arch->buf->buf, "\x7F\x45\x4c\x46", 4) && arch->buf->buf[4] != 2)
		return R_TRUE;
	return R_FALSE;
}

extern struct r_bin_meta_t r_bin_meta_elf;
extern struct r_bin_write_t r_bin_write_elf;

static RBuffer* create(RBin* bin, const ut8 *code, int codelen, const ut8 *data, int datalen) {
	ut32 filesize, code_va, code_pa, phoff;
	ut32 p_start, p_phoff, p_phdr;
	ut32 p_ehdrsz, p_phdrsz;
	ut16 ehdrsz, phdrsz;
	ut32 p_vaddr, p_paddr, p_fs, p_fs2;
	ut32 baddr;
	int is_arm = !strcmp (bin->cur.o->info->arch, "arm");
	RBuffer *buf = r_buf_new ();
	// XXX: hardcoded
	if (is_arm) baddr = 0x40000;
	else baddr = 0x8048000;

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

static int size(RBinArch *arch) {
	ut64 off = 0;
	ut64 len = 0;
	if (!arch->o->sections) {
		RListIter *iter;
		RBinSection *section;
		arch->o->sections = sections (arch);
		r_list_foreach (arch->o->sections, iter, section) {
			if (section->offset > off) {
				off = section->offset;
				len = section->size;
			}
		}
	}
	return off+len;
}

static ut64 get_elf_vaddr (RBinArch *arch, ut64 baddr, ut64 paddr, ut64 vaddr) {
	//NOTE(aaSSfxxx): since RVA is vaddr - "official" image base, we just need to add imagebase to vaddr
	struct Elf_(r_bin_elf_obj_t)* obj = arch->bin_obj;
	return obj->baddr - obj->boffset + vaddr;

}

RBinPlugin r_bin_plugin_elf = {
	.name = "elf",
	.desc = "ELF format r_bin plugin",
	.license = "LGPL3",
	.init = NULL,
	.fini = NULL,
	.load = &load,
	.destroy = &destroy,
	.check = &check,
	.baddr = &baddr,
	.boffset = &boffset,
	.binsym = &binsym,
	.entries = &entries,
	.sections = &sections,
	.symbols = &symbols,
	.imports = &imports,
	.strings = NULL,
	.info = &info,
	.fields = &fields,
	.size = &size,
	.libs = &libs,
	.relocs = &relocs,
	.meta = &r_bin_meta_elf,
	.create = &create,
	.write = &r_bin_write_elf,
	.get_vaddr = &get_elf_vaddr
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_elf
};
#endif
#endif
