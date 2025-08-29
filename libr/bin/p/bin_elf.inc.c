/* radare - LGPL - Copyright 2009-2025 - nibble, pancake, luctielen */

#define R_LOG_ORIGIN "bin.elf"

#include <r_lib.h>
#include <r_bin.h>
#include "../i/private.h"
#include "elf/elf.h"
#include <sdb/ht_uu.h>

static RBinInfo* info(RBinFile *bf);

static RList *maps(RBinFile *bf) {
	R_RETURN_VAL_IF_FAIL (bf && bf->bo, NULL);
	return Elf_(get_maps)(bf->bo->bin_obj);
}

static char* regstate(RBinFile *bf) {
	ELFOBJ *eo = bf->bo->bin_obj;
	switch (eo->ehdr.e_machine) {
	case EM_ARM:
	case EM_AARCH64:
	case EM_386:
	case EM_X86_64:
		{
			int len = 0;
			ut8 *regs = Elf_(grab_regstate) (eo, &len);
			char *hexregs = (regs && len > 0) ? r_hex_bin2strdup (regs, len) : NULL;
			free (regs);
			return hexregs;
		}
	}
	R_LOG_ERROR ("Cannot retrieve regstate on unsupported arch %s", Elf_(get_machine_name)(eo));
	return NULL;
}

static void setimpord(ELFOBJ* eo, ut32 ord, RBinImport *ptr) {
	if (!eo->imports_by_ord || ord >= eo->imports_by_ord_size) {
		return;
	}
	// leak or uaf wtf
	// r_bin_import_free (eo->imports_by_ord[ord]);
	eo->imports_by_ord[ord] = r_bin_import_clone (ptr);
}

static Sdb* get_sdb(RBinFile *bf) {
	ELFOBJ *eo = R_UNWRAP3 (bf, bo, bin_obj);
	return eo? eo->kv: NULL;
}

static bool load(RBinFile *bf, RBuffer *buf, ut64 loadaddr) {
	ut64 user_baddr = bf->user_baddr;
	ELFOBJ *res = Elf_(new_buf) (buf, user_baddr, bf->rbin->options.verbose);
	if (res) {
	//	sdb_ns_set (sdb, "info", res->kv);
		res->limit = bf->rbin->options.limit;
		bf->bo->bin_obj = res;
		return true;
	}
	return false;
}

static void destroy(RBinFile *bf) {
	Elf_(free) ((ELFOBJ*)bf->bo->bin_obj);
}

static ut64 baddr(RBinFile *bf) {
	return Elf_(get_baddr) (bf->bo->bin_obj);
}

static RBinAddr* binsym(RBinFile *bf, int sym) {
	ELFOBJ* eo = bf->bo->bin_obj;
	RBinAddr *ret = NULL;
	ut64 addr = 0LL; // must be ut64_max

	switch (sym) {
	case R_BIN_SYM_ENTRY:
		addr = Elf_(get_entry_offset) (eo);
		break;
	case R_BIN_SYM_MAIN:
		addr = Elf_(get_main_offset) (eo);
		break;
	case R_BIN_SYM_INIT:
		addr = Elf_(get_init_offset) (eo);
		break;
	case R_BIN_SYM_FINI:
		addr = Elf_(get_fini_offset) (eo);
		break;
	}
	if (addr && addr != UT64_MAX && (ret = R_NEW0 (RBinAddr))) {
		bool is_arm = eo->ehdr.e_machine == EM_ARM;
		ret->paddr = addr;
		ret->vaddr = Elf_(p2v) (eo, addr);
		if (is_arm) {
			if (addr & 1) {
				ret->bits = 16;
				ret->vaddr--;
				ret->paddr--;
			}
		}
	}
	return ret;
}

#if R2_590
static bool sections_vec(RBinFile *bf) {
	R_RETURN_VAL_IF_FAIL (bf && bf->bo, false);
	ELFOBJ *eo = bf->bo->bin_obj
	return eo? Elf_(load_sections) (bf, eo) != NULL: false;
}
#else

// DEPRECATE: we must use sections_vec instead
static RList* sections(RBinFile *bf) {
	ELFOBJ *eo = (bf && bf->bo)? bf->bo->bin_obj : NULL;
	if (!eo) {
		return NULL;
	}

	// there is no leak here with sections since they are cached by elf.c
	// and freed within Elf_(free) R2_590. must return bool
	const RVector *sections = Elf_(load_sections) (bf, eo);
	if (!sections) {
		return NULL;
	}

	RList *ret = r_list_newf ((RListFree)r_bin_section_free);
	if (ret) {
		RBinSection *section;
		r_vector_foreach (sections, section) {
			r_list_append (ret, r_bin_section_clone (section));
		}
	}

	return ret;
}
#endif

static RBinAddr* newEntry(RBinFile *bf, ut64 hpaddr, ut64 hvaddr, ut64 vaddr, int type, int bits) {
	R_RETURN_VAL_IF_FAIL (bf && bf->bo && bf->bo->bin_obj, NULL);

	RBinAddr *ptr = R_NEW0 (RBinAddr);
	ELFOBJ *eo = bf->bo->bin_obj;
	ptr->paddr = Elf_(v2p) (eo, vaddr);
	ptr->vaddr = vaddr;
	ptr->hpaddr = hpaddr;
	ptr->hvaddr = hvaddr;
	ptr->bits = bits;
	ptr->type = type;
	// realign due to thumb
	if (bits == 16 && ptr->vaddr & 1) {
		ptr->paddr--;
		ptr->vaddr--;
	}
	return ptr;
}

static void process_constructors(RBinFile *bf, RList *ret, int bits) {
#if R2_590
	if (!sections_vec (bf)) {
		return;
	}
	RVecRBinSection *secs = &(bf->bo->sections_vec);
	RBinSection *sec;
	R_VEC_FOREACH (secs, sec) {
#else
	RList *secs = sections (bf);
	RListIter *iter;
	RBinSection *sec;
	r_list_foreach (secs, iter, sec) {
#endif
		if (sec->size > ALLOC_SIZE_LIMIT) {
			continue;
		}

		const char *sec_name = sec->name;
		int type = -1;
		if (*sec_name == '.') {
			if (!strcmp (sec_name, ".fini_array")) {
				type = R_BIN_ENTRY_TYPE_FINI;
			} else if (!strcmp (sec_name, ".init_array")) {
				type = R_BIN_ENTRY_TYPE_INIT;
			} else if (!strcmp (sec_name, ".preinit_array")) {
				type = R_BIN_ENTRY_TYPE_PREINIT;
			}
		}
		if (type == -1) {
			continue;
		}
		ut8 *buf = calloc (sec->size, 1);
		if (!buf) {
			continue;
		}

		st64 size = r_buf_read_at(bf->buf, sec->paddr, buf, sec->size);
		if (size != sec->size) {
			if (size < sec->size) {
				R_LOG_WARN ("unexpected section size");
			}
			buf = realloc (buf, size);
			if (!buf) {
				continue;
			}
			sec->size = size;
		}
// XXX R2_590 this can be done once with proper compile time ifdef
		if (bits == 32) {
			int i;
			for (i = 0; (i + 3) < sec->size; i += 4) {
				ut32 addr32 = r_read_le32 (buf + i);
				if (addr32) {
					RBinAddr *ba = newEntry (bf, sec->paddr + i, sec->vaddr + i,
					                         (ut64)addr32, type, bits);
					r_list_append (ret, ba);
				}
			}
		} else {
			int i;
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
	r_list_free (secs);
}

static RList* entries(RBinFile *bf) {
	R_RETURN_VAL_IF_FAIL (bf && bf->bo && bf->bo->bin_obj, NULL);

	RList *ret = r_list_newf ((RListFree)free);
	if (!ret) {
		return NULL;
	}

	ELFOBJ* eo = bf->bo->bin_obj;
	ut64 paddr = Elf_(get_entry_offset) (eo);
	if (paddr != UT64_MAX) {
		RBinAddr *ptr = R_NEW0 (RBinAddr);
		if (!ptr) {
			return ret;
		}

		ptr->paddr = paddr;
		ptr->vaddr = Elf_(p2v) (eo, ptr->paddr);
		ptr->hpaddr = 0x18;  // e_entry offset in ELF header
		ptr->hvaddr = UT64_MAX; // 0x18 + baddr (bf);

		if (ptr->vaddr != (ut64)eo->ehdr.e_entry && Elf_(is_executable) (eo) && !Elf_(is_sbpf_binary) (eo)) {
			R_LOG_ERROR ("Cannot determine entrypoint, using 0x%08" PFMT64x, ptr->vaddr);
		}

		if (bf->bo->sections) {
			// XXX store / cache sections by name in hashmap
			const RVector *sections = Elf_(load_sections) (bf, bf->bo->bin_obj);
			RBinSection *section;
			r_vector_foreach_prev (sections, section) {
				if (!strcmp (section->name, "ehdr")) {
					ptr->hvaddr = section->vaddr + ptr->hpaddr;
					break;
				}
			}
		}
		if (ptr->hvaddr == UT64_MAX) {
			ptr->hvaddr = Elf_(p2v_new) (eo, ptr->hpaddr);
		}

		if (eo->ehdr.e_machine == EM_ARM) {
			int bin_bits = Elf_(get_bits) (eo);
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
	}

	// add entrypoint for jni libraries
	// NOTE: this is slow, we shouldnt find for java constructors here
	if (!Elf_(load_symbols) (eo)) {
		return ret;
	}

	RBinElfSymbol *symbol;
	RVecRBinElfSymbol *symbols = eo->g_symbols_vec;
	if (!symbols) {
		return ret;
	}
	R_VEC_FOREACH (symbols, symbol) {
		// why?
		if (!r_str_startswith (symbol->name, "Java")) {
			continue;
		}
		if (!r_str_endswith (symbol->name, "_init")) {
			continue;
		}
		RBinAddr *ptr = R_NEW0 (RBinAddr);
		if (ptr) {
			ptr->paddr = symbol->offset;
			ptr->vaddr = Elf_(p2v) (eo, ptr->paddr);
			ptr->hpaddr = UT64_MAX;
			ptr->type = R_BIN_ENTRY_TYPE_INIT;
			r_list_append (ret, ptr);
		}
		break;
	}

	const int bin_bits = Elf_(get_bits) (eo);
	process_constructors (bf, ret, bin_bits < 32 ? 32: bin_bits);
	RListIter *iter, *iter2;
	RBinAddr *foo, *bar;
	r_list_foreach (eo->inits, iter, foo) {
		bool is_new_symbol = true;
		// avoid dupes
		r_list_foreach (ret, iter2, bar) {
			if (foo->type == bar->type && foo->paddr == bar->paddr) {
				is_new_symbol = false;
				break;
			}
		}
		if (is_new_symbol) {
			r_list_append (ret, r_mem_dup (foo, sizeof (RBinAddr)));
		}
	}
	return ret;
}

// fill bf->bo->symbols_vec (RBinSymbol) with the processed contents of eo->g_symbols_vec (RBinElfSymbol)
// thats kind of dup because rbinelfsymbol shouldnt exist, rbinsymbol should be enough, rvec makes this easily typed
static bool symbols_vec(RBinFile *bf) {
	R_RETURN_VAL_IF_FAIL (bf && bf->bo && bf->bo->bin_obj, false);

	ELFOBJ *eo = bf->bo->bin_obj;
	// traverse symbols
	if (!Elf_(load_symbols) (eo)) {
		return false;
	}
	if (!RVecRBinSymbol_empty (&bf->bo->symbols_vec)) {
		return true;
	}
	RVecRBinSymbol *list = &bf->bo->symbols_vec;
#if 1
	RVecRBinElfSymbol *elf_symbols = eo->g_symbols_vec;
	RBinElfSymbol *symbol;
	R_VEC_FOREACH (elf_symbols, symbol) {
		if (symbol->is_sht_null) {
			// add it to the list of symbols only if it doesn't point to SHT_NULL
			continue;
		}
		RBinSymbol *ptr = Elf_(convert_symbol) (eo, symbol);
		if (!ptr) {
			break;
		}
		RVecRBinSymbol_push_back (list, ptr);
	}

	// traverse imports
	if (!Elf_(load_imports) (eo)) {
		return false;
	}
	R_VEC_FOREACH (eo->g_imports_vec, symbol) {
		if (!symbol->size) {
			continue;
		}
		if (symbol->is_sht_null) {
			// add it to the list of symbols only if it doesn't point to SHT_NULL
			continue;
		}

		RBinSymbol *ptr = Elf_(convert_symbol) (eo, symbol);
		if (!ptr) {
			break;
		}
		ptr->is_imported = true;
		// object files have no plt section, imports are referenced by relocs not trampolines
		if (ptr->paddr == 0) {
			ptr->paddr = UT64_MAX;
			ptr->vaddr = UT64_MAX;
		}
		// special case where there is no entry in the plt for the import
		if (ptr->vaddr == UT32_MAX) {
			ptr->paddr = 0;
			ptr->vaddr = 0;
		}
		RVecRBinSymbol_push_back (list, ptr);
	}
	return true;
#endif
}

static RList* imports(RBinFile *bf) {
	R_RETURN_VAL_IF_FAIL (bf && bf->bo, NULL);

	RList *ret = r_list_newf ((RListFree)r_bin_import_free);
	if (!ret) {
		return NULL;
	}

	ELFOBJ *eo = bf->bo->bin_obj;
	if (!Elf_(load_imports) (eo)) {
		r_list_free (ret);
		return NULL;
	}
	const RVecRBinElfSymbol *imports = eo->g_imports_vec;

	RBinElfSymbol *is;
	R_VEC_FOREACH (imports, is) {
		RBinImport *ptr = R_NEW0 (RBinImport);
		if (!ptr) {
			break;
		}
		ptr->name = r_bin_name_new (is->name);
		ptr->bind = is->bind;
		ptr->type = is->type;
		ptr->ordinal = is->ordinal;
		setimpord (eo, ptr->ordinal, ptr);
		r_list_append (ret, ptr);
	}
	return ret;
}

static RList* libs(RBinFile *bf) {
	R_RETURN_VAL_IF_FAIL (bf && bf->bo && bf->bo->bin_obj, NULL);

	RList *ret = r_list_newf (free);
	if (!ret) {
		return NULL;
	}

	// No leak, libs is automatically freed when r_bin_elf_free is called
	const RVector *libs = Elf_(load_libs) (bf->bo->bin_obj);
	if (libs) {
		RBinElfLib *lib;
		r_vector_foreach (libs, lib) {
			r_list_append (ret, strdup (lib->name));
		}
	}
	return ret;
}

static RBinReloc *reloc_convert(ELFOBJ* eo, RBinElfReloc *rel, ut64 got_addr) {
	R_RETURN_VAL_IF_FAIL (eo && rel, NULL);
	ut64 B = eo->baddr;
	ut64 P = rel->rva; // rva has taken baddr into account
	RBinReloc *r = R_NEW0 (RBinReloc);
	r->import = NULL;
	r->ntype = rel->type;
	r->symbol = NULL;
	r->is_ifunc = false;
	r->addend = rel->addend;
	// Special handling for CREL relocations
	if (rel->mode == DT_CREL) {
		// No special handling needed for symbol lookup, it works the same way
		// Set appropriate relocation type based on architecture
		if (eo->ehdr.e_machine == EM_X86_64 || eo->ehdr.e_machine == EM_AARCH64) {
			r->type = R_BIN_RELOC_64;
		} else if (eo->ehdr.e_machine == EM_386 || eo->ehdr.e_machine == EM_ARM) {
			r->type = R_BIN_RELOC_32;
		} else {
			r->type = R_BIN_RELOC_64; // Default to 64-bit relocation type
		}
		r->additive = true;       // CREL relocations are typically additive
		// Ensure valid vaddr and paddr
		if (!r->vaddr) {
			r->vaddr = rel->rva;
		}
		if (!r->paddr) {
			r->paddr = rel->offset;
		}
	}
	if (rel->sym) {
		if (rel->sym < eo->imports_by_ord_size && eo->imports_by_ord[rel->sym]) {
			r->import = eo->imports_by_ord[rel->sym];
		} else if (rel->sym < eo->symbols_by_ord_size && eo->symbols_by_ord[rel->sym]) {
			r->symbol = eo->symbols_by_ord[rel->sym];
		}
	}
	r->vaddr = rel->rva;
	r->paddr = rel->offset;
	r->laddr = rel->laddr;

	ut64 sym_vaddr = 0;
	if (r->symbol) {
		sym_vaddr = r->symbol->vaddr;
	} else if (rel->sym) { // r->import) {
		sym_vaddr = rel->rva;
	}

	#define SET(T) r->type = R_BIN_RELOC_ ## T; r->additive = 0; return r
	#define ADD(T, A) r->type = R_BIN_RELOC_ ## T; if (!ST32_ADD_OVFCHK (r->addend, A)) { r->addend += A; } r->additive = rel->mode == DT_RELA || rel->mode == DT_CREL; return r

	// Early return if it's a CREL relocation - it was already set up in the initialization above
	if (rel->mode == DT_CREL) {
		// If there's a symbol, use it to determine appropriate type
		if (r->symbol || r->import) {
			// Make sure the relocation has a valid vaddr and paddr before returning
			if (!r->vaddr) {
				r->vaddr = rel->rva;
			}
			if (!r->paddr) {
				r->paddr = rel->offset;
			}
			return r;
		}
		// Default CREL handling based on machine type
		switch (eo->ehdr.e_machine) {
		case EM_X86_64:
			ADD(64, 0);
			break;
		case EM_386:
			ADD(32, 0);
			break;
		case EM_AARCH64:
			ADD(64, 0);
			break;
		case EM_ARM:
			ADD(32, 0);
			break;
		default:
			// Default to 64-bit for other architectures
			ADD(64, 0);
			break;
		}
	}

	switch (eo->ehdr.e_machine) {
	case EM_S390:
		switch (rel->type) {
		case R_390_GLOB_DAT: // globals
			SET (64);
			break;
		case R_390_RELATIVE:
			ADD (64, 0);
			break;
		}
		break;
	case EM_386: switch (rel->type) {
		case R_386_NONE:     break; // malloc then free. meh. then again, there's no real world use for _NONE.
		case R_386_32:       ADD(32, 0); break;
		case R_386_PC32:     ADD(32,-(st64)P); break;
		case R_386_GLOB_DAT: SET(32); break;
		case R_386_JMP_SLOT: SET(32); break;
		case R_386_RELATIVE: ADD(32, B); break;
		case R_386_GOTOFF:   ADD(32, -(st64)got_addr); break;
		case R_386_GOTPC:    ADD(32, got_addr - P); break;
		case R_386_16:       ADD(16, 0); break;
		case R_386_PC16:     ADD(16,-(st64)P); break;
		case R_386_8:        ADD(8,  0); break;
		case R_386_PC8:      ADD(8, -(st64)P); break;
		case R_386_COPY:     ADD(32, 0); break; // XXX: copy symbol at runtime
		case R_386_IRELATIVE:
			r->is_ifunc = true;
			SET (32);
			break;
		default:
			R_LOG_WARN ("Unsupported reloc type %d for x86-32", rel->type);
			break;
		}
		break;
	case EM_X86_64: switch (rel->type) {
		case R_X86_64_NONE:      break; // malloc then free. meh. then again, there's no real world use for _NONE.
		case R_X86_64_64:        ADD(64, 0); break;
		case R_X86_64_PLT32:     ADD(32,-(st64)P /* +L */); break;
		case R_X86_64_GOT32:     ADD(32, got_addr); break;
		case R_X86_64_PC32:      ADD(32,-(st64)P); break;
		case R_X86_64_GLOB_DAT:  r->vaddr -= rel->sto; SET(64); break;
		case R_X86_64_JUMP_SLOT: r->vaddr -= rel->sto; SET(64); break;
		case R_X86_64_RELATIVE:  ADD(64, B); break;
		case R_X86_64_32:        ADD(32, 0); break;
		case R_X86_64_32S:       ADD(32, 0); break;
		case R_X86_64_16:        ADD(16, 0); break;
		case R_X86_64_PC16:      ADD(16,-(st64)P); break;
		case R_X86_64_8:         ADD(8,  0); break;
		case R_X86_64_PC8:       ADD(8, -(st64)P); break;
		case R_X86_64_GOTPCREL:  ADD(64, got_addr - P); break;
		case R_X86_64_COPY:      ADD(64, 0); break; // XXX: copy symbol at runtime
		case R_X86_64_IRELATIVE: r->is_ifunc = true; SET(64); break;
		case R_X86_64_TPOFF64:   ADD(64, 0); break;
		case R_X86_64_DTPMOD64:  break; // id of module containing symbol (keep it as zero)
		case R_X86_64_DTPOFF64:  ADD(64, 0); break; // offset inside module's tls
		// case 1027: // this is aarc64_relative, if this appears here we are mixing x64 and arm64 reloc types
		default:
			R_LOG_WARN ("Unsupported reloc type %d for x64", rel->type);
			break;
		}
		break;
	case EM_ARM:
		switch (rel->type) {
		case R_ARM_NONE:             break;
		case R_ARM_ABS32:            ADD(32, 0); break;
		case R_ARM_REL32:            ADD(32,-(st64)P); break;
		case R_ARM_ABS16:            ADD(16, 0); break;
		case R_ARM_ABS8:             ADD(8,  0); break;
		case R_ARM_SBREL32:          ADD(32, -(st64)B); break;
		case R_ARM_GLOB_DAT:         ADD(32, 0); break;
		case R_ARM_JUMP_SLOT:        ADD(32, 0); break;
		case R_ARM_COPY:             ADD(32, 0); break; // copy symbol at runtime
		case R_ARM_RELATIVE:         ADD(32, B); break;
		case R_ARM_GOTOFF:           ADD(32,-(st64)got_addr); break;
		case R_ARM_GOTPC:            ADD(32, got_addr - P); break;
		case R_ARM_CALL:             ADD(24, -(st64)P); break;
		case R_ARM_JUMP24:           ADD(24, -(st64)P); break;
		case R_ARM_THM_JUMP24:       ADD(24, -(st64)P); break;
		case R_ARM_PREL31:           ADD(32, -(st64)P); break;
		case R_ARM_MOVW_PREL_NC:     ADD(16, -(st64)P); break;
		case R_ARM_MOVT_PREL:        ADD(32, -(st64)P); break;
		case R_ARM_THM_MOVW_PREL_NC: ADD(16, -(st64)P); break;
		case R_ARM_REL32_NOI:        ADD(32, -(st64)P); break;
		case R_ARM_ABS32_NOI:        ADD(32, 0); break;
		case R_ARM_ALU_PC_G0_NC:     ADD(32, -(st64)P); break;
		case R_ARM_ALU_PC_G0:        ADD(32, -(st64)P); break;
		case R_ARM_ALU_PC_G1_NC:     ADD(32, -(st64)P); break;
		case R_ARM_ALU_PC_G1:        ADD(32, -(st64)P); break;
		case R_ARM_ALU_PC_G2:        ADD(32, -(st64)P); break;
		case R_ARM_LDR_PC_G1:        ADD(32, -(st64)P); break;
		case R_ARM_LDR_PC_G2:        ADD(32, -(st64)P); break;
		case R_ARM_LDRS_PC_G0:       ADD(32, -(st64)P); break;
		case R_ARM_LDRS_PC_G1:       ADD(32, -(st64)P); break;
		case R_ARM_LDRS_PC_G2:       ADD(32, -(st64)P); break;
		case R_ARM_LDC_PC_G0:        ADD(32, -(st64)P); break;
		case R_ARM_LDC_PC_G1:        ADD(32, -(st64)P); break;
		case R_ARM_LDC_PC_G2:        ADD(32, -(st64)P); break;
		default: ADD(32, got_addr); break; // reg relocations
		}
		break;
	case EM_RISCV:
		switch (rel->type) {
		case R_RISCV_NONE: break;
		case R_RISCV_JUMP_SLOT: ADD(64, 0); break;
		case R_RISCV_RELATIVE: ADD(64, B); break;
		default: ADD(64, got_addr); break; // reg relocations
		}
		break;
	case EM_AARCH64: switch (rel->type) {
		case R_AARCH64_NONE: break;
		case R_AARCH64_GLOB_DAT: SET (64); break;
		case R_AARCH64_JUMP_SLOT: SET (64); break;
		case R_AARCH64_RELATIVE: ADD (64, B); break;
		// data references
		case R_AARCH64_PREL16: ADD (16, B); break;
		case R_AARCH64_PREL32: ADD (32, B); break;
		case R_AARCH64_PREL64:
			r->addend = (st64) sym_vaddr + rel->addend - rel->rva;
			r->type = R_BIN_RELOC_64;
			break;
		case R_AARCH64_ABS64: ADD (64, 0); break;
		case R_AARCH64_ABS32: ADD (32, 0); break;
		case R_AARCH64_ABS16: ADD (16, 0); break;
		// instructions
		case R_AARCH64_ADR_PREL_PG_HI21:
			R_LOG_WARN ("Poorly supported AARCH64 instruction reloc type %d at 0x%08"PFMT64x, rel->type, rel->rva);
			ADD (32, 0);
			break;
		case R_AARCH64_ADD_ABS_LO12_NC:
		case R_AARCH64_CALL26:
		case R_AARCH64_LDST32_ABS_LO12_NC:
		case R_AARCH64_LDST64_ABS_LO12_NC:
			ADD (32, 0);
			break;
		case R_AARCH64_MOVW_UABS_G0:
		case R_AARCH64_MOVW_UABS_G0_NC:
			r->addend = sym_vaddr & 0xFFFF;
			r->type = R_BIN_RELOC_16;
			break;
		case R_AARCH64_MOVW_UABS_G1:
		case R_AARCH64_MOVW_UABS_G1_NC:
			r->addend = (sym_vaddr >> 16) & 0xFFFF;
			r->type = R_BIN_RELOC_16;
			break;
		case R_AARCH64_MOVW_UABS_G2:
		case R_AARCH64_MOVW_UABS_G2_NC:
			r->addend = (sym_vaddr >> 32) & 0xFFFF;
			r->type = R_BIN_RELOC_16;
			break;
		case R_AARCH64_MOVW_UABS_G3:
			r->addend = (sym_vaddr >> 48) & 0xFFFF;
			r->type = R_BIN_RELOC_16;
			break;
#if 0
		case R_AARCH64_TLS_TPREL64:
			r->type = R_BIN_RELOC_TLS;
			SET(64);
			break;
#endif
#if 0
/* Instructions. */
#define R_AARCH64_MOVW_SABS_G0		270
#define R_AARCH64_MOVW_SABS_G1		271
#define R_AARCH64_MOVW_SABS_G2		272

#define R_AARCH64_LD_PREL_LO19		273
#define R_AARCH64_ADR_PREL_LO21		274
#define R_AARCH64_ADR_PREL_PG_HI21	275
#define R_AARCH64_ADR_PREL_PG_HI21_NC	276
#define R_AARCH64_ADD_ABS_LO12_NC	277
#define R_AARCH64_LDST8_ABS_LO12_NC	278

#define R_AARCH64_TSTBR14		279
#define R_AARCH64_CONDBR19		280
#define R_AARCH64_JUMP26		282
#define R_AARCH64_CALL26		283
#define R_AARCH64_LDST16_ABS_LO12_NC	284
#define R_AARCH64_LDST32_ABS_LO12_NC	285
#define R_AARCH64_LDST64_ABS_LO12_NC	286
#define R_AARCH64_LDST128_ABS_LO12_NC	299

#define R_AARCH64_MOVW_PREL_G0		287
#define R_AARCH64_MOVW_PREL_G0_NC	288
#define R_AARCH64_MOVW_PREL_G1		289
#define R_AARCH64_MOVW_PREL_G1_NC	290
#define R_AARCH64_MOVW_PREL_G2		291
#define R_AARCH64_MOVW_PREL_G2_NC	292
#define R_AARCH64_MOVW_PREL_G3		293
#endif
		default:
			R_LOG_WARN ("Unsupported reloc type %d for aarch64", rel->type);
			break; // reg relocations
		}
		break;
	case EM_PPC: switch (rel->type) {
		case R_PPC_NONE:        break;
		case R_PPC_GLOB_DAT:    ADD (32, 0); break;
		case R_PPC_JMP_SLOT:    ADD (32, 0); break;
		case R_PPC_COPY: ADD(32, 0); break; // copy symbol at runtime
		case R_PPC_REL24: ADD(24, -(st64)P); break;
		case R_PPC_REL14: ADD(16, -(st64)P); break;
		case R_PPC_REL32: ADD(32, -(st64)P); break;
		case R_PPC_RELATIVE: ADD(32, -(st64)P); break;
		case R_PPC_PLT32: ADD(32, -(st64)P); break;
		case R_PPC_ADDR16: ADD(16, 0); break;
		case R_PPC_ADDR32: ADD(32, 0); break;
		case R_PPC_ADDR16_LO: ADD(16, 0); break;  // XXX extract lower 16 bits of (target - vaddr - addend)
		case R_PPC_ADDR16_HI: ADD(16, 0); break;  // XXX extract upper 16 bits of (target - vaddr - addend)
		case R_PPC_ADDR16_HA: ADD(16, 0); break;  // XXX extract high adjusted 16 bits of (target - vaddr - addend)
		default:
			R_LOG_DEBUG ("unimplemented ELF/PPC reloc type %d", rel->type);
		}
		break;
	case EM_PPC64:
		switch (rel->type) {
		case R_PPC64_JMP_SLOT: // 21
			r->type = R_BIN_RELOC_64;
			r->vaddr = got_addr + rel->offset; //  - 0x01028;
			return r;
		case R_PPC64_ADDR64: // 38
			r->type = R_BIN_RELOC_64;
			r->vaddr = got_addr + rel->offset; //  - 0x10028 + 0x1000;
			return r;
		default:
			R_LOG_DEBUG ("Unimplemented ELF/BPF reloc type %d", rel->type);
			break;
		}
		break;
	case EM_LOONGARCH:
		// 3 and 5 :: switch (rel->type) {
		ADD (32, 0);
		break;
	case EM_MIPS:
		ADD (32, 0);
		break;
	case EM_SPARC:
	case EM_SPARCV9:
	case EM_SPARC32PLUS:
		ADD (32, 0);
		break;
<<<<<<< HEAD
	case EM_BPF:
		if (!Elf_(is_sbpf_binary) (eo)) {
			R_LOG_DEBUG ("Unimplemented BPF reloc type %d", rel->type);
			break;
		}
	case EM_SBPF:
		switch (rel->type) {
		case R_BPF_64_64: // 64-bit immediate for lddw instruction
			r->type = R_BIN_RELOC_64;
			r->vaddr = B + rel->offset;
			return r;
		case R_BPF_64_RELATIVE: // PC relative 64-bit address
			r->type = R_BIN_RELOC_64;
			r->vaddr = B + rel->offset;
			return r;
		case R_BPF_64_32: // 32-bit function/syscall ID for call instruction
			r->type = R_BIN_RELOC_32;
			// The immediate value will be a function ID or syscall ID, not an address
			r->vaddr = B + rel->offset;
			return r;
		default:
			R_LOG_DEBUG ("Unimplemented sBPF reloc type %d", rel->type);
			break;
		}
		break;
	default:
		R_LOG_ERROR ("Unimplemented ELF reloc type %d", rel->type);
		break;
	}
#undef SET
#undef ADD
	free (r);
	return NULL;
}

// Helper macro for left bit rotation
#define rotl32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

// Murmur3 32-bit hash function for sBPF syscalls
static ut32 murmur3_32(const char* data, ut32 len, ut32 seed) {
	const ut32 c1 = 0xcc9e2d51U;
	const ut32 c2 = 0x1b873593U;
	const ut32 r1 = 15;
	const ut32 r2 = 13;
	const ut32 m = 5;
	const ut32 n = 0xe6546b64U;

	ut32 hash = seed;
	const ut8* bytes = (const ut8*)data;

	// Process 4-byte chunks
	ut32 chunks = len / 4;
	ut32 i;
	for (i = 0; i < chunks; i++) {
		ut32 k = bytes[i*4] | (bytes[i*4+1] << 8) | (bytes[i*4+2] << 16) | (bytes[i*4+3] << 24);
		k *= c1;
		k = rotl32(k, r1);
		k *= c2;
		hash ^= k;
		hash = rotl32(hash, r2);
		hash = hash * m + n;
	}

	// Process remaining bytes
	ut32 tail = 0;
	switch (len & 3) {
	case 3: tail ^= bytes[chunks * 4 + 2] << 16; /* fallthrough */
	case 2: tail ^= bytes[chunks * 4 + 1] << 8;  /* fallthrough */
	case 1: tail ^= bytes[chunks * 4];
		tail *= c1;
		tail = rotl32(tail, r1);
		tail *= c2;
		hash ^= tail;
	}
	// Finalization
	hash ^= len;
	hash ^= hash >> 16;
	hash *= 0x85ebca6bU;
	hash ^= hash >> 13;
	hash *= 0xc2b2ae35U;
	hash ^= hash >> 16;
	return hash;
}

static RList* relocs(RBinFile *bf) {
	R_RETURN_VAL_IF_FAIL (bf && bf->bo && bf->bo->bin_obj, NULL);
	ELFOBJ *eo = bf->bo->bin_obj;
	if (eo->relocs_list) {
		return eo->relocs_list;
	}
	RList *ret = r_list_newf (free);
	if (!ret) {
		return NULL;
	}

	ut64 got_addr = Elf_(get_section_addr) (eo, ".got");
	if (got_addr == UT64_MAX) {
		got_addr = Elf_(get_section_addr) (eo, ".got.plt");
	}
	if (got_addr == UT64_MAX && eo->ehdr.e_type == ET_REL) {
		got_addr = Elf_(get_section_addr) (eo, ".got.r2");
	}

	const RVector *relocs = Elf_(load_relocs) (eo);
	if (!relocs) {
		return ret;
	}

	HtUP *reloc_ht = ht_up_new0 ();
	if (!reloc_ht) {
		return ret;
	}

	RBinElfReloc *reloc;
	r_vector_foreach (relocs, reloc) {
		RBinReloc *already_inserted = ht_up_find (reloc_ht, reloc->rva, NULL);
		if (already_inserted) {
			continue;
		}

		RBinReloc *ptr = reloc_convert (eo, reloc, got_addr);
		if (ptr && ptr->paddr != UT64_MAX) {
			r_list_append (ret, ptr);
			ht_up_insert (reloc_ht, reloc->rva, ptr);
		} else {
			if (ptr) {
				ht_up_insert (reloc_ht, reloc->rva, ptr);
			} else {
				if (reloc->rva != reloc->offset) {
					ht_up_insert (reloc_ht, reloc->rva, ptr);
					R_LOG_DEBUG ("Suspicious reloc patching at 0x%"PFMT64x" for 0x%08"PFMT64x" via 0x%"PFMT64x,
						got_addr, reloc->rva, reloc->offset);
				} else {
					if (reloc->rva) {
						R_LOG_WARN ("reloc conversion failed for 0x%"PFMT64x, got_addr);
					} else {
						R_LOG_DEBUG ("wrong reloc conversion failed for 0x%"PFMT64x, got_addr);
					}
				}
			}
		}
	}
	ht_up_free (reloc_ht);
	eo->relocs_list = ret;
	ret->free = NULL; // already freed in the hashtable
	return r_list_clone (eo->relocs_list, NULL);
}

static void _patch_reloc(ELFOBJ *bo, ut16 e_machine, RIOBind *iob, RBinElfReloc *rel, ut64 S, ut64 B, ut64 L) {
	ut64 V = 0;
	ut64 A = rel->addend;
	ut64 P = rel->rva;
	ut8 buf[8] = {0};
	switch (e_machine) {
	case EM_S390:
		switch (rel->type) {
		case R_390_GLOB_DAT: // globals
			iob->overlay_write_at (iob->io, rel->rva, buf, 8);
			break;
		case R_390_RELATIVE:
			iob->overlay_write_at (iob->io, rel->rva, buf, 8);
			break;
		}
		break;
	case EM_ARM:
		if (!rel->sym && rel->mode == DT_REL) {
			iob->read_at (iob->io, rel->rva, buf, 4);
		} else {
			V = S + A;
			r_write_ble32 (buf, V, bo->endian);
		}
		iob->overlay_write_at (iob->io, rel->rva, buf, 4);
		break;
	case EM_AARCH64:
		V = S + A;
#if 0
		r_write_le64 (buf, V);
		iob->overlay_write_at (iob->io, rel->rva, buf, 8);
#else
		iob->read_at (iob->io, rel->rva, buf, 8);
		// only patch the relocs that are initialized with zeroes
		// if the destination contains a different value it's a constant useful for static analysis
		ut64 addr = r_read_le64 (buf);
		r_write_le64 (buf, addr? A: S);
		iob->overlay_write_at (iob->io, rel->rva, buf, 8);
#endif
		break;
	case EM_PPC64: {
		int low = 0, word = 0;
		switch (rel->type) {
		case R_PPC64_REL16_HA:
			word = 2;
			V = (S + A - P + 0x8000) >> 16;
			break;
		case R_PPC64_REL16_LO:
			word = 2;
			V = (S + A - P) & 0xffff;
			break;
		case R_PPC64_REL14:
			low = 14;
			V = (st64)(S + A - P) >> 2;
			break;
		case R_PPC64_REL24:
			low = 24;
			V = (st64)(S + A - P) >> 2;
			break;
		case R_PPC64_REL32:
			word = 4;
			V = S + A - P;
			break;
		default:
			break;
		}
		if (low) {
			// TODO big-endian
			switch (low) {
			case 14:
				V &= (1 << 14) - 1;
				iob->read_at (iob->io, rel->rva, buf, 2);
				r_write_le32 (buf, (r_read_le32 (buf) & ~((1<<16) - (1<<2))) | V << 2);
				iob->overlay_write_at (iob->io, rel->rva, buf, 2);
				break;
			case 24:
				V &= (1 << 24) - 1;
				iob->read_at (iob->io, rel->rva, buf, 4);
				r_write_le32 (buf, (r_read_le32 (buf) & ~((1<<26) - (1<<2))) | V << 2);
				iob->overlay_write_at (iob->io, rel->rva, buf, 4);
				break;
			}
		} else if (word) {
			// TODO big-endian
			switch (word) {
			case 2:
				r_write_le16 (buf, V);
				iob->overlay_write_at (iob->io, rel->rva, buf, 2);
				break;
			case 4:
				r_write_le32 (buf, V);
				iob->overlay_write_at (iob->io, rel->rva, buf, 4);
				break;
			}
		}
		break;
	}
	case EM_386:
 		switch (rel->type) {
 		case R_386_32:
 		case R_386_PC32:
			{
 			r_io_read_at (iob->io, rel->rva, buf, 4);
 			ut32 v = r_read_le32 (buf) + S + A;
 			if (rel->type == R_386_PC32) {
 				v -= P;
 			}
 			r_write_le32 (buf, v);
			iob->overlay_write_at (iob->io, rel->rva, buf, 4);
			}
			break;
 		default:
 			break;
 		}
 		break;
	case EM_X86_64: {
		int word = 0;
		switch (rel->type) {
		case R_X86_64_DTPMOD64:
			word = 0;
			// do nothing
			break;
		case R_X86_64_DTPOFF64:
			word = 8;
			V = S + A;
			break;
		case R_X86_64_TPOFF64:
			word = 8;
			V = S + A;
			break;
		case R_X86_64_8:
			word = 1;
			V = S + A;
			break;
		case R_X86_64_16:
			word = 2;
			V = S + A;
			break;
		case R_X86_64_32:
		case R_X86_64_32S:
			word = 4;
			V = S + A;
			break;
		case R_X86_64_64:
			word = 8;
			V = S + A;
			break;
		case R_X86_64_GLOB_DAT:
		case R_X86_64_JUMP_SLOT:
			word = 4;
			V = S;
			break;
		case R_X86_64_PC8:
			word = 1;
			V = S + A - P;
			break;
		case R_X86_64_PC16:
			word = 2;
			V = S + A - P;
			break;
		case R_X86_64_PC32:
			word = 4;
			V = S + A - P;
			break;
		case R_X86_64_PC64:
			word = 8;
			V = S + A - P;
			break;
		case R_X86_64_PLT32:
			word = 4;
			V = L + A - P;
			break;
		case R_X86_64_RELATIVE:
			word = 8;
			V = B + A;
			break;
		default:
			//eprintf ("relocation %d not handle at this time\n", rel->type);
			break;
		}
		switch (word) {
		case 0:
			break;
		case 1:
			buf[0] = V;
			iob->overlay_write_at (iob->io, rel->rva, buf, 1);
			break;
		case 2:
			r_write_le16 (buf, V);
			iob->overlay_write_at (iob->io, rel->rva, buf, 2);
			break;
		case 4:
			r_write_le32 (buf, V);
			iob->overlay_write_at (iob->io, rel->rva, buf, 4);
			break;
		case 8:
			r_write_le64 (buf, V);
			iob->overlay_write_at (iob->io, rel->rva, buf, 8);
			break;
		}
		break;
	}
	case EM_BPF: // CHECK: some older solana programs have set an ehdr.e_machine of EM_BPF
		if (!Elf_(is_sbpf_binary) (bo)) {
			R_LOG_DEBUG ("Unhandled BPF relocation type %d", rel->type);
			break;
		}
		// fallthrough
	case EM_SBPF: {
		switch (rel->type) {
		case R_BPF_64_64: // 64-bit immediate for lddw instructions
			V = S + A;
			// Add sBPF base address if result < base address
			if (V < SBPF_PROGRAM_ADDR) {
				V += SBPF_PROGRAM_ADDR;
			}
			// Write as split 32-bit values to immediate fields (offset+4 and offset+12)
			r_write_le32 (buf, (ut32)(V & UT32_MAX));
			iob->overlay_write_at (iob->io, rel->rva + 4, buf, 4);
			r_write_le32 (buf, (ut32)(V >> 32));
			iob->overlay_write_at (iob->io, rel->rva + 12, buf, 4);
			break;

		case R_BPF_64_RELATIVE: { // PC relative 64-bit address

			// Check if relocation is in .text section
			bool is_text = false;
			ut64 text_start = Elf_(get_section_offset)(bo, ".text");
			ut64 text_size = Elf_(get_section_size)(bo, ".text");
			if (text_start != UT64_MAX && text_size != UT64_MAX) {
				ut64 text_end = text_start + text_size;
				is_text = (rel->offset >= text_start && rel->offset < text_end);
			}
			if (is_text) {
				// In .text: behave like R_BPF_64_64 but ignore symbol and handle addend
				// Read implicit addend from both immediate fields (lddw instruction)
				ut8 buf_lo[4], buf_hi[4];
				iob->read_at (iob->io, rel->rva + 4, buf_lo, 4);
				iob->read_at (iob->io, rel->rva + 12, buf_hi, 4);

				ut32 va_lo = r_read_le32 (buf_lo);
				ut32 va_hi = r_read_le32 (buf_hi);
				ut64 va = ((ut64)va_hi << 32) | va_lo;

				if (va != 0) {
					// If looks like physical address, make it virtual
					if (va < SBPF_PROGRAM_ADDR) {
						va += SBPF_PROGRAM_ADDR;
					}
					// Write back to both immediate fields
					r_write_le32 (buf_lo, (ut32)(va & 0xffffffff));
					r_write_le32 (buf_hi, (ut32)(va >> 32));
					iob->overlay_write_at (iob->io, rel->rva + 4, buf_lo, 4);
					iob->overlay_write_at (iob->io, rel->rva + 12, buf_hi, 4);
				}
			} else {
				// Outside .text: do 64-bit write
				ut8 buf_addend[4];
				iob->read_at (iob->io, rel->rva + 4, buf_addend, 4);
				ut32 va = r_read_le32 (buf_addend);
				// Add base address
				ut64 result = va + SBPF_PROGRAM_ADDR;
				// Write back as 64-bit value
				r_write_le64 (buf, result);
				iob->overlay_write_at (iob->io, rel->rva, buf, 8);
			}
			break;
		}
		case R_BPF_64_32: { // 32-bit function/syscall ID for call instruction
			ut32 hash_value = 0;
			const char *sym_name = NULL;
			if (rel->sym) {
				// Check imports first
				if (rel->sym < bo->imports_by_ord_size && bo->imports_by_ord[rel->sym]) {
					RBinImport *import = bo->imports_by_ord[rel->sym];
					if (import && import->name) {
						sym_name = r_bin_name_tostring (import->name);
					}
				}
				// Then check symbols
				else if (rel->sym < bo->symbols_by_ord_size && bo->symbols_by_ord[rel->sym]) {
					RBinSymbol *symbol = bo->symbols_by_ord[rel->sym];
					if (symbol && symbol->name) {
						sym_name = r_bin_name_tostring (symbol->name);
					}
				}
			}
			if (R_STR_ISNOTEMPTY (sym_name)) {
				// Compute Murmur3 hash with seed 0
				hash_value = murmur3_32 (sym_name, strlen (sym_name), 0);
				R_LOG_DEBUG ("sBPF R_BPF_64_32: symbol '%s' -> hash 0x%08x", sym_name, hash_value);
			} else {
				R_LOG_WARN ("sBPF R_BPF_64_32: no symbol name found for relocation at 0x%"PFMT64x, rel->rva);
				hash_value = 0;
			}
			// write hash to immediate field (offset + 4)
			r_write_le32 (buf, hash_value);
			iob->overlay_write_at (iob->io, rel->rva + 4, buf, 4);
			break;
		}
		default:
			R_LOG_DEBUG ("Unhandled sBPF relocation type %d", rel->type);
			break;
		}
		break;
	}
	}
}

static RList* patch_relocs(RBinFile *bf) {
	R_RETURN_VAL_IF_FAIL (bf && bf->rbin, NULL);
	RBinReloc *ptr = NULL;
	RBin *b = bf->rbin;
	RIO *io = b->iob.io;
	if (!io || !io->desc) {
		return NULL;
	}
	RBinObject *obj = r_bin_cur_object (b);
	if (!obj) {
	   	return NULL;
	}
	ELFOBJ *eo = obj->bin_obj;
	size_t cdsz = obj->info? (obj->info->bits / 8): 0;
	if (eo->ehdr.e_type != ET_REL && eo->ehdr.e_type != ET_DYN) {
		return NULL;
	}
	ut64 size = eo->g_reloc_num * cdsz;
	if (size == 0) {
		return NULL;
	}
	RIOBank *bank = b->iob.bank_get (io, io->bank);
	RListIter *iter;
	RIOMapRef *mapref;
	RIOMap *g = NULL;
	ut64 offset = 0;
	r_list_foreach (bank->maprefs, iter, mapref) {
		RIOMap *map = b->iob.map_get (io, mapref->id);
		if (r_io_map_from (map) > offset) {
			offset = r_io_map_from (map);
			g = map;
		}
	}
	if (!g) {
		return NULL;
	}
	ut64 n_vaddr = g->itv.addr + g->itv.size;
	// reserve at least that space
	size = eo->g_reloc_num * cdsz;
	char *muri = r_str_newf ("malloc://%" PFMT64u, size);
	if (!muri) {
		return NULL;
	}
	RIODesc *gotr2desc = b->iob.open_at (io, muri, R_PERM_R, 0664, n_vaddr);
	free (muri);
	if (!gotr2desc) {
		return NULL;
	}

	RIOMap *gotr2map = b->iob.map_get_at (io, n_vaddr);
	if (!gotr2map) {
		return NULL;
	}
	gotr2map->name = strdup (".got.r2");

	const RVector *relocs = Elf_(load_relocs) (eo);
	if (!relocs) {
		return NULL;
	}
	RList *ret = r_list_newf ((RListFree)free);
	if (!ret) {
		return NULL;
	}
	HtUU *relocs_by_sym = ht_uu_new0 ();
	if (!relocs_by_sym) {
		r_list_free (ret);
		return NULL;
	}
	ut64 vaddr = n_vaddr;
	RBinElfReloc *reloc;
	r_vector_foreach (relocs, reloc) {
		ut64 plt_entry_addr = vaddr;
		ut64 sym_addr = UT64_MAX;

		if (reloc->sym) {
			if (reloc->sym < eo->imports_by_ord_size && eo->imports_by_ord[reloc->sym]) {
				bool found;
				sym_addr = ht_uu_find (relocs_by_sym, reloc->sym, &found);
				if (found) {
					plt_entry_addr = sym_addr;
				}
			} else if (reloc->sym < eo->symbols_by_ord_size && eo->symbols_by_ord[reloc->sym]) {
				sym_addr = eo->symbols_by_ord[reloc->sym]->vaddr;
				plt_entry_addr = sym_addr;
			}
		}
		// ut64 raddr = sym_addr? sym_addr: vaddr;
		ut64 raddr = (sym_addr && sym_addr != UT64_MAX)? sym_addr: vaddr;
		_patch_reloc (eo, eo->ehdr.e_machine, &b->iob, reloc, raddr, 0, plt_entry_addr);
		ptr = reloc_convert (eo, reloc, n_vaddr);
		if (!ptr) {
			continue;
		}

		if (sym_addr && sym_addr != UT64_MAX) {
			ptr->vaddr = sym_addr;
		} else {
			ptr->vaddr = vaddr;
			ht_uu_insert (relocs_by_sym, reloc->sym, vaddr);
			vaddr += cdsz;
		}
		r_list_append (ret, ptr);
	}
	ht_uu_free (relocs_by_sym);
	return ret;
}

static void lookup_symbols(RBinFile *bf, RBinInfo *ret) {
	if (!symbols_vec (bf)) {
		return;
	}
	RVecRBinSymbol* symbols = &bf->bo->symbols_vec;
	RBinSymbol *symbol;
	bool is_rust = false;
	bool is_dart = false;
	if (symbols) {
		R_VEC_FOREACH (symbols, symbol) {
			if (ret->has_canary && is_rust) {
				break;
			}
			const char *oname = r_bin_name_tostring2 (symbol->name, 'o');
			if (!strcmp (oname, "_NSConcreteGlobalBlock")) {
				ret->lang = (ret->lang && !strcmp (ret->lang, "c++"))? "c++ blocks ext.": "c blocks ext.";
			}
			if (!ret->has_canary) {
				if (strstr (oname, "__stack_chk_fail") || strstr (oname, "__stack_smash_handler")) {
					ret->has_canary = true;
				}
			}
			if (!is_rust && !strcmp (oname, "__rust_oom")) {
				is_rust = true;
				ret->lang = "rust";
			} else if (!is_dart && !strcmp (oname, "_kDartVmSnapshotInstructions")) {
				is_dart = true;
				ret->lang = "dart";
			}
		}
		// symbols->free = r_bin_symbol_free;
		// r_list_free (symbols);
	}
}

static void lookup_sections(RBinFile *bf, RBinInfo *ret) {
	RBinSection *section;
	bool is_go = false;
	ret->has_retguard = -1;
#if R2_590
	if (!sections_vec (bf)) {
		return;
	}
	RVecRBinSection *sections = &(bf->bo->sections_vec);
	R_VEC_FOREACH (sections, section) {
#else
	RList *secs = sections (bf);
	RListIter *iter;
	r_list_foreach (secs, iter, section) {
#endif
		if (is_go && ret->has_retguard != -1) {
			break;
		}
		if (strstr (section->name, "note.go.buildid") ||
		    strstr (section->name, ".gopclntab") ||
		    strstr (section->name, ".go_export")) {
			ret->lang = "go";
			is_go = true;
		}
		if (!strcmp (section->name, ".gnu_debuglink")) {
			char buf[128] = {0};
			ut64 addr = section->paddr;
			ut64 size = sizeof (buf) - 1;
			if (r_buf_read_at (bf->buf, addr, (ut8*)buf, size) == size) {
				// R_LOG_INFO ("SideloadDwarf with this command: obf %s", buf);
				if (IS_PRINTABLE (buf[0])) {
					ret->dbglink = r_str_ndup (buf, sizeof (buf));
				}
			}
		}
		# define R_BIN_RANDOMDATA_RETGUARD_SZ 48
		if (!strcmp (section->name, ".openbsd.randomdata")) {
			// The retguard cookie adds 8 per return function inst.
			ret->has_retguard = (section->size >= R_BIN_RANDOMDATA_RETGUARD_SZ);
			break;
		}
	}
	r_list_free (secs);
}

static bool has_sanitizers(RBinFile *bf) {
	bool ret = false;
	RList* imports_list = imports (bf);
	RListIter *iter;
	RBinImport *import;
	r_list_foreach (imports_list, iter, import) {
		const char *iname = r_bin_name_tostring2 (import->name, 'o');
		if (*iname == '_' && (strstr (iname, "__sanitizer") || strstr (iname, "__ubsan"))) {
			ret = true;
			break;
		}
	}
	r_list_free (imports_list);
	return ret;
}

static RBinInfo* info(RBinFile *bf) {
	RBinInfo *ret = R_NEW0 (RBinInfo);
	ret->file = bf->file
		? strdup (bf->file)
		: NULL;
	void *obj = bf->bo->bin_obj;
	char *str = Elf_(get_rpath)(obj);
	if (str) {
		ret->rpath = strdup (str);
		free (str);
	} else {
		ret->rpath = strdup ("NONE");
	}
	str = Elf_(get_file_type) (obj);
	if (!str) {
		free (ret->rpath);
		free (ret);
		return NULL;
	}
	ret->type = str;
	ret->has_pi = (strstr (str, "DYN"))? 1: 0;
	ret->has_lit = true;
	ret->has_sanitizers = has_sanitizers (bf);
	if (!(str = Elf_(get_elf_class) (obj))) {
		free (ret->rpath);
		free (ret);
		return NULL;
	}
	ret->bclass = str;
	if (!(str = Elf_(get_osabi_name) (obj))) {
		free (ret->rpath);
		free (ret->type);
		free (ret);
		return NULL;
	}
	ret->os = str;
	if (!(str = Elf_(get_osabi_name) (obj))) {
		free (ret->rpath);
		free (ret->type);
		free (ret);
		return NULL;
	}
	ret->subsystem = str;
	if (!(str = Elf_(get_machine_name) (obj))) {
		free (ret->rpath);
		free (ret->type);
		free (ret->os);
		free (ret);
		return NULL;
	}
	ret->machine = str;
	if (!(str = Elf_(get_arch) (obj))) {
		free (ret->subsystem);
		free (ret->rpath);
		free (ret->type);
		free (ret->os);
		free (ret);
		return NULL;
	}
	ret->arch = str;
	ret->cpu = Elf_(get_cpu) (obj);

	ut32 elf_flags = ((ELFOBJ *)obj)->ehdr.e_flags;
	if (elf_flags) {
		ret->flags = r_str_newf ("0x%x", elf_flags);
	}
	ret->abi = Elf_(get_abi) (obj);
	ret->rclass = strdup ("elf");
	ret->bits = Elf_(get_bits) (obj);
	if (!strcmp (ret->arch, "avr")) {
		ret->bits = 16;
	}
	ret->big_endian = Elf_(is_big_endian) (obj);
	ret->has_va = Elf_(has_va) (obj);
	ret->has_nx = Elf_(has_nx) (obj);
	ret->has_nobtcfi = Elf_(has_nobtcfi) (obj);
	ret->intrp = Elf_(intrp) (obj);
	ret->compiler = Elf_(compiler) (obj);
	ret->dbg_info = 0;
	if (!Elf_(get_stripped) (obj)) {
		ret->dbg_info |= R_BIN_DBG_LINENUMS | R_BIN_DBG_SYMS | R_BIN_DBG_RELOCS;
	} else {
		ret->dbg_info |= R_BIN_DBG_STRIPPED;
	}
	if (Elf_(is_static) (obj)) {
		ret->dbg_info |= R_BIN_DBG_STATIC;
		ret->has_libinjprot = true;
	}
	lookup_sections (bf, ret);
	lookup_symbols (bf, ret);
	return ret;
}

static RList* fields(RBinFile *bf) {
	RList *ret = r_list_newf ((RListFree)free);
	if (!ret) {
		return NULL;
	}
	ELFOBJ *eo = bf->bo->bin_obj;
	const bool be = eo->endian;
	#define ROW(nam, siz, val, fmt, cmt) \
		r_list_append (ret, r_bin_field_new (addr, addr, val, siz, nam, cmt, fmt, false));
	if (r_buf_size (bf->buf) < sizeof (Elf_ (Ehdr))) {
		return ret;
	}
	ut64 addr = 0;
	ROW ("ELF", 4, r_buf_read_le32_at (bf->buf, addr), "x", NULL);
	addr += 0x10;
	ROW ("Type", 2, r_buf_read_ble16_at (bf->buf, addr, be), "w", NULL);
	addr += 0x2;
	ROW ("Machine", 2, r_buf_read_ble16_at (bf->buf, addr, be), "w", NULL);
	addr += 0x2;
	ROW ("Version", 4, r_buf_read_ble32_at (bf->buf, addr, be), "x", NULL);
	addr += 0x4;

	if (r_buf_read8_at (bf->buf, 0x04) == 1) {
		ROW ("EntryPoint", 4, r_buf_read_ble32_at (bf->buf, addr, be), "x", NULL);
		addr += 0x4;
		ROW ("PhOff", 4, r_buf_read_ble32_at (bf->buf, addr, be), "x", NULL);
		addr += 0x4;
		ut32 shoff = r_buf_read_ble32_at (bf->buf, addr, be);
		ROW ("ShOff", 4, shoff, "x", NULL);
		addr += 0x4;
	} else {
		ROW ("EntryPoint", 8, r_buf_read_ble64_at (bf->buf, addr, be), "q", NULL);
		addr += 0x8;
		ut64 phoff = r_buf_read_ble64_at (bf->buf, addr, be);
		ROW ("PhOff", 8, phoff, "q", NULL);
		addr += 0x8;
		ut64 shoff = r_buf_read_ble64_at (bf->buf, addr, be);
		ROW ("ShOff", 8, shoff, "q", NULL);
		addr += 0x8;
	}

	ROW ("Flags", 4, r_buf_read_ble32_at (bf->buf, addr, be), "x", NULL);
	addr += 0x4;
	ROW ("EhSize", 2, r_buf_read_ble16_at (bf->buf, addr, be), "w", NULL);
	addr += 0x2;
	ROW ("PhentSize", 2, r_buf_read_ble16_at (bf->buf, addr, be), "w", NULL);
	addr += 0x2;
	ROW ("PhNum", 2, r_buf_read_ble16_at (bf->buf, addr, be), "w", NULL);
	addr += 0x2;
	ROW ("ShentSize", 2, r_buf_read_ble16_at (bf->buf, addr, be), "w", NULL);
	addr += 0x2;
	ROW ("ShNum", 2, r_buf_read_ble16_at (bf->buf, addr, be), "w", NULL);
	addr += 0x2;
	ROW ("ShrStrndx", 2, r_buf_read_ble16_at (bf->buf, addr, be), "w", NULL);

	return ret;
}

static ut64 size(RBinFile *bf) {
	ut64 off = 0;
	ut64 len = 0;
#if R2_590
	if (!bf->bo->sections && sections_vec (bf)) {
		RBinSection *section;
		RVecRBinSection *sections = &(bf->bo->sections_vec);
		R_VEC_FOREACH (sections, section) {
#else
	if (!bf->bo->sections) {
		RBinSection *section;
		RList *secs = sections (bf);
		RListIter *iter;
		r_list_foreach (secs, iter, section) {
#endif
			if (section->paddr > off) {
				off = section->paddr;
				len = section->size;
			}
		}
		r_list_free (secs);
	}
	return off + len;
}
