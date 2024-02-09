/* radare - LGPL - Copyright 2009-2023 - nibble, pancake, luctielen */

#define R_LOG_ORIGIN "bin.elf"

#include <r_lib.h>
#include <r_bin.h>
#include "../i/private.h"
#include "elf/elf.h"
#include <sdb/ht_uu.h>

static RBinInfo* info(RBinFile *bf);

static RList *maps(RBinFile *bf) {
	r_return_val_if_fail (bf && bf->bo, NULL);
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
	ELFOBJ *res = Elf_(new_buf) (buf, user_baddr, bf->rbin->verbose);
	if (res) {
	//	sdb_ns_set (sdb, "info", res->kv);
		res->limit = bf->rbin->limit;
		bf->bo->bin_obj = res;
		return true;
	}
	return false;
}

static void destroy(RBinFile *bf) {
	ELFOBJ* eo = bf->bo->bin_obj;
	if (eo && eo->imports_by_ord) {
		int i;
		for (i = 0; i < eo->imports_by_ord_size; i++) {
			RBinImport *imp = eo->imports_by_ord[i];
			if (imp) {
				free (imp->name);
				free (imp);
				eo->imports_by_ord[i] = NULL;
			}
		}
		R_FREE (eo->imports_by_ord);
	}
	Elf_(free) (eo);
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
		if (is_arm && addr & 1) {
			ret->bits = 16;
			ret->vaddr--;
			ret->paddr--;
		}
	}
	return ret;
}

#if R2_590
static bool sections_vec(RBinFile *bf) {
	r_return_val_if_fail (bf && bf->bo, false);
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
	r_return_val_if_fail (bf && bf->bo && bf->bo->bin_obj, NULL);

	RBinAddr *ptr = R_NEW0 (RBinAddr);
	if (ptr) {
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
}

static RList* entries(RBinFile *bf) {
	r_return_val_if_fail (bf && bf->bo && bf->bo->bin_obj, NULL);

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

		if (ptr->vaddr != (ut64)eo->ehdr.e_entry && Elf_(is_executable) (eo)) {
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
	r_return_val_if_fail (bf && bf->bo && bf->bo->bin_obj, false);

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
	r_return_val_if_fail (bf && bf->bo, NULL);

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
	r_return_val_if_fail (bf && bf->bo && bf->bo->bin_obj, NULL);

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
	r_return_val_if_fail (eo && rel, NULL);
	ut64 B = eo->baddr;
	ut64 P = rel->rva; // rva has taken baddr into account
	RBinReloc *r = R_NEW0 (RBinReloc);
	if (!r) {
		return NULL;
	}
	r->import = NULL;
	r->symbol = NULL;
	r->is_ifunc = false;
	r->addend = rel->addend;
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

	#define SET(T) r->type = R_BIN_RELOC_ ## T; r->additive = 0; return r
	#define ADD(T, A) r->type = R_BIN_RELOC_ ## T; r->addend += A; r->additive = rel->mode == DT_RELA; return r

	switch (eo->ehdr.e_machine) {
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
		case R_386_IRELATIVE: r->is_ifunc = true; SET(32);
		default: break;
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
		default: break;
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
		case R_RISCV_NONE:      break;
		case R_RISCV_JUMP_SLOT: ADD(64, 0); break;
		case R_RISCV_RELATIVE:  ADD(64, B); break;
		default: ADD(64, got_addr); break; // reg relocations
		}
		break;
	case EM_AARCH64: switch (rel->type) {
		case R_AARCH64_NONE:      break;
		case R_AARCH64_ABS32:     ADD (32, 0); break;
		case R_AARCH64_ABS16:     ADD (16, 0); break;
		case R_AARCH64_GLOB_DAT:  SET (64); break;
		case R_AARCH64_JUMP_SLOT: SET (64); break;
		case R_AARCH64_RELATIVE:  ADD (64, B); break;
		default: break; // reg relocations
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
	case EM_BPF: switch (rel->type) {
		case R_BPF_NONE:        break;
		case R_BPF_64_64:       r->vaddr += 4; ADD (32, 0); break;
		case R_BPF_64_ABS64:    ADD (64, 0); break;
		case R_BPF_64_ABS32:    ADD (32, 0); break;
		case R_BPF_64_NODYLD32: ADD (32, 0); break;
		default:
			R_LOG_DEBUG ("unimplemented ELF/BPF reloc type %d", rel->type);
			break;
		}
		break;
	case EM_MIPS:
		ADD (32, 0);
		break;
	case EM_SPARC:
	case EM_SPARCV9:
	case EM_SPARC32PLUS:
		ADD (32, 0);
		break;
	default:
		R_LOG_DEBUG ("unimplemented ELF reloc type %d", rel->type);
		break;
	}
#undef SET
#undef ADD
	free (r);
	return NULL;
}

static RList* relocs(RBinFile *bf) {
	r_return_val_if_fail (bf && bf->bo && bf->bo->bin_obj, NULL);
	RList *ret = NULL;
	ELFOBJ *eo = bf->bo->bin_obj;
	if (!(ret = r_list_newf (free))) {
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
		}
	}

	ht_up_free (reloc_ht);
	return ret;
}

static void _patch_reloc(ELFOBJ *bo, ut16 e_machine, RIOBind *iob, RBinElfReloc *rel, ut64 S, ut64 B, ut64 L) {
	ut64 V = 0;
	ut64 A = rel->addend;
	ut64 P = rel->rva;
	ut8 buf[8] = {0};
	switch (e_machine) {
	case EM_ARM:
		if (!rel->sym && rel->mode == DT_REL) {
			iob->read_at (iob->io, rel->rva, buf, 4);
			V = r_read_ble32 (buf, bo->endian);
		} else {
			V = S + A;
		}
		r_write_le32 (buf, V);
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
 		default:
 			break;
 		}
 		break;
	case EM_X86_64: {
		int word = 0;
		switch (rel->type) {
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
	}
}

static RList* patch_relocs(RBinFile *bf) {
	r_return_val_if_fail (bf && bf->rbin, NULL);
	RList *ret = NULL;
	RBinReloc *ptr = NULL;
	HtUU *relocs_by_sym;
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
	if (!(ret = r_list_newf ((RListFree)free))) {
		return NULL;
	}
	if (!(relocs_by_sym = ht_uu_new0 ())) {
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
		//ut64 raddr = sym_addr? sym_addr: vaddr;
		ut64 raddr = (sym_addr && sym_addr != UT64_MAX)? sym_addr: vaddr;
		_patch_reloc (eo, eo->ehdr.e_machine, &b->iob, reloc, raddr, 0, plt_entry_addr);
		if (!(ptr = reloc_convert (eo, reloc, n_vaddr))) {
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
		# define R_BIN_RANDOMDATA_RETGUARD_SZ 48
		if (!strcmp (section->name, ".openbsd.randomdata")) {
			// The retguard cookie adds 8 per return function inst.
			ret->has_retguard = (section->size >= R_BIN_RANDOMDATA_RETGUARD_SZ);
			break;
		}
	}
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
	if (!ret) {
		return NULL;
	}
	ret->file = bf->file
		? strdup (bf->file)
		: NULL;
	void *obj = bf->bo->bin_obj;
	char *str;
	if ((str = Elf_(get_rpath)(obj))) {
		ret->rpath = strdup (str);
		free (str);
	} else {
		ret->rpath = strdup ("NONE");
	}
	if (!(str = Elf_(get_file_type) (obj))) {
		free (ret);
		return NULL;
	}
	ret->type = str;
	ret->has_pi = (strstr (str, "DYN"))? 1: 0;
	ret->has_lit = true;
	ret->has_sanitizers = has_sanitizers (bf);
	if (!(str = Elf_(get_elf_class) (obj))) {
		free (ret);
		return NULL;
	}
	ret->bclass = str;
	if (!(str = Elf_(get_osabi_name) (obj))) {
		free (ret);
		return NULL;
	}
	ret->os = str;
	if (!(str = Elf_(get_osabi_name) (obj))) {
		free (ret);
		return NULL;
	}
	ret->subsystem = str;
	if (!(str = Elf_(get_machine_name) (obj))) {
		free (ret);
		return NULL;
	}
	ret->machine = str;
	if (!(str = Elf_(get_arch) (obj))) {
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
	#define ROW(nam, siz, val, fmt, cmt) \
		r_list_append (ret, r_bin_field_new (addr, addr, val, siz, nam, cmt, fmt, false));
	if (r_buf_size (bf->buf) < sizeof (Elf_ (Ehdr))) {
		return ret;
	}
	ut64 addr = 0;
	ROW ("ELF", 4, r_buf_read_le32_at (bf->buf, addr), "x", NULL);
	addr += 0x10;
	ROW ("Type", 2, r_buf_read_le16_at (bf->buf, addr), "w", NULL);
	addr += 0x2;
	ROW ("Machine", 2, r_buf_read_le16_at (bf->buf, addr), "w", NULL);
	addr += 0x2;
	ROW ("Version", 4, r_buf_read_le32_at (bf->buf, addr), "x", NULL);
	addr += 0x4;

	if (r_buf_read8_at (bf->buf, 0x04) == 1) {
		ROW ("Entry point", 4, r_buf_read_le32_at (bf->buf, addr), "x", NULL);
		addr += 0x4;
		ROW ("PhOff", 4, r_buf_read_le32_at (bf->buf, addr), "x", NULL);
		addr += 0x4;
		ut32 shoff = r_buf_read_le32_at (bf->buf, addr);
		ROW ("ShOff", 4, shoff, "x", NULL);
		addr += 0x4;
	} else {
		ROW ("EntryPoint", 8, r_buf_read_le64_at (bf->buf, addr), "q", NULL);
		addr += 0x8;
		ut64 phoff = r_buf_read_le64_at (bf->buf, addr);
		ROW ("PhOff", 8, phoff, "q", NULL);
		addr += 0x8;
		ut64 shoff = r_buf_read_le64_at (bf->buf, addr);
		ROW ("ShOff", 8, shoff, "q", NULL);
		addr += 0x8;
	}

	ROW ("Flags", 4, r_buf_read_le32_at (bf->buf, addr), "x", NULL);
	addr += 0x4;
	ROW ("EhSize", 2, r_buf_read_le16_at (bf->buf, addr), "w", NULL);
	addr += 0x2;
	ROW ("PhentSize", 2, r_buf_read_le16_at (bf->buf, addr), "w", NULL);
	addr += 0x2;
	ROW ("PhNum", 2, r_buf_read_le16_at (bf->buf, addr), "w", NULL);
	addr += 0x2;
	ROW ("ShentSize", 2, r_buf_read_le16_at (bf->buf, addr), "w", NULL);
	addr += 0x2;
	ROW ("ShNum", 2, r_buf_read_le16_at (bf->buf, addr), "w", NULL);
	addr += 0x2;
	ROW ("ShrStrndx", 2, r_buf_read_le16_at (bf->buf, addr), "w", NULL);

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
	}
	return off + len;
}
