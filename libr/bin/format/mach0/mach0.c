/* radare - LGPL - Copyright 2010-2014 - nibble, pancake */

#include <stdio.h>
#include <r_types.h>
#include <r_util.h>
#include "mach0.h"

static int MACH0_(r_bin_mach0_addr_to_offset)(struct MACH0_(r_bin_mach0_obj_t)* bin, ut64 addr) {
	ut64 section_base, section_size;
	int i;

	if (!bin->sects)
		return 0;
	for (i = 0; i < bin->nsects; i++) {
		section_base = (ut64)bin->sects[i].addr;
		section_size = (ut64)bin->sects[i].size;
		if (addr >= section_base && addr < section_base + section_size) {
			if (bin->sects[i].offset == 0)
				return 0;
			return bin->sects[i].offset + (addr - section_base);
		}
	}
	return 0;
}

static int MACH0_(r_bin_mach0_init_hdr)(struct MACH0_(r_bin_mach0_obj_t)* bin) {
	ut32 magic = 0;
	int len;

	if (r_buf_read_at (bin->b, 0, (ut8*)&magic, 4) == -1) {
		eprintf ("Error: read (magic)\n");
		return R_FALSE;
	}
	if (magic == MACH0_(MH_MAGIC))
		bin->endian = !LIL_ENDIAN;
	else if (magic == MACH0_(MH_CIGAM))
		bin->endian = LIL_ENDIAN;
	else if (magic == FAT_CIGAM)
		bin->endian = LIL_ENDIAN;
	else return R_FALSE; // object files are magic == 0, but body is different :?
	len = r_buf_fread_at (bin->b, 0, (ut8*)&bin->hdr, 
#if R_BIN_MACH064
		bin->endian?"8I":"8i", 1
#else
		bin->endian?"7I":"7i", 1
#endif
	);
	if (len == -1) {
		eprintf ("Error: read (hdr)\n");
		return R_FALSE;
	}
	return R_TRUE;
}

static int MACH0_(r_bin_mach0_parse_seg)(struct MACH0_(r_bin_mach0_obj_t)* bin, ut64 off) {
	int sect, len, seg = bin->nsegs - 1;
	if (!(bin->segs = realloc (bin->segs, bin->nsegs * sizeof(struct MACH0_(segment_command))))) {
		perror ("realloc (seg)");
		return R_FALSE;
	}
#if R_BIN_MACH064
	len = r_buf_fread_at (bin->b, off, (ut8*)&bin->segs[seg],
		bin->endian?"2I16c4L4I":"2i16c4l4i", 1);
#else
	len = r_buf_fread_at (bin->b, off, (ut8*)&bin->segs[seg],
		bin->endian?"2I16c8I":"2i16c8i", 1);
#endif
	if (len == -1) {
		eprintf ("Error: read (seg)\n");
		return R_FALSE;
	}
	if (bin->segs[seg].nsects > 0) {
		sect = bin->nsects;
		bin->nsects += bin->segs[seg].nsects;
		if (bin->nsects > 128) {
			eprintf ("WARNING: mach0 header contains too many sections. Wrapping to 128\n");
			bin->nsects = 128;
		}
		if (!(bin->sects = realloc (bin->sects, bin->nsects * sizeof (struct MACH0_(section))))) {
			perror ("realloc (sects)");
			return R_FALSE;
		}
		len = r_buf_fread_at (bin->b, off + sizeof (struct MACH0_(segment_command)),
			(ut8*)&bin->sects[sect],
#if R_BIN_MACH064
			bin->endian?"16c16c2L8I":"16c16c2l8i", 
#else
			bin->endian?"16c16c9I":"16c16c9i", 
#endif
			bin->nsects - sect);
		if (len == -1) {
			eprintf ("Error: read (sects)\n");
			return R_FALSE;
		}
	}
	return R_TRUE;
}

static int MACH0_(r_bin_mach0_parse_symtab)(struct MACH0_(r_bin_mach0_obj_t)* bin, ut64 off) {
	struct symtab_command st;
	int len = r_buf_fread_at(bin->b, off, (ut8*)&st, bin->endian?"6I":"6i", 1);
	if (len == -1) {
		eprintf ("Error: read (symtab)\n");
		return R_FALSE;
	}
	if (st.strsize > 0 && st.strsize < bin->size && st.nsyms > 0) {
		bin->nsymtab = st.nsyms;
		if (!(bin->symstr = malloc (st.strsize))) {
			perror ("malloc (symstr)");
			return R_FALSE;
		}
		bin->symstrlen = st.strsize;
		if (r_buf_read_at (bin->b, st.stroff, (ut8*)bin->symstr, st.strsize) == -1) {
			eprintf ("Error: read (symstr)\n");
			R_FREE (bin->symstr);
			return R_FALSE;
		}
		if (!(bin->symtab = malloc (bin->nsymtab * sizeof (struct MACH0_(nlist))))) {
			perror ("malloc (symtab)");
			return R_FALSE;
		}
#if R_BIN_MACH064
		len = r_buf_fread_at (bin->b, st.symoff, (ut8*)bin->symtab,
			bin->endian?"I2cSL":"i2csl", bin->nsymtab);
#else
		len = r_buf_fread_at (bin->b, st.symoff, (ut8*)bin->symtab,
			bin->endian?"I2cSI":"i2csi", bin->nsymtab);
#endif
		if (len == -1) {
			eprintf ("Error: read (nlist)\n");
			R_FREE (bin->symtab);
			return R_FALSE;
		}
	}
	return R_TRUE;
}

static int MACH0_(r_bin_mach0_parse_dysymtab)(struct MACH0_(r_bin_mach0_obj_t)* bin, ut64 off) {
	int len;

	len = r_buf_fread_at(bin->b, off, (ut8*)&bin->dysymtab, bin->endian?"20I":"20i", 1);
	if (len == -1) {
		eprintf ("Error: read (dysymtab)\n");
		return R_FALSE;
	}
	bin->ntoc = bin->dysymtab.ntoc;
	if (bin->ntoc > 0) {
		if (!(bin->toc = malloc (bin->ntoc * sizeof(struct dylib_table_of_contents)))) {
			perror ("malloc (toc)");
			return R_FALSE;
		}
		len = r_buf_fread_at(bin->b, bin->dysymtab.tocoff,
			(ut8*)bin->toc, bin->endian?"2I":"2i", bin->ntoc);
		if (len == -1) {
			eprintf ("Error: read (toc)\n");
			R_FREE (bin->toc);
			return R_FALSE;
		}
	}
	bin->nmodtab = bin->dysymtab.nmodtab;
	if (bin->nmodtab > 0) {
		if (!(bin->modtab = malloc (bin->nmodtab * sizeof(struct MACH0_(dylib_module))))) {
			perror ("malloc (modtab)");
			return R_FALSE;
		}
#if R_BIN_MACH064
		len = r_buf_fread_at (bin->b, bin->dysymtab.modtaboff,
			(ut8*)bin->modtab, bin->endian?"12IL":"12il", bin->nmodtab);
#else
		len = r_buf_fread_at (bin->b, bin->dysymtab.modtaboff,
			(ut8*)bin->modtab, bin->endian?"13I":"13i", bin->nmodtab);
#endif
		if (len == -1) {
			eprintf ("Error: read (modtab)\n");
			R_FREE (bin->modtab);
			return R_FALSE;
		}
	}
	bin->nindirectsyms = bin->dysymtab.nindirectsyms;
	if (bin->nindirectsyms > 0) {
		if (!(bin->indirectsyms = malloc (bin->nindirectsyms * sizeof(ut32)))) {
			perror ("malloc (indirectsyms)");
			return R_FALSE;
		}
		len = r_buf_fread_at (bin->b, bin->dysymtab.indirectsymoff,
				(ut8*)bin->indirectsyms, bin->endian?"I":"i", bin->nindirectsyms);
		if (len == -1) {
			eprintf ("Error: read (indirect syms)\n");
			R_FREE (bin->indirectsyms);
			return R_FALSE;
		}
	}
	/* TODO extrefsyms, extrel, locrel */
	return R_TRUE;
}

static int MACH0_(r_bin_mach0_parse_thread)(struct MACH0_(r_bin_mach0_obj_t)* bin, ut64 off) {
	int len = r_buf_fread_at (bin->b, off, (ut8*)&bin->thread,
		bin->endian?"4I":"4i", 1);
	if (len == -1) {
		eprintf ("Error: read (thread)\n");
		return R_FALSE;
	}
	switch (bin->hdr.cputype) {
	case CPU_TYPE_I386:
	case CPU_TYPE_X86_64:
		switch (bin->thread.flavor) {
		case X86_THREAD_STATE32:
			if ((len = r_buf_fread_at (bin->b, off + sizeof(struct thread_command),
				(ut8*)&bin->thread_state.x86_32, "16i", 1)) == -1) {
				eprintf ("Error: read (thread state x86_32)\n");
				return R_FALSE;
			}
			bin->entry = bin->thread_state.x86_32.eip;
			sdb_num_set (bin->kv, "mach0.entry", off+sizeof (struct thread_command) + 
				r_offsetof (struct x86_thread_state32, eip), 0);
			break;
		case X86_THREAD_STATE64:
			if ((len = r_buf_fread_at (bin->b, off + sizeof (struct thread_command)+4,
				(ut8*)&bin->thread_state.x86_64, "32l", 1)) == -1) {
				eprintf ("Error: read (thread state x86_64)\n");
				return R_FALSE;
			}
			bin->entry = bin->thread_state.x86_64.rip;
			sdb_num_set (bin->kv, "mach0.entry", off+sizeof(struct thread_command) + 
				r_offsetof (struct x86_thread_state64, rip), 0);
			break;
		//default: eprintf ("Unknown type\n");
		}
		break;
	case CPU_TYPE_POWERPC:
	case CPU_TYPE_POWERPC64:
		if (bin->thread.flavor == X86_THREAD_STATE32) {
			if ((len = r_buf_fread_at (bin->b, off + sizeof(struct thread_command),
				(ut8*)&bin->thread_state.ppc_32, bin->endian?"40I":"40i", 1)) == -1) {
				eprintf ("Error: read (thread state ppc_32)\n");
				return R_FALSE;
			}
			bin->entry = bin->thread_state.ppc_32.srr0;
		} else if (bin->thread.flavor == X86_THREAD_STATE64) {
			if ((len = r_buf_fread_at (bin->b, off + sizeof(struct thread_command),
				(ut8*)&bin->thread_state.ppc_64, bin->endian?"34LI3LI":"34li3li", 1)) == -1) {
				eprintf ("Error: read (thread state ppc_64)\n");
				return R_FALSE;
			}
			bin->entry = bin->thread_state.ppc_64.srr0;
		}
		break;
	case CPU_TYPE_ARM:
		if ((len = r_buf_fread_at (bin->b, off + sizeof (struct thread_command),
				(ut8*)&bin->thread_state.arm_32, bin->endian?"17I":"17i", 1)) == -1) {
			eprintf ("Error: read (thread state arm)\n");
			return R_FALSE;
		}
		bin->entry = bin->thread_state.arm_32.r15;
		break;
	case CPU_TYPE_ARM64:
		if ((len = r_buf_fread_at(bin->b, off + sizeof (struct thread_command),
				(ut8*)&bin->thread_state.arm_64, bin->endian?"34LI1I":"34Li1i", 1)) == -1) {
			eprintf ("Error: read (thread state arm)\n");
			return R_FALSE;
		}
		bin->entry = bin->thread_state.arm_64.pc;
		break;
	default:
		eprintf ("Error: read (unknown thread state structure)\n");
		return R_FALSE;
	}
	return R_TRUE;
}

static int MACH0_(r_bin_mach0_parse_dylib)(struct MACH0_(r_bin_mach0_obj_t)* bin, ut64 off) {
	struct dylib_command dl;
	int lib, len;

	lib = bin->nlibs - 1;
	if (!(bin->libs = realloc (bin->libs, bin->nlibs * R_BIN_MACH0_STRING_LENGTH))) {
		perror ("realloc (libs)");
		return R_FALSE;
	}
	len = r_buf_fread_at (bin->b, off, (ut8*)&dl, bin->endian?"6I":"6i", 1);
	if (len == -1) {
		eprintf ("Error: read (dylib)\n");
		return R_FALSE;
	}
	if (r_buf_read_at (bin->b, off+dl.dylib.name.offset, (ut8*)bin->libs[lib], R_BIN_MACH0_STRING_LENGTH) == -1) {
		eprintf ("Error: read (dylib str)");
		return R_FALSE;
	}
	return R_TRUE;
}

static int MACH0_(r_bin_mach0_init_items)(struct MACH0_(r_bin_mach0_obj_t)* bin) {
	struct load_command lc = {0, 0};
	ut64 off = 0LL;
	int i, len;

	bin->os = 0;
	for (i = 0, off = sizeof (struct MACH0_(mach_header)); \
			i < bin->hdr.ncmds; i++, off += lc.cmdsize) {
		len = r_buf_fread_at (bin->b, off, (ut8*)&lc, bin->endian?"2I":"2i", 1);
		if (len == -1) {
			eprintf ("Error: read (lc) at 0x%08"PFMT64x"\n", off);
			return R_FALSE;
		}
		if (lc.cmdsize<1 || off+lc.cmdsize>bin->size) {
			eprintf ("Warning: mach0_header %d = cmdsize<1.\n", i);
			break;
		}
		switch (lc.cmd) {
		case LC_DATA_IN_CODE:
			// TODO table of non-instructions in __text
			break;
		case LC_RPATH:
			//eprintf ("--->\n");
			break;
		case LC_SEGMENT_64:
		case LC_SEGMENT:
			bin->nsegs++;
			if (!MACH0_(r_bin_mach0_parse_seg)(bin, off)) {
				bin->nsegs--;
				return R_FALSE;
			}
			break;
		case LC_SYMTAB:
			if (!MACH0_(r_bin_mach0_parse_symtab)(bin, off))
				return R_FALSE;
			break;
		case LC_DYSYMTAB:
			if (!MACH0_(r_bin_mach0_parse_dysymtab)(bin, off))
				return R_FALSE;
			break;
		case LC_DYLIB_CODE_SIGN_DRS:
			//eprintf ("[mach0] code is signed\n");
			break;
		case LC_VERSION_MIN_MACOSX:
			bin->os = 1;
			// set OS = osx
			//eprintf ("[mach0] Requires OSX >= x\n");
			break;
		case LC_VERSION_MIN_IPHONEOS:
			bin->os = 2;
			// set OS = ios
			//eprintf ("[mach0] Requires iOS >= x\n");
			break;
		case LC_UUID:
			//eprintf ("[mach0] UUID\n");
			break;
		case LC_LOAD_DYLINKER:
			//eprintf ("[mach0] load dynamic linker\n");
			break;
		case LC_MAIN:
		case LC_UNIXTHREAD:
		case LC_THREAD:
			if (!MACH0_(r_bin_mach0_parse_thread)(bin, off))
				return R_FALSE;
			break;
		case LC_LOAD_DYLIB:
			bin->nlibs++;
			if (!MACH0_(r_bin_mach0_parse_dylib)(bin, off))
				return R_FALSE;
			break;
		case LC_DYLD_INFO:
		case LC_DYLD_INFO_ONLY:
			bin->dyld_info = malloc (sizeof(struct dyld_info_command));
			if (r_buf_fread_at (bin->b, off, (ut8*)bin->dyld_info,
					bin->endian?"12I":"12i", 1) == -1) {
				free (bin->dyld_info);
				bin->dyld_info = NULL;
				eprintf ("Error: read (LC_DYLD_INFO) at 0x%08"PFMT64x"\n", off);
			}
			break;
		default:
			///eprintf ("Unknown header command %x\n", lc.cmd);
			break;
		}
	}
	return R_TRUE;
}

static int MACH0_(r_bin_mach0_init)(struct MACH0_(r_bin_mach0_obj_t)* bin) {
	if (!MACH0_(r_bin_mach0_init_hdr)(bin)) {
		eprintf ("Warning: File is not MACH0\n");
		return R_FALSE;
	}
	if (!MACH0_(r_bin_mach0_init_items)(bin))
		eprintf ("Warning: Cannot initialize items\n");
	return R_TRUE;
}

void* MACH0_(r_bin_mach0_free)(struct MACH0_(r_bin_mach0_obj_t)* bin) {
	if (!bin) return NULL;
	free (bin->segs);
	free (bin->sects);
	free (bin->symtab);
	free (bin->symstr);
	free (bin->indirectsyms);
	free (bin->imports_by_ord);
	free (bin->dyld_info);
	free (bin->toc);
	free (bin->modtab);
	free (bin->libs);
	r_buf_free (bin->b);
	free (bin);
	return NULL;
}

struct MACH0_(r_bin_mach0_obj_t)* MACH0_(r_bin_mach0_new)(const char* file) {
	ut8 *buf;
	struct MACH0_(r_bin_mach0_obj_t) *bin;

	if (!(bin = malloc(sizeof(struct MACH0_(r_bin_mach0_obj_t)))))
		return NULL;
	memset (bin, 0, sizeof (struct MACH0_(r_bin_mach0_obj_t)));
	bin->file = file;
	if (!(buf = (ut8*)r_file_slurp(file, &bin->size))) 
		return MACH0_(r_bin_mach0_free)(bin);
	bin->b = r_buf_new ();
	if (!r_buf_set_bytes(bin->b, buf, bin->size))
		return MACH0_(r_bin_mach0_free)(bin);
	free (buf);

	bin->dyld_info = NULL;

	if (!MACH0_(r_bin_mach0_init)(bin))
		return MACH0_(r_bin_mach0_free)(bin);

	bin->imports_by_ord_size = 0;
	bin->imports_by_ord = NULL;

	return bin;
}

struct MACH0_(r_bin_mach0_obj_t)* MACH0_(r_bin_mach0_new_buf)(RBuffer *buf) {
	struct MACH0_(r_bin_mach0_obj_t) *bin = R_NEW0 (struct MACH0_(r_bin_mach0_obj_t));
	if (!bin) return NULL;
	bin->kv = sdb_new (NULL, "bin.mach0", 0);
	bin->b = buf;
	bin->size = buf->length;
	if (!MACH0_(r_bin_mach0_init)(bin))
		return MACH0_(r_bin_mach0_free)(bin);
	return bin;
}

// prot: r = 1, w = 2, x = 4
// perm: r = 4, w = 2, x = 1
static int prot2perm (int x) {
	int r = 0;
	if (x&1) r |= 4;
	if (x&2) r |= 2;
	if (x&4) r |= 1;
	return r;
}

struct r_bin_mach0_section_t* MACH0_(r_bin_mach0_get_sections)(struct MACH0_(r_bin_mach0_obj_t)* bin) {
	struct r_bin_mach0_section_t *sections;
	char segname[17], sectname[17];
	int i, j, to;

	if (!bin->sects)
		return NULL;
	to = R_MIN (bin->nsects, 128); // limit number of sections here to avoid fuzzed bins
	if (!(sections = malloc ((bin->nsects + 1) * sizeof (struct r_bin_mach0_section_t))))
		return NULL;
	for (i = 0; i<to; i++) {
		sections[i].offset = (ut64)bin->sects[i].offset;
		sections[i].addr = (ut64)bin->sects[i].addr;
		sections[i].size = (ut64)bin->sects[i].size;
		sections[i].align = bin->sects[i].align;
		sections[i].flags = bin->sects[i].flags;
		strncpy (segname, bin->sects[i].segname, sizeof (segname)-1);
		strncpy (sectname, bin->sects[i].sectname, sizeof (sectname)-1);
		// hack to support multiple sections with same name
		snprintf (segname, sizeof (segname), "%d", i); // wtf
		snprintf (sectname, sizeof (sectname), "%s", bin->sects[i].sectname);
		for (j=0; j<bin->nsegs; j++) {
			if (sections[i].addr >= bin->segs[j].vmaddr &&
				sections[i].addr < (bin->segs[j].vmaddr + bin->segs[j].vmsize)) {
				sections[i].srwx = prot2perm (bin->segs[j].initprot);
				break;
			}
		}
		// XXX: if two sections have the same name are merged :O
		// XXX: append section index in flag name maybe?
		// XXX: do not load out of bound sections?
		// XXX: load segments instead of sections? what about PAGEZERO and ...
		snprintf (sections[i].name, sizeof (sections[i].name), "%s.%s", segname, sectname);
		sections[i].last = 0;
	}
	sections[i].last = 1;
	return sections;
}

static int MACH0_(r_bin_mach0_parse_import_stub)(struct MACH0_(r_bin_mach0_obj_t)* bin, struct r_bin_mach0_symbol_t *symbol, int idx) {
	int i, j, nsyms, stridx;
	const char *symstr;

	symbol->offset = 0LL;
	symbol->addr = 0LL;
	symbol->name[0] = '\0';
	for (i = 0; i < bin->nsects; i++) {
		if ((bin->sects[i].flags & SECTION_TYPE) == S_SYMBOL_STUBS &&
				bin->sects[i].reserved2 > 0) {
			nsyms = (int)(bin->sects[i].size / bin->sects[i].reserved2);
			for (j = 0; j < nsyms; j++) {
				if (bin->sects[i].reserved1 + j >= bin->nindirectsyms)
					continue;
				if (idx != bin->indirectsyms[bin->sects[i].reserved1 + j])
					continue;
				symbol->type = R_BIN_MACH0_SYMBOL_TYPE_LOCAL;
				symbol->offset = bin->sects[i].offset + j * bin->sects[i].reserved2;
				symbol->addr = bin->sects[i].addr + j * bin->sects[i].reserved2;
				stridx = bin->symtab[idx].n_un.n_strx;
				if (stridx>=0 && stridx<bin->symstrlen)
					symstr = (char *)bin->symstr+stridx;
				else symstr = "???";

				// Remove the extra underscore that every import seems to have in Mach-O.
				if (*symstr == '_')
					symstr++;

				snprintf (symbol->name, R_BIN_MACH0_STRING_LENGTH, "imp.%s", symstr);
				return R_TRUE;
			}
		}
	}
	return R_FALSE;
}

struct r_bin_mach0_symbol_t* MACH0_(r_bin_mach0_get_symbols)(struct MACH0_(r_bin_mach0_obj_t)* bin) {
	const char *symstr;
	struct r_bin_mach0_symbol_t *symbols;
	int from, to, i, j, s, stridx, symbols_size;

	if (!bin->symtab || !bin->symstr)
		return NULL;
	symbols_size = (bin->dysymtab.nextdefsym + \
			bin->dysymtab.nlocalsym + \
			bin->dysymtab.nundefsym + 1) * \
			sizeof (struct r_bin_mach0_symbol_t);

	if (!(symbols = malloc (symbols_size)))
		return NULL;
	for (s = j = 0; s < 2; s++) {
		if (s == 0) {
			from = bin->dysymtab.iextdefsym;
			to = from + bin->dysymtab.nextdefsym;
		} else {
			from = bin->dysymtab.ilocalsym;
			to = from + bin->dysymtab.nlocalsym;
		}
		from = R_MIN (R_MAX (0, from), symbols_size/sizeof(struct r_bin_mach0_symbol_t));
		to = R_MIN (to , symbols_size/sizeof(struct r_bin_mach0_symbol_t));
		if (to>0x40000) {
			eprintf ("WARNING: corrupted mach0 header: symbol table is too big\n");
			free (symbols);
			return NULL;
		}
		for (i = from; i < to; i++, j++) {
			symbols[j].offset = MACH0_(r_bin_mach0_addr_to_offset)(bin, bin->symtab[i].n_value);
			symbols[j].addr = bin->symtab[i].n_value;
			symbols[j].size = 0; /* TODO: Is it anywhere? */
			if (bin->symtab[i].n_type & N_EXT)
				symbols[j].type = R_BIN_MACH0_SYMBOL_TYPE_EXT;
			else symbols[j].type = R_BIN_MACH0_SYMBOL_TYPE_LOCAL;
			stridx = bin->symtab[i].n_un.n_strx;
			if (stridx>=0 && stridx<bin->symstrlen)
				symstr = (char*)bin->symstr+stridx;
			else symstr = "???";
			strncpy (symbols[j].name, symstr, R_BIN_MACH0_STRING_LENGTH);
			symbols[j].last = 0;
		}
	}
	for (i = bin->dysymtab.iundefsym; i < bin->dysymtab.iundefsym + bin->dysymtab.nundefsym; i++)
		if (MACH0_(r_bin_mach0_parse_import_stub)(bin, &symbols[j], i))
			symbols[j++].last = 0;
	symbols[j].last = 1;
	return symbols;
}

static int MACH0_(r_bin_mach0_parse_import_ptr)(struct MACH0_(r_bin_mach0_obj_t)* bin, struct r_bin_mach0_reloc_t *reloc, int idx) {
	int i, j, sym, wordsize;
	ut32 stype;

	wordsize = MACH0_(r_bin_mach0_get_bits)(bin) / 8;
	if ((bin->symtab[idx].n_desc & REFERENCE_TYPE) == REFERENCE_FLAG_UNDEFINED_LAZY)
		stype = S_LAZY_SYMBOL_POINTERS;
	else stype = S_NON_LAZY_SYMBOL_POINTERS;

	reloc->offset = 0;
	reloc->addr = 0;
	reloc->addend = 0;
#define CASE(T) case (T / 8): reloc->type = R_BIN_RELOC_ ## T; break
	switch (wordsize) {
		CASE(8);
		CASE(16);
		CASE(32);
		CASE(64);
		default: return R_FALSE;
	}
#undef CASE

	for (i = 0; i < bin->nsects; i++) {
		if ((bin->sects[i].flags & SECTION_TYPE) == stype) {
			for (j=0, sym=-1; bin->sects[i].reserved1+j < bin->nindirectsyms; j++)
				if (idx == bin->indirectsyms[bin->sects[i].reserved1 + j]) {
					sym = j;
					break;
				}

			reloc->offset = sym == -1 ? 0 : bin->sects[i].offset + sym * wordsize;
			reloc->addr = sym == -1 ? 0 : bin->sects[i].addr + sym * wordsize;
			return R_TRUE;
		}
	}
	return R_FALSE;
}

struct r_bin_mach0_import_t* MACH0_(r_bin_mach0_get_imports)(struct MACH0_(r_bin_mach0_obj_t)* bin) {
	struct r_bin_mach0_import_t *imports;
	int i, j, idx, stridx;
	const char *symstr;

	if (!bin->symtab || !bin->symstr || !bin->sects || !bin->indirectsyms)
		return NULL;
	if (!(imports = malloc ((bin->dysymtab.nundefsym + 1) * sizeof(struct r_bin_mach0_import_t))))
		return NULL;
	for (i = j = 0; i < bin->dysymtab.nundefsym; i++) {
		idx = bin->dysymtab.iundefsym +i;
		if (idx<0 || idx>bin->nsymtab) {
			eprintf ("WARNING: Imports index out of bounds. Ignoring relocs\n");
			free (imports);
			return NULL;
		}
		stridx = bin->symtab[idx].n_un.n_strx;
		if (stridx >= 0 && stridx < bin->symstrlen)
			symstr = (char *)bin->symstr + stridx;
		else symstr = "";
		if (!*symstr)
			continue;
		strncpy (imports[j].name, symstr, R_BIN_MACH0_STRING_LENGTH);
		imports[j].ord = i;
		imports[j++].last = 0;
	}
	imports[j].last = 1;

	if (!bin->imports_by_ord_size) {
		bin->imports_by_ord_size = j;
		bin->imports_by_ord = (RBinImport**)malloc (j * sizeof (RBinImport*));
		memset (bin->imports_by_ord, 0, j * sizeof (RBinImport*));
	}

	return imports;
}

static ut64 read_uleb128(ut8 **p) {
	ut64 r = 0, byte;
	int bit = 0;
	do {
		if (bit > 63) {
			eprintf ("uleb128 too big for u64 (%d bits) - partial result: 0x%08"PFMT64x"\n", bit, r);
			return r;
		}

		byte = *(*p)++;
		r |= (byte & 0x7f) << bit;
		bit += 7;
	} while (byte & 0x80);
	return r;
}


static st64 read_sleb128(ut8 **p) {
	st64 r = 0, byte;
	int bit = 0;
	do {
		byte = *(*p)++;
		r |= (byte & 0x7f) << bit;
		bit += 7;
	} while (byte & 0x80);

	// Sign extend negative numbers.
	if (byte & 0x40)
		r |= -1LL << bit;
	return r;
}

struct r_bin_mach0_reloc_t* MACH0_(r_bin_mach0_get_relocs)(struct MACH0_(r_bin_mach0_obj_t)* bin) {
	struct r_bin_mach0_reloc_t *relocs;
	int i = 0;

	if (bin->dyld_info) {
		ut8 *opcodes, *p, *end, type, rel_type;
		int lib_ord, seg_idx = -1, sym_ord = -1, wordsize;
		size_t j, count, skip, bind_size, lazy_size;
		st64 addend = 0;
		ut64 addr = 0LL;

		wordsize = MACH0_(r_bin_mach0_get_bits)(bin) / 8;
#define CASE(T) case (T / 8): rel_type = R_BIN_RELOC_ ## T; break
		switch (wordsize) {
			CASE(8);
			CASE(16);
			CASE(32);
			CASE(64);
			default: return NULL;
		}
#undef CASE
		bind_size = bin->dyld_info->bind_size;
		lazy_size = bin->dyld_info->lazy_bind_size;

		if (!bind_size || !lazy_size)
			return NULL;

		// NOTE(eddyb) it's a waste of memory, but we don't know the actual number of relocs.
		if (!(relocs = malloc ((bind_size + lazy_size) * sizeof(struct r_bin_mach0_reloc_t))))
			return NULL;

		opcodes = malloc (bind_size + lazy_size);
		if (r_buf_read_at (bin->b, bin->dyld_info->bind_off, opcodes, bind_size) == -1
			|| r_buf_read_at (bin->b, bin->dyld_info->lazy_bind_off, opcodes + bind_size, lazy_size) == -1) {
			eprintf ("Error: read (dyld_info bind) at 0x%08"PFMT64x"\n", 
			(ut64)(size_t)bin->dyld_info->bind_off);
			free (opcodes);
			relocs[i].last = 1;
			return relocs;
		}

		for (p = opcodes, end = opcodes + bind_size + lazy_size; p < end; ) {
			ut8 imm = *p & BIND_IMMEDIATE_MASK, op = *p & BIND_OPCODE_MASK;
			p++;
			switch (op) {
#define ULEB() read_uleb128 (&p)
#define SLEB() read_sleb128 (&p)
				case BIND_OPCODE_DONE:
					break;
				case BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:
					lib_ord = imm;
					break;
				case BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB:
					lib_ord = ULEB();
					break;
				case BIND_OPCODE_SET_DYLIB_SPECIAL_IMM:
					if (!imm)
						lib_ord = 0;
					else
						lib_ord = (st8)(BIND_OPCODE_MASK | imm);
					break;
				case BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM: {
					char *sym_name = (char*)p;
					//ut8 sym_flags = imm;
					while (*p++);
					sym_ord = -1;
					for (j = 0; j < bin->dysymtab.nundefsym; j++) {
						int stridx = bin->symtab[bin->dysymtab.iundefsym + j].n_un.n_strx;
						if (stridx < 0 || stridx >= bin->symstrlen)
							continue;
						if (!strcmp((char *)bin->symstr + stridx, sym_name)) {
							sym_ord = j;
							break;
						}
					}
					break;
				}
				case BIND_OPCODE_SET_TYPE_IMM:
					type = imm;
					break;
				case BIND_OPCODE_SET_ADDEND_SLEB:
					addend = SLEB();
					break;
				case BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
					seg_idx = imm;
					if (seg_idx > bin->nsegs )
						eprintf ("Error: BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB has unexistent segment %d\n", seg_idx);
					addr = bin->segs[seg_idx].vmaddr + ULEB();
					break;
				case BIND_OPCODE_ADD_ADDR_ULEB:
					addr += ULEB();
					break;

#define DO_BIND() do {\
	if (sym_ord == -1)\
		break;\
	relocs[i].addr = addr;\
	relocs[i].offset = addr - bin->segs[seg_idx].vmaddr + bin->segs[seg_idx].fileoff;\
	if (type == BIND_TYPE_TEXT_PCREL32)\
		relocs[i].addend = addend - (bin->baddr + addr);\
	else\
		relocs[i].addend = addend;\
	relocs[i].ord = sym_ord;\
	relocs[i].type = rel_type;\
	relocs[i++].last = 0;\
} while (0)

				case BIND_OPCODE_DO_BIND:
					DO_BIND();
					addr += wordsize;
					break;
				case BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB:
					DO_BIND();
					addr += ULEB() + wordsize;
					break;
				case BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED:
					DO_BIND();
					addr += imm * wordsize + wordsize;
					break;
				case BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB:
					count = ULEB();
					skip = ULEB();
					for (j = 0; j < count; j++) {
						DO_BIND();
						addr += skip + wordsize;
					}
					break;
#undef DO_BIND

#undef ULEB
#undef SLEB
				default:
					eprintf ("Error: unknown bind opcode 0x%02x in dyld_info\n", *p);
					free (opcodes);
					relocs[i].last = 1;
					return relocs;
			}
		}
		free (opcodes);
	} else {
		int j;
		if (!bin->symtab || !bin->symstr || !bin->sects || !bin->indirectsyms)
			return NULL;
		if (!(relocs = malloc((bin->dysymtab.nundefsym + 1) * sizeof(struct r_bin_mach0_reloc_t))))
			return NULL;
		for (j = 0; j < bin->dysymtab.nundefsym; j++)
			if (MACH0_(r_bin_mach0_parse_import_ptr)(bin, &relocs[i], bin->dysymtab.iundefsym + j)) {
				relocs[i].ord = j;
				relocs[i++].last = 0;
			}
	}
	relocs[i].last = 1;

	return relocs;
}

struct r_bin_mach0_addr_t* MACH0_(r_bin_mach0_get_entrypoint)(struct MACH0_(r_bin_mach0_obj_t)* bin) {
	struct r_bin_mach0_addr_t *entry;
	int i;

	if (!bin->entry && !bin->sects)
		return NULL;
	if (!(entry = malloc (sizeof (struct r_bin_mach0_addr_t))))
		return NULL;
	if (bin->entry) {
		entry->offset = MACH0_(r_bin_mach0_addr_to_offset)(bin, bin->entry);
		entry->addr = bin->entry;
		return entry;
	}
	entry->addr = 0LL;
	if (!bin->entry || (entry->offset==0)) {
		// XXX: section name doesnt matters at all.. just check for exec flags
		for (i = 0; i < bin->nsects; i++) {
			if (!memcmp (bin->sects[i].sectname, "__text", 6)) {
				entry->offset = (ut64)bin->sects[i].offset;
				sdb_num_set (bin->kv, "mach0.entry", entry->offset, 0);
				entry->addr = (ut64)bin->sects[i].addr;
				if (entry->addr==0) // workaround for object files
					entry->addr = entry->offset;
				break;
			}
		}
		bin->entry = entry->addr;
	}
	return entry;
}

struct r_bin_mach0_lib_t* MACH0_(r_bin_mach0_get_libs)(struct MACH0_(r_bin_mach0_obj_t)* bin) {
	struct r_bin_mach0_lib_t *libs;
	int i;

	if (!bin->nlibs)
		return NULL;
	if (!(libs = malloc((bin->nlibs + 1) * sizeof(struct r_bin_mach0_lib_t))))
		return NULL;
	for (i = 0; i < bin->nlibs; i++) {
		strncpy (libs[i].name, bin->libs[i], R_BIN_MACH0_STRING_LENGTH);
		libs[i].name[R_BIN_MACH0_STRING_LENGTH-1] = '\0';
		libs[i].last = 0;
	}
	libs[i].last = 1;
	return libs;
}

ut64 MACH0_(r_bin_mach0_get_baddr)(struct MACH0_(r_bin_mach0_obj_t)* bin) {
	return 0LL;
}

char* MACH0_(r_bin_mach0_get_class)(struct MACH0_(r_bin_mach0_obj_t)* bin) {
#if R_BIN_MACH064
	return r_str_new ("MACH064");
#else
	return r_str_new ("MACH0");
#endif
}

int MACH0_(r_bin_mach0_get_bits)(struct MACH0_(r_bin_mach0_obj_t)* bin) {
#if R_BIN_MACH064
	return 64;
#else
	return 32;
#endif
}

int MACH0_(r_bin_mach0_is_big_endian)(struct MACH0_(r_bin_mach0_obj_t)* bin) {
	return bin->endian;
}

const char* MACH0_(r_bin_mach0_get_os)(struct MACH0_(r_bin_mach0_obj_t)* bin) {
	switch (bin->os) {
	case 1: return "osx";
	case 2: return "ios";
	}
	return "darwin";
}

char* MACH0_(r_bin_mach0_get_cputype)(struct MACH0_(r_bin_mach0_obj_t)* bin) {
	switch (bin->hdr.cputype) {
	case CPU_TYPE_VAX: 	return strdup ("vax");
	case CPU_TYPE_MC680x0:	return strdup ("mc680x0");
	case CPU_TYPE_I386:
	case CPU_TYPE_X86_64:	return strdup ("x86");
	case CPU_TYPE_MC88000:	return strdup ("mc88000");
	case CPU_TYPE_MC98000:	return strdup ("mc98000");
	case CPU_TYPE_HPPA:	return strdup ("hppa");
	case CPU_TYPE_ARM:
	case CPU_TYPE_ARM64:	return strdup ("arm");
	case CPU_TYPE_SPARC:	return strdup ("sparc");
	case CPU_TYPE_MIPS:	return strdup ("mips");
	case CPU_TYPE_I860:	return strdup ("i860");
	case CPU_TYPE_POWERPC:
	case CPU_TYPE_POWERPC64:return strdup ("ppc");
	default:		return strdup ("unknown");
	}
}

// TODO: use const char* 
char* MACH0_(r_bin_mach0_get_cpusubtype)(struct MACH0_(r_bin_mach0_obj_t)* bin) {
	switch (bin->hdr.cputype) {
	case CPU_TYPE_VAX:
		switch (bin->hdr.cpusubtype) {
		case CPU_SUBTYPE_VAX_ALL:	return strdup ("all");
		case CPU_SUBTYPE_VAX780:	return strdup ("vax780");
		case CPU_SUBTYPE_VAX785:	return strdup ("vax785");
		case CPU_SUBTYPE_VAX750:	return strdup ("vax750");
		case CPU_SUBTYPE_VAX730:	return strdup ("vax730");
		case CPU_SUBTYPE_UVAXI:		return strdup ("uvaxI");
		case CPU_SUBTYPE_UVAXII:	return strdup ("uvaxII");
		case CPU_SUBTYPE_VAX8200:	return strdup ("vax8200");
		case CPU_SUBTYPE_VAX8500:	return strdup ("vax8500");
		case CPU_SUBTYPE_VAX8600:	return strdup ("vax8600");
		case CPU_SUBTYPE_VAX8650:	return strdup ("vax8650");
		case CPU_SUBTYPE_VAX8800:	return strdup ("vax8800");
		case CPU_SUBTYPE_UVAXIII:	return strdup ("uvaxIII");
		default:			return strdup ("Unknown vax subtype");
		}
	case CPU_TYPE_MC680x0:
		switch (bin->hdr.cpusubtype) {
		case CPU_SUBTYPE_MC68030:	return strdup ("mc68030");
		case CPU_SUBTYPE_MC68040:	return strdup ("mc68040");
		case CPU_SUBTYPE_MC68030_ONLY:	return strdup ("mc68030 only");
		default:			return strdup ("Unknown mc680x0 subtype");
		}
	case CPU_TYPE_I386:
		switch (bin->hdr.cpusubtype) {
		case CPU_SUBTYPE_386: 			return strdup ("386");
		case CPU_SUBTYPE_486: 			return strdup ("486");
		case CPU_SUBTYPE_486SX: 		return strdup ("486sx");
		case CPU_SUBTYPE_PENT: 			return strdup ("Pentium");
		case CPU_SUBTYPE_PENTPRO: 		return strdup ("Pentium Pro");
		case CPU_SUBTYPE_PENTII_M3: 		return strdup ("Pentium 3 M3");
		case CPU_SUBTYPE_PENTII_M5: 		return strdup ("Pentium 3 M5");
		case CPU_SUBTYPE_CELERON: 		return strdup ("Celeron");
		case CPU_SUBTYPE_CELERON_MOBILE:	return strdup ("Celeron Mobile");
		case CPU_SUBTYPE_PENTIUM_3:		return strdup ("Pentium 3");
		case CPU_SUBTYPE_PENTIUM_3_M:		return strdup ("Pentium 3 M");
		case CPU_SUBTYPE_PENTIUM_3_XEON:	return strdup ("Pentium 3 Xeon");
		case CPU_SUBTYPE_PENTIUM_M:		return strdup ("Pentium Mobile");
		case CPU_SUBTYPE_PENTIUM_4:		return strdup ("Pentium 4");
		case CPU_SUBTYPE_PENTIUM_4_M:		return strdup ("Pentium 4 M");
		case CPU_SUBTYPE_ITANIUM:		return strdup ("Itanium");
		case CPU_SUBTYPE_ITANIUM_2:		return strdup ("Itanium 2");
		case CPU_SUBTYPE_XEON:			return strdup ("Xeon");
		case CPU_SUBTYPE_XEON_MP:		return strdup ("Xeon MP");
		default:				return strdup ("Unknown i386 subtype");
		}
	case CPU_TYPE_X86_64:
		switch (bin->hdr.cpusubtype & 0xff) {
		case CPU_SUBTYPE_X86_64_ALL:	return strdup ("x86 64 all");
		case CPU_SUBTYPE_X86_ARCH1:	return strdup ("x86 arch 1");
		default:			return strdup ("Unknown x86 subtype");
		}
	case CPU_TYPE_MC88000:
		switch (bin->hdr.cpusubtype & 0xff) {
		case CPU_SUBTYPE_MC88000_ALL:	return strdup ("all");
		case CPU_SUBTYPE_MC88100:	return strdup ("mc88100");
		case CPU_SUBTYPE_MC88110:	return strdup ("mc88110");
		default:			return strdup ("Unknown mc88000 subtype");
		}
	case CPU_TYPE_MC98000:
		switch (bin->hdr.cpusubtype & 0xff) {
		case CPU_SUBTYPE_MC98000_ALL:	return strdup ("all");
		case CPU_SUBTYPE_MC98601:	return strdup ("mc98601");
		default:			return strdup ("Unknown mc98000 subtype");
		}
	case CPU_TYPE_HPPA:
		switch (bin->hdr.cpusubtype & 0xff) {
		case CPU_SUBTYPE_HPPA_7100:	return strdup ("hppa7100");
		case CPU_SUBTYPE_HPPA_7100LC:	return strdup ("hppa7100LC");
		default:			return strdup ("Unknown hppa subtype");
		}
	case CPU_TYPE_ARM64:
		return strdup ("v8");
	case CPU_TYPE_ARM:
		switch (bin->hdr.cpusubtype & 0xff) {
		case CPU_SUBTYPE_ARM_ALL:
			return strdup ("all");
		case CPU_SUBTYPE_ARM_V4T:
			return strdup ("v4t");
		case CPU_SUBTYPE_ARM_V6:
			return strdup ("v6");
		case CPU_SUBTYPE_ARM_V5TEJ:
			return strdup ("v5tej");
		case CPU_SUBTYPE_ARM_XSCALE:
			return strdup ("xscale");
		case CPU_SUBTYPE_ARM_V7:
			return strdup ("v7");
		default:return strdup ("unknown ARM subtype");
		}
	case CPU_TYPE_SPARC:
		switch (bin->hdr.cpusubtype & 0xff) {
		case CPU_SUBTYPE_SPARC_ALL:	return strdup ("all");
		default:			return strdup ("Unknown sparc subtype");
		}
	case CPU_TYPE_MIPS:
		switch (bin->hdr.cpusubtype & 0xff) {
		case CPU_SUBTYPE_MIPS_ALL:	return strdup ("all");
		case CPU_SUBTYPE_MIPS_R2300:	return strdup ("r2300");
		case CPU_SUBTYPE_MIPS_R2600:	return strdup ("r2600");
		case CPU_SUBTYPE_MIPS_R2800:	return strdup ("r2800");
		case CPU_SUBTYPE_MIPS_R2000a:	return strdup ("r2000a");
		case CPU_SUBTYPE_MIPS_R2000:	return strdup ("r2000");
		case CPU_SUBTYPE_MIPS_R3000a:	return strdup ("r3000a");
		case CPU_SUBTYPE_MIPS_R3000:	return strdup ("r3000");
		default:			return strdup ("Unknown mips subtype");
		}
	case CPU_TYPE_I860:
		switch (bin->hdr.cpusubtype & 0xff) {
		case CPU_SUBTYPE_I860_ALL:	return strdup ("all");
		case CPU_SUBTYPE_I860_860:	return strdup ("860");
		default:			return strdup ("Unknown i860 subtype");
		}
	case CPU_TYPE_POWERPC:
	case CPU_TYPE_POWERPC64:
		switch (bin->hdr.cpusubtype & 0xff) {
		case CPU_SUBTYPE_POWERPC_ALL:	return strdup ("all");
		case CPU_SUBTYPE_POWERPC_601:	return strdup ("601");
		case CPU_SUBTYPE_POWERPC_602:	return strdup ("602");
		case CPU_SUBTYPE_POWERPC_603:	return strdup ("603");
		case CPU_SUBTYPE_POWERPC_603e:	return strdup ("603e");
		case CPU_SUBTYPE_POWERPC_603ev:	return strdup ("603ev");
		case CPU_SUBTYPE_POWERPC_604:	return strdup ("604");
		case CPU_SUBTYPE_POWERPC_604e:	return strdup ("604e");
		case CPU_SUBTYPE_POWERPC_620:	return strdup ("620");
		case CPU_SUBTYPE_POWERPC_750:	return strdup ("750");
		case CPU_SUBTYPE_POWERPC_7400:	return strdup ("7400");
		case CPU_SUBTYPE_POWERPC_7450:	return strdup ("7450");
		case CPU_SUBTYPE_POWERPC_970:	return strdup ("970");
		default:			return strdup ("Unknown ppc subtype");
		}
	default:
		return strdup ("Unknown cputype");
	}
}

int MACH0_(r_bin_mach0_is_pie)(struct MACH0_(r_bin_mach0_obj_t)* bin) {
	return (bin->hdr.filetype == MH_EXECUTE && bin->hdr.flags & MH_PIE);
}

char* MACH0_(r_bin_mach0_get_filetype)(struct MACH0_(r_bin_mach0_obj_t)* bin) {
	switch (bin->hdr.filetype) {
	case MH_OBJECT:		return strdup ("Relocatable object");
	case MH_EXECUTE:	return strdup ("Executable file");
	case MH_FVMLIB:		return strdup ("Fixed VM shared library");
	case MH_CORE:		return strdup ("Core file");
	case MH_PRELOAD:	return strdup ("Preloaded executable file");
	case MH_DYLIB:		return strdup ("Dynamically bound shared library");
	case MH_DYLINKER:	return strdup ("Dynamic link editor");
	case MH_BUNDLE:		return strdup ("Dynamically bound bundle file");
	case MH_DYLIB_STUB:	return strdup ("Shared library stub for static linking (no sections)");
	case MH_DSYM:		return strdup ("Companion file with only debug sections");
	default:		return strdup ("Unknown");
	}
}

ut64 MACH0_(r_bin_mach0_get_main)(struct MACH0_(r_bin_mach0_obj_t)* bin) {
	ut64 addr = 0LL;
	struct r_bin_mach0_symbol_t *symbols;
	int i;

	if (!(symbols = MACH0_(r_bin_mach0_get_symbols) (bin)))
		return 0;
	for (i = 0; !symbols[i].last; i++)
		if (!strcmp (symbols[i].name, "_main")) {
			addr = symbols[i].addr;
			break;
		}
	free (symbols);
	if (!addr) {
		ut8 b[128];
		ut64 entry = MACH0_(r_bin_mach0_addr_to_offset)(bin, bin->entry);
		// XXX: X86 only and hacky!
		if (r_buf_read_at (bin->b, entry, b, sizeof (b)) == -1)
			return 0;
		for (i=0; i<64; i++) {
			if (b[i] == 0xe8 && !b[i+3] && !b[i+4]) {
				int delta = b[i+1] | (b[i+2]<<8) | (b[i+3]<<16) | (b[i+4]<<24);
				return bin->entry + i + 5 + delta;

			}
		}
	}
	return addr;
}
