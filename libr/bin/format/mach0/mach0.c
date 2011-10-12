/* radare - LGPL - Copyright 2010-2011 nibble at develsec.org */

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
			else return bin->sects[i].offset + (addr - section_base);
		}
	}
	return 0;
}

static int MACH0_(r_bin_mach0_init_hdr)(struct MACH0_(r_bin_mach0_obj_t)* bin) {
	int magic, len;

	if (r_buf_read_at (bin->b, 0, (ut8*)&magic, 4) == -1) {
		eprintf ("Error: read (magic)\n");
		return R_FALSE;
	}
	if (magic == MH_MAGIC)
		bin->endian = !LIL_ENDIAN;
	else if (magic == MH_CIGAM)
		bin->endian = LIL_ENDIAN;
	else if (magic == FAT_CIGAM)
		bin->endian = LIL_ENDIAN;
	else return R_FALSE;
#if R_BIN_MACH064
	len = r_buf_fread_at(bin->b, 0, (ut8*)&bin->hdr, bin->endian?"8I":"8i", 1);
#else
	len = r_buf_fread_at(bin->b, 0, (ut8*)&bin->hdr, bin->endian?"7I":"7i", 1);
#endif
	if (len == -1) {
		eprintf ("Error: read (hdr)\n");
		return R_FALSE;
	}
	return R_TRUE;
}

static int MACH0_(r_bin_mach0_parse_seg)(struct MACH0_(r_bin_mach0_obj_t)* bin, ut64 off) {
	int sect, len, seg = bin->nsegs - 1;
	if (!(bin->segs = realloc(bin->segs, bin->nsegs * sizeof(struct MACH0_(segment_command))))) {
		perror ("realloc (seg)");
		return R_FALSE;
	}
#if R_BIN_MACH064
	len = r_buf_fread_at (bin->b, off, (ut8*)&bin->segs[seg], bin->endian?"2I16c4L4I":"2i16c4l4i", 1);
#else
	len = r_buf_fread_at (bin->b, off, (ut8*)&bin->segs[seg], bin->endian?"2I16c8I":"2i16c8i", 1);
#endif
	if (len == -1) {
		eprintf ("Error: read (seg)\n");
		return R_FALSE;
	}
	if (bin->segs[seg].nsects > 0) {
		sect = bin->nsects;
		bin->nsects += bin->segs[seg].nsects;
		if (!(bin->sects = realloc (bin->sects, bin->nsects * sizeof (struct MACH0_(section))))) {
			perror ("realloc (sects)");
			return R_FALSE;
		}
#if R_BIN_MACH064
		len = r_buf_fread_at (bin->b, off + sizeof(struct MACH0_(segment_command)),
				(ut8*)&bin->sects[sect], bin->endian?"16c16c2L8I":"16c16c2l8i", bin->nsects - sect);
#else
		len = r_buf_fread_at (bin->b, off + sizeof(struct MACH0_(segment_command)),
				(ut8*)&bin->sects[sect], bin->endian?"16c16c9I":"16c16c9i", bin->nsects - sect);
#endif
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
		len = r_buf_fread_at(bin->b, st.symoff, (ut8*)bin->symtab, bin->endian?"I2cSL":"i2csl", bin->nsymtab);
#else
		len = r_buf_fread_at(bin->b, st.symoff, (ut8*)bin->symtab, bin->endian?"I2cSI":"i2csi", bin->nsymtab);
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
		len = r_buf_fread_at(bin->b, bin->dysymtab.tocoff, (ut8*)bin->toc, bin->endian?"2I":"2i", bin->ntoc);
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
		len = r_buf_fread_at(bin->b, bin->dysymtab.modtaboff, (ut8*)bin->modtab, bin->endian?"12IL":"12il", bin->nmodtab);
#else
		len = r_buf_fread_at(bin->b, bin->dysymtab.modtaboff, (ut8*)bin->modtab, bin->endian?"13I":"13i", bin->nmodtab);
#endif
		if (len == -1) {
			eprintf ("Error: read (modtab)\n");
			R_FREE (bin->modtab);
			return R_FALSE;
		}
	}
	bin->nindirectsyms = bin->dysymtab.nindirectsyms;
	if (bin->nindirectsyms > 0) {
		if (!(bin->indirectsyms = malloc(bin->nindirectsyms * sizeof(ut32)))) {
			perror ("malloc (indirectsyms)");
			return R_FALSE;
		}
		len = r_buf_fread_at(bin->b, bin->dysymtab.indirectsymoff,
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
	int len = -1;

	len = r_buf_fread_at(bin->b, off, (ut8*)&bin->thread, bin->endian?"4I":"4i", 1);
	if (len == -1) {
		eprintf ("Error: read (thread)\n");
		return R_FALSE;
	}
	switch (bin->hdr.cputype) {
	case CPU_TYPE_I386:
	case CPU_TYPE_X86_64:
		if (bin->thread.flavor == X86_THREAD_STATE32) {
			if ((len = r_buf_fread_at(bin->b, off + sizeof(struct thread_command),
				(ut8*)&bin->thread_state.x86_32, bin->endian?"16I":"16i", 1)) == -1) {
				eprintf ("Error: read (thread state x86_32)\n");
				return R_FALSE;
			}
			bin->entry = bin->thread_state.x86_32.eip;

		} else if (bin->thread.flavor == X86_THREAD_STATE64) {
			if ((len = r_buf_fread_at(bin->b, off + sizeof(struct thread_command),
				(ut8*)&bin->thread_state.x86_64, bin->endian?"21L":"21l", 1)) == -1) {
				eprintf ("Error: read (thread state x86_64)\n");
				return R_FALSE;
			}
			bin->entry = bin->thread_state.x86_64.rip;
		}
		break;
	case CPU_TYPE_POWERPC:
	case CPU_TYPE_POWERPC64:
		if (bin->thread.flavor == X86_THREAD_STATE32) {
			if ((len = r_buf_fread_at(bin->b, off + sizeof(struct thread_command),
				(ut8*)&bin->thread_state.ppc_32, bin->endian?"40I":"40i", 1)) == -1) {
				eprintf ("Error: read (thread state ppc_32)\n");
				return R_FALSE;
			}
			bin->entry = bin->thread_state.ppc_32.srr0;
		} else if (bin->thread.flavor == X86_THREAD_STATE64) {
			if ((len = r_buf_fread_at(bin->b, off + sizeof(struct thread_command),
				(ut8*)&bin->thread_state.ppc_64, bin->endian?"34LI3LI":"34li3li", 1)) == -1) {
				eprintf ("Error: read (thread state ppc_64)\n");
				return R_FALSE;
			}
			bin->entry =  bin->thread_state.ppc_64.srr0;
		}
		break;
	case CPU_TYPE_ARM:
		if ((len = r_buf_fread_at(bin->b, off + sizeof (struct thread_command),
					(ut8*)&bin->thread_state.arm, bin->endian?"17I":"17i", 1)) == -1) {
			eprintf ("Error: read (thread state arm)\n");
			return R_FALSE;
		}
		bin->entry =  bin->thread_state.arm.r15;
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

	for (i = 0, off = sizeof (struct MACH0_(mach_header)); i < bin->hdr.ncmds; i++, off += lc.cmdsize) {
		len = r_buf_fread_at (bin->b, off, (ut8*)&lc, bin->endian?"2I":"2i", 1);
		if (len == -1) {
			eprintf ("Error: read (lc) at 0x%08"PFMT64x"\n", off);
			return R_FALSE;
		}
		switch (lc.cmd) {
#if R_BIN_MACH064
		case LC_SEGMENT_64:
#else
		case LC_SEGMENT:
#endif
			bin->nsegs++;
			if (!MACH0_(r_bin_mach0_parse_seg)(bin, off))
				return R_FALSE;
			break;
		case LC_SYMTAB:
			if (!MACH0_(r_bin_mach0_parse_symtab)(bin, off))
				return R_FALSE;
			break;
		case LC_DYSYMTAB:
			if (!MACH0_(r_bin_mach0_parse_dysymtab)(bin, off))
				return R_FALSE;
			break;
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
	bin->b = r_buf_new();
	if (!r_buf_set_bytes(bin->b, buf, bin->size))
		return MACH0_(r_bin_mach0_free)(bin);
	free (buf);
	if (!MACH0_(r_bin_mach0_init)(bin))
		return MACH0_(r_bin_mach0_free)(bin);
	return bin;
}

struct MACH0_(r_bin_mach0_obj_t)* MACH0_(r_bin_mach0_new_buf)(struct r_buf_t *buf) {
	struct MACH0_(r_bin_mach0_obj_t) *bin = R_NEW0 (struct MACH0_(r_bin_mach0_obj_t));
	if (!bin) return NULL;
	bin->b = buf;
	bin->size = buf->length;
	if (!MACH0_(r_bin_mach0_init)(bin))
		return MACH0_(r_bin_mach0_free)(bin);
	return bin;
}

struct r_bin_mach0_section_t* MACH0_(r_bin_mach0_get_sections)(struct MACH0_(r_bin_mach0_obj_t)* bin) {
	struct r_bin_mach0_section_t *sections;
	char segname[17], sectname[17];
	int i, j;

	if (!bin->sects)
		return NULL;
	if (!(sections = malloc ((bin->nsects + 1) * sizeof(struct r_bin_mach0_section_t))))
		return NULL;
	for (i = 0; i < bin->nsects; i++) {
		sections[i].offset = (ut64)bin->sects[i].offset;
		sections[i].addr = (ut64)bin->sects[i].addr;
		sections[i].size = (ut64)bin->sects[i].size;
		sections[i].align = bin->sects[i].align;
		sections[i].flags = bin->sects[i].flags;;
		segname[16] = sectname[16] = '\0';
		memcpy(segname, bin->sects[i].segname, 16);
		memcpy(sectname, bin->sects[i].sectname, 16);
		for (j=0;j<bin->nsegs;j++) {
			if (!strcmp (bin->segs[j].segname, segname)) {
				sections[i].srwx = bin->segs[j].initprot;
				break;
			}
		}
		snprintf (sections[i].name, sizeof (sections[i].name), "%s.%s", segname, sectname);
		sections[i].last = 0;
	}
	sections[i].last = 1;
	return sections;
}

struct r_bin_mach0_symbol_t* MACH0_(r_bin_mach0_get_symbols)(struct MACH0_(r_bin_mach0_obj_t)* bin) {
	const char *symstr;
	struct r_bin_mach0_symbol_t *symbols;
	int from, to, i, j, s, stridx;

	if (!bin->symtab || !bin->symstr)
		return NULL;
	if (!(symbols = malloc ((bin->dysymtab.nextdefsym + bin->dysymtab.nlocalsym + 1) * sizeof(struct r_bin_mach0_symbol_t))))
		return NULL;
	for (s = j = 0; s < 2; s++) {
		if (s == 0) {
			from = bin->dysymtab.iextdefsym;
			to = from + bin->dysymtab.nextdefsym;
		} else {
			from = bin->dysymtab.ilocalsym;
			to = from + bin->dysymtab.nlocalsym;
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
	symbols[j].last = 1;
	return symbols;
}

static int MACH0_(r_bin_mach0_parse_import_stub)(struct MACH0_(r_bin_mach0_obj_t)* bin, struct r_bin_mach0_import_t *import, int idx) {
	char sectname[17];
	int i, j, nsyms, stridx;
	const char *symstr;

	import->offset = 0LL;
	import->addr = 0LL;
	import->name[0] = '\0';
	for (i = 0; i < bin->nsects; i++) {
		sectname[16] = '\0';
		memcpy(sectname, bin->sects[i].sectname, 16);
		if ((bin->sects[i].flags & SECTION_TYPE) == S_SYMBOL_STUBS &&
			bin->sects[i].reserved1 >= 0 && bin->sects[i].reserved2 > 0) {
			nsyms = (int)(bin->sects[i].size / bin->sects[i].reserved2);
			for (j = 0; j < nsyms; j++) {
				if (bin->sects[i].reserved1 + j >= bin->nindirectsyms)
					continue;
				if (idx != bin->indirectsyms[bin->sects[i].reserved1 + j])
					continue;
				import->type = R_BIN_MACH0_IMPORT_TYPE_FUNC;
				import->offset = bin->sects[i].offset + j * bin->sects[i].reserved2;
				import->addr = bin->sects[i].addr + j * bin->sects[i].reserved2;
				stridx = bin->symtab[idx].n_un.n_strx;
				if (stridx>=0 && stridx<bin->symstrlen)
					symstr = (char *)bin->symstr+stridx;
				else symstr = "???";
				snprintf (import->name, R_BIN_MACH0_STRING_LENGTH, "%s:%s",
						sectname, symstr);
				return R_TRUE;
			}
		}
	}
	return R_FALSE;
}

static int MACH0_(r_bin_mach0_parse_import_ptr)(struct MACH0_(r_bin_mach0_obj_t)* bin, struct r_bin_mach0_import_t *import, int idx, int lazy) {
	char sectname[17];
	int i, j, sym, wordsize, stridx;
	ut32 stype;
	const char *symstr;

	import->offset = 0LL;
	import->addr = 0LL;
	import->name[0] = '\0';
	wordsize = (int)(MACH0_(r_bin_mach0_get_bits)(bin)/8);
	if (lazy)
		stype = S_LAZY_SYMBOL_POINTERS;
	else stype = S_NON_LAZY_SYMBOL_POINTERS;
	for (i = 0; i < bin->nsects; i++) {
		sectname[16] = '\0';
		memcpy(sectname, bin->sects[i].sectname, 16);
		if ((bin->sects[i].flags & SECTION_TYPE) == stype &&
			bin->sects[i].reserved1 >= 0) {
			for (j=0, sym=-1; bin->sects[i].reserved1+j < bin->nindirectsyms; j++)
				if (idx == bin->indirectsyms[bin->sects[i].reserved1 + j]) {
					sym = j;
					break;
				}
			import->type = R_BIN_MACH0_IMPORT_TYPE_OBJECT;
			import->offset = sym == -1 ? 0 : bin->sects[i].offset + sym * wordsize;
			import->addr = sym == -1 ? 0 : bin->sects[i].addr + sym * wordsize;
			stridx = bin->symtab[idx].n_un.n_strx;
			if (stridx>=0 && stridx<bin->symstrlen)
				symstr = (char *)bin->symstr+stridx;
			else symstr = "???";
			snprintf (import->name, R_BIN_MACH0_STRING_LENGTH, "%s:%s",
					sym == -1 ? "" : sectname, symstr);
			return R_TRUE;
		} 
	}
	return R_FALSE;
}

struct r_bin_mach0_import_t* MACH0_(r_bin_mach0_get_imports)(struct MACH0_(r_bin_mach0_obj_t)* bin) {
	struct r_bin_mach0_import_t *imports;
	int i, j, ret;

	if (!bin->symtab || !bin->symstr || !bin->sects || !bin->indirectsyms)
		return NULL;
	/* It's necessary to alloc nundefsym*2 because each import has stub+ptr */
	if (!(imports = malloc((bin->dysymtab.nundefsym * 2 + 1) * sizeof(struct r_bin_mach0_import_t))))
		return NULL;
	for (i = 0, j = bin->dysymtab.iundefsym; j < bin->dysymtab.iundefsym + bin->dysymtab.nundefsym; j++) {
		ret = MACH0_(r_bin_mach0_parse_import_stub)(bin, &imports[i], j);
		if (ret) {
			imports[i].last = 0;
			i = i + 1;
		}
		ret = MACH0_(r_bin_mach0_parse_import_ptr)(bin, &imports[i], j,
				((bin->symtab[j].n_desc & REFERENCE_TYPE) == REFERENCE_FLAG_UNDEFINED_LAZY));
		if (ret) {
			imports[i].last = 0;
			i = i + 1;
		}
	}
	imports[i].last = 1;
	return imports;
}

struct r_bin_mach0_addr_t* MACH0_(r_bin_mach0_get_entrypoint)(struct MACH0_(r_bin_mach0_obj_t)* bin) {
	struct r_bin_mach0_addr_t *entry;
	int i;

	if (!bin->entry && !bin->sects)
		return NULL;
	if (!(entry = malloc(sizeof(struct r_bin_mach0_addr_t))))
		return NULL;
	if (bin->entry) {
		entry->offset = MACH0_(r_bin_mach0_addr_to_offset)(bin, bin->entry);
		entry->addr = bin->entry;
	} else
		for (i = 0; i < bin->nsects; i++)
			if (!memcmp (bin->sects[i].sectname, "__text", 6)) {
				entry->offset = (ut64)bin->sects[i].offset;
				entry->addr = (ut64)bin->sects[i].addr;
				break;
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
	return UT64_MIN;
}

char* MACH0_(r_bin_mach0_get_class)(struct MACH0_(r_bin_mach0_obj_t)* bin) {
#if R_BIN_MACH064
	return r_str_dup_printf ("MACH064");
#else
	return r_str_dup_printf ("MACH0");
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

char* MACH0_(r_bin_mach0_get_cputype)(struct MACH0_(r_bin_mach0_obj_t)* bin) {
	switch (bin->hdr.cputype) {
	case CPU_TYPE_VAX: 	return r_str_dup_printf ("vax");
	case CPU_TYPE_MC680x0:	return r_str_dup_printf ("mc680x0");
	case CPU_TYPE_I386:
	case CPU_TYPE_X86_64:	return r_str_dup_printf ("x86");
	case CPU_TYPE_MC88000:	return r_str_dup_printf ("mc88000");
	case CPU_TYPE_MC98000:	return r_str_dup_printf ("mc98000");
	case CPU_TYPE_HPPA:	return r_str_dup_printf ("hppa");
	case CPU_TYPE_ARM:	return r_str_dup_printf ("arm");
	case CPU_TYPE_SPARC:	return r_str_dup_printf ("sparc");
	case CPU_TYPE_MIPS:	return r_str_dup_printf ("mips");
	case CPU_TYPE_I860:	return r_str_dup_printf ("i860");
	case CPU_TYPE_POWERPC:
	case CPU_TYPE_POWERPC64:return r_str_dup_printf ("ppc");
	default:		return r_str_dup_printf ("unknown");
	}
}

char* MACH0_(r_bin_mach0_get_cpusubtype)(struct MACH0_(r_bin_mach0_obj_t)* bin) {
	switch (bin->hdr.cputype) {
	case CPU_TYPE_VAX:
		switch (bin->hdr.cpusubtype) {
		case CPU_SUBTYPE_VAX_ALL:	return r_str_dup_printf ("all");
		case CPU_SUBTYPE_VAX780:	return r_str_dup_printf ("vax780");
		case CPU_SUBTYPE_VAX785:	return r_str_dup_printf ("vax785");
		case CPU_SUBTYPE_VAX750:	return r_str_dup_printf ("vax750");
		case CPU_SUBTYPE_VAX730:	return r_str_dup_printf ("vax730");
		case CPU_SUBTYPE_UVAXI:		return r_str_dup_printf ("uvaxI");
		case CPU_SUBTYPE_UVAXII:	return r_str_dup_printf ("uvaxII");
		case CPU_SUBTYPE_VAX8200:	return r_str_dup_printf ("vax8200");
		case CPU_SUBTYPE_VAX8500:	return r_str_dup_printf ("vax8500");
		case CPU_SUBTYPE_VAX8600:	return r_str_dup_printf ("vax8600");
		case CPU_SUBTYPE_VAX8650:	return r_str_dup_printf ("vax8650");
		case CPU_SUBTYPE_VAX8800:	return r_str_dup_printf ("vax8800");
		case CPU_SUBTYPE_UVAXIII:	return r_str_dup_printf ("uvaxIII");
		default:			return r_str_dup_printf ("Unknown vax subtype");
		}
	case CPU_TYPE_MC680x0:
		switch (bin->hdr.cpusubtype) {
		case CPU_SUBTYPE_MC68030:	return r_str_dup_printf ("mc68030");
		case CPU_SUBTYPE_MC68040:	return r_str_dup_printf ("mc68040");
		case CPU_SUBTYPE_MC68030_ONLY:	return r_str_dup_printf ("mc68030 only");
		default:			return r_str_dup_printf ("Unknown mc680x0 subtype");
		}
	case CPU_TYPE_I386:
		switch (bin->hdr.cpusubtype) {
		case CPU_SUBTYPE_386: 			return r_str_dup_printf ("386");
		case CPU_SUBTYPE_486: 			return r_str_dup_printf ("486");
		case CPU_SUBTYPE_486SX: 		return r_str_dup_printf ("486sx");
		case CPU_SUBTYPE_PENT: 			return r_str_dup_printf ("Pentium");
		case CPU_SUBTYPE_PENTPRO: 		return r_str_dup_printf ("Pentium Pro");
		case CPU_SUBTYPE_PENTII_M3: 		return r_str_dup_printf ("Pentium 3 M3");
		case CPU_SUBTYPE_PENTII_M5: 		return r_str_dup_printf ("Pentium 3 M5");
		case CPU_SUBTYPE_CELERON: 		return r_str_dup_printf ("Celeron");
		case CPU_SUBTYPE_CELERON_MOBILE:	return r_str_dup_printf ("Celeron Mobile");
		case CPU_SUBTYPE_PENTIUM_3:		return r_str_dup_printf ("Pentium 3");
		case CPU_SUBTYPE_PENTIUM_3_M:		return r_str_dup_printf ("Pentium 3 M");
		case CPU_SUBTYPE_PENTIUM_3_XEON:	return r_str_dup_printf ("Pentium 3 Xeon");
		case CPU_SUBTYPE_PENTIUM_M:		return r_str_dup_printf ("Pentium Mobile");
		case CPU_SUBTYPE_PENTIUM_4:		return r_str_dup_printf ("Pentium 4");
		case CPU_SUBTYPE_PENTIUM_4_M:		return r_str_dup_printf ("Pentium 4 M");
		case CPU_SUBTYPE_ITANIUM:		return r_str_dup_printf ("Itanium");
		case CPU_SUBTYPE_ITANIUM_2:		return r_str_dup_printf ("Itanium 2");
		case CPU_SUBTYPE_XEON:			return r_str_dup_printf ("Xeon");
		case CPU_SUBTYPE_XEON_MP:		return r_str_dup_printf ("Xeon MP");
		default:				return r_str_dup_printf ("Unknown i386 subtype");
		}
	case CPU_TYPE_X86_64:
//bin->hdr.cpusubtype &= 0xff; // HACK to avoid 0x80000000
// TODO: handle 0x80000000 type
		switch (bin->hdr.cpusubtype) {
		case CPU_SUBTYPE_X86_64_ALL:	return r_str_dup_printf ("x86 64 all");
		case CPU_SUBTYPE_X86_ARCH1:	return r_str_dup_printf ("x86 arch 1");
		default:			return r_str_dup_printf ("Unknown x86 subtype");
		}
	case CPU_TYPE_MC88000:
		switch (bin->hdr.cpusubtype) {
		case CPU_SUBTYPE_MC88000_ALL:	return r_str_dup_printf ("all");
		case CPU_SUBTYPE_MC88100:	return r_str_dup_printf ("mc88100");
		case CPU_SUBTYPE_MC88110:	return r_str_dup_printf ("mc88110");
		default:			return r_str_dup_printf ("Unknown mc88000 subtype");
		}
	case CPU_TYPE_MC98000:
		switch (bin->hdr.cpusubtype) {
		case CPU_SUBTYPE_MC98000_ALL:	return r_str_dup_printf ("all");
		case CPU_SUBTYPE_MC98601:	return r_str_dup_printf ("mc98601");
		default:			return r_str_dup_printf ("Unknown mc98000 subtype");
		}
	case CPU_TYPE_HPPA:
		switch (bin->hdr.cpusubtype) {
		case CPU_SUBTYPE_HPPA_7100:	return r_str_dup_printf ("hppa7100");
		case CPU_SUBTYPE_HPPA_7100LC:	return r_str_dup_printf ("hppa7100LC");
		default:			return r_str_dup_printf ("Unknown hppa subtype");
		}
	case CPU_TYPE_ARM:
		switch (bin->hdr.cpusubtype) {
		default:			return r_str_dup_printf ("Unknown arm subtype");
		}
	case CPU_TYPE_SPARC:
		switch (bin->hdr.cpusubtype) {
		case CPU_SUBTYPE_SPARC_ALL:		return r_str_dup_printf ("all");
		default:				return r_str_dup_printf ("Unknown sparc subtype");
		}
	case CPU_TYPE_MIPS:
		switch (bin->hdr.cpusubtype) {
		case CPU_SUBTYPE_MIPS_ALL:	return r_str_dup_printf ("all");
		case CPU_SUBTYPE_MIPS_R2300:	return r_str_dup_printf ("r2300");
		case CPU_SUBTYPE_MIPS_R2600:	return r_str_dup_printf ("r2600");
		case CPU_SUBTYPE_MIPS_R2800:	return r_str_dup_printf ("r2800");
		case CPU_SUBTYPE_MIPS_R2000a:	return r_str_dup_printf ("r2000a");
		case CPU_SUBTYPE_MIPS_R2000:	return r_str_dup_printf ("r2000");
		case CPU_SUBTYPE_MIPS_R3000a:	return r_str_dup_printf ("r3000a");
		case CPU_SUBTYPE_MIPS_R3000:	return r_str_dup_printf ("r3000");
		default:			return r_str_dup_printf ("Unknown mips subtype");
		}
	case CPU_TYPE_I860:
		switch (bin->hdr.cpusubtype) {
		case CPU_SUBTYPE_I860_ALL:	return r_str_dup_printf ("all");
		case CPU_SUBTYPE_I860_860:	return r_str_dup_printf ("860");
		default:			return r_str_dup_printf ("Unknown i860 subtype");
		}
	case CPU_TYPE_POWERPC:
	case CPU_TYPE_POWERPC64:
		switch (bin->hdr.cpusubtype) {
		case CPU_SUBTYPE_POWERPC_ALL:	return r_str_dup_printf ("all");
		case CPU_SUBTYPE_POWERPC_601:	return r_str_dup_printf ("601");
		case CPU_SUBTYPE_POWERPC_602:	return r_str_dup_printf ("602");
		case CPU_SUBTYPE_POWERPC_603:	return r_str_dup_printf ("603");
		case CPU_SUBTYPE_POWERPC_603e:	return r_str_dup_printf ("603e");
		case CPU_SUBTYPE_POWERPC_603ev:	return r_str_dup_printf ("603ev");
		case CPU_SUBTYPE_POWERPC_604:	return r_str_dup_printf ("604");
		case CPU_SUBTYPE_POWERPC_604e:	return r_str_dup_printf ("604e");
		case CPU_SUBTYPE_POWERPC_620:	return r_str_dup_printf ("620");
		case CPU_SUBTYPE_POWERPC_750:	return r_str_dup_printf ("750");
		case CPU_SUBTYPE_POWERPC_7400:	return r_str_dup_printf ("7400");
		case CPU_SUBTYPE_POWERPC_7450:	return r_str_dup_printf ("7450");
		case CPU_SUBTYPE_POWERPC_970:	return r_str_dup_printf ("970");
		default:			return r_str_dup_printf ("Unknown ppc subtype");
		}
	default:
		return r_str_dup_printf ("Unknown cputype");
	}
}

char* MACH0_(r_bin_mach0_get_filetype)(struct MACH0_(r_bin_mach0_obj_t)* bin) {
	switch (bin->hdr.filetype) {
	case MH_OBJECT:		return r_str_dup_printf ("Relocatable object");
	case MH_EXECUTE:	return r_str_dup_printf ("Executable file");
	case MH_FVMLIB:		return r_str_dup_printf ("Fixed VM shared library");
	case MH_CORE:		return r_str_dup_printf ("Core file");
	case MH_PRELOAD:	return r_str_dup_printf ("Preloaded executable file");
	case MH_DYLIB:		return r_str_dup_printf ("Dynamically bound shared library");
	case MH_DYLINKER:	return r_str_dup_printf ("Dynamic link editor");
	case MH_BUNDLE:		return r_str_dup_printf ("Dynamically bound bundle file");
	case MH_DYLIB_STUB:	return r_str_dup_printf ("Shared library stub for static linking (no sections)");
	case MH_DSYM:		return r_str_dup_printf ("Companion file with only debug sections");
	default:		return r_str_dup_printf ("Unknown");
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
		ut8 b[64];
		ut64 entry = MACH0_(r_bin_mach0_addr_to_offset)(bin, bin->entry);
		// XXX: X86 only and hacky!
		if (r_buf_read_at (bin->b, entry, b, 64) == -1)
			return 0;
		for (i=0; i<64; i++) {
			if (b[i] == 0xe8 && !b[i+2] && !b[i+3]) {
				int delta = b[i+1] | (b[i+2]<<8) | (b[i+3]<<16) | (b[i+4]<<24);
				return bin->entry + i + 5 + delta;
			}
		}
	}
	return addr;
}
