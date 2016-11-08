/* radare - LGPL - Copyright 2010-2016 - nibble, pancake */

#include <stdio.h>
#include <r_types.h>
#include <r_util.h>
#include "mach0.h"

typedef struct _ulebr {
	ut8 *p;
} ulebr;

static bool little_;

static ut64 read_uleb128(ulebr *r, ut8 *end) {
	ut64 result = 0;
	int bit = 0;
	ut64 slice = 0;
	ut8 *p = r->p;
	do {
		if (p == end) {
			eprintf ("malformed uleb128");
		}
		slice = *p & 0x7f;
		if (bit > 63) {
			eprintf ("uleb128 too big for uint64, bit=%d, result=0x%"PFMT64x, bit, result);
		} else {
			result |= (slice << bit);
			bit += 7;
		}
	} while (*p++ & 0x80);
	r->p = p;
	return result;
}

static st64 read_sleb128(ulebr *r, ut8 *end) {
	st64 result = 0;
	int bit = 0;
	ut8 byte;
	ut8 *p = r->p;
	do {
		if (p == end) {
			eprintf ("malformed sleb128");
		}
		byte = *p++;
		result |= (((st64)(byte & 0x7f)) << bit);
		bit += 7;
	} while (byte & 0x80);
	// sign extend negative numbers
	if ((byte & 0x40)) {
		result |= (-1LL) << bit;
	}
	r->p = p;
	return result;
}


static ut64 entry_to_vaddr(struct MACH0_(obj_t)* bin) {
	switch (bin->main_cmd.cmd) {
	case LC_MAIN:
		return bin->entry + bin->baddr;
	case LC_UNIXTHREAD:
	case LC_THREAD:
		return bin->entry;
	default:
		return 0;
	}
}

static ut64 addr_to_offset(struct MACH0_(obj_t)* bin, ut64 addr) {
	ut64 segment_base, segment_size;
	int i;
 
	if (!bin->segs) {
		return 0;
	}
	for (i = 0; i < bin->nsegs; i++) {
		segment_base = (ut64)bin->segs[i].vmaddr;
		segment_size = (ut64)bin->segs[i].vmsize;
		if (addr >= segment_base && addr < segment_base + segment_size) {
			return bin->segs[i].fileoff + (addr - segment_base);
		}
	}
	return 0;
}

static int init_hdr(struct MACH0_(obj_t)* bin) {
	ut8 magicbytes[4]= {0};
	ut8 machohdrbytes[sizeof (struct MACH0_(mach_header))] = {0};
	int len;

	if (r_buf_read_at (bin->b, 0, magicbytes, 4) < 1) {
		eprintf ("Error: read (magic)\n");
		return false;
	}
	if (r_read_le32(magicbytes) == 0xfeedface) {
		bin->big_endian = false;
	} else if (r_read_be32(magicbytes) == 0xfeedface) { 
		bin->big_endian = true;
	} else if (r_read_le32(magicbytes) == FAT_MAGIC) {
		bin->big_endian = false;
	} else if (r_read_be32(magicbytes) == FAT_MAGIC) {
		bin->big_endian = true;
	} else if (r_read_le32(magicbytes) == 0xfeedfacf) {
		bin->big_endian = false;
	} else if (r_read_be32(magicbytes) == 0xfeedfacf) {
		bin->big_endian = true;
	} else {
		return false; // object files are magic == 0, but body is different :?
	}
	len = r_buf_read_at (bin->b, 0, machohdrbytes, sizeof (machohdrbytes));
	if (len != sizeof (machohdrbytes)) {
		eprintf ("Error: read (hdr)\n");
		return false;
	}
	bin->hdr.magic = r_read_ble (&machohdrbytes[0], bin->big_endian, 32);
	bin->hdr.cputype = r_read_ble (&machohdrbytes[4], bin->big_endian, 32);
	bin->hdr.cpusubtype = r_read_ble (&machohdrbytes[8], bin->big_endian, 32);
	bin->hdr.filetype = r_read_ble (&machohdrbytes[12], bin->big_endian, 32);
	bin->hdr.ncmds = r_read_ble (&machohdrbytes[16], bin->big_endian, 32);
	bin->hdr.sizeofcmds = r_read_ble (&machohdrbytes[20], bin->big_endian, 32);
	bin->hdr.flags = r_read_ble (&machohdrbytes[24], bin->big_endian, 32);
#if R_BIN_MACH064
	bin->hdr.reserved = r_read_ble (&machohdrbytes[28], bin->big_endian, 32);
#endif
	sdb_set (bin->kv, "mach0_header.format",
		"xxxxddx "
		"magic cputype cpusubtype filetype ncmds sizeofcmds flags", 0);
	sdb_num_set (bin->kv, "mach0_header.offset", 0, 0); // wat about fatmach0?
	sdb_set (bin->kv, "mach_filetype.cparse", "enum mach_filetype{MH_OBJECT=1,"
			"MH_EXECUTE=2, MH_FVMLIB=3, MH_CORE=4, MH_PRELOAD=5, MH_DYLIB=6,"
			"MH_DYLINKER=7, MH_BUNDLE=8, MH_DYLIB_STUB=9, MH_DSYM=10,"
			"MH_KEXT_BUNDLE=11}"
			,0);
	sdb_set (bin->kv, "mach_flags.cparse", "enum mach_flags{MH_NOUNDEFS=1,"
			"MH_INCRLINK=2,MH_DYLDLINK=4,MH_BINDATLOAD=8,MH_PREBOUND=0x10,"
			"MH_SPLIT_SEGS=0x20,MH_LAZY_INIT=0x40,MH_TWOLEVEL=0x80,"
			"MH_FORCE_FLAT=0x100,MH_NOMULTIDEFS=0x200,MH_NOFIXPREBINDING=0x400,"
			"MH_PREBINDABLE=0x800, MH_ALLMODSBOUND=0x1000,"
			"MH_SUBSECTIONS_VIA_SYMBOLS=0x2000,"
			"MH_CANONICAL=0x4000,MH_WEAK_DEFINES=0x8000,"
			"MH_BINDS_TO_WEAK=0x10000,MH_ALLOW_STACK_EXECUTION=0x20000,"
			"MH_ROOT_SAFE=0x40000,MH_SETUID_SAFE=0x80000,"
			"MH_NO_REEXPORTED_DYLIBS=0x100000,MH_PIE=0x200000,"
			"MH_DEAD_STRIPPABLE_DYLIB=0x400000,"
			"MH_HAS_TLV_DESCRIPTORS=0x800000,"
			"MH_NO_HEAP_EXECUTION=0x1000000 }",0);
	return true;
}

static int parse_segments(struct MACH0_(obj_t)* bin, ut64 off) {
	int i, j, k, sect, len;
	ut32 size_sects;
	ut8 segcom[sizeof (struct MACH0_(segment_command))] = {0};
	ut8 sec[sizeof (struct MACH0_(section))] = {0};

	if (!UT32_MUL (&size_sects, bin->nsegs, sizeof (struct MACH0_(segment_command)))) {
		return false;
	}
	if (!size_sects || size_sects > bin->size) {
		return false;
	}
	if (off > bin->size || off + sizeof (struct MACH0_(segment_command)) > bin->size) {
		return false;
	}
	if (!(bin->segs = realloc (bin->segs, bin->nsegs * sizeof(struct MACH0_(segment_command))))) {
		perror ("realloc (seg)");
		return false;
	}
	j = bin->nsegs - 1;
	len = r_buf_read_at (bin->b, off, segcom, sizeof (struct MACH0_(segment_command)));
	if (len != sizeof (struct MACH0_(segment_command))) {
		eprintf ("Error: read (seg)\n");
		return false;
	}
	i = 0;
	bin->segs[j].cmd = r_read_ble32 (&segcom[i], bin->big_endian);
	i += sizeof (ut32);
	bin->segs[j].cmdsize = r_read_ble32 (&segcom[i], bin->big_endian);
	i += sizeof (ut32);
	memcpy (&bin->segs[j].segname, &segcom[i], 16);
	i += 16;
#if R_BIN_MACH064
	bin->segs[j].vmaddr = r_read_ble64 (&segcom[i], bin->big_endian);
	i += sizeof (ut64);
	bin->segs[j].vmsize = r_read_ble64 (&segcom[i], bin->big_endian);
	i += sizeof (ut64);
	bin->segs[j].fileoff = r_read_ble64 (&segcom[i], bin->big_endian);
	i += sizeof (ut64);
	bin->segs[j].filesize = r_read_ble64 (&segcom[i], bin->big_endian);
	i += sizeof (ut64);
#else
	bin->segs[j].vmaddr = r_read_ble32 (&segcom[i], bin->big_endian);
	i += sizeof (ut32);
	bin->segs[j].vmsize = r_read_ble32 (&segcom[i], bin->big_endian);
	i += sizeof (ut32);
	bin->segs[j].fileoff = r_read_ble32 (&segcom[i], bin->big_endian);
	i += sizeof (ut32);
	bin->segs[j].filesize = r_read_ble32 (&segcom[i], bin->big_endian);
	i += sizeof (ut32);
#endif
	bin->segs[j].maxprot = r_read_ble32 (&segcom[i], bin->big_endian);
	i += sizeof (ut32);
	bin->segs[j].initprot = r_read_ble32 (&segcom[i], bin->big_endian);
	i += sizeof (ut32);
	bin->segs[j].nsects = r_read_ble32 (&segcom[i], bin->big_endian);
	i += sizeof (ut32);
	bin->segs[j].flags = r_read_ble32 (&segcom[i], bin->big_endian);

	sdb_num_set (bin->kv, sdb_fmt (0, "mach0_segment_%d.offset", j), off, 0);
	sdb_num_set (bin->kv, "mach0_segments.count", 0, 0);
	sdb_set (bin->kv, "mach0_segment.format",
		"xd[16]zxxxxoodx "
		"cmd cmdsize segname vmaddr vmsize "
		"fileoff filesize maxprot initprot nsects flags", 0);

	if (bin->segs[j].nsects > 0) {
		sect = bin->nsects;
		bin->nsects += bin->segs[j].nsects;
		if (bin->nsects > 128) {
			int new_nsects = bin->nsects & 0xf;
			eprintf ("WARNING: mach0 header contains too many sections (%d). Wrapping to %d\n",
				 bin->nsects, new_nsects);
			bin->nsects = new_nsects;
		}
		if ((int)bin->nsects > 0) {
			if (!UT32_MUL (&size_sects, bin->nsects-sect, sizeof (struct MACH0_(section)))){
				bin->nsects = sect;
				return false;
			}
			if (!size_sects || size_sects > bin->size){
				bin->nsects = sect;
				return false;
			}

			if (bin->segs[j].cmdsize != sizeof (struct MACH0_(segment_command)) \
					  + (sizeof (struct MACH0_(section))*bin->segs[j].nsects)){
				bin->nsects = sect;
				return false;
			}

			if (off + sizeof (struct MACH0_(segment_command)) > bin->size ||\
					off + sizeof (struct MACH0_(segment_command)) + size_sects > bin->size){
				bin->nsects = sect;
				return false;
			}

			if (!(bin->sects = realloc (bin->sects, bin->nsects * sizeof (struct MACH0_(section))))) {
				perror ("realloc (sects)");
				bin->nsects = sect;
				return false;
			}

			for (k = sect, j = 0; k < bin->nsects; k++, j++) {
				ut64 offset = off + sizeof (struct MACH0_(segment_command)) + j * sizeof (struct MACH0_(section));
				len = r_buf_read_at (bin->b, offset, sec, sizeof (struct MACH0_(section)));
				if (len != sizeof (struct MACH0_(section))) {
					eprintf ("Error: read (sects)\n");
					bin->nsects = sect;
					return false;
				}

				i = 0;
				memcpy (&bin->sects[k].sectname, &sec[i], 16);
				i += 16;
				memcpy (&bin->sects[k].segname, &sec[i], 16);
				i += 16;
#if R_BIN_MACH064
				bin->sects[k].addr = r_read_ble64 (&sec[i], bin->big_endian);
				i += sizeof (ut64);
				bin->sects[k].size = r_read_ble64 (&sec[i], bin->big_endian);
				i += sizeof (ut64);
#else
				bin->sects[k].addr = r_read_ble32 (&sec[i], bin->big_endian);
				i += sizeof (ut32);
				bin->sects[k].size = r_read_ble32 (&sec[i], bin->big_endian);
				i += sizeof (ut32);
#endif
				bin->sects[k].offset = r_read_ble32 (&sec[i], bin->big_endian);
				i += sizeof (ut32);
				bin->sects[k].align = r_read_ble32 (&sec[i], bin->big_endian);
				i += sizeof (ut32);
				bin->sects[k].reloff = r_read_ble32 (&sec[i], bin->big_endian);
				i += sizeof (ut32);
				bin->sects[k].nreloc = r_read_ble32 (&sec[i], bin->big_endian);
				i += sizeof (ut32);
				bin->sects[k].flags = r_read_ble32 (&sec[i], bin->big_endian);
				i += sizeof (ut32);
				bin->sects[k].reserved1 = r_read_ble32 (&sec[i], bin->big_endian);
				i += sizeof (ut32);
				bin->sects[k].reserved2 = r_read_ble32 (&sec[i], bin->big_endian);
				i += sizeof (ut32);
#if R_BIN_MACH064
				bin->sects[k].reserved3 = r_read_ble32 (&sec[i], bin->big_endian);
#endif
			}
		} else {
			eprintf ("Warning: Invalid number of sections\n");
			bin->nsects = sect;
			return false;
		}
	}
	return true;
}

static int parse_symtab(struct MACH0_(obj_t)* bin, ut64 off) {
	struct symtab_command st;
	ut32 size_sym;
	int i;
	ut8 symt[sizeof (struct symtab_command)] = {0};
	ut8 nlst[sizeof (struct MACH0_(nlist))] = {0};

	if (off > (ut64)bin->size || off + sizeof (struct symtab_command) > (ut64)bin->size) { 
		return false;
	}	
	int len = r_buf_read_at (bin->b, off, symt, sizeof (struct symtab_command));
	if (len != sizeof (struct symtab_command)) {
		eprintf ("Error: read (symtab)\n");
		return false;
	}
	st.cmd = r_read_ble32 (&symt[0], bin->big_endian);
	st.cmdsize = r_read_ble32 (&symt[4], bin->big_endian);
	st.symoff = r_read_ble32 (&symt[8], bin->big_endian);
	st.nsyms = r_read_ble32 (&symt[12], bin->big_endian);
	st.stroff = r_read_ble32 (&symt[16], bin->big_endian);
	st.strsize = r_read_ble32 (&symt[20], bin->big_endian);

	bin->symtab = NULL;
	bin->nsymtab = 0;
	if (st.strsize > 0 && st.strsize < bin->size && st.nsyms > 0) {
		bin->nsymtab = st.nsyms;
		if (st.stroff > bin->size || st.stroff + st.strsize > bin->size) {
			return false;
		}
		if (!UT32_MUL (&size_sym, bin->nsymtab, sizeof (struct MACH0_(nlist)))) {
			eprintf("fail2\n");
			return false;
		}
		if (!size_sym) {
			eprintf("fail3\n");
			return false;
		}
		if (st.symoff > bin->size || st.symoff + size_sym > bin->size) {
			eprintf("fail4\n");
			return false;
		}
		if (!(bin->symstr = calloc (1, st.strsize + 2))) {
			perror ("calloc (symstr)");
			return false;
		}
		bin->symstrlen = st.strsize;
		len = r_buf_read_at (bin->b, st.stroff, (ut8*)bin->symstr, st.strsize);
		if (len != st.strsize) {
			eprintf ("Error: read (symstr)\n");
			R_FREE (bin->symstr);
			return false;
		}
		if (!(bin->symtab = calloc (bin->nsymtab, sizeof (struct MACH0_(nlist))))) {
			perror ("calloc (symtab)");
			return false;
		}
		for (i = 0; i < bin->nsymtab; i++) {
			len = r_buf_read_at (bin->b, st.symoff + (i * sizeof (struct MACH0_(nlist))), 
								nlst, sizeof (struct MACH0_(nlist)));
			if (len != sizeof (struct MACH0_(nlist))) {
				eprintf ("Error: read (nlist)\n");
				R_FREE (bin->symtab);
				return false;
			}
			//XXX not very safe what if is n_un.n_name instead?
			bin->symtab[i].n_strx = r_read_ble32 (&nlst[0], bin->big_endian);
			bin->symtab[i].n_type = r_read_ble8 (&nlst[4]);
			bin->symtab[i].n_sect = r_read_ble8 (&nlst[5]);
			bin->symtab[i].n_desc = r_read_ble16 (&nlst[6], bin->big_endian);
#if R_BIN_MACH064
			bin->symtab[i].n_value = r_read_ble64 (&nlst[8], bin->big_endian);
#else
			bin->symtab[i].n_value = r_read_ble32 (&nlst[8], bin->big_endian);
#endif
		}
	}
	return true;
}

static int parse_dysymtab(struct MACH0_(obj_t)* bin, ut64 off) {
	int len, i;
	ut32 size_tab;
	ut8 dysym[sizeof (struct dysymtab_command)] = {0};
	ut8 dytoc[sizeof (struct dylib_table_of_contents)] = {0};
	ut8 dymod[sizeof (struct MACH0_(dylib_module))] = {0};
	ut8 idsyms[sizeof (ut32)] = {0};

	if (off > bin->size || off + sizeof (struct dysymtab_command) > bin->size) {
		return false;
	}

	len = r_buf_read_at(bin->b, off, dysym, sizeof (struct dysymtab_command));
	if (len != sizeof (struct dysymtab_command)) {
		eprintf ("Error: read (dysymtab)\n");
		return false;
	}

	bin->dysymtab.cmd = r_read_ble32 (&dysym[0], bin->big_endian);
	bin->dysymtab.cmdsize = r_read_ble32 (&dysym[4], bin->big_endian);
	bin->dysymtab.ilocalsym = r_read_ble32 (&dysym[8], bin->big_endian);
	bin->dysymtab.nlocalsym = r_read_ble32 (&dysym[12], bin->big_endian);
	bin->dysymtab.iextdefsym = r_read_ble32 (&dysym[16], bin->big_endian);
	bin->dysymtab.nextdefsym = r_read_ble32 (&dysym[20], bin->big_endian);
	bin->dysymtab.iundefsym = r_read_ble32 (&dysym[24], bin->big_endian);
	bin->dysymtab.nundefsym = r_read_ble32 (&dysym[28], bin->big_endian);
	bin->dysymtab.tocoff = r_read_ble32 (&dysym[32], bin->big_endian);
	bin->dysymtab.ntoc = r_read_ble32 (&dysym[36], bin->big_endian);
	bin->dysymtab.modtaboff = r_read_ble32 (&dysym[40], bin->big_endian);
	bin->dysymtab.nmodtab = r_read_ble32 (&dysym[44], bin->big_endian);
	bin->dysymtab.extrefsymoff = r_read_ble32 (&dysym[48], bin->big_endian);
	bin->dysymtab.nextrefsyms = r_read_ble32 (&dysym[52], bin->big_endian);
	bin->dysymtab.indirectsymoff = r_read_ble32 (&dysym[56], bin->big_endian);
	bin->dysymtab.nindirectsyms = r_read_ble32 (&dysym[60], bin->big_endian);
	bin->dysymtab.extreloff = r_read_ble32 (&dysym[64], bin->big_endian);
	bin->dysymtab.nextrel = r_read_ble32 (&dysym[68], bin->big_endian);
	bin->dysymtab.locreloff = r_read_ble32 (&dysym[72], bin->big_endian);
	bin->dysymtab.nlocrel = r_read_ble32 (&dysym[76], bin->big_endian);

	bin->ntoc = bin->dysymtab.ntoc;
	if (bin->ntoc > 0) {
		if (!(bin->toc = calloc (bin->ntoc, sizeof(struct dylib_table_of_contents)))) {
			perror ("calloc (toc)");
			return false;
		}
		if (!UT32_MUL (&size_tab, bin->ntoc, sizeof (struct dylib_table_of_contents))){
			R_FREE (bin->toc);
			return false;
		}
		if (!size_tab){
			R_FREE (bin->toc);
			return false;
		}
		if (bin->dysymtab.tocoff > bin->size || bin->dysymtab.tocoff + size_tab > bin->size){
			R_FREE (bin->toc);
			return false;
		}
		for (i = 0; i < bin->ntoc; i++) {
			len = r_buf_read_at(bin->b, bin->dysymtab.tocoff +
				i * sizeof (struct dylib_table_of_contents),
				dytoc, sizeof (struct dylib_table_of_contents));
			if (len != sizeof (struct dylib_table_of_contents)) {
				eprintf ("Error: read (toc)\n");
				R_FREE (bin->toc);
				return false;
			}
			bin->toc[i].symbol_index = r_read_ble32 (&dytoc[0], bin->big_endian);
			bin->toc[i].module_index = r_read_ble32 (&dytoc[4], bin->big_endian);
		}
	}
	bin->nmodtab = bin->dysymtab.nmodtab;
	if (bin->nmodtab > 0) {
		if (!(bin->modtab = calloc (bin->nmodtab, sizeof(struct MACH0_(dylib_module))))) {
			perror ("calloc (modtab)");
			return false;
		}
		if (!UT32_MUL (&size_tab, bin->nmodtab, sizeof (struct MACH0_(dylib_module)))){
			R_FREE (bin->modtab);
			return false;
		}
		if (!size_tab){
			R_FREE (bin->modtab);
			return false;
		}
		if (bin->dysymtab.modtaboff > bin->size || \
		  bin->dysymtab.modtaboff + size_tab > bin->size){
			R_FREE (bin->modtab);
			return false;
		}
		for (i = 0; i < bin->nmodtab; i++) {
			len = r_buf_read_at(bin->b, bin->dysymtab.modtaboff +
				i * sizeof (struct MACH0_(dylib_module)),
				dymod, sizeof (struct MACH0_(dylib_module)));
			if (len == -1) {
				eprintf ("Error: read (modtab)\n");
				R_FREE (bin->modtab);
				return false;
			}

			bin->modtab[i].module_name = r_read_ble32 (&dymod[0], bin->big_endian);
			bin->modtab[i].iextdefsym = r_read_ble32 (&dymod[4], bin->big_endian);
			bin->modtab[i].nextdefsym = r_read_ble32 (&dymod[8], bin->big_endian);
			bin->modtab[i].irefsym = r_read_ble32 (&dymod[12], bin->big_endian);
			bin->modtab[i].nrefsym = r_read_ble32 (&dymod[16], bin->big_endian);
			bin->modtab[i].ilocalsym = r_read_ble32 (&dymod[20], bin->big_endian);
			bin->modtab[i].nlocalsym = r_read_ble32 (&dymod[24], bin->big_endian);
			bin->modtab[i].iextrel = r_read_ble32 (&dymod[28], bin->big_endian);
			bin->modtab[i].nextrel = r_read_ble32 (&dymod[32], bin->big_endian);
			bin->modtab[i].iinit_iterm = r_read_ble32 (&dymod[36], bin->big_endian);
			bin->modtab[i].ninit_nterm = r_read_ble32 (&dymod[40], bin->big_endian);
#if R_BIN_MACH064
			bin->modtab[i].objc_module_info_size = r_read_ble32 (&dymod[44], bin->big_endian);
			bin->modtab[i].objc_module_info_addr = r_read_ble64 (&dymod[48], bin->big_endian);
#else
			bin->modtab[i].objc_module_info_addr = r_read_ble32 (&dymod[44], bin->big_endian);
			bin->modtab[i].objc_module_info_size = r_read_ble32 (&dymod[48], bin->big_endian);
#endif
		}
	}
	bin->nindirectsyms = bin->dysymtab.nindirectsyms;
	if (bin->nindirectsyms > 0) {
		if (!(bin->indirectsyms = calloc (bin->nindirectsyms, sizeof(ut32)))) {
			perror ("calloc (indirectsyms)");
			return false;
		}
		if (!UT32_MUL (&size_tab, bin->nindirectsyms, sizeof (ut32))){
			R_FREE (bin->indirectsyms);
			return false;
		}
		if (!size_tab){
			R_FREE (bin->indirectsyms);
			return false;
		}
		if (bin->dysymtab.indirectsymoff > bin->size || \
				bin->dysymtab.indirectsymoff + size_tab > bin->size){
			R_FREE (bin->indirectsyms);
			return false;
		}

		for (i = 0; i < bin->nindirectsyms; i++) {
			len = r_buf_read_at (bin->b, bin->dysymtab.indirectsymoff + i * sizeof (ut32), idsyms, 4);
			if (len == -1) {
				eprintf ("Error: read (indirect syms)\n");
				R_FREE (bin->indirectsyms);
				return false;
			}
			bin->indirectsyms[i] = r_read_ble32 (&idsyms[0], bin->big_endian);
		}
	}
	/* TODO extrefsyms, extrel, locrel */
	return true;
}

static bool parse_signature(struct MACH0_(obj_t) *bin, ut64 off) {
	int i,len;
	ut32 data;
	bin->signature = NULL;
	struct linkedit_data_command link = {};
	ut8 lit[sizeof (struct linkedit_data_command)] = {0};
	struct blob_index_t idx = {};
	struct super_blob_t super = {};

	if (off > bin->size || off + sizeof (struct linkedit_data_command) > bin->size) {
		return false;
	}
	len = r_buf_read_at (bin->b, off, lit, sizeof (struct linkedit_data_command));
	if (len != sizeof (struct linkedit_data_command)) {
		eprintf ("Failed to get data while parsing LC_CODE_SIGNATURE command\n");
		return false;
	}
	link.cmd = r_read_ble32 (&lit[0], bin->big_endian);
	link.cmdsize = r_read_ble32 (&lit[4], bin->big_endian);
	link.dataoff = r_read_ble32 (&lit[8], bin->big_endian);
	link.datasize = r_read_ble32 (&lit[12], bin->big_endian);

	data = link.dataoff;
	if (data > bin->size || data + sizeof (struct super_blob_t) > bin->size) {
		bin->signature = (ut8 *)strdup ("Malformed entitlement");
		return true;
	}
	super.blob.magic = r_read_ble32 (bin->b->buf + data, little_);
	super.blob.length = r_read_ble32 (bin->b->buf + data + 4, little_);
	super.count = r_read_ble32 (bin->b->buf + data + 8, little_);
	for (i = 0; i < super.count; ++i) {
		if ((ut8 *)(bin->b->buf + data + i) > (ut8 *)(bin->b->buf + bin->size)) {
			bin->signature = (ut8 *)strdup ("Malformed entitlement");
			break;
		}
		struct blob_index_t bi;
		if (r_buf_read_at (bin->b, data + 12 + (i * sizeof (struct blob_index_t)),
			(ut8*)&bi, sizeof (struct blob_index_t)) < sizeof (struct blob_index_t)) {
			break;
		}
		idx.type = r_read_ble32 (&bi.type, little_);
		idx.offset = r_read_ble32 (&bi.offset, little_);
		if (idx.type == CSSLOT_ENTITLEMENTS) {
			if (idx.offset > bin->size || idx.offset + sizeof (struct blob_t) > bin->size) {
				bin->signature = (ut8 *)strdup ("Malformed entitlement");
				break;
			}
			struct blob_t entitlements = {}; 
			entitlements.magic = r_read_ble32 (bin->b->buf + data + idx.offset, little_);
			entitlements.length = r_read_ble32 (bin->b->buf + data + idx.offset + 4, little_);
			len = entitlements.length - sizeof(struct blob_t);
			if (len <= bin->size && len > 1) {
				bin->signature = calloc (1, len + 1);
				if (bin->signature) {
					ut8 *src = bin->b->buf + data + idx.offset + sizeof (struct blob_t);
					memcpy (bin->signature, src, len);
					bin->signature[len] = '\0';
					return true;
				}
			} else {
				bin->signature = (ut8 *)strdup ("Malformed entitlement");
			}
		}
	}
	if (!bin->signature) {
		bin->signature = (ut8 *)strdup ("No entitlement found");
	}
	return true;
}

static int parse_thread(struct MACH0_(obj_t)* bin, struct load_command *lc, ut64 off, bool is_first_thread) {
	ut64 ptr_thread, pc = UT64_MAX, pc_offset = UT64_MAX;
	ut32 flavor, count;
	ut8 *arw_ptr = NULL;
	int arw_sz, len = 0;
	ut8 thc[sizeof (struct thread_command)] = {0};

	if (off > bin->size || off + sizeof (struct thread_command) > bin->size)
		return false;

	len = r_buf_read_at (bin->b, off, thc, 8);
	if (len < 1)
		goto wrong_read;
	bin->thread.cmd = r_read_ble32 (&thc[0], bin->big_endian);
	bin->thread.cmdsize = r_read_ble32 (&thc[4], bin->big_endian);
	flavor = r_read_ble32 (bin->b->buf + off + sizeof(struct thread_command), bin->big_endian);
	if (len == -1)
		goto wrong_read;

	if (off + sizeof(struct thread_command) + sizeof(flavor) > bin->size || \
	  off + sizeof(struct thread_command) + sizeof(flavor) + sizeof (ut32) > bin->size)
		return false;

	// TODO: use count for checks
	count = r_read_ble32 (bin->b->buf + off + sizeof(struct thread_command) + sizeof(flavor),
				bin->big_endian);
	ptr_thread = off + sizeof(struct thread_command) + sizeof(flavor) + sizeof(count);

	if (ptr_thread > bin->size)
		return false;

	switch (bin->hdr.cputype) {
	case CPU_TYPE_I386:
	case CPU_TYPE_X86_64:
		switch (flavor) {
		case X86_THREAD_STATE32:
			if (ptr_thread + sizeof (struct x86_thread_state32) > bin->size)
				return false;
			if ((len = r_buf_fread_at (bin->b, ptr_thread,
				(ut8*)&bin->thread_state.x86_32, "16i", 1)) == -1) {
				eprintf ("Error: read (thread state x86_32)\n");
				return false;
			}
			pc = bin->thread_state.x86_32.eip;
			pc_offset = ptr_thread + r_offsetof(struct x86_thread_state32, eip);
			arw_ptr = (ut8 *)&bin->thread_state.x86_32;
			arw_sz = sizeof (struct x86_thread_state32);
			break;
		case X86_THREAD_STATE64:
			if (ptr_thread + sizeof (struct x86_thread_state64) > bin->size)
				return false;
			if ((len = r_buf_fread_at (bin->b, ptr_thread,
				(ut8*)&bin->thread_state.x86_64, "32l", 1)) == -1) {
				eprintf ("Error: read (thread state x86_64)\n");
				return false;
			}
			pc = bin->thread_state.x86_64.rip;
			pc_offset = ptr_thread + r_offsetof(struct x86_thread_state64, rip);
			arw_ptr = (ut8 *)&bin->thread_state.x86_64;
			arw_sz = sizeof (struct x86_thread_state64);
			break;
		//default: eprintf ("Unknown type\n");
		}
		break;
	case CPU_TYPE_POWERPC:
	case CPU_TYPE_POWERPC64:
		if (flavor == X86_THREAD_STATE32) {
			if (ptr_thread + sizeof (struct ppc_thread_state32) > bin->size)
				return false;
			if ((len = r_buf_fread_at (bin->b, ptr_thread,
				(ut8*)&bin->thread_state.ppc_32, bin->big_endian?"40I":"40i", 1)) == -1) {
				eprintf ("Error: read (thread state ppc_32)\n");
				return false;
			}
			pc = bin->thread_state.ppc_32.srr0;
			pc_offset = ptr_thread + r_offsetof(struct ppc_thread_state32, srr0);
			arw_ptr = (ut8 *)&bin->thread_state.ppc_32;
			arw_sz = sizeof (struct ppc_thread_state32);
		} else if (flavor == X86_THREAD_STATE64) {
			if (ptr_thread + sizeof (struct ppc_thread_state64) > bin->size)
				return false;
			if ((len = r_buf_fread_at (bin->b, ptr_thread,
				(ut8*)&bin->thread_state.ppc_64, bin->big_endian?"34LI3LI":"34li3li", 1)) == -1) {
				eprintf ("Error: read (thread state ppc_64)\n");
				return false;
			}
			pc = bin->thread_state.ppc_64.srr0;
			pc_offset = ptr_thread + r_offsetof(struct ppc_thread_state64, srr0);
			arw_ptr = (ut8 *)&bin->thread_state.ppc_64;
			arw_sz = sizeof (struct ppc_thread_state64);
		}
		break;
	case CPU_TYPE_ARM:
		if (ptr_thread + sizeof (struct arm_thread_state32) > bin->size)
			return false;
		if ((len = r_buf_fread_at (bin->b, ptr_thread,
				(ut8*)&bin->thread_state.arm_32, bin->big_endian?"17I":"17i", 1)) == -1) {
			eprintf ("Error: read (thread state arm)\n");
			return false;
		}
		pc = bin->thread_state.arm_32.r15;
		pc_offset = ptr_thread + r_offsetof (struct arm_thread_state32, r15);
		arw_ptr = (ut8 *)&bin->thread_state.arm_32;
		arw_sz = sizeof (struct arm_thread_state32);
		break;
	case CPU_TYPE_ARM64:
		if (ptr_thread + sizeof (struct arm_thread_state64) > bin->size)
			return false;
		if ((len = r_buf_fread_at(bin->b, ptr_thread,
				(ut8*)&bin->thread_state.arm_64, bin->big_endian?"34LI1I":"34Li1i", 1)) == -1) {
			eprintf ("Error: read (thread state arm)\n");
			return false;
		}
		pc = bin->thread_state.arm_64.pc;
		pc_offset = ptr_thread + r_offsetof(struct arm_thread_state64, pc);
		arw_ptr = (ut8*)&bin->thread_state.arm_64;
		arw_sz = sizeof (struct arm_thread_state64);
		break;
	default:
		eprintf ("Error: read (unknown thread state structure)\n");
		return false;
	}

	// TODO: this shouldnt be an eprintf...
	if (arw_ptr && arw_sz > 0) {
		int i;
		ut8 *p = arw_ptr;
		eprintf ("arw ");
		for (i=0; i< arw_sz; i++) {
			eprintf ("%02x", 0xff & p[i]);
		}
		eprintf ("\n");
	}

	if (is_first_thread) {
		bin->main_cmd = *lc;
		if (pc != UT64_MAX)
			bin->entry = pc;
		if (pc_offset != UT64_MAX)
			sdb_num_set (bin->kv, "mach0.entry.offset", pc_offset, 0);
	}

	return true;

wrong_read:
	eprintf("Error: read (thread)\n");
	return false;
}

static int parse_function_starts (struct MACH0_(obj_t)* bin, ut64 off) {
	struct linkedit_data_command fc;
	ut8 sfc[sizeof (struct linkedit_data_command)] = {0};
	ut8 *buf;
	int len;

	if (off > bin->size || off + sizeof (struct linkedit_data_command) > bin->size) {
		eprintf ("Likely overflow while parsing"
			" LC_FUNCTION_STARTS command\n");
	}
	bin->func_start = NULL;
	len = r_buf_read_at (bin->b, off, sfc, sizeof (struct linkedit_data_command));
	if (len < 1) {
		eprintf ("Failed to get data while parsing"
			" LC_FUNCTION_STARTS command\n");
	}
	fc.cmd = r_read_ble32 (&sfc[0], bin->big_endian);
	fc.cmdsize = r_read_ble32 (&sfc[4], bin->big_endian);
	fc.dataoff = r_read_ble32 (&sfc[8], bin->big_endian);
	fc.datasize = r_read_ble32 (&sfc[12], bin->big_endian);

	buf = calloc (1, fc.datasize + 1);
	if (!buf) {
		eprintf ("Failed to allocate buffer\n");
		return false;
	}
	bin->func_size = fc.datasize;
	if (fc.dataoff > bin->size || fc.dataoff + fc.datasize > bin->size) {
		free (buf);
		eprintf ("Likely overflow while parsing "
			"LC_FUNCTION_STARTS command\n");
		return false;
	}
	len = r_buf_read_at (bin->b, fc.dataoff, buf, fc.datasize);
	if (len != fc.datasize) {
		free (buf);
		eprintf ("Failed to get data while parsing"
			" LC_FUNCTION_STARTS\n");
		return false;
	}
	buf[fc.datasize] = 0; // null-terminated buffer
	bin->func_start = buf;
	return true;
}

static int parse_dylib(struct MACH0_(obj_t)* bin, ut64 off) {
	struct dylib_command dl;
	int lib, len;
	ut8 sdl[sizeof (struct dylib_command)] = {0};

	if (off > bin->size || off + sizeof (struct dylib_command) > bin->size)
		return false;
	lib = bin->nlibs - 1;

	if (!(bin->libs = realloc (bin->libs, bin->nlibs * R_BIN_MACH0_STRING_LENGTH))) {
		perror ("realloc (libs)");
		return false;
	}
	len = r_buf_read_at (bin->b, off, sdl, sizeof (struct dylib_command));
	if (len < 1) {
		eprintf ("Error: read (dylib)\n");
		return false;
	}
	dl.cmd = r_read_ble32 (&sdl[0], bin->big_endian);
	dl.cmdsize = r_read_ble32 (&sdl[4], bin->big_endian);
	dl.dylib.name = r_read_ble32 (&sdl[8], bin->big_endian);
	dl.dylib.timestamp = r_read_ble32 (&sdl[12], bin->big_endian);
	dl.dylib.current_version = r_read_ble32 (&sdl[16], bin->big_endian);
	dl.dylib.compatibility_version = r_read_ble32 (&sdl[20], bin->big_endian);

	if (off + dl.dylib.name > bin->size ||\
	  off + dl.dylib.name + R_BIN_MACH0_STRING_LENGTH > bin->size)
		return false;

	len = r_buf_read_at (bin->b, off+dl.dylib.name, (ut8*)bin->libs[lib], R_BIN_MACH0_STRING_LENGTH);
	if (len < 1) {
		eprintf ("Error: read (dylib str)");
		return false;
	}
	return true;
}

static int init_items(struct MACH0_(obj_t)* bin) {
	struct load_command lc = {0, 0};
	ut8 loadc[sizeof (struct load_command)] = {0};
	bool is_first_thread = true;
	ut64 off = 0LL;
	int i, len;

	bin->uuidn = 0;
	bin->os = 0;
	bin->has_crypto = 0;
	if (bin->hdr.sizeofcmds > bin->size) {
		eprintf ("Warning: chopping hdr.sizeofcmds\n");
		bin->hdr.sizeofcmds = bin->size - 128;
		//return false;
	}
	//eprintf ("Commands: %d\n", bin->hdr.ncmds);
	for (i = 0, off = sizeof (struct MACH0_(mach_header)); \
			i < bin->hdr.ncmds; i++, off += lc.cmdsize) {
		if (off > bin->size || off + sizeof (struct load_command) > bin->size){
			eprintf ("mach0: out of bounds command\n");
			return false;
		}
		len = r_buf_read_at (bin->b, off, loadc, sizeof (struct load_command));
		if (len < 1) {
			eprintf ("Error: read (lc) at 0x%08"PFMT64x"\n", off);
			return false;
		}
		lc.cmd = r_read_ble32 (&loadc[0], bin->big_endian);
		lc.cmdsize = r_read_ble32 (&loadc[4], bin->big_endian);

		if (lc.cmdsize < 1 || off + lc.cmdsize > bin->size) {
			eprintf ("Warning: mach0_header %d = cmdsize<1.\n", i);
			break;
		}

		// TODO: a different format for each cmd
		sdb_num_set (bin->kv, sdb_fmt (0, "mach0_cmd_%d.offset", i), off, 0);
		sdb_set (bin->kv, sdb_fmt (0, "mach0_cmd_%d.format", i), "xd cmd size", 0);

		//eprintf ("%d\n", lc.cmd);
		switch (lc.cmd) {
		case LC_DATA_IN_CODE:
			sdb_set (bin->kv, sdb_fmt (0, "mach0_cmd_%d.cmd", i), "data_in_code", 0);
			// TODO table of non-instructions in __text
			break;
		case LC_RPATH:
			sdb_set (bin->kv, sdb_fmt (0, "mach0_cmd_%d.cmd", i), "rpath", 0);
			//eprintf ("--->\n");
			break;
		case LC_SEGMENT_64:
		case LC_SEGMENT:
			sdb_set (bin->kv, sdb_fmt (0, "mach0_cmd_%d.cmd", i), "segment", 0);
			bin->nsegs++;
			if (!parse_segments (bin, off)) {
				eprintf ("error parsing segment\n");
				bin->nsegs--;
				return false;
			}
			break;
		case LC_SYMTAB:
			sdb_set (bin->kv, sdb_fmt (0, "mach0_cmd_%d.cmd", i), "symtab", 0);
			if (!parse_symtab (bin, off)) {
				eprintf ("error parsing symtab\n");
				return false;
			}
			break;
		case LC_DYSYMTAB:
			sdb_set (bin->kv, sdb_fmt (0, "mach0_cmd_%d.cmd", i), "dysymtab", 0);
			if (!parse_dysymtab(bin, off)) {
				eprintf ("error parsing dysymtab\n");
				return false;
			}
			break;
		case LC_DYLIB_CODE_SIGN_DRS:
			sdb_set (bin->kv, sdb_fmt (0, "mach0_cmd_%d.cmd", i), "dylib_code_sign_drs", 0);
			//eprintf ("[mach0] code is signed\n");
			break;
		case LC_VERSION_MIN_MACOSX:
			sdb_set (bin->kv, sdb_fmt (0, "mach0_cmd_%d.cmd", i), "version_min_macosx", 0);
			bin->os = 1;
			// set OS = osx
			//eprintf ("[mach0] Requires OSX >= x\n");
			break;
		case LC_VERSION_MIN_IPHONEOS:
			sdb_set (bin->kv, sdb_fmt (0, "mach0_cmd_%d.cmd", i), "version_min_iphoneos", 0);
			bin->os = 2;
			// set OS = ios
			//eprintf ("[mach0] Requires iOS >= x\n");
			break;
		case LC_VERSION_MIN_TVOS:
			sdb_set (bin->kv, sdb_fmt (0, "mach0_cmd_%d.cmd", i), "version_min_tvos", 0);
			bin->os = 4;
			break;
		case LC_VERSION_MIN_WATCHOS:
			sdb_set (bin->kv, sdb_fmt (0, "mach0_cmd_%d.cmd", i), "version_min_watchos", 0);
			bin->os = 3;
			break;
		case LC_UUID:
			sdb_set (bin->kv, sdb_fmt (0, "mach0_cmd_%d.cmd", i), "uuid", 0);
			{
			struct uuid_command uc = {0};
			if (off + sizeof (struct uuid_command) > bin->size) {
				eprintf ("UUID out of obunds\n");
				return false;
			}
			if (r_buf_fread_at (bin->b, off, (ut8*)&uc, "24c", 1) != -1) {
				char key[128];
				char val[128];
				snprintf (key, sizeof (key)-1, "uuid.%d", bin->uuidn++);
				r_hex_bin2str ((ut8*)&uc.uuid, 16, val);
				sdb_set (bin->kv, key, val, 0);
				//for (i=0;i<16; i++) eprintf ("%02x%c", uc.uuid[i], (i==15)?'\n':'-');
			}
			}
			break;
		case LC_ENCRYPTION_INFO_64:
			/* TODO: the struct is probably different here */
		case LC_ENCRYPTION_INFO:
			sdb_set (bin->kv, sdb_fmt (0, "mach0_cmd_%d.cmd", i), "encryption_info", 0);
			{
			struct MACH0_(encryption_info_command) eic = {0};
			ut8 seic[sizeof (struct MACH0_(encryption_info_command))] = {0};
			if (off + sizeof (struct MACH0_(encryption_info_command)) > bin->size) {
				eprintf ("encryption info out of bounds\n");
				return false;
			}
			if (r_buf_read_at (bin->b, off, seic, sizeof (struct MACH0_(encryption_info_command))) != -1) {
				eic.cmd = r_read_ble32 (&seic[0], bin->big_endian);
				eic.cmdsize = r_read_ble32 (&seic[4], bin->big_endian);
				eic.cryptoff = r_read_ble32 (&seic[8], bin->big_endian);
				eic.cryptsize = r_read_ble32 (&seic[12], bin->big_endian);
				eic.cryptid = r_read_ble32 (&seic[16], bin->big_endian);

				bin->has_crypto = eic.cryptid;
				sdb_set (bin->kv, "crypto", "true", 0);
				sdb_num_set (bin->kv, "cryptid", eic.cryptid, 0);
				sdb_num_set (bin->kv, "cryptoff", eic.cryptoff, 0);
				sdb_num_set (bin->kv, "cryptsize", eic.cryptsize, 0);
				sdb_num_set (bin->kv, "cryptheader", off, 0);
			} }
			break;
		case LC_LOAD_DYLINKER:
			{
				sdb_set (bin->kv, sdb_fmt (0, "mach0_cmd_%d.cmd", i), "dylinker", 0);
				free (bin->intrp);
				bin->intrp = NULL;
				//eprintf ("[mach0] load dynamic linker\n");
				struct dylinker_command dy = {0};
				ut8 sdy[sizeof (struct dylinker_command)] = {0};
				if (off + sizeof (struct dylinker_command) > bin->size){
					eprintf ("Warning: Cannot parse dylinker command\n");
					return false;
				}
				if (r_buf_read_at (bin->b, off, sdy, sizeof (struct dylinker_command)) == -1) {
					eprintf ("Warning: read (LC_DYLD_INFO) at 0x%08"PFMT64x"\n", off);
				} else {
					dy.cmd = r_read_ble32 (&sdy[0], bin->big_endian);
					dy.cmdsize = r_read_ble32 (&sdy[4], bin->big_endian);
					dy.name = r_read_ble32 (&sdy[8], bin->big_endian);

					int len = dy.cmdsize;
					char *buf = malloc (len+1);
					if (buf) {
						// wtf @ off + 0xc ?
						r_buf_read_at (bin->b, off + 0xc, (ut8*)buf, len);
						buf[len] = 0;
						free (bin->intrp);
						bin->intrp = buf;
					}
				}
			}
			break;
		case LC_MAIN:
			{
			struct {
				ut64 eo;
				ut64 ss;
			} ep = {0};
			ut8 sep[2 * sizeof (ut64)] = {0};
			sdb_set (bin->kv, sdb_fmt (0, "mach0_cmd_%d.cmd", i), "main", 0);

			if (!is_first_thread) {
				eprintf("Error: LC_MAIN with other threads\n");
				return false;
			}
			if (off+8 > bin->size || off + sizeof (ep) > bin->size) {
				eprintf ("invalid command size for main\n");
				return false;
			}
			r_buf_read_at (bin->b, off+8, sep, 2 * sizeof (ut64));
			ep.eo = r_read_ble64 (&sep[0], bin->big_endian);
			ep.ss = r_read_ble64 (&sep[8], bin->big_endian);

			bin->entry = ep.eo;
			bin->main_cmd = lc;

			sdb_num_set (bin->kv, "mach0.entry.offset", off+8, 0);
			sdb_num_set (bin->kv, "stacksize", ep.ss, 0);

			is_first_thread = false;
			}
			break;
		case LC_UNIXTHREAD:
			sdb_set (bin->kv, sdb_fmt (0, "mach0_cmd_%d.cmd", i), "unixthread", 0);
			if (!is_first_thread) {
				eprintf("Error: LC_UNIXTHREAD with other threads\n");
				return false;
			}
		case LC_THREAD:
			sdb_set (bin->kv, sdb_fmt (0, "mach0_cmd_%d.cmd", i), "thread", 0);
			if (!parse_thread(bin, &lc, off, is_first_thread)) {
				eprintf ("Cannot parse thread\n");
				return false;
			}
			is_first_thread = false;
			break;
		case LC_LOAD_DYLIB:
		case LC_LOAD_WEAK_DYLIB:
			sdb_set (bin->kv, sdb_fmt (0, "mach0_cmd_%d.cmd", i), "load_dylib", 0);
			bin->nlibs++;
			if (!parse_dylib(bin, off)){
				eprintf ("Cannot parse dylib\n");
				bin->nlibs--;
				return false;
			}
			break;
		case LC_DYLD_INFO:
		case LC_DYLD_INFO_ONLY:
			{
			ut8 dyldi[sizeof (struct dyld_info_command)] = {0};
			sdb_set (bin->kv, sdb_fmt (0, "mach0_cmd_%d.cmd", i), "dyld_info", 0);
			bin->dyld_info = malloc (sizeof(struct dyld_info_command));

			if (off + sizeof (struct dyld_info_command) > bin->size){
				eprintf ("Cannot parse dyldinfo\n");
				free (bin->dyld_info);
				return false;
			}
			if (r_buf_read_at (bin->b, off, dyldi, sizeof (struct dyld_info_command)) == -1) {
				free (bin->dyld_info);
				bin->dyld_info = NULL;
				eprintf ("Error: read (LC_DYLD_INFO) at 0x%08"PFMT64x"\n", off);
			} else {
				bin->dyld_info->cmd = r_read_ble32 (&dyldi[0], bin->big_endian);
				bin->dyld_info->cmdsize = r_read_ble32 (&dyldi[4], bin->big_endian);
				bin->dyld_info->rebase_off = r_read_ble32 (&dyldi[8], bin->big_endian);
				bin->dyld_info->rebase_size = r_read_ble32 (&dyldi[12], bin->big_endian);
				bin->dyld_info->bind_off = r_read_ble32 (&dyldi[16], bin->big_endian);
				bin->dyld_info->bind_size = r_read_ble32 (&dyldi[20], bin->big_endian);
				bin->dyld_info->weak_bind_off = r_read_ble32 (&dyldi[24], bin->big_endian);
				bin->dyld_info->weak_bind_size = r_read_ble32 (&dyldi[28], bin->big_endian);
				bin->dyld_info->lazy_bind_off = r_read_ble32 (&dyldi[32], bin->big_endian);
				bin->dyld_info->lazy_bind_size = r_read_ble32 (&dyldi[36], bin->big_endian);
				bin->dyld_info->export_off = r_read_ble32 (&dyldi[40], bin->big_endian);
				bin->dyld_info->export_size = r_read_ble32 (&dyldi[44], bin->big_endian);
			}
			}
			break;
		case LC_CODE_SIGNATURE:
			parse_signature (bin, off);
			sdb_set (bin->kv, sdb_fmt (0, "mach0_cmd_%d.cmd", i), "signature", 0);
			/* ut32 dataoff
			// ut32 datasize */
			break;
		case LC_SOURCE_VERSION:
			sdb_set (bin->kv, sdb_fmt (0, "mach0_cmd_%d.cmd", i), "version", 0);
			/* uint64_t  version;  */
			/* A.B.C.D.E packed as a24.b10.c10.d10.e10 */
			//eprintf ("mach0: TODO: Show source version\n");
			break;
		case LC_SEGMENT_SPLIT_INFO:
			sdb_set (bin->kv, sdb_fmt (0, "mach0_cmd_%d.cmd", i), "split_info", 0);
			/* TODO */
			break;
		case LC_FUNCTION_STARTS:
			sdb_set (bin->kv, sdb_fmt (0, "mach0_cmd_%d.cmd", i), "function_starts", 0);
			if (!parse_function_starts (bin, off)) {
				eprintf ("Cannot parse LC_FUNCTION_STARTS\n");
			}
			break;
		case LC_REEXPORT_DYLIB:
			sdb_set (bin->kv, sdb_fmt (0, "mach0_cmd_%d.cmd", i), "dylib", 0);
			/* TODO */
			break;
		default:
			//eprintf ("mach0: Unknown header command %x\n", lc.cmd);
			break;
		}
	}
	return true;
}

static int init(struct MACH0_(obj_t)* bin) {
	union {
		ut16 word;
		ut8 byte[2];
	} endian = { 1 };
	little_ = endian.byte[0];
	if (!init_hdr(bin)) {
		eprintf ("Warning: File is not MACH0\n");
		return false;
	}
	if (!init_items(bin))
		eprintf ("Warning: Cannot initialize items\n");

	bin->baddr = MACH0_(get_baddr)(bin);
	return true;
}

void* MACH0_(mach0_free)(struct MACH0_(obj_t)* bin) {
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
	free (bin->func_start);
	free (bin->signature);
	r_buf_free (bin->b);
	free (bin);
	return NULL;
}

struct MACH0_(obj_t)* MACH0_(mach0_new)(const char* file) {
	ut8 *buf;
	struct MACH0_(obj_t) *bin;

	if (!(bin = malloc (sizeof (struct MACH0_(obj_t)))))
		return NULL;
	memset (bin, 0, sizeof (struct MACH0_(obj_t)));
	bin->file = file;
	if (!(buf = (ut8*)r_file_slurp(file, &bin->size)))
		return MACH0_(mach0_free)(bin);
	bin->b = r_buf_new ();
	if (!r_buf_set_bytes(bin->b, buf, bin->size)) {
		free (buf);
		return MACH0_(mach0_free)(bin);
	}
	free (buf);

	bin->dyld_info = NULL;

	if (!init(bin))
		return MACH0_(mach0_free)(bin);

	bin->imports_by_ord_size = 0;
	bin->imports_by_ord = NULL;

	return bin;
}

struct MACH0_(obj_t)* MACH0_(new_buf)(RBuffer *buf) {
	struct MACH0_(obj_t) *bin = R_NEW0 (struct MACH0_(obj_t));
	if (!bin) return NULL;
	bin->kv = sdb_new (NULL, "bin.mach0", 0);
	bin->b = r_buf_new ();
	bin->size = buf->length;
	if (!r_buf_set_bytes (bin->b, buf->buf, bin->size)){
		return MACH0_(mach0_free) (bin);
	}
	if (!init(bin))
		return MACH0_(mach0_free)(bin);
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

struct section_t* MACH0_(get_sections)(struct MACH0_(obj_t)* bin) {
	struct section_t *sections;
	char segname[32], sectname[32];
	int i, j, to;

	if (!bin) {
		return NULL;
	}
	/* for core files */
	if (bin->nsects < 1 && bin->nsegs > 0) {
		struct MACH0_(segment_command) *seg;
		if (!(sections = calloc ((bin->nsegs + 1), sizeof (struct section_t)))) {
			return NULL;
		}
		for (i = 0; i < bin->nsegs; i++) {
			seg = &bin->segs[i];
			sections[i].addr = seg->vmaddr;
			sections[i].offset = seg->fileoff;
			sections[i].size = seg->vmsize;
			sections[i].align = 4096;
			sections[i].flags = seg->flags;
			r_str_ncpy (sectname, seg->segname, sizeof (sectname)-1);
			// hack to support multiple sections with same name
			sections[i].srwx = prot2perm (seg->initprot);
			sections[i].last = 0;
		}
		sections[i].last = 1;
		return sections;
	}

	if (!bin->sects) {
		return NULL;
	}
	to = R_MIN (bin->nsects, 128); // limit number of sections here to avoid fuzzed bins
	if (to < 1) {
		return NULL;
	}
	if (!(sections = malloc ((bin->nsects + 1) * sizeof (struct section_t)))) {
		return NULL;
	}
	for (i = 0; i < to; i++) {
		sections[i].offset = (ut64)bin->sects[i].offset;
		sections[i].addr = (ut64)bin->sects[i].addr;
		sections[i].size = (ut64)bin->sects[i].size;
		sections[i].align = bin->sects[i].align;
		sections[i].flags = bin->sects[i].flags;
		r_str_ncpy (sectname, bin->sects[i].sectname, sizeof (sectname)-1);
		// hack to support multiple sections with same name
		snprintf (segname, sizeof (segname), "%d", i); // wtf
		for (j = 0; j < bin->nsegs; j++) {
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

static int parse_import_stub(struct MACH0_(obj_t)* bin, struct symbol_t *symbol, int idx) {
	int i, j, nsyms, stridx;
	const char *symstr;
	if (idx < 0) {
		return 0;
	}
	symbol->offset = 0LL;
	symbol->addr = 0LL;
	symbol->name[0] = '\0';

	if (!bin || !bin->sects) {
		return false;
	}
	for (i = 0; i < bin->nsects; i++) {
		if ((bin->sects[i].flags & SECTION_TYPE) == S_SYMBOL_STUBS && bin->sects[i].reserved2 > 0) {
			nsyms = (int)(bin->sects[i].size / bin->sects[i].reserved2);
			if (nsyms > bin->size) {
				eprintf ("mach0: Invalid symbol table size\n");
			}
			for (j = 0; j < nsyms; j++) {
				if (bin->sects) {
					if (bin->sects[i].reserved1 + j >= bin->nindirectsyms) {
						continue;
					}
				}
				if (bin->indirectsyms) {
					if (idx != bin->indirectsyms[bin->sects[i].reserved1 + j]) {
						continue;
					}
				}
				if (idx > bin->nsymtab) {
					continue;
				}
				symbol->type = R_BIN_MACH0_SYMBOL_TYPE_LOCAL;
				symbol->offset = bin->sects[i].offset + j * bin->sects[i].reserved2;
				symbol->addr = bin->sects[i].addr + j * bin->sects[i].reserved2;
				symbol->size = 0;
				stridx = bin->symtab[idx].n_strx;
				if (stridx >= 0 && stridx < bin->symstrlen) {
					symstr = (char *)bin->symstr+stridx;
				} else {
					symstr = "???";
				}
				// Remove the extra underscore that every import seems to have in Mach-O.
				if (*symstr == '_') {
					symstr++;
				}
				snprintf (symbol->name, R_BIN_MACH0_STRING_LENGTH, "imp.%s", symstr);
				return true;
			}
		}
	}
	return false;
}

#if 0
static ut64 get_text_base(struct MACH0_(obj_t)* bin) {
	ut64 ret = 0LL;
	struct section_t *sections;
	if ((sections = MACH0_(get_sections) (bin))) {
		int i;
		for (i = 0; !sections[i].last; i++) {
			if (strstr(sections[i].name, "text")) {
				ret =  sections[i].offset;
				break;
			}
		}
		free (sections);
	}
	return ret;
}
#endif

static int inSymtab(Sdb *db, struct symbol_t *symbols, int last, const char *name, ut64 addr) {
	const char *key = sdb_fmt (0, "%s.%"PFMT64x, name, addr);
	if (sdb_const_get (db, key, NULL)) {
		return true;
	}
	sdb_set (db, key, "1", 0);
	return false;
}

struct symbol_t* MACH0_(get_symbols)(struct MACH0_(obj_t)* bin) {
	const char *symstr;
	struct symbol_t *symbols;
	int from, to, i, j, s, stridx, symbols_size, symbols_count;
	Sdb *db;
	//ut64 text_base = get_text_base (bin);

	if (!bin || !bin->symtab || !bin->symstr) {
		return NULL;
	}
	/* parse symbol table */
	/* parse dynamic symbol table */
	symbols_count = (bin->dysymtab.nextdefsym + \
			bin->dysymtab.nlocalsym + \
			bin->dysymtab.nundefsym );
	symbols_count += bin->nsymtab;
	//symbols_count = bin->nsymtab;
	symbols_size = (symbols_count + 1) * 2 * sizeof (struct symbol_t);

	if (symbols_size < 1) {
		return NULL;
	}

	if (!(symbols = calloc (1, symbols_size))) {
		return NULL;
	}
	db = sdb_new0 ();
	j = 0; // symbol_idx
	for (s = 0; s < 2; s++) {
		switch (s) {
		case 0:
			from = bin->dysymtab.iextdefsym;
			to = from + bin->dysymtab.nextdefsym;
			break;
		case 1:
			from = bin->dysymtab.ilocalsym;
			to = from + bin->dysymtab.nlocalsym;
			break;
#if NOT_USED
		case 2:
			from = bin->dysymtab.iundefsym;
			to = from + bin->dysymtab.nundefsym;
			break;
#endif
		}
		if (from == to) {
			continue;
		}
#define OLD 1
#if OLD
		from = R_MIN (R_MAX (0, from), symbols_size / sizeof (struct symbol_t));
		to = R_MIN (to , symbols_size / sizeof (struct symbol_t));
		to = R_MIN (to, bin->nsymtab);
#else
		from = R_MIN (R_MAX (0, from), symbols_size/sizeof(struct symbol_t));
		to = symbols_count; //symbols_size/sizeof(struct symbol_t);
#endif
		int maxsymbols = symbols_size / sizeof(struct symbol_t);
		if (to > 0x500000) {
			eprintf ("WARNING: corrupted mach0 header: symbol table is too big %d\n", to);
			free (symbols);
			sdb_free (db);
			return NULL;
		}
		if (symbols_count >= maxsymbols) {
			symbols_count = maxsymbols - 1;
		}
		for (i = from; i < to && j < symbols_count; i++, j++) {
			symbols[j].offset = addr_to_offset (bin, bin->symtab[i].n_value);
			symbols[j].addr = bin->symtab[i].n_value;
			symbols[j].size = 0; /* TODO: Is it anywhere? */
			if (bin->symtab[i].n_type & N_EXT) {
				symbols[j].type = R_BIN_MACH0_SYMBOL_TYPE_EXT;
			} else {
				symbols[j].type = R_BIN_MACH0_SYMBOL_TYPE_LOCAL;
			}
			stridx = bin->symtab[i].n_strx;
			if (stridx >= 0 && stridx < bin->symstrlen) {
				symstr = (char*)bin->symstr+stridx;
			} else {
				symstr = "???";
			}
			{
				int i = 0;
				int len = 0;
				len = bin->symstrlen - stridx;
				if (len > 0) {
					for (i = 0; i < len; i++) {
						if ((ut8)(symstr[i] & 0xff) == 0xff || !symstr[i]) {
							len = i;
							break;
						}
					}
					char *symstr_dup = NULL;
					if (len > 0) {
						symstr_dup = r_str_ndup (symstr, len);
					}
					if (!symstr_dup) {
						symbols[j].name[0] = 0;
					} else {
						strncpy (symbols[j].name, symstr_dup, R_BIN_MACH0_STRING_LENGTH-1);
						symbols[j].name[R_BIN_MACH0_STRING_LENGTH - 2] = 0;
					}
					free (symstr_dup);
				} else {
					symbols[j].name[0] = 0;
				}
				symbols[j].last = 0;
			}
			if (inSymtab (db, symbols, j, symbols[j].name, symbols[j].addr)) {
				symbols[j].name[0] = 0;
				j--;
			}
		}
	}
	to = R_MIN (bin->nsymtab, bin->dysymtab.iundefsym + bin->dysymtab.nundefsym);
	for (i = bin->dysymtab.iundefsym; i < to; i++) {
		if (j > symbols_count) {
			eprintf ("mach0-get-symbols: error\n");
			break;
		}
		if (parse_import_stub(bin, &symbols[j], i))
			symbols[j++].last = 0;
	}

#if 1
// symtab is wrongly parsed and produces dupped syms with incorrect vaddr */
	for (i = 0; i < bin->nsymtab; i++) {
		struct MACH0_(nlist) *st = &bin->symtab[i];
#if 0
		eprintf ("stridx %d -> section %d type %d value = %d\n",
			st->n_strx, st->n_sect, st->n_type, st->n_value);
#endif
		stridx = st->n_strx;
		if (stridx >= 0 && stridx < bin->symstrlen) {
			symstr = (char*)bin->symstr + stridx;
		} else {
			symstr = "???";
		}
		// 0 is for imports
		// 1 is for symbols
		// 2 is for func.eh (exception handlers?)
		int section = st->n_sect;
		if (section == 1 && j < symbols_count) { // text ??st->n_type == 1)
			/* is symbol */
			symbols[j].addr = st->n_value; // + text_base;
			symbols[j].offset = addr_to_offset (bin, symbols[j].addr);
			symbols[j].size = 0; /* find next symbol and crop */
			if (st->n_type & N_EXT) {
				symbols[j].type = R_BIN_MACH0_SYMBOL_TYPE_EXT;
			} else {
				symbols[j].type = R_BIN_MACH0_SYMBOL_TYPE_LOCAL; 
			}
			strncpy (symbols[j].name, symstr, R_BIN_MACH0_STRING_LENGTH);
			symbols[j].name[R_BIN_MACH0_STRING_LENGTH-1] = 0;
			symbols[j].last = 0;
			if (inSymtab (db, symbols, j, symbols[j].name, symbols[j].addr)) {
				symbols[j].name[0] = 0;
			} else {
				j++;
			}
		}
	}
#endif
	sdb_free (db);
	symbols[j].last = 1;
	return symbols;
}

static int parse_import_ptr(struct MACH0_(obj_t)* bin, struct reloc_t *reloc, int idx) {
	int i, j, sym, wordsize;
	ut32 stype;
	wordsize = MACH0_(get_bits)(bin) / 8;
	if (idx<0 || idx>= bin->nsymtab)
		return 0;
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
		default: return false;
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
			return true;
		}
	}
	return false;
}

struct import_t* MACH0_(get_imports)(struct MACH0_(obj_t)* bin) {
	struct import_t *imports;
	int i, j, idx, stridx;
	const char *symstr;

	if (!bin->symtab || !bin->symstr || !bin->sects || !bin->indirectsyms)
		return NULL;
	if (bin->dysymtab.nundefsym < 1 || bin->dysymtab.nundefsym > 0xfffff) {
		return NULL;
	}
	if (!(imports = malloc ((bin->dysymtab.nundefsym + 1) * sizeof(struct import_t))))
		return NULL;
	for (i = j = 0; i < bin->dysymtab.nundefsym; i++) {
		idx = bin->dysymtab.iundefsym +i;
		if (idx < 0 || idx >= bin->nsymtab) {
			eprintf ("WARNING: Imports index out of bounds. Ignoring relocs\n");
			free (imports);
			return NULL;
		}
		stridx = bin->symtab[idx].n_strx;
		if (stridx >= 0 && stridx < bin->symstrlen) {
			symstr = (char *)bin->symstr + stridx;
		} else {
			symstr = "";
		}
		if (!*symstr) {
			continue;
		}
		{
			int i = 0;
			int len = 0;
			char *symstr_dup = NULL;
			len = bin->symstrlen - stridx;
			imports[j].name[0] = 0;
			if (len > 0) {
				for (i = 0; i < len; i++) {
					if ((unsigned char)symstr[i] == 0xff || !symstr[i]) {
						len = i;
						break;
					}
				}
				symstr_dup = r_str_ndup (symstr, len);
				if (symstr_dup) {
					strncpy (imports[j].name, symstr_dup, R_BIN_MACH0_STRING_LENGTH - 1);
					imports[j].name[R_BIN_MACH0_STRING_LENGTH - 2] = 0;
					free (symstr_dup);
				}
			}
		}
		imports[j].ord = i;
		imports[j++].last = 0;
	}
	imports[j].last = 1;

	if (!bin->imports_by_ord_size) {
		if (j > 0) {
			bin->imports_by_ord_size = j;
			bin->imports_by_ord = (RBinImport**)calloc (j, sizeof (RBinImport*));
		} else {
			bin->imports_by_ord_size = 0;
			bin->imports_by_ord = NULL;
		}
	}

	return imports;
}



struct reloc_t* MACH0_(get_relocs)(struct MACH0_(obj_t)* bin) {
	struct reloc_t *relocs;
	int i = 0, len;
	ulebr ur = {NULL};
	int wordsize = MACH0_(get_bits)(bin) / 8;
	if (bin->dyld_info) {
		ut8 *opcodes,*end, type = 0, rel_type = 0;
		int lib_ord, seg_idx = -1, sym_ord = -1;
		size_t j, count, skip, bind_size, lazy_size;
		st64 addend = 0;
		ut64 segmentAddress = 0LL;
		ut64 addr = 0LL;
		ut8 done = 0;

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

		if (!bind_size || !lazy_size) {
			return NULL;
		}

		if ((bind_size + lazy_size)<1) {
			return NULL;
		}
		if (bin->dyld_info->bind_off > bin->size || bin->dyld_info->bind_off + bind_size > bin->size)
			return NULL;
		if (bin->dyld_info->lazy_bind_off > bin->size || \
			bin->dyld_info->lazy_bind_off + lazy_size > bin->size)
			return NULL;
		if (bin->dyld_info->bind_off+bind_size+lazy_size > bin->size)
			return NULL;
		// NOTE(eddyb) it's a waste of memory, but we don't know the actual number of relocs.
		if (!(relocs = calloc (1, (1 + bind_size + lazy_size) * sizeof (struct reloc_t))))
			return NULL;

		opcodes = calloc (1, bind_size + lazy_size + 1);
		if (!opcodes) {
			free (relocs);
			return NULL;
		}
		len = r_buf_read_at (bin->b, bin->dyld_info->bind_off, opcodes, bind_size);
		i = r_buf_read_at (bin->b, bin->dyld_info->lazy_bind_off, opcodes + bind_size, lazy_size);
		if (len < 1 || i < 1) {
			eprintf ("Error: read (dyld_info bind) at 0x%08"PFMT64x"\n",
			(ut64)(size_t)bin->dyld_info->bind_off);
			free (opcodes);
			relocs[i].last = 1;
			return relocs;
		}
		i = 0;
		// that +2 is a minimum required for uleb128, this may be wrong,
		// the correct fix would be to make ULEB() must use rutil's
		// implementation that already checks for buffer boundaries
		for (ur.p = opcodes, end = opcodes + bind_size + lazy_size ; (ur.p+2 < end) && !done; ) {
			ut8 imm = *ur.p & BIND_IMMEDIATE_MASK, op = *ur.p & BIND_OPCODE_MASK;
			++ur.p;
			switch (op) {
#define ULEB() read_uleb128 (&ur,end)
#define SLEB() read_sleb128 (&ur,end)
			case BIND_OPCODE_DONE:
				done = 1;
				break;
			case BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:
				lib_ord = imm;
				break;
			case BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB:
				lib_ord = ULEB();
				break;
			case BIND_OPCODE_SET_DYLIB_SPECIAL_IMM:
				lib_ord = imm? (st8)(BIND_OPCODE_MASK | imm) : 0;
				break;
			case BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM: {
				char *sym_name = (char*)ur.p;
				//ut8 sym_flags = imm;
				while (*ur.p++ && ur.p<end) {
					/* empty loop */
				}
				sym_ord = -1;
				if (bin->symtab && bin->dysymtab.nundefsym < 0xffff)
				for (j = 0; j < bin->dysymtab.nundefsym; j++) {
					int stridx = 0;
					int iundefsym = bin->dysymtab.iundefsym;
					if (iundefsym>=0 && iundefsym < bin->nsymtab) {
						int sidx = iundefsym +j;
						if (sidx<0 || sidx>= bin->nsymtab)
							continue;
						stridx = bin->symtab[sidx].n_strx;
						if (stridx < 0 || stridx >= bin->symstrlen)
							continue;
					}
					if (!strcmp ((char *)bin->symstr + stridx, sym_name)) {
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
				if (seg_idx < 0 || seg_idx >= bin->nsegs) {
					eprintf ("Error: BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB"
						" has unexistent segment %d\n", seg_idx);
					addr = 0LL;
					return 0; // early exit to avoid future mayhem
				} else {
					addr = bin->segs[seg_idx].vmaddr + ULEB();
					segmentAddress = bin->segs[seg_idx].vmaddr \
							+ bin->segs[seg_idx].vmsize;
				}
				break;
			case BIND_OPCODE_ADD_ADDR_ULEB:
				addr += ULEB();
				break;
#define DO_BIND() do {\
if (sym_ord < 0 || seg_idx < 0 ) break;\
if (i >= (bind_size + lazy_size)) break;\
relocs[i].addr = addr;\
relocs[i].offset = addr - bin->segs[seg_idx].vmaddr + bin->segs[seg_idx].fileoff;\
if (type == BIND_TYPE_TEXT_PCREL32)\
	relocs[i].addend = addend - (bin->baddr + addr);\
else relocs[i].addend = addend;\
/* library ordinal ??? */ \
relocs[i].ord = lib_ord;\
relocs[i].ord = sym_ord;\
relocs[i].type = rel_type;\
relocs[i++].last = 0;\
} while (0)
			case BIND_OPCODE_DO_BIND:
				if (addr >= segmentAddress) {
					eprintf ("Error: Malformed DO bind opcode\n");
					goto beach;
				}
				DO_BIND();
				addr += wordsize;
				break;
			case BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB:
				if (addr >= segmentAddress) {
					eprintf ("Error: Malformed ADDR ULEB bind opcode\n");
					goto beach;
				}
				DO_BIND();
				addr += ULEB() + wordsize;
				break;
			case BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED:
				if (addr >= segmentAddress) {
					eprintf ("Error: Malformed IMM SCALED bind opcode\n");
					goto beach;
				}
				DO_BIND();
				addr += (ut64)imm * (ut64)wordsize + wordsize;
				break;
			case BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB:
				count = ULEB();
				skip = ULEB();
				for (j = 0; j < count; j++) {
					if (addr >= segmentAddress) {
						eprintf ("Error: Malformed ULEB TIMES bind opcode\n");
						goto beach;
					}
					DO_BIND();
					addr += skip + wordsize;
				}
				break;
#undef DO_BIND
#undef ULEB
#undef SLEB
			default:
				eprintf ("Error: unknown bind opcode 0x%02x in dyld_info\n", *ur.p);
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
		if (!(relocs = malloc ((bin->dysymtab.nundefsym + 1) * sizeof(struct reloc_t))))
			return NULL;
		for (j = 0; j < bin->dysymtab.nundefsym; j++) {
			if (parse_import_ptr(bin, &relocs[i], bin->dysymtab.iundefsym + j)) {
				relocs[i].ord = j;
				relocs[i++].last = 0;
			}
		}
	}
beach:
	relocs[i].last = 1;

	return relocs;
}

struct addr_t* MACH0_(get_entrypoint)(struct MACH0_(obj_t)* bin) {
	struct addr_t *entry;
	int i;

	if (!bin->entry && !bin->sects)
		return NULL;
	if (!(entry = calloc (1, sizeof (struct addr_t))))
		return NULL;

	if (bin->entry) {
		entry->addr = entry_to_vaddr(bin);
		entry->offset = addr_to_offset (bin, entry->addr);
	}

	if (!bin->entry || entry->offset == 0) {
		// XXX: section name doesnt matters at all.. just check for exec flags
		for (i = 0; i < bin->nsects; i++) {
			if (!strncmp (bin->sects[i].sectname, "__text", 6)) {
				entry->offset = (ut64)bin->sects[i].offset;
				sdb_num_set (bin->kv, "mach0.entry", entry->offset, 0);
				entry->addr = (ut64)bin->sects[i].addr;
				if (!entry->addr) // workaround for object files
					entry->addr = entry->offset;
				break;
			}
		}
		bin->entry = entry->addr;
	}

	return entry;
}

struct lib_t* MACH0_(get_libs)(struct MACH0_(obj_t)* bin) {
	struct lib_t *libs;
	int i;

	if (!bin->nlibs)
		return NULL;
	if (!(libs = calloc ((bin->nlibs + 1), sizeof(struct lib_t))))
		return NULL;
	for (i = 0; i < bin->nlibs; i++) {
		strncpy (libs[i].name, bin->libs[i], R_BIN_MACH0_STRING_LENGTH);
		libs[i].name[R_BIN_MACH0_STRING_LENGTH-1] = '\0';
		libs[i].last = 0;
	}
	libs[i].last = 1;
	return libs;
}

ut64 MACH0_(get_baddr)(struct MACH0_(obj_t)* bin) {
	int i;

	if (bin->hdr.filetype != MH_EXECUTE && bin->hdr.filetype != MH_DYLINKER)
		return 0;

	for (i = 0; i < bin->nsegs; ++i)
		if (bin->segs[i].fileoff == 0 && bin->segs[i].filesize != 0)
			return bin->segs[i].vmaddr;
	return 0;
}

char* MACH0_(get_class)(struct MACH0_(obj_t)* bin) {
#if R_BIN_MACH064
	return r_str_new ("MACH064");
#else
	return r_str_new ("MACH0");
#endif
}

//XXX we are mixing up bits from cpu and opcodes
//since thumb use 16 bits opcode but run in 32 bits
//cpus  so here we should only return 32 or 64
int MACH0_(get_bits)(struct MACH0_(obj_t)* bin) {
	if (bin) {
		int bits = MACH0_(get_bits_from_hdr) (&bin->hdr);
		if (bin->hdr.cputype == CPU_TYPE_ARM && bin->entry & 1) {
			return 16;
		}
		return bits;
	} 
	return 32;
}

int MACH0_(get_bits_from_hdr)(struct MACH0_(mach_header)* hdr) {
	if (hdr->magic == MH_MAGIC_64 || hdr->magic == MH_CIGAM_64) {
		return 64;
	}
	if ((hdr->cpusubtype & CPU_SUBTYPE_MASK) == (CPU_SUBTYPE_ARM_V7K << 24)) {
		return 16;
	}
	return 32;
}

bool MACH0_(is_big_endian)(struct MACH0_(obj_t)* bin) {
	if (bin) {
		const int cpu = bin->hdr.cputype;
		return cpu == CPU_TYPE_POWERPC || cpu == CPU_TYPE_POWERPC64;
	}
	return false;
}

const char* MACH0_(get_intrp)(struct MACH0_(obj_t)* bin) {
	return bin? bin->intrp: NULL;
}

const char* MACH0_(get_os)(struct MACH0_(obj_t)* bin) {
	if (bin)
	switch (bin->os) {
	case 1: return "osx";
	case 2: return "ios";
	case 3: return "watchos";
	case 4: return "tvos";
	}
	return "darwin";
}

char* MACH0_(get_cputype_from_hdr)(struct MACH0_(mach_header) *hdr) {
	const char *archstr = "unknown";
	switch (hdr->cputype) {
	case CPU_TYPE_VAX:
		archstr = "vax";
		break;
	case CPU_TYPE_MC680x0:
		archstr = "mc680x0";
		break;
	case CPU_TYPE_I386:
	case CPU_TYPE_X86_64:
		archstr = "x86";
		break;
	case CPU_TYPE_MC88000:
		archstr = "mc88000";
		break;
	case CPU_TYPE_MC98000:
		archstr = "mc98000";
		break;
	case CPU_TYPE_HPPA:
		archstr = "hppa";
		break;
	case CPU_TYPE_ARM:
	case CPU_TYPE_ARM64:
		archstr = "arm";
		break;
	case CPU_TYPE_SPARC:
		archstr = "sparc";
		break;
	case CPU_TYPE_MIPS:
		archstr = "mips";
		break;
	case CPU_TYPE_I860:
		archstr = "i860";
		break;
	case CPU_TYPE_POWERPC:
	case CPU_TYPE_POWERPC64:
		archstr = "ppc";
	}
	return strdup (archstr);
}

char* MACH0_(get_cputype)(struct MACH0_(obj_t)* bin) {
	if (bin) {
		return MACH0_(get_cputype_from_hdr) (&bin->hdr);
	}
	return strdup ("unknown");
}

// TODO: use const char*

char* MACH0_(get_cpusubtype_from_hdr)(struct MACH0_(mach_header) *hdr) {
	if (hdr) {
		switch (hdr->cputype) {
		case CPU_TYPE_VAX:
			switch (hdr->cpusubtype) {
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
			switch (hdr->cpusubtype) {
			case CPU_SUBTYPE_MC68030:	return strdup ("mc68030");
			case CPU_SUBTYPE_MC68040:	return strdup ("mc68040");
			case CPU_SUBTYPE_MC68030_ONLY:	return strdup ("mc68030 only");
			default:			return strdup ("Unknown mc680x0 subtype");
			}
		case CPU_TYPE_I386:
			switch (hdr->cpusubtype) {
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
			switch (hdr->cpusubtype & 0xff) {
			case CPU_SUBTYPE_X86_64_ALL:	return strdup ("x86 64 all");
			case CPU_SUBTYPE_X86_ARCH1:	return strdup ("x86 arch 1");
			default:			return strdup ("Unknown x86 subtype");
			}
		case CPU_TYPE_MC88000:
			switch (hdr->cpusubtype & 0xff) {
			case CPU_SUBTYPE_MC88000_ALL:	return strdup ("all");
			case CPU_SUBTYPE_MC88100:	return strdup ("mc88100");
			case CPU_SUBTYPE_MC88110:	return strdup ("mc88110");
			default:			return strdup ("Unknown mc88000 subtype");
			}
		case CPU_TYPE_MC98000:
			switch (hdr->cpusubtype & 0xff) {
			case CPU_SUBTYPE_MC98000_ALL:	return strdup ("all");
			case CPU_SUBTYPE_MC98601:	return strdup ("mc98601");
			default:			return strdup ("Unknown mc98000 subtype");
			}
		case CPU_TYPE_HPPA:
			switch (hdr->cpusubtype & 0xff) {
			case CPU_SUBTYPE_HPPA_7100:	return strdup ("hppa7100");
			case CPU_SUBTYPE_HPPA_7100LC:	return strdup ("hppa7100LC");
			default:			return strdup ("Unknown hppa subtype");
			}
		case CPU_TYPE_ARM64:
			return strdup ("v8");
		case CPU_TYPE_ARM:
			switch (hdr->cpusubtype & 0xff) {
			case CPU_SUBTYPE_ARM_ALL:
				return strdup ("all");
			case CPU_SUBTYPE_ARM_V4T:
				return strdup ("v4t");
			case CPU_SUBTYPE_ARM_V5:
				return strdup ("v5");
			case CPU_SUBTYPE_ARM_V6:
				return strdup ("v6");
			case CPU_SUBTYPE_ARM_XSCALE:
				return strdup ("xscale");
			case CPU_SUBTYPE_ARM_V7:
				return strdup ("v7");
			case CPU_SUBTYPE_ARM_V7F:
				return strdup ("v7f");
			case CPU_SUBTYPE_ARM_V7S:
				return strdup ("v7s");
			case CPU_SUBTYPE_ARM_V7K:
				return strdup ("v7k");
			case CPU_SUBTYPE_ARM_V7M:
				return strdup ("v7m");
			case CPU_SUBTYPE_ARM_V7EM:
				return strdup ("v7em");
			default:
				return r_str_newf ("unknown ARM subtype %d", hdr->cpusubtype & 0xff);
			}
		case CPU_TYPE_SPARC:
			switch (hdr->cpusubtype & 0xff) {
			case CPU_SUBTYPE_SPARC_ALL:	return strdup ("all");
			default:			return strdup ("Unknown sparc subtype");
			}
		case CPU_TYPE_MIPS:
			switch (hdr->cpusubtype & 0xff) {
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
			switch (hdr->cpusubtype & 0xff) {
			case CPU_SUBTYPE_I860_ALL:	return strdup ("all");
			case CPU_SUBTYPE_I860_860:	return strdup ("860");
			default:			return strdup ("Unknown i860 subtype");
			}
		case CPU_TYPE_POWERPC:
		case CPU_TYPE_POWERPC64:
			switch (hdr->cpusubtype & 0xff) {
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
		}
	}
	return strdup ("Unknown cputype");
}


char* MACH0_(get_cpusubtype)(struct MACH0_(obj_t)* bin) { 
	if (bin) {
		return MACH0_(get_cpusubtype_from_hdr) (&bin->hdr);
	}
	return strdup ("Unknown");
}

int MACH0_(is_pie)(struct MACH0_(obj_t)* bin) {
	return (bin && bin->hdr.filetype == MH_EXECUTE && bin->hdr.flags & MH_PIE);
}

char* MACH0_(get_filetype_from_hdr)(struct MACH0_(mach_header) *hdr) {
	const char *mhtype = "Unknown";
	switch (hdr->filetype) {
	case MH_OBJECT:		mhtype = "Relocatable object";
	case MH_EXECUTE:	mhtype = "Executable file";
	case MH_FVMLIB:		mhtype = "Fixed VM shared library";
	case MH_CORE:		mhtype = "Core file";
	case MH_PRELOAD:	mhtype = "Preloaded executable file";
	case MH_DYLIB:		mhtype = "Dynamically bound shared library";
	case MH_DYLINKER:	mhtype = "Dynamic link editor";
	case MH_BUNDLE:		mhtype = "Dynamically bound bundle file";
	case MH_DYLIB_STUB:	mhtype = "Shared library stub for static linking (no sections)";
	case MH_DSYM:		mhtype = "Companion file with only debug sections";
	}
	return strdup (mhtype);
}

char* MACH0_(get_filetype)(struct MACH0_(obj_t)* bin) {
	if (bin) {
		return MACH0_(get_filetype_from_hdr) (&bin->hdr);
	}
	return strdup ("Unknown");
}

ut64 MACH0_(get_main)(struct MACH0_(obj_t)* bin) {
	ut64 addr = 0LL;
	struct symbol_t *symbols;
	int i;

	if (!(symbols = MACH0_(get_symbols) (bin))) {
		return 0;
	}
	for (i = 0; !symbols[i].last; i++) {
		if (!strcmp (symbols[i].name, "_main")) {
			addr = symbols[i].addr;
			break;
		}
	}
	free (symbols);

	if (!addr && bin->main_cmd.cmd == LC_MAIN)
		addr = bin->entry + bin->baddr;

	if (!addr) {
		ut8 b[128];
		ut64 entry = addr_to_offset(bin, bin->entry);
		// XXX: X86 only and hacky!
		if (entry > bin->size || entry + sizeof (b) > bin->size)
			return 0;
		i = r_buf_read_at (bin->b, entry, b, sizeof (b));
		if (i < 1)
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

struct MACH0_(mach_header) * MACH0_(get_hdr_from_bytes)(RBuffer *buf) {
	ut8 magicbytes[sizeof (ut32)] = {0};
	ut8 machohdrbytes[sizeof (struct MACH0_(mach_header))] = {0};
	int len;
	struct MACH0_(mach_header) *macho_hdr = R_NEW0 (struct MACH0_(mach_header));
	bool big_endian = false;
	if (!macho_hdr) {
		return NULL;
	}
	if (r_buf_read_at (buf, 0, magicbytes, 4) < 1) {
		eprintf ("Error: read (magic)\n");
		free (macho_hdr);
		return false;
	}

	if (r_read_le32 (magicbytes) == 0xfeedface) {
		big_endian = false;
	} else if (r_read_be32 (magicbytes) == 0xfeedface) { 
		big_endian = true;
	} else if (r_read_le32 (magicbytes) == FAT_MAGIC) {
		big_endian = false;
	} else if (r_read_be32 (magicbytes) == FAT_MAGIC) {
		big_endian = true;
	} else if (r_read_le32 (magicbytes) == 0xfeedfacf) {
		big_endian = false;
	} else if (r_read_be32 (magicbytes) == 0xfeedfacf) {
		big_endian = true;
	} else {
		/* also extract non-mach0s */
#if 0 
		free (macho_hdr);
		return NULL;
#endif
	}
	len = r_buf_read_at (buf, 0, machohdrbytes, sizeof (machohdrbytes));
	if (len != sizeof(struct MACH0_(mach_header))) {
		free (macho_hdr);
		return NULL;
	}
	macho_hdr->magic = r_read_ble (&machohdrbytes[0], big_endian, 32);
	macho_hdr->cputype = r_read_ble (&machohdrbytes[4], big_endian, 32);
	macho_hdr->cpusubtype = r_read_ble (&machohdrbytes[8], big_endian, 32);
	macho_hdr->filetype = r_read_ble (&machohdrbytes[12], big_endian, 32);
	macho_hdr->ncmds = r_read_ble (&machohdrbytes[16], big_endian, 32);
	macho_hdr->sizeofcmds = r_read_ble (&machohdrbytes[20], big_endian, 32);
	macho_hdr->flags = r_read_ble (&machohdrbytes[24], big_endian, 32);
#if R_BIN_MACH064
	macho_hdr->reserved = r_read_ble (&machohdrbytes[28], big_endian, 32);
#endif
	return macho_hdr;
}
