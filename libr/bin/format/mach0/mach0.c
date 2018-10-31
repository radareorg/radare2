/* radare - LGPL - Copyright 2010-2018 - nibble, pancake */

#include <stdio.h>
#include <r_types.h>
#include <r_util.h>
#include "mach0.h"
#include <r_hash.h>

#define bprintf if (bin->verbose) eprintf

typedef struct _ulebr {
	ut8 *p;
} ulebr;

// OMG; THIS SHOULD BE KILLED; this var exposes the local native endian, which is completely unnecessary
#define mach0_endian 1

static ut64 read_uleb128(ulebr *r, ut8 *end) {
	ut64 result = 0;
	int bit = 0;
	ut64 slice = 0;
	ut8 *p = r->p;
	do {
		if (p == end) {
			eprintf ("malformed uleb128");
			break;
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
	ut8 byte = 0;
	ut8 *p = r->p;
	do {
		if (p == end) {
			eprintf ("malformed sleb128");
			break;
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
	ut8 magicbytes[4] = {0};
	ut8 machohdrbytes[sizeof (struct MACH0_(mach_header))] = {0};
	int len;

	if (r_buf_read_at (bin->b, 0 + bin->header_at, magicbytes, 4) < 1) {
		return false;
	}
	if (r_read_le32 (magicbytes) == 0xfeedface) {
		bin->big_endian = false;
	} else if (r_read_be32 (magicbytes) == 0xfeedface) {
		bin->big_endian = true;
	} else if (r_read_le32 (magicbytes) == FAT_MAGIC) {
		bin->big_endian = false;
	} else if (r_read_be32 (magicbytes) == FAT_MAGIC) {
		bin->big_endian = true;
	} else if (r_read_le32 (magicbytes) == 0xfeedfacf) {
		bin->big_endian = false;
	} else if (r_read_be32 (magicbytes) == 0xfeedfacf) {
		bin->big_endian = true;
	} else {
		return false; // object files are magic == 0, but body is different :?
	}
	len = r_buf_read_at (bin->b, 0 + bin->header_at, machohdrbytes, sizeof (machohdrbytes));
	if (len != sizeof (machohdrbytes)) {
		bprintf ("Error: read (hdr)\n");
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
		bprintf ("Error: read (seg)\n");
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

	sdb_num_set (bin->kv, sdb_fmt ("mach0_segment_%d.offset", j), off, 0);
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
			bprintf ("WARNING: mach0 header contains too many sections (%d). Wrapping to %d\n",
				 bin->nsects, new_nsects);
			bin->nsects = new_nsects;
		}
		if ((int)bin->nsects < 1) {
			bprintf ("Warning: Invalid number of sections\n");
			bin->nsects = sect;
			return false;
		}
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
				bprintf ("Error: read (sects)\n");
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
#if R_BIN_MACH064
			i += sizeof (ut32);
			bin->sects[k].reserved3 = r_read_ble32 (&sec[i], bin->big_endian);
#endif
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
		bprintf ("Error: read (symtab)\n");
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
			bprintf("fail2\n");
			return false;
		}
		if (!size_sym) {
			bprintf("fail3\n");
			return false;
		}
		if (st.symoff > bin->size || st.symoff + size_sym > bin->size) {
			bprintf("fail4\n");
			return false;
		}
		if (!(bin->symstr = calloc (1, st.strsize + 2))) {
			perror ("calloc (symstr)");
			return false;
		}
		bin->symstrlen = st.strsize;
		len = r_buf_read_at (bin->b, st.stroff, (ut8*)bin->symstr, st.strsize);
		if (len != st.strsize) {
			bprintf ("Error: read (symstr)\n");
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
				bprintf ("Error: read (nlist)\n");
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

	len = r_buf_read_at (bin->b, off, dysym, sizeof (struct dysymtab_command));
	if (len != sizeof (struct dysymtab_command)) {
		bprintf ("Error: read (dysymtab)\n");
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
		if (!(bin->toc = calloc (bin->ntoc, sizeof (struct dylib_table_of_contents)))) {
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
			len = r_buf_read_at (bin->b, bin->dysymtab.tocoff +
				i * sizeof (struct dylib_table_of_contents),
				dytoc, sizeof (struct dylib_table_of_contents));
			if (len != sizeof (struct dylib_table_of_contents)) {
				bprintf ("Error: read (toc)\n");
				R_FREE (bin->toc);
				return false;
			}
			bin->toc[i].symbol_index = r_read_ble32 (&dytoc[0], bin->big_endian);
			bin->toc[i].module_index = r_read_ble32 (&dytoc[4], bin->big_endian);
		}
	}
	bin->nmodtab = bin->dysymtab.nmodtab;
	if (bin->nmodtab > 0) {
		if (!(bin->modtab = calloc (bin->nmodtab, sizeof (struct MACH0_(dylib_module))))) {
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
			len = r_buf_read_at (bin->b, bin->dysymtab.modtaboff +
				i * sizeof (struct MACH0_(dylib_module)),
				dymod, sizeof (struct MACH0_(dylib_module)));
			if (len == -1) {
				bprintf ("Error: read (modtab)\n");
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
		if (!(bin->indirectsyms = calloc (bin->nindirectsyms, sizeof (ut32)))) {
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
				bprintf ("Error: read (indirect syms)\n");
				R_FREE (bin->indirectsyms);
				return false;
			}
			bin->indirectsyms[i] = r_read_ble32 (&idsyms[0], bin->big_endian);
		}
	}
	/* TODO extrefsyms, extrel, locrel */
	return true;
}

static char *readString (ut8 *p, int off, int len) {
	if (off < 0 || off >= len) {
		return NULL;
	}
	return r_str_ndup ((const char *)p + off, len - off);
}

static void parseCodeDirectory (RBuffer *b, int offset, int datasize) {
	typedef struct __CodeDirectory {
		uint32_t magic;					/* magic number (CSMAGIC_CODEDIRECTORY) */
		uint32_t length;				/* total length of CodeDirectory blob */
		uint32_t version;				/* compatibility version */
		uint32_t flags;					/* setup and mode flags */
		uint32_t hashOffset;			/* offset of hash slot element at index zero */
		uint32_t identOffset;			/* offset of identifier string */
		uint32_t nSpecialSlots;			/* number of special hash slots */
		uint32_t nCodeSlots;			/* number of ordinary (code) hash slots */
		uint32_t codeLimit;				/* limit to main image signature range */
		uint8_t hashSize;				/* size of each hash in bytes */
		uint8_t hashType;				/* type of hash (cdHashType* constants) */
		uint8_t platform;					/* unused (must be zero) */
		uint8_t	pageSize;				/* log2(page size in bytes); 0 => infinite */
		uint32_t spare2;				/* unused (must be zero) */
		/* followed by dynamic content as located by offset fields above */
		uint32_t scatterOffset;
		uint32_t teamIDOffset;
		uint32_t spare3;
		ut64 codeLimit64;
		ut64 execSegBase;
		ut64 execSegLimit;
		ut64 execSegFlags;
	} CS_CodeDirectory;
	ut64 off = offset;
	int psize = datasize;
	ut8 *p = calloc (1, psize);
	if (!p) {
		return;
	}
	eprintf ("Offset: 0x%08"PFMT64x"\n", off);
	r_buf_read_at (b, off, p, datasize);
	CS_CodeDirectory cscd = {0};
	#define READFIELD(x) cscd.x = r_read_ble32 (p + r_offsetof (CS_CodeDirectory, x), 1)
	#define READFIELD8(x) cscd.x = p[r_offsetof (CS_CodeDirectory, x)]
	READFIELD (length);
	READFIELD (version);
	READFIELD (flags);
	READFIELD (hashOffset);
	READFIELD (identOffset);
	READFIELD (nSpecialSlots);
	READFIELD (nCodeSlots);
	READFIELD (hashSize);
	READFIELD (teamIDOffset);
	READFIELD8 (hashType);
	READFIELD (pageSize);
	READFIELD (codeLimit);
	eprintf ("Version: %x\n", cscd.version);
	eprintf ("Flags: %x\n", cscd.flags);
	eprintf ("Length: %d\n", cscd.length);
	eprintf ("PageSize: %d\n", cscd.pageSize);
	eprintf ("hashOffset: %d\n", cscd.hashOffset);
	eprintf ("codeLimit: %d\n", cscd.codeLimit);
	eprintf ("hashSize: %d\n", cscd.hashSize);
	eprintf ("hashType: %d\n", cscd.hashType);
	char *identity = readString (p, cscd.identOffset, psize);
	eprintf ("Identity: %s\n", identity);
	char *teamId = readString (p, cscd.teamIDOffset, psize);
	eprintf ("TeamID: %s\n", teamId);
	eprintf ("CodeSlots: %d\n", cscd.nCodeSlots);
	free (identity);
	free (teamId);
	
	int hashSize = 20; // SHA1 is default
	int algoType = R_HASH_SHA1;
	const char *hashName = "sha1";
	switch (cscd.hashType) {
	case 0: // SHA1 == 20 bytes
	case 1: // SHA1 == 20 bytes
		hashSize = 20;
		hashName = "sha1";
		algoType = R_HASH_SHA1;
		break;
	case 2: // SHA256 == 32 bytes
		hashSize = 32;
		algoType = R_HASH_SHA256;
		hashName = "sha256";
		break;
	}
	// computed cdhash
	RHash *ctx = r_hash_new (true, algoType);
	int fofsz = cscd.length;
	ut8 *fofbuf = calloc (fofsz, 1);
	if (fofbuf) {
		int i;
		if (r_buf_read_at (b, off, fofbuf, fofsz) != fofsz) {
			eprintf ("Invalid cdhash offset/length values\n");
		}
		r_hash_do_begin (ctx, algoType);
		if (algoType == R_HASH_SHA1) {
			r_hash_do_sha1 (ctx, fofbuf, fofsz);
		} else {
			r_hash_do_sha256 (ctx, fofbuf, fofsz);
		}
		r_hash_do_end (ctx, algoType);
		eprintf ("ph %s @ 0x%"PFMT64x"!%d\n", hashName, off, fofsz);
		eprintf ("ComputedCDHash: ");
		for (i = 0; i < hashSize;i++) {
			eprintf ("%02x", ctx->digest[i]);
		}
		eprintf ("\n");
		free (fofbuf);
	}
	// show and check the rest of hashes
	ut8 *hash = p + cscd.hashOffset;
	int j = 0;
	int k = 0;
	eprintf ("Hashed region: 0x%08"PFMT64x" - 0x%08"PFMT64x"\n", (ut64)0, (ut64)cscd.codeLimit);
	for (j = 0; j < cscd.nCodeSlots; j++) {
		int fof = 4096 * j;
		int idx = j * hashSize;
		eprintf ("0x%08"PFMT64x"  ", off + cscd.hashOffset + idx);
		for (k = 0; k < hashSize; k++) {
			eprintf ("%02x", hash[idx + k]);
		}
		ut8 fofbuf[4096];
		int fofsz = R_MIN (sizeof (fofbuf), cscd.codeLimit - fof);
		r_buf_read_at (b, fof, fofbuf, sizeof (fofbuf));
		r_hash_do_begin (ctx, algoType);
		if (algoType == R_HASH_SHA1) {
			r_hash_do_sha1 (ctx, fofbuf, fofsz);
		} else {
			r_hash_do_sha256 (ctx, fofbuf, fofsz);
		}
		r_hash_do_end (ctx, algoType);
		if (memcmp (hash + idx, ctx->digest, hashSize)) {
			eprintf ("  wx ");
			int i;
			for (i = 0; i < hashSize;i++) {
				eprintf ("%02x", ctx->digest[i]);
			}
		} else {
			eprintf ("  OK");
		}
		eprintf ("\n");
	}
	r_hash_free (ctx);
	free (p);
}

// parse the Load Command
static bool parse_signature(struct MACH0_(obj_t) *bin, ut64 off) {
	int i,len;
	ut32 data;
	bin->signature = NULL;
	struct linkedit_data_command link = {0};
	ut8 lit[sizeof (struct linkedit_data_command)] = {0};
	struct blob_index_t idx = {0};
	struct super_blob_t super = {{0}};

	if (off > bin->size || off + sizeof (struct linkedit_data_command) > bin->size) {
		return false;
	}
	len = r_buf_read_at (bin->b, off, lit, sizeof (struct linkedit_data_command));
	if (len != sizeof (struct linkedit_data_command)) {
		bprintf ("Failed to get data while parsing LC_CODE_SIGNATURE command\n");
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
	super.blob.magic = r_read_ble32 (bin->b->buf + data, mach0_endian);
	super.blob.length = r_read_ble32 (bin->b->buf + data + 4, mach0_endian);
	super.count = r_read_ble32 (bin->b->buf + data + 8, mach0_endian);
	char *verbose = r_sys_getenv ("RABIN2_CODESIGN_VERBOSE");
	bool isVerbose = false;
	if (verbose) {
		isVerbose = *verbose;
		free (verbose);
	}
	// to dump all certificates
	// [0x00053f75]> b 5K;/x 30800609;wtf @@ hit*
	// then do this:
	// $ openssl asn1parse -inform der -in a|less
	// $ openssl pkcs7 -inform DER -print_certs -text -in a
	for (i = 0; i < super.count; i++) {
		if ((ut8 *)(bin->b->buf + data + i) > (ut8 *)(bin->b->buf + bin->size)) {
			bin->signature = (ut8 *)strdup ("Malformed entitlement");
			break;
		}
		struct blob_index_t bi;
		if (r_buf_read_at (bin->b, data + 12 + (i * sizeof (struct blob_index_t)),
			(ut8*)&bi, sizeof (struct blob_index_t)) < sizeof (struct blob_index_t)) {
			break;
		}
		idx.type = r_read_ble32 (&bi.type, mach0_endian);
		idx.offset = r_read_ble32 (&bi.offset, mach0_endian);
		switch (idx.type) {
		case CSSLOT_ENTITLEMENTS:
			if (true || isVerbose) {
			ut64 off = data + idx.offset;
			if (off > bin->size || off + sizeof (struct blob_t) > bin->size) {
				bin->signature = (ut8 *)strdup ("Malformed entitlement");
				break;
			}
			struct blob_t entitlements = {0};
			entitlements.magic = r_read_ble32 (bin->b->buf + off, mach0_endian);
			entitlements.length = r_read_ble32 (bin->b->buf + off + 4, mach0_endian);
			len = entitlements.length - sizeof (struct blob_t);
			if (len <= bin->size && len > 1) {
				bin->signature = calloc (1, len + 1);
				if (!bin->signature) {
					break;
				}
				ut8 *src = bin->b->buf + off + sizeof (struct blob_t);
				if (off + sizeof (struct blob_t) + len < bin->b->length) {
					memcpy (bin->signature, src, len);
					bin->signature[len] = '\0';
				} else {
					bin->signature = (ut8 *)strdup ("Malformed entitlement");
				}
			} else {
				bin->signature = (ut8 *)strdup ("Malformed entitlement");
			}
			}
			break;
		case CSSLOT_CODEDIRECTORY:
			if (isVerbose) {
				parseCodeDirectory (bin->b, data + idx.offset, link.datasize);
			}
			break;
		case 0x1000:
			// unknown
			break;
		case CSSLOT_CMS_SIGNATURE: // ASN1/DER certificate
			if (isVerbose) {
				ut8 header[8] = {0};
				r_buf_read_at (bin->b, data + idx.offset, header, sizeof (header));
				ut32 length = R_MIN (UT16_MAX, r_read_ble32 (header + 4, 1));
				ut8 *p = calloc (length, 1);
				if (p) {
					r_buf_read_at (bin->b, data + idx.offset + 0, p, length);
					ut32 *words = (ut32*)p;
					eprintf ("Magic: %x\n", words[0]);
					words += 2;
					eprintf ("wtf DUMP @%d!%d\n",
						(int)data + idx.offset + 8, (int)length);
					eprintf ("openssl pkcs7 -print_certs -text -inform der -in DUMP\n");
					eprintf ("openssl asn1parse -offset %d -length %d -inform der -in /bin/ls\n",
						(int)data + idx.offset + 8, (int)length);
					eprintf ("pFp@%d!%d\n",
						(int)data + idx.offset + 8, (int)length);
					free (p);
				}
			}
			break;
		case CSSLOT_REQUIREMENTS: // 2
			{
				ut8 p[256];
				r_buf_read_at (bin->b, data + idx.offset + 16, p, sizeof (p));
				p[sizeof (p) - 1] = 0;
				ut32 slot_size = r_read_ble32 (p  + 8, 1);
				if (slot_size < sizeof (p)) {
					ut32 ident_size = r_read_ble32 (p  + 8, 1);
					char *ident = r_str_ndup ((const char *)p + 28, ident_size);
					if (ident) {
						sdb_set (bin->kv, "mach0.ident", ident, 0);
						free (ident);
					}
				} else {
					eprintf ("Invalid code slot size\n");
				}
			}
			break;
		case CSSLOT_INFOSLOT: // 1;
		case CSSLOT_RESOURCEDIR: // 3;
		case CSSLOT_APPLICATION: // 4;
			// TODO: parse those codesign slots
			eprintf ("TODO: Some codesign slots are not yet supported\n");
			break;
		default:
			eprintf ("Unknown Code signature slot %d\n", idx.type);
			break;
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
	ut8 tmp[4];

	if (off > bin->size || off + sizeof (struct thread_command) > bin->size) {
		return false;
	}

	len = r_buf_read_at (bin->b, off, thc, 8);
	if (len < 1) {
		goto wrong_read;
	}
	bin->thread.cmd = r_read_ble32 (&thc[0], bin->big_endian);
	bin->thread.cmdsize = r_read_ble32 (&thc[4], bin->big_endian);
	if (r_buf_read_at (bin->b, off + sizeof (struct thread_command), tmp, 4) < 4) {
		goto wrong_read;
	}
	flavor = r_read_ble32 (tmp, bin->big_endian);
	if (len == -1) {
		goto wrong_read;
	}

	if (off + sizeof (struct thread_command) + sizeof (flavor) > bin->size ||
		off + sizeof (struct thread_command) + sizeof (flavor) + sizeof (ut32) > bin->size) {
		return false;
	}

	// TODO: use count for checks
	if (r_buf_read_at (bin->b, off + sizeof (struct thread_command) + sizeof (flavor), tmp, 4) < 4) {
		goto wrong_read;
	}
	count = r_read_ble32 (tmp, bin->big_endian);
	ptr_thread = off + sizeof (struct thread_command) + sizeof (flavor) + sizeof (count);

	if (ptr_thread > bin->size) {
		return false;
	}

	switch (bin->hdr.cputype) {
	case CPU_TYPE_I386:
	case CPU_TYPE_X86_64:
		switch (flavor) {
		case X86_THREAD_STATE32:
			if (ptr_thread + sizeof (struct x86_thread_state32) > bin->size) {
				return false;
			}
			if ((len = r_buf_fread_at (bin->b, ptr_thread,
				(ut8*)&bin->thread_state.x86_32, "16i", 1)) == -1) {
				bprintf ("Error: read (thread state x86_32)\n");
				return false;
			}
			pc = bin->thread_state.x86_32.eip;
			pc_offset = ptr_thread + r_offsetof(struct x86_thread_state32, eip);
			arw_ptr = (ut8 *)&bin->thread_state.x86_32;
			arw_sz = sizeof (struct x86_thread_state32);
			break;
		case X86_THREAD_STATE64:
			if (ptr_thread + sizeof (struct x86_thread_state64) > bin->size) {
				return false;
			}
			if ((len = r_buf_fread_at (bin->b, ptr_thread,
				(ut8*)&bin->thread_state.x86_64, "32l", 1)) == -1) {
				bprintf ("Error: read (thread state x86_64)\n");
				return false;
			}
			pc = bin->thread_state.x86_64.rip;
			pc_offset = ptr_thread + r_offsetof(struct x86_thread_state64, rip);
			arw_ptr = (ut8 *)&bin->thread_state.x86_64;
			arw_sz = sizeof (struct x86_thread_state64);
			break;
		//default: bprintf ("Unknown type\n");
		}
		break;
	case CPU_TYPE_POWERPC:
	case CPU_TYPE_POWERPC64:
		if (flavor == X86_THREAD_STATE32) {
			if (ptr_thread + sizeof (struct ppc_thread_state32) > bin->size) {
				return false;
			}
			if ((len = r_buf_fread_at (bin->b, ptr_thread,
				(ut8*)&bin->thread_state.ppc_32, bin->big_endian?"40I":"40i", 1)) == -1) {
				bprintf ("Error: read (thread state ppc_32)\n");
				return false;
			}
			pc = bin->thread_state.ppc_32.srr0;
			pc_offset = ptr_thread + r_offsetof(struct ppc_thread_state32, srr0);
			arw_ptr = (ut8 *)&bin->thread_state.ppc_32;
			arw_sz = sizeof (struct ppc_thread_state32);
		} else if (flavor == X86_THREAD_STATE64) {
			if (ptr_thread + sizeof (struct ppc_thread_state64) > bin->size) {
				return false;
			}
			if ((len = r_buf_fread_at (bin->b, ptr_thread,
				(ut8*)&bin->thread_state.ppc_64, bin->big_endian?"34LI3LI":"34li3li", 1)) == -1) {
				bprintf ("Error: read (thread state ppc_64)\n");
				return false;
			}
			pc = bin->thread_state.ppc_64.srr0;
			pc_offset = ptr_thread + r_offsetof(struct ppc_thread_state64, srr0);
			arw_ptr = (ut8 *)&bin->thread_state.ppc_64;
			arw_sz = sizeof (struct ppc_thread_state64);
		}
		break;
	case CPU_TYPE_ARM:
		if (ptr_thread + sizeof (struct arm_thread_state32) > bin->size) {
			return false;
		}
		if ((len = r_buf_fread_at (bin->b, ptr_thread,
				(ut8*)&bin->thread_state.arm_32, bin->big_endian?"17I":"17i", 1)) == -1) {
			bprintf ("Error: read (thread state arm)\n");
			return false;
		}
		pc = bin->thread_state.arm_32.r15;
		pc_offset = ptr_thread + r_offsetof (struct arm_thread_state32, r15);
		arw_ptr = (ut8 *)&bin->thread_state.arm_32;
		arw_sz = sizeof (struct arm_thread_state32);
		break;
	case CPU_TYPE_ARM64:
		if (ptr_thread + sizeof (struct arm_thread_state64) > bin->size) {
			return false;
		}
		if ((len = r_buf_fread_at(bin->b, ptr_thread,
				(ut8*)&bin->thread_state.arm_64, bin->big_endian?"34LI1I":"34Li1i", 1)) == -1) {
			bprintf ("Error: read (thread state arm)\n");
			return false;
		}
		pc = r_read_be64 (&bin->thread_state.arm_64.pc);
		pc_offset = ptr_thread + r_offsetof (struct arm_thread_state64, pc);
		arw_ptr = (ut8*)&bin->thread_state.arm_64;
		arw_sz = sizeof (struct arm_thread_state64);
		break;
	default:
		bprintf ("Error: read (unknown thread state structure)\n");
		return false;
	}

	// TODO: this shouldnt be an bprintf...
	if (arw_ptr && arw_sz > 0) {
		int i;
		ut8 *p = arw_ptr;
		bprintf ("arw ");
		for (i = 0; i < arw_sz; i++) {
			bprintf ("%02x", 0xff & p[i]);
		}
		bprintf ("\n");
	}

	if (is_first_thread) {
		bin->main_cmd = *lc;
		if (pc != UT64_MAX) {
			bin->entry = pc;
		}
		if (pc_offset != UT64_MAX) {
			sdb_num_set (bin->kv, "mach0.entry.offset", pc_offset, 0);
		}
	}

	return true;
wrong_read:
	bprintf ("Error: read (thread)\n");
	return false;
}

static int parse_function_starts (struct MACH0_(obj_t)* bin, ut64 off) {
	struct linkedit_data_command fc;
	ut8 sfc[sizeof (struct linkedit_data_command)] = {0};
	ut8 *buf;
	int len;

	if (off > bin->size || off + sizeof (struct linkedit_data_command) > bin->size) {
		bprintf ("Likely overflow while parsing"
			" LC_FUNCTION_STARTS command\n");
	}
	bin->func_start = NULL;
	len = r_buf_read_at (bin->b, off, sfc, sizeof (struct linkedit_data_command));
	if (len < 1) {
		bprintf ("Failed to get data while parsing"
			" LC_FUNCTION_STARTS command\n");
	}
	fc.cmd = r_read_ble32 (&sfc[0], bin->big_endian);
	fc.cmdsize = r_read_ble32 (&sfc[4], bin->big_endian);
	fc.dataoff = r_read_ble32 (&sfc[8], bin->big_endian);
	fc.datasize = r_read_ble32 (&sfc[12], bin->big_endian);

	buf = calloc (1, fc.datasize + 1);
	if (!buf) {
		bprintf ("Failed to allocate buffer\n");
		return false;
	}
	bin->func_size = fc.datasize;
	if (fc.dataoff > bin->size || fc.dataoff + fc.datasize > bin->size) {
		free (buf);
		bprintf ("Likely overflow while parsing "
			"LC_FUNCTION_STARTS command\n");
		return false;
	}
	len = r_buf_read_at (bin->b, fc.dataoff, buf, fc.datasize);
	if (len != fc.datasize) {
		free (buf);
		bprintf ("Failed to get data while parsing"
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

	if (off > bin->size || off + sizeof (struct dylib_command) > bin->size) {
		return false;
	}
	lib = bin->nlibs - 1;

	void *relibs = realloc (bin->libs, bin->nlibs * R_BIN_MACH0_STRING_LENGTH);
	if (!relibs) {
		perror ("realloc (libs)");
		return false;
	}
	bin->libs = relibs;
	len = r_buf_read_at (bin->b, off, sdl, sizeof (struct dylib_command));
	if (len < 1) {
		bprintf ("Error: read (dylib)\n");
		return false;
	}
	dl.cmd = r_read_ble32 (&sdl[0], bin->big_endian);
	dl.cmdsize = r_read_ble32 (&sdl[4], bin->big_endian);
	dl.dylib.name = r_read_ble32 (&sdl[8], bin->big_endian);
	dl.dylib.timestamp = r_read_ble32 (&sdl[12], bin->big_endian);
	dl.dylib.current_version = r_read_ble32 (&sdl[16], bin->big_endian);
	dl.dylib.compatibility_version = r_read_ble32 (&sdl[20], bin->big_endian);

	if (off + dl.dylib.name > bin->size ||\
	  off + dl.dylib.name + R_BIN_MACH0_STRING_LENGTH > bin->size) {
		return false;
	}

	memset (bin->libs[lib], 0, R_BIN_MACH0_STRING_LENGTH);
	len = r_buf_read_at (bin->b, off + dl.dylib.name,
		(ut8*)bin->libs[lib], R_BIN_MACH0_STRING_LENGTH);
	bin->libs[lib][R_BIN_MACH0_STRING_LENGTH - 1] = 0;
	if (len < 1) {
		bprintf ("Error: read (dylib str)");
		return false;
	}
	return true;
}

static const char *cmd_to_string(ut32 cmd) {
	switch (cmd) {
	case LC_DATA_IN_CODE:
		return "LC_DATA_IN_CODE";
	case LC_CODE_SIGNATURE:
		return "LC_CODE_SIGNATURE";
	case LC_RPATH:
		return "LC_RPATH";
	case LC_TWOLEVEL_HINTS:
		return "LC_TWOLEVEL_HINTS";
	case LC_PREBIND_CKSUM:
		return "LC_PREBIND_CKSUM";
	case LC_SEGMENT:
		return "LC_SEGMENT";
	case LC_SEGMENT_64:
		return "LC_SEGMENT_64";
	case LC_SYMTAB:
		return "LC_SYMTAB";
	case LC_SYMSEG:
		return "LC_SYMSEG";
	case LC_ID_DYLIB:
		return "LC_ID_DYLIB";
	case LC_DYSYMTAB:
		return "LC_DYSYMTAB";
	case LC_PREBOUND_DYLIB:
		return "LC_PREBOUND_DYLIB";
	case LC_ROUTINES:
		return "LC_ROUTINES";
	case LC_ROUTINES_64:
		return "LC_ROUTINES_64";
	case LC_SUB_FRAMEWORK:
		return "LC_SUB_FRAMEWORK";
	case LC_SUB_UMBRELLA:
		return "LC_SUB_UMBRELLA";
	case LC_SUB_CLIENT:
		return "LC_SUB_CLIENT";
	case LC_SUB_LIBRARY:
		return "LC_SUB_LIBRARY";
	case LC_FUNCTION_STARTS:
		return "LC_FUNCTION_STARTS";
	case LC_DYLIB_CODE_SIGN_DRS:
		return "LC_DYLIB_CODE_SIGN_DRS";
	case LC_BUILD_VERSION:
		return "LC_BUILD_VERSION";
	case LC_VERSION_MIN_MACOSX:
		return "LC_VERSION_MIN_MACOSX";
	case LC_VERSION_MIN_IPHONEOS:
		return "LC_VERSION_MIN_IPHONEOS";
	case LC_VERSION_MIN_TVOS:
		return "LC_VERSION_MIN_TVOS";
	case LC_VERSION_MIN_WATCHOS:
		return "LC_VERSION_MIN_WATCHOS";
	case LC_DYLD_INFO:
		return "LC_DYLD_INFO";
	case LC_DYLD_INFO_ONLY:
		return "LC_DYLD_INFO_ONLY";
	case LC_DYLD_ENVIRONMENT:
		return "LC_DYLD_ENVIRONMENT";
	case LC_SOURCE_VERSION:
		return "LC_SOURCE_VERSION";
	case LC_MAIN:
		return "LC_MAIN";
	case LC_UUID:
		return "LC_UUID";
	case LC_LAZY_LOAD_DYLIB:
		return "LC_LAZY_LOAD_DYLIB";
	case LC_ENCRYPTION_INFO:
		return "LC_ENCRYPTION_INFO";
	case LC_ENCRYPTION_INFO_64:
		return "LC_ENCRYPTION_INFO_64";
	case LC_SEGMENT_SPLIT_INFO:
		return "LC_SEGMENT_SPLIT_INFO";
	case LC_REEXPORT_DYLIB:
		return "LC_REEXPORT_DYLIB";
	case LC_LINKER_OPTION:
		return "LC_LINKER_OPTION";
	case LC_LINKER_OPTIMIZATION_HINT:
		return "LC_LINKER_OPTIMIZATION_HINT";
	case LC_LOAD_DYLINKER:
		return "LC_LOAD_DYLINKER";
	case LC_LOAD_DYLIB:
		return "LC_LOAD_DYLIB";
	case LC_LOAD_WEAK_DYLIB:
		return "LC_LOAD_WEAK_DYLIB";
	case LC_THREAD:
		return "LC_THREAD";
	case LC_UNIXTHREAD:
		return "LC_UNIXTHREAD";
	case LC_LOADFVMLIB:
		return "LC_LOADFVMLIB";
	case LC_IDFVMLIB:
		return "LC_IDFVMLIB";
	case LC_IDENT:
		return "LC_IDENT";
	case LC_FVMFILE:
		return "LC_FVMFILE";
	case LC_PREPAGE:
		return "LC_PREPAGE";
	}
	return "";
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
		bprintf ("Warning: chopping hdr.sizeofcmds\n");
		bin->hdr.sizeofcmds = bin->size - 128;
		//return false;
	}
	//bprintf ("Commands: %d\n", bin->hdr.ncmds);
	for (i = 0, off = sizeof (struct MACH0_(mach_header)) + bin->header_at; \
			i < bin->hdr.ncmds; i++, off += lc.cmdsize) {
		if (off > bin->size || off + sizeof (struct load_command) > bin->size){
			bprintf ("mach0: out of bounds command\n");
			return false;
		}
		len = r_buf_read_at (bin->b, off, loadc, sizeof (struct load_command));
		if (len < 1) {
			bprintf ("Error: read (lc) at 0x%08"PFMT64x"\n", off);
			return false;
		}
		lc.cmd = r_read_ble32 (&loadc[0], bin->big_endian);
		lc.cmdsize = r_read_ble32 (&loadc[4], bin->big_endian);

		if (lc.cmdsize < 1 || off + lc.cmdsize > bin->size) {
			bprintf ("Warning: mach0_header %d = cmdsize<1. (0x%llx vs 0x%llx)\n", i,
				(ut64)(off + lc.cmdsize), (ut64)(bin->size));
			break;
		}

		// TODO: a different format for each cmd
		sdb_num_set (bin->kv, sdb_fmt ("mach0_cmd_%d.offset", i), off, 0);
		sdb_set (bin->kv, sdb_fmt ("mach0_cmd_%d.format", i), "xd cmd size", 0);

		//bprintf ("%d\n", lc.cmd);
		switch (lc.cmd) {
		case LC_DATA_IN_CODE:
			sdb_set (bin->kv, sdb_fmt ("mach0_cmd_%d.cmd", i), "data_in_code", 0);
			// TODO table of non-instructions in __text
			break;
		case LC_RPATH:
			sdb_set (bin->kv, sdb_fmt ("mach0_cmd_%d.cmd", i), "rpath", 0);
			//bprintf ("--->\n");
			break;
		case LC_SEGMENT_64:
		case LC_SEGMENT:
			sdb_set (bin->kv, sdb_fmt ("mach0_cmd_%d.cmd", i), "segment", 0);
			bin->nsegs++;
			if (!parse_segments (bin, off)) {
				bprintf ("error parsing segment\n");
				bin->nsegs--;
				return false;
			}
			break;
		case LC_SYMTAB:
			sdb_set (bin->kv, sdb_fmt ("mach0_cmd_%d.cmd", i), "symtab", 0);
			if (!parse_symtab (bin, off)) {
				bprintf ("error parsing symtab\n");
				return false;
			}
			break;
		case LC_DYSYMTAB:
			sdb_set (bin->kv, sdb_fmt ("mach0_cmd_%d.cmd", i), "dysymtab", 0);
			if (!parse_dysymtab(bin, off)) {
				bprintf ("error parsing dysymtab\n");
				return false;
			}
			break;
		case LC_DYLIB_CODE_SIGN_DRS:
			sdb_set (bin->kv, sdb_fmt ("mach0_cmd_%d.cmd", i), "dylib_code_sign_drs", 0);
			//bprintf ("[mach0] code is signed\n");
			break;
		case LC_VERSION_MIN_MACOSX:
			sdb_set (bin->kv, sdb_fmt ("mach0_cmd_%d.cmd", i), "version_min_macosx", 0);
			bin->os = 1;
			// set OS = osx
			//bprintf ("[mach0] Requires OSX >= x\n");
			break;
		case LC_VERSION_MIN_IPHONEOS:
			sdb_set (bin->kv, sdb_fmt ("mach0_cmd_%d.cmd", i), "version_min_iphoneos", 0);
			bin->os = 2;
			// set OS = ios
			//bprintf ("[mach0] Requires iOS >= x\n");
			break;
		case LC_VERSION_MIN_TVOS:
			sdb_set (bin->kv, sdb_fmt ("mach0_cmd_%d.cmd", i), "version_min_tvos", 0);
			bin->os = 4;
			break;
		case LC_VERSION_MIN_WATCHOS:
			sdb_set (bin->kv, sdb_fmt ("mach0_cmd_%d.cmd", i), "version_min_watchos", 0);
			bin->os = 3;
			break;
		case LC_UUID:
			sdb_set (bin->kv, sdb_fmt ("mach0_cmd_%d.cmd", i), "uuid", 0);
			{
			struct uuid_command uc = {0};
			if (off + sizeof (struct uuid_command) > bin->size) {
				bprintf ("UUID out of obunds\n");
				return false;
			}
			if (r_buf_fread_at (bin->b, off, (ut8*)&uc, "24c", 1) != -1) {
				char key[128];
				char val[128];
				snprintf (key, sizeof (key)-1, "uuid.%d", bin->uuidn++);
				r_hex_bin2str ((ut8*)&uc.uuid, 16, val);
				sdb_set (bin->kv, key, val, 0);
				//for (i=0;i<16; i++) bprintf ("%02x%c", uc.uuid[i], (i==15)?'\n':'-');
			}
			}
			break;
		case LC_ENCRYPTION_INFO_64:
			/* TODO: the struct is probably different here */
		case LC_ENCRYPTION_INFO:
			sdb_set (bin->kv, sdb_fmt ("mach0_cmd_%d.cmd", i), "encryption_info", 0);
			{
			struct MACH0_(encryption_info_command) eic = {0};
			ut8 seic[sizeof (struct MACH0_(encryption_info_command))] = {0};
			if (off + sizeof (struct MACH0_(encryption_info_command)) > bin->size) {
				bprintf ("encryption info out of bounds\n");
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
				sdb_set (bin->kv, sdb_fmt ("mach0_cmd_%d.cmd", i), "dylinker", 0);
				free (bin->intrp);
				bin->intrp = NULL;
				//bprintf ("[mach0] load dynamic linker\n");
				struct dylinker_command dy = {0};
				ut8 sdy[sizeof (struct dylinker_command)] = {0};
				if (off + sizeof (struct dylinker_command) > bin->size){
					bprintf ("Warning: Cannot parse dylinker command\n");
					return false;
				}
				if (r_buf_read_at (bin->b, off, sdy, sizeof (struct dylinker_command)) == -1) {
					bprintf ("Warning: read (LC_DYLD_INFO) at 0x%08"PFMT64x"\n", off);
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
			sdb_set (bin->kv, sdb_fmt ("mach0_cmd_%d.cmd", i), "main", 0);

			if (!is_first_thread) {
				bprintf("Error: LC_MAIN with other threads\n");
				return false;
			}
			if (off + 8 > bin->size || off + sizeof (ep) > bin->size) {
				bprintf ("invalid command size for main\n");
				return false;
			}
			r_buf_read_at (bin->b, off + 8, sep, 2 * sizeof (ut64));
			ep.eo = r_read_ble64 (&sep[0], bin->big_endian);
			ep.ss = r_read_ble64 (&sep[8], bin->big_endian);

			bin->entry = ep.eo;
			bin->main_cmd = lc;

			sdb_num_set (bin->kv, "mach0.entry.offset", off + 8, 0);
			sdb_num_set (bin->kv, "stacksize", ep.ss, 0);

			is_first_thread = false;
			}
			break;
		case LC_UNIXTHREAD:
			sdb_set (bin->kv, sdb_fmt ("mach0_cmd_%d.cmd", i), "unixthread", 0);
			if (!is_first_thread) {
				bprintf("Error: LC_UNIXTHREAD with other threads\n");
				return false;
			}
		case LC_THREAD:
			sdb_set (bin->kv, sdb_fmt ("mach0_cmd_%d.cmd", i), "thread", 0);
			if (!parse_thread (bin, &lc, off, is_first_thread)) {
				bprintf ("Cannot parse thread\n");
				return false;
			}
			is_first_thread = false;
			break;
		case LC_LOAD_DYLIB:
		case LC_LOAD_WEAK_DYLIB:
			sdb_set (bin->kv, sdb_fmt ("mach0_cmd_%d.cmd", i), "load_dylib", 0);
			bin->nlibs++;
			if (!parse_dylib (bin, off)){
				bprintf ("Cannot parse dylib\n");
				bin->nlibs--;
				return false;
			}
			break;
		case LC_DYLD_INFO:
		case LC_DYLD_INFO_ONLY:
			{
			ut8 dyldi[sizeof (struct dyld_info_command)] = {0};
			sdb_set (bin->kv, sdb_fmt ("mach0_cmd_%d.cmd", i), "dyld_info", 0);
			bin->dyld_info = calloc (1, sizeof (struct dyld_info_command));
			if (bin->dyld_info) {
				if (off + sizeof (struct dyld_info_command) > bin->size){
					bprintf ("Cannot parse dyldinfo\n");
					R_FREE (bin->dyld_info);
					return false;
				}
				if (r_buf_read_at (bin->b, off, dyldi, sizeof (struct dyld_info_command)) == -1) {
					free (bin->dyld_info);
					bin->dyld_info = NULL;
					bprintf ("Error: read (LC_DYLD_INFO) at 0x%08"PFMT64x"\n", off);
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
			}
			break;
		case LC_CODE_SIGNATURE:
			parse_signature (bin, off);
			sdb_set (bin->kv, sdb_fmt ("mach0_cmd_%d.cmd", i), "signature", 0);
			/* ut32 dataoff
			// ut32 datasize */
			break;
		case LC_SOURCE_VERSION:
			sdb_set (bin->kv, sdb_fmt ("mach0_cmd_%d.cmd", i), "version", 0);
			/* uint64_t  version;  */
			/* A.B.C.D.E packed as a24.b10.c10.d10.e10 */
			//bprintf ("mach0: TODO: Show source version\n");
			break;
		case LC_SEGMENT_SPLIT_INFO:
			sdb_set (bin->kv, sdb_fmt ("mach0_cmd_%d.cmd", i), "split_info", 0);
			/* TODO */
			break;
		case LC_FUNCTION_STARTS:
			sdb_set (bin->kv, sdb_fmt ("mach0_cmd_%d.cmd", i), "function_starts", 0);
			if (!parse_function_starts (bin, off)) {
				bprintf ("Cannot parse LC_FUNCTION_STARTS\n");
			}
			break;
		case LC_REEXPORT_DYLIB:
			sdb_set (bin->kv, sdb_fmt ("mach0_cmd_%d.cmd", i), "dylib", 0);
			/* TODO */
			break;
		default:
			//bprintf ("mach0: Unknown header command %x\n", lc.cmd);
			break;
		}
	}
	return true;
}

static int init(struct MACH0_(obj_t)* bin) {
	if (!init_hdr (bin)) {
		bprintf ("Warning: File is not MACH0\n");
		return false;
	}
	if (!init_items (bin)) {
		bprintf ("Warning: Cannot initialize items\n");
	}
	bin->baddr = MACH0_(get_baddr)(bin);
	return true;
}

void* MACH0_(mach0_free)(struct MACH0_(obj_t)* mo) {
	if (!mo) {
		return NULL;
	}
	free (mo->segs);
	free (mo->sects);
	free (mo->symtab);
	free (mo->symstr);
	free (mo->indirectsyms);
	free (mo->imports_by_ord);
	free (mo->dyld_info);
	free (mo->toc);
	free (mo->modtab);
	free (mo->libs);
	free (mo->func_start);
	free (mo->signature);
	// this is freed in bfile.c:792
	// r_buf_free (mo->b);
	free (mo);
	return NULL;
}

void MACH0_(opts_set_default)(struct MACH0_(opts_t) *options, RBinFile * bf) {
	if (!options) {
		return;
	}

	options->header_at = 0;
	if (bf && bf->rbin) {
		options->verbose = bf->rbin->verbose;
	} else {
		options->verbose = false;
	}
}

struct MACH0_(obj_t)* MACH0_(mach0_new)(const char* file, struct MACH0_(opts_t) *options) {
	ut8 *buf;
	struct MACH0_(obj_t) *bin;
	if (!(bin = malloc (sizeof (struct MACH0_(obj_t))))) {
		return NULL;
	}
	memset (bin, 0, sizeof (struct MACH0_(obj_t)));
	if (options) {
		bin->verbose = options->verbose;
		bin->header_at = options->header_at;
	}
	bin->file = file;
	if (!(buf = (ut8*)r_file_slurp (file, &bin->size))) {
		return MACH0_(mach0_free)(bin);
	}
	bin->b = r_buf_new ();
	if (!r_buf_set_bytes (bin->b, buf, bin->size)) {
		free (buf);
		return MACH0_(mach0_free)(bin);
	}
	free (buf);
	bin->dyld_info = NULL;
	if (!init (bin)) {
		return MACH0_(mach0_free)(bin);
	}
	bin->imports_by_ord_size = 0;
	bin->imports_by_ord = NULL;
	return bin;
}

struct MACH0_(obj_t)* MACH0_(new_buf)(RBuffer *buf, struct MACH0_(opts_t) *options) {
	if (!buf) {
		return NULL;
	}

	RBuffer * buf_ref = r_buf_ref (buf);
	struct MACH0_(obj_t) *bin = R_NEW0 (struct MACH0_(obj_t));
	if (!bin) {
		return NULL;
	}
	bin->kv = sdb_new (NULL, "bin.mach0", 0);
	bin->size = r_buf_size (buf_ref);
	if (options) {
		bin->verbose = options->verbose;
		bin->header_at = options->header_at;
	}
	bin->b = buf_ref;
	if (!init (bin)) {
		return MACH0_(mach0_free)(bin);
	}
	return bin;
}

// prot: r = 1, w = 2, x = 4
// perm: r = 4, w = 2, x = 1
static int prot2perm (int x) {
	int r = 0;
	if (x & 1) {
		r |= 4;
	}
	if (x & 2) {
		r |= 2;
	}
	if (x & 4) {
		r |= 1;
	}
	return r;
}

struct section_t* MACH0_(get_sections)(struct MACH0_(obj_t)* bin) {
	struct section_t *sections;
	char segname[32], sectname[32], raw_segname[17];
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
			sections[i].vsize = seg->vmsize;
			sections[i].align = 4096;
			sections[i].flags = seg->flags;
			r_str_ncpy (sectname, seg->segname, 16);
			sectname[16] = 0;
			r_str_filter (sectname, -1);
			// hack to support multiple sections with same name
			sections[i].perm = prot2perm (seg->initprot);
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
	if (!(sections = calloc (bin->nsects + 1, sizeof (struct section_t)))) {
		return NULL;
	}
	for (i = 0; i < to; i++) {
		sections[i].offset = (ut64)bin->sects[i].offset;
		sections[i].addr = (ut64)bin->sects[i].addr;
		sections[i].size = (bin->sects[i].flags == S_ZEROFILL) ? 0 : (ut64)bin->sects[i].size;
		sections[i].vsize = (ut64)bin->sects[i].size;
		sections[i].align = bin->sects[i].align;
		sections[i].flags = bin->sects[i].flags;
		r_str_ncpy (sectname, bin->sects[i].sectname, 17);
		r_str_filter (sectname, -1);
		// hack to support multiple sections with same name
		// snprintf (segname, sizeof (segname), "%d", i); // wtf
		memcpy (raw_segname, bin->sects[i].segname, 16);
		raw_segname[16] = 0;
		snprintf (segname, sizeof (segname), "%d.%s", i, raw_segname);
		for (j = 0; j < bin->nsegs; j++) {
			if (sections[i].addr >= bin->segs[j].vmaddr &&
				sections[i].addr < (bin->segs[j].vmaddr + bin->segs[j].vmsize)) {
				sections[i].perm = prot2perm (bin->segs[j].initprot);
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
			ut64 sect_size = bin->sects[i].size;
			ut32 sect_fragment = bin->sects[i].reserved2;
			if (bin->sects[i].offset > bin->size) {
				bprintf ("mach0: section offset starts way beyond the end of the file\n");
				continue;
			}
			if (sect_size > bin->size) {
				bprintf ("mach0: Invalid symbol table size\n");
				sect_size = bin->size - bin->sects[i].offset;
			}
			nsyms = (int)(sect_size / sect_fragment);
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
					symstr = (char *)bin->symstr + stridx;
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

static int inSymtab(SdbHt *hash, const char *name, ut64 addr) {
	bool found;
	const char *key = sdb_fmt ("%s.%"PFMT64x, name, addr);
	(void)sdb_ht_find (hash, key, &found);
	if (found) {
		return true;
	}
	sdb_ht_insert (hash, key, "1");
	return false;
}

static char *get_name(struct MACH0_(obj_t)* mo, ut32 stridx, bool filter) {
	int i = 0;
	if (stridx >= mo->symstrlen) {
		return NULL;
	}
	int len = mo->symstrlen - stridx;
	const char *symstr = (const char*)mo->symstr + stridx;
	for (i = 0; i < len; i++) {
		if ((ut8)(symstr[i] & 0xff) == 0xff || !symstr[i]) {
			len = i;
			break;
		}
	}
	if (len > 0) {
		char *res = r_str_ndup (symstr, len);
		if (filter) {
			r_str_filter (res, -1);
		}
		return res;
	}
	return NULL;
}

struct symbol_t* MACH0_(get_symbols)(struct MACH0_(obj_t)* bin) {
	struct symbol_t *symbols;
	int j, s, stridx, symbols_size, symbols_count;
	ut32 to, from, i;

	r_return_val_if_fail (bin && bin->symtab && bin->symstr, NULL);

	/* parse dynamic symbol table */
	symbols_count = (bin->dysymtab.nextdefsym + \
			bin->dysymtab.nlocalsym + \
			bin->dysymtab.nundefsym );
	symbols_count += bin->nsymtab;
	symbols_size = (symbols_count + 1) * 2 * sizeof (struct symbol_t);

	if (symbols_size < 1) {
		return NULL;
	}
	if (!(symbols = calloc (1, symbols_size))) {
		return NULL;
	}
	SdbHt *hash = sdb_ht_new ();
	if (!hash) {
		free (symbols);
		return NULL;
	}
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

		from = R_MIN (R_MAX (0, from), symbols_size / sizeof (struct symbol_t));
		to = R_MIN (R_MIN (to, bin->nsymtab), symbols_size / sizeof (struct symbol_t));

		int maxsymbols = symbols_size / sizeof (struct symbol_t);
		if (to > 0x500000) {
			bprintf ("WARNING: corrupted mach0 header: symbol table is too big %d\n", to);
			free (symbols);
			sdb_ht_free (hash);
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
			char *sym_name = get_name (bin, stridx, false);
			if (sym_name) {
				r_str_ncpy (symbols[j].name, sym_name, R_BIN_MACH0_STRING_LENGTH);
				free (sym_name);
			}
			symbols[j].name[R_BIN_MACH0_STRING_LENGTH - 2] = 0;
			symbols[j].last = 0;
			if (inSymtab (hash, symbols[j].name, symbols[j].addr)) {
				symbols[j].name[0] = 0;
				j--;
			}
		}
	}
	to = R_MIN ((ut32)bin->nsymtab, bin->dysymtab.iundefsym + bin->dysymtab.nundefsym);
	for (i = bin->dysymtab.iundefsym; i < to; i++) {
		if (j > symbols_count) {
			bprintf ("mach0-get-symbols: error\n");
			break;
		}
		if (parse_import_stub (bin, &symbols[j], i)) {
			symbols[j++].last = 0;
		}
	}

	for (i = 0; i < bin->nsymtab; i++) {
		struct MACH0_(nlist) *st = &bin->symtab[i];
		stridx = st->n_strx;
		// 0 is for imports
		// 1 is for symbols
		// 2 is for func.eh (exception handlers?)
		int section = st->n_sect;
		if (section == 1 && j < symbols_count) { // text ??st->n_type == 1)
			/* is symbol */
			symbols[j].addr = st->n_value;
			symbols[j].offset = addr_to_offset (bin, symbols[j].addr);
			symbols[j].size = 0; /* find next symbol and crop */
			if (st->n_type & N_EXT) {
				symbols[j].type = R_BIN_MACH0_SYMBOL_TYPE_EXT;
			} else {
				symbols[j].type = R_BIN_MACH0_SYMBOL_TYPE_LOCAL;
			}
			char *sym_name = get_name (bin, stridx, false);
			if (sym_name) {
				strncpy (symbols[j].name, sym_name, R_BIN_MACH0_STRING_LENGTH);
				free (sym_name);
			} else {
				symbols[j].name[0] = 0;
			}
			symbols[j].name[R_BIN_MACH0_STRING_LENGTH - 1] = 0;
			symbols[j].last = 0;
			if (inSymtab (hash, symbols[j].name, symbols[j].addr)) {
				symbols[j].name[0] = 0;
			} else {
				j++;
			}
		}
	}
	sdb_ht_free (hash);
	symbols[j].last = 1;
	return symbols;
}

static int parse_import_ptr(struct MACH0_(obj_t)* bin, struct reloc_t *reloc, int idx) {
	int i, j, sym, wordsize;
	ut32 stype;
	wordsize = MACH0_(get_bits)(bin) / 8;
	if (idx < 0 || idx >= bin->nsymtab) {
		return 0;
	}
	if ((bin->symtab[idx].n_desc & REFERENCE_TYPE) == REFERENCE_FLAG_UNDEFINED_LAZY) {
		stype = S_LAZY_SYMBOL_POINTERS;
	} else {
		stype = S_NON_LAZY_SYMBOL_POINTERS;
	}

	reloc->offset = 0;
	reloc->addr = 0;
	reloc->addend = 0;
#define CASE(T) case ((T) / 8): reloc->type = R_BIN_RELOC_ ## T; break
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
			for (j = 0, sym = -1; bin->sects[i].reserved1 + j < bin->nindirectsyms; j++) {
				int indidx = bin->sects[i].reserved1 + j;
				if (indidx < 0 || indidx >= bin->nindirectsyms) {
					break;
				}
				if (idx == bin->indirectsyms[indidx]) {
					sym = j;
					break;
				}
			}
			reloc->offset = sym == -1 ? 0 : bin->sects[i].offset + sym * wordsize;
			reloc->addr = sym == -1 ? 0 : bin->sects[i].addr + sym * wordsize;
			return true;
		}
	}
	return false;
}

struct import_t* MACH0_(get_imports)(struct MACH0_(obj_t)* bin) {
	int i, j, idx, stridx;

	r_return_val_if_fail (bin && bin->symtab && bin->symstr && bin->sects && bin->indirectsyms, NULL);

	if (bin->dysymtab.nundefsym < 1 || bin->dysymtab.nundefsym > 0xfffff) {
		return NULL;
	}

	struct import_t *imports = calloc (bin->dysymtab.nundefsym + 1, sizeof (struct import_t));
	if (!imports) {
		return NULL;
	}
	for (i = j = 0; i < bin->dysymtab.nundefsym; i++) {
		idx = bin->dysymtab.iundefsym + i;
		if (idx < 0 || idx >= bin->nsymtab) {
			bprintf ("WARNING: Imports index out of bounds. Ignoring relocs\n");
			free (imports);
			return NULL;
		}
		stridx = bin->symtab[idx].n_strx;
		char *imp_name = get_name (bin, stridx, false);
		if (imp_name) {
			r_str_ncpy (imports[j].name, imp_name, R_BIN_MACH0_STRING_LENGTH);
			free (imp_name);
		} else {
			//imports[j].name[0] = 0;
			continue;
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

#define CASE(T) case ((T) / 8): rel_type = R_BIN_RELOC_ ## T; break
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
		if (bin->dyld_info->bind_off > bin->size || bin->dyld_info->bind_off + bind_size > bin->size) {
			return NULL;
		}
		if (bin->dyld_info->lazy_bind_off > bin->size || \
			bin->dyld_info->lazy_bind_off + lazy_size > bin->size) {
			return NULL;
		}
		if (bin->dyld_info->bind_off+bind_size+lazy_size > bin->size) {
			return NULL;
		}
		// NOTE(eddyb) it's a waste of memory, but we don't know the actual number of relocs.
		if (!(relocs = calloc (1, (1 + bind_size + lazy_size) * sizeof (struct reloc_t)))) {
			return NULL;
		}
		opcodes = calloc (1, bind_size + lazy_size + 1);
		if (!opcodes) {
			free (relocs);
			return NULL;
		}
		len = r_buf_read_at (bin->b, bin->dyld_info->bind_off, opcodes, bind_size);
		i = r_buf_read_at (bin->b, bin->dyld_info->lazy_bind_off, opcodes + bind_size, lazy_size);
		if (len < 1 || i < 1) {
			bprintf ("Error: read (dyld_info bind) at 0x%08"PFMT64x"\n",
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
				if (bin->symtab && bin->dysymtab.nundefsym < 0xffff) {
					for (j = 0; j < bin->dysymtab.nundefsym; j++) {
						int stridx = 0;
						int iundefsym = bin->dysymtab.iundefsym;
						if (iundefsym >= 0 && iundefsym < bin->nsymtab) {
							int sidx = iundefsym + j;
							if (sidx < 0 || sidx >= bin->nsymtab) {
								continue;
							}
							stridx = bin->symtab[sidx].n_strx;
							if (stridx < 0 || stridx >= bin->symstrlen) {
								continue;
							}
						}
						if (!strcmp ((char *)bin->symstr + stridx, sym_name)) {
							sym_ord = j;
							break;
						}
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
					bprintf ("Error: BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB"
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
					bprintf ("Error: Malformed DO bind opcode\n");
					goto beach;
				}
				DO_BIND();
				addr += wordsize;
				break;
			case BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB:
				if (addr >= segmentAddress) {
					bprintf ("Error: Malformed ADDR ULEB bind opcode\n");
					goto beach;
				}
				DO_BIND();
				addr += ULEB() + wordsize;
				break;
			case BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED:
				if (addr >= segmentAddress) {
					bprintf ("Error: Malformed IMM SCALED bind opcode\n");
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
						bprintf ("Error: Malformed ULEB TIMES bind opcode\n");
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
				bprintf ("Error: unknown bind opcode 0x%02x in dyld_info\n", *ur.p);
				free (opcodes);
				relocs[i].last = 1;
				return relocs;
			}
		}
		free (opcodes);
	} else {
		int j;
		if (!bin->symtab || !bin->symstr || !bin->sects || !bin->indirectsyms) {
			return NULL;
		}
		if (!(relocs = malloc ((bin->dysymtab.nundefsym + 1) * sizeof (struct reloc_t)))) {
			return NULL;
		}
		for (j = 0; j < bin->dysymtab.nundefsym; j++) {
			if (parse_import_ptr (bin, &relocs[i], bin->dysymtab.iundefsym + j)) {
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
	r_return_val_if_fail (bin && bin->sects, NULL);

	/* it's probably a dylib */
	if (!bin->entry) {
		return NULL;
	}
	
	struct addr_t *entry = R_NEW0 (struct addr_t);
	if (!entry) {
		return NULL;
	}
	entry->addr = entry_to_vaddr (bin);
	entry->offset = addr_to_offset (bin, entry->addr);
	entry->haddr = sdb_num_get (bin->kv, "mach0.entry.offset", 0);
	sdb_num_set (bin->kv, "mach0.entry.vaddr", entry->addr, 0);
	sdb_num_set (bin->kv, "mach0.entry.paddr", bin->entry, 0);

	if (entry->offset == 0) {
		int i;
		for (i = 0; i < bin->nsects; i++) {
			// XXX: section name shoudnt matter .. just check for exec flags
			if (!strncmp (bin->sects[i].sectname, "__text", 6)) {
				entry->offset = (ut64)bin->sects[i].offset;
				sdb_num_set (bin->kv, "mach0.entry", entry->offset, 0);
				entry->addr = (ut64)bin->sects[i].addr;
				if (!entry->addr) { // workaround for object files
					eprintf ("entrypoint is 0...\n");
					// XXX(lowlyw) there's technically not really entrypoints
					// for .o files, so ignore this...
					// entry->addr = entry->offset;
				}
				break;
			}
		}
		bin->entry = entry->addr;
	}
	return entry;
}

void MACH0_(kv_loadlibs)(struct MACH0_(obj_t)* bin) {
	int i;
	for (i = 0; i < bin->nlibs; i++) {
		sdb_set (bin->kv, sdb_fmt ("libs.%d.name", i), bin->libs[i], 0);
	}
}

struct lib_t* MACH0_(get_libs)(struct MACH0_(obj_t)* bin) {
	struct lib_t *libs;
	int i;

	if (!bin->nlibs) {
		return NULL;
	}
	if (!(libs = calloc ((bin->nlibs + 1), sizeof (struct lib_t)))) {
		return NULL;
	}
	for (i = 0; i < bin->nlibs; i++) {
		sdb_set (bin->kv, sdb_fmt ("libs.%d.name", i), bin->libs[i], 0);
		strncpy (libs[i].name, bin->libs[i], R_BIN_MACH0_STRING_LENGTH);
		libs[i].name[R_BIN_MACH0_STRING_LENGTH - 1] = '\0';
		libs[i].last = 0;
	}
	libs[i].last = 1;
	return libs;
}

ut64 MACH0_(get_baddr)(struct MACH0_(obj_t)* bin) {
	int i;

	if (bin->hdr.filetype != MH_EXECUTE && bin->hdr.filetype != MH_DYLINKER) {
		return 0;
	}
	for (i = 0; i < bin->nsegs; ++i) {
		if (bin->segs[i].fileoff == 0 && bin->segs[i].filesize != 0) {
			return bin->segs[i].vmaddr;
		}
	}
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
	if (hdr->cputype == CPU_TYPE_ARM64_32) { // new apple watch aka arm64_32
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
	if (bin) {
		switch (bin->os) {
		case 1: return "macos";
		case 2: return "ios";
		case 3: return "watchos";
		case 4: return "tvos";
		}
	}
	return "darwin";
}

const char* MACH0_(get_cputype_from_hdr)(struct MACH0_(mach_header) *hdr) {
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
	case CPU_TYPE_ARM64_32:
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
		break;
	default:
		eprintf ("Unknown arch %d\n", hdr->cputype);
		break;
	}
	return archstr;
}

const char* MACH0_(get_cputype)(struct MACH0_(obj_t)* bin) {
	return bin? MACH0_(get_cputype_from_hdr) (&bin->hdr): "unknown";
}

static const char *cpusubtype_tostring (ut32 cputype, ut32 cpusubtype) {
	switch (cputype) {
	case CPU_TYPE_VAX:
		switch (cpusubtype) {
		case CPU_SUBTYPE_VAX_ALL:	return "all";
		case CPU_SUBTYPE_VAX780:	return "vax780";
		case CPU_SUBTYPE_VAX785:	return "vax785";
		case CPU_SUBTYPE_VAX750:	return "vax750";
		case CPU_SUBTYPE_VAX730:	return "vax730";
		case CPU_SUBTYPE_UVAXI:		return "uvaxI";
		case CPU_SUBTYPE_UVAXII:	return "uvaxII";
		case CPU_SUBTYPE_VAX8200:	return "vax8200";
		case CPU_SUBTYPE_VAX8500:	return "vax8500";
		case CPU_SUBTYPE_VAX8600:	return "vax8600";
		case CPU_SUBTYPE_VAX8650:	return "vax8650";
		case CPU_SUBTYPE_VAX8800:	return "vax8800";
		case CPU_SUBTYPE_UVAXIII:	return "uvaxIII";
		default:			return "Unknown vax subtype";
		}
	case CPU_TYPE_MC680x0:
		switch (cpusubtype) {
		case CPU_SUBTYPE_MC68030:	return "mc68030";
		case CPU_SUBTYPE_MC68040:	return "mc68040";
		case CPU_SUBTYPE_MC68030_ONLY:	return "mc68030 only";
		default:			return "Unknown mc680x0 subtype";
		}
	case CPU_TYPE_I386:
		switch (cpusubtype) {
		case CPU_SUBTYPE_386: 			return "386";
		case CPU_SUBTYPE_486: 			return "486";
		case CPU_SUBTYPE_486SX: 		return "486sx";
		case CPU_SUBTYPE_PENT: 			return "Pentium";
		case CPU_SUBTYPE_PENTPRO: 		return "Pentium Pro";
		case CPU_SUBTYPE_PENTII_M3: 		return "Pentium 3 M3";
		case CPU_SUBTYPE_PENTII_M5: 		return "Pentium 3 M5";
		case CPU_SUBTYPE_CELERON: 		return "Celeron";
		case CPU_SUBTYPE_CELERON_MOBILE:	return "Celeron Mobile";
		case CPU_SUBTYPE_PENTIUM_3:		return "Pentium 3";
		case CPU_SUBTYPE_PENTIUM_3_M:		return "Pentium 3 M";
		case CPU_SUBTYPE_PENTIUM_3_XEON:	return "Pentium 3 Xeon";
		case CPU_SUBTYPE_PENTIUM_M:		return "Pentium Mobile";
		case CPU_SUBTYPE_PENTIUM_4:		return "Pentium 4";
		case CPU_SUBTYPE_PENTIUM_4_M:		return "Pentium 4 M";
		case CPU_SUBTYPE_ITANIUM:		return "Itanium";
		case CPU_SUBTYPE_ITANIUM_2:		return "Itanium 2";
		case CPU_SUBTYPE_XEON:			return "Xeon";
		case CPU_SUBTYPE_XEON_MP:		return "Xeon MP";
		default:				return "Unknown i386 subtype";
		}
	case CPU_TYPE_X86_64:
		switch (cpusubtype & 0xff) {
		case CPU_SUBTYPE_X86_64_ALL:	return "x86 64 all";
		case CPU_SUBTYPE_X86_ARCH1:	return "x86 arch 1";
		default:			return "Unknown x86 subtype";
		}
	case CPU_TYPE_MC88000:
		switch (cpusubtype & 0xff) {
		case CPU_SUBTYPE_MC88000_ALL:	return "all";
		case CPU_SUBTYPE_MC88100:	return "mc88100";
		case CPU_SUBTYPE_MC88110:	return "mc88110";
		default:			return "Unknown mc88000 subtype";
		}
	case CPU_TYPE_MC98000:
		switch (cpusubtype & 0xff) {
		case CPU_SUBTYPE_MC98000_ALL:	return "all";
		case CPU_SUBTYPE_MC98601:	return "mc98601";
		default:			return "Unknown mc98000 subtype";
		}
	case CPU_TYPE_HPPA:
		switch (cpusubtype & 0xff) {
		case CPU_SUBTYPE_HPPA_7100:	return "hppa7100";
		case CPU_SUBTYPE_HPPA_7100LC:	return "hppa7100LC";
		default:			return "Unknown hppa subtype";
		}
	case CPU_TYPE_ARM64:
		return "v8";
	case CPU_TYPE_ARM:
		switch (cpusubtype & 0xff) {
		case CPU_SUBTYPE_ARM_ALL:
			return "all";
		case CPU_SUBTYPE_ARM_V4T:
			return "v4t";
		case CPU_SUBTYPE_ARM_V5:
			return "v5";
		case CPU_SUBTYPE_ARM_V6:
			return "v6";
		case CPU_SUBTYPE_ARM_XSCALE:
			return "xscale";
		case CPU_SUBTYPE_ARM_V7:
			return "v7";
		case CPU_SUBTYPE_ARM_V7F:
			return "v7f";
		case CPU_SUBTYPE_ARM_V7S:
			return "v7s";
		case CPU_SUBTYPE_ARM_V7K:
			return "v7k";
		case CPU_SUBTYPE_ARM_V7M:
			return "v7m";
		case CPU_SUBTYPE_ARM_V7EM:
			return "v7em";
		default:
			eprintf ("Unknown arm subtype %d\n", cpusubtype & 0xff);
			return "unknown arm subtype";
		}
	case CPU_TYPE_SPARC:
		switch (cpusubtype & 0xff) {
		case CPU_SUBTYPE_SPARC_ALL:	return "all";
		default:			return "Unknown sparc subtype";
		}
	case CPU_TYPE_MIPS:
		switch (cpusubtype & 0xff) {
		case CPU_SUBTYPE_MIPS_ALL:	return "all";
		case CPU_SUBTYPE_MIPS_R2300:	return "r2300";
		case CPU_SUBTYPE_MIPS_R2600:	return "r2600";
		case CPU_SUBTYPE_MIPS_R2800:	return "r2800";
		case CPU_SUBTYPE_MIPS_R2000a:	return "r2000a";
		case CPU_SUBTYPE_MIPS_R2000:	return "r2000";
		case CPU_SUBTYPE_MIPS_R3000a:	return "r3000a";
		case CPU_SUBTYPE_MIPS_R3000:	return "r3000";
		default:			return "Unknown mips subtype";
		}
	case CPU_TYPE_I860:
		switch (cpusubtype & 0xff) {
		case CPU_SUBTYPE_I860_ALL:	return "all";
		case CPU_SUBTYPE_I860_860:	return "860";
		default:			return "Unknown i860 subtype";
		}
	case CPU_TYPE_POWERPC:
	case CPU_TYPE_POWERPC64:
		switch (cpusubtype & 0xff) {
		case CPU_SUBTYPE_POWERPC_ALL:	return "all";
		case CPU_SUBTYPE_POWERPC_601:	return "601";
		case CPU_SUBTYPE_POWERPC_602:	return "602";
		case CPU_SUBTYPE_POWERPC_603:	return "603";
		case CPU_SUBTYPE_POWERPC_603e:	return "603e";
		case CPU_SUBTYPE_POWERPC_603ev:	return "603ev";
		case CPU_SUBTYPE_POWERPC_604:	return "604";
		case CPU_SUBTYPE_POWERPC_604e:	return "604e";
		case CPU_SUBTYPE_POWERPC_620:	return "620";
		case CPU_SUBTYPE_POWERPC_750:	return "750";
		case CPU_SUBTYPE_POWERPC_7400:	return "7400";
		case CPU_SUBTYPE_POWERPC_7450:	return "7450";
		case CPU_SUBTYPE_POWERPC_970:	return "970";
		default:			return "Unknown ppc subtype";
		}
	}
	return "Unknown cputype";
}

char* MACH0_(get_cpusubtype_from_hdr)(struct MACH0_(mach_header) *hdr) {
	r_return_val_if_fail (hdr, NULL);
	return strdup (cpusubtype_tostring (hdr->cputype, hdr->cpusubtype));
}

char* MACH0_(get_cpusubtype)(struct MACH0_(obj_t)* bin) {
	if (bin) {
		return MACH0_(get_cpusubtype_from_hdr) (&bin->hdr);
	}
	return strdup ("Unknown");
}

bool MACH0_(is_pie)(struct MACH0_(obj_t)* bin) {
	return (bin && bin->hdr.filetype == MH_EXECUTE && bin->hdr.flags & MH_PIE);
}

bool MACH0_(has_nx)(struct MACH0_(obj_t)* bin) {
	return (bin && bin->hdr.filetype == MH_EXECUTE &&
		bin->hdr.flags & MH_NO_HEAP_EXECUTION);
}

char* MACH0_(get_filetype_from_hdr)(struct MACH0_(mach_header) *hdr) {
	const char *mhtype = "Unknown";
	switch (hdr->filetype) {
	case MH_OBJECT:     mhtype = "Relocatable object"; break;
	case MH_EXECUTE:    mhtype = "Executable file"; break;
	case MH_FVMLIB:     mhtype = "Fixed VM shared library"; break;
	case MH_CORE:       mhtype = "Core file"; break;
	case MH_PRELOAD:    mhtype = "Preloaded executable file"; break;
	case MH_DYLIB:      mhtype = "Dynamically bound shared library"; break;
	case MH_DYLINKER:   mhtype = "Dynamic link editor"; break;
	case MH_BUNDLE:     mhtype = "Dynamically bound bundle file"; break;
	case MH_DYLIB_STUB: mhtype = "Shared library stub for static linking (no sections)"; break;
	case MH_DSYM:       mhtype = "Companion file with only debug sections"; break;
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
		const char *name = symbols[i].name;
		if (!strcmp (name, "__Dmain")) {
			addr = symbols[i].addr;
			break;
		}
		if (strstr (name, "4main") && !strstr (name, "STATIC")) {
			addr = symbols[i].addr;
			break;
		}
		if (!strcmp (symbols[i].name, "_main")) {
			addr = symbols[i].addr;
	//		break;
		}
	}
	free (symbols);

	if (!addr && bin->main_cmd.cmd == LC_MAIN) {
		addr = bin->entry + bin->baddr;
	}

	if (!addr) {
		ut8 b[128];
		ut64 entry = addr_to_offset(bin, bin->entry);
		// XXX: X86 only and hacky!
		if (entry > bin->size || entry + sizeof (b) > bin->size) {
			return 0;
		}
		i = r_buf_read_at (bin->b, entry, b, sizeof (b));
		if (i < 1) {
			return 0;
		}
		for (i = 0; i < 64; i++) {
			if (b[i] == 0xe8 && !b[i+3] && !b[i+4]) {
				int delta = b[i+1] | (b[i+2] << 8) | (b[i+3] << 16) | (b[i+4] << 24);
				return bin->entry + i + 5 + delta;

			}
		}
	}
	return addr;
}

void MACH0_(mach_headerfields)(RBinFile *file) {
	RBuffer *buf = file->buf;
	int n = 0;
	struct MACH0_(mach_header) *mh = MACH0_(get_hdr_from_bytes)(buf);
	if (!mh) {
		return;
	}
	printf ("0x00000000  Magic       0x%x\n", mh->magic);
	printf ("0x00000004  CpuType     0x%x\n", mh->cputype);
	printf ("0x00000008  CpuSubType  0x%x\n", mh->cpusubtype);
	printf ("0x0000000c  FileType    0x%x\n", mh->filetype);
	printf ("0x00000010  nCmds       %d\n", mh->ncmds);
	printf ("0x00000014  sizeOfCmds  %d\n", mh->sizeofcmds);
	printf ("0x00000018  Flags       0x%x\n", mh->flags);
	bool is64 = mh->cputype >> 16;

	ut64 addr = 0x20 - 4;
	ut32 word = 0;
	ut8 wordbuf[sizeof (word)];
#define READWORD() \
		if (!r_buf_read_at (buf, addr, (ut8*)wordbuf, 4)) { \
			eprintf ("Invalid address in buffer."); \
			break; \
		} \
		addr += 4; \
		word = r_read_le32 (wordbuf);
	if (is64) {
		addr += 4;
	}
	for (n = 0; n < mh->ncmds; n++) {
		READWORD ();
		int lcType = word;
		eprintf ("0x%08"PFMT64x"  cmd %7d 0x%x %s\n",
			addr, n, lcType, cmd_to_string (lcType));
		READWORD ();
		int lcSize = word;
		word &= 0xFFFFFF;
		printf ("0x%08"PFMT64x"  cmdsize     %d\n", addr, word);
		if (lcSize < 1) {
			eprintf ("Invalid size for a load command\n");
			break;
		}
		switch (lcType) {
		case LC_MAIN:
			{
				ut8 data[64];
				r_buf_read_at (buf, addr, data, sizeof (data));
#if R_BIN_MACH064
				ut64 ep = r_read_ble64 (&data, false); //  bin->big_endian);
				printf ("0x%08"PFMT64x"  entry0      0x%" PFMT64x "\n", addr, ep);
				ut64 ss = r_read_ble64 (&data[8], false); //  bin->big_endian);
				printf ("0x%08"PFMT64x"  stacksize   0x%" PFMT64x "\n", addr +  8, ss);
#else
				ut32 ep = r_read_ble32 (&data, false); //  bin->big_endian);
				printf ("0x%08"PFMT32x"  entry0      0x%" PFMT32x "\n", (ut32)addr, ep);
				ut32 ss = r_read_ble32 (&data[4], false); //  bin->big_endian);
				printf ("0x%08"PFMT32x"  stacksize   0x%" PFMT32x "\n", (ut32)addr +  4, ss);
#endif
			}
			break;
		case LC_ID_DYLIB: // install_name_tool
			printf ("0x%08"PFMT64x"  id           %s\n",
				addr + 20, r_buf_get_at (buf, addr + 20, NULL));
			break;
		case LC_UUID:
			printf ("0x%08"PFMT64x"  uuid         %s\n",
				addr + 20, r_buf_get_at (buf, addr + 28, NULL));
			break;
		case LC_LOAD_DYLIB:
		case LC_LOAD_WEAK_DYLIB:
			printf ("0x%08"PFMT64x"  load_dylib  %s\n",
				addr + 16, r_buf_get_at (buf, addr + 16, NULL));
			break;
		case LC_RPATH:
			printf ("0x%08"PFMT64x"  rpath       %s\n",
				addr + 4, r_buf_get_at (buf, addr + 4, NULL));
			break;
		case LC_CODE_SIGNATURE:
			{
			ut32 *words = (ut32*)r_buf_get_at (buf, addr, NULL);
			printf ("0x%08"PFMT64x"  dataoff     0x%08x\n", addr, words[0]);
			printf ("0x%08"PFMT64x"  datasize    %d\n", addr + 4, words[1]);
			printf ("# wtf mach0.sign %d @ 0x%x\n", words[1], words[0]);
			}
			break;
		}
		addr += word - 8;
	}
	free (mh);
}

RList* MACH0_(mach_fields)(RBinFile *bf) {
	struct MACH0_(mach_header) *mh = MACH0_(get_hdr_from_bytes)(bf->buf);
	if (!mh) {
		return NULL;
	}
	RList *ret = r_list_new ();
	if (!ret) {
		return NULL;
	}
	ret->free = free;
	ut64 addr = 0;

#define ROW(nam,siz,val,fmt) \
	r_list_append (ret, r_bin_field_new (addr, addr, siz, nam, sdb_fmt ("0x%08x", val), fmt)); \
	addr += 4;
	ROW ("hdr.magic", 4, mh->magic, "x");
	ROW ("hdr.cputype", 4, mh->cputype, "x");
	ROW ("hdr.cpusubtype", 4, mh->cpusubtype, "x");
	ROW ("hdr.filetype", 4, mh->filetype, "x");
	ROW ("hdr.nbcmds", 4, mh->ncmds, "x");
	ROW ("hdr.sizeofcmds", 4, mh->sizeofcmds, "x");
	free (mh);
	return ret;
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
	if (len != sizeof (struct MACH0_(mach_header))) {
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
