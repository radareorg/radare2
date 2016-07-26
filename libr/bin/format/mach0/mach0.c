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
		if (p == end)
			eprintf ("malformed sleb128");
		byte = *p++;
		result |= (((st64)(byte & 0x7f)) << bit);
		bit += 7;
	} while (byte & 0x80);
	// sign extend negative numbers
	if ( (byte & 0x40) != 0 )
		result |= (-1LL) << bit;
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

	if (!bin->segs)
		return 0;

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
	ut32 magic = 0;
	int len;

	if (r_buf_read_at (bin->b, 0, (ut8*)&magic, 4) < 1) {
		eprintf ("Error: read (magic)\n");
		return false;
	}
	if (magic == MACH0_(MH_MAGIC)) {
		bin->big_endian = false;
	} else if (magic == MACH0_(MH_CIGAM)) {
		bin->big_endian = true;
	} else if (magic == FAT_CIGAM) {
		bin->big_endian = true;
	} else {
		return false; // object files are magic == 0, but body is different :?
	}
	len = r_buf_fread_at (bin->b, 0, (ut8*)&bin->hdr,
#if R_BIN_MACH064
		bin->big_endian?"8I":"8i", 1
#else
		bin->big_endian?"7I":"7i", 1
#endif
	);

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
	if (len < 1) {
		eprintf ("Error: read (hdr)\n");
		return false;
	}
	return true;
}

static int parse_segments(struct MACH0_(obj_t)* bin, ut64 off) {
	int sect, len, seg = bin->nsegs - 1;
	ut32 size_sects;

	if (!UT32_MUL (&size_sects, bin->nsegs, sizeof (struct MACH0_(segment_command))))
		return false;
	if (!size_sects || size_sects > bin->size)
		return false;
	if (off > bin->size || off + sizeof (struct MACH0_(segment_command)) > bin->size)
		return false;
	if (!(bin->segs = realloc (bin->segs, bin->nsegs * sizeof(struct MACH0_(segment_command))))) {
		perror ("realloc (seg)");
		return false;
	}
#if R_BIN_MACH064
	len = r_buf_fread_at (bin->b, off, (ut8*)&bin->segs[seg], bin->big_endian?"2I16c4L4I":"2i16c4l4i", 1);
#else
	len = r_buf_fread_at (bin->b, off, (ut8*)&bin->segs[seg], bin->big_endian?"2I16c8I":"2i16c8i", 1);
#endif
	if (len < 1)
		return false;
	sdb_num_set (bin->kv, sdb_fmt (0, "mach0_segment_%d.offset", seg), off, 0);
	sdb_num_set (bin->kv, "mach0_segments.count", 0, 0);
	sdb_set (bin->kv, "mach0_segment.format",
		"xd[16]zxxxxoodx "
		"cmd cmdsize segname vmaddr vmsize "
		"fileoff filesize maxprot initprot nsects flags", 0);

	if (len < 1) {
		eprintf ("Error: read (seg)\n");
		return false;
	}
	if (bin->segs[seg].nsects > 0) {
		sect = bin->nsects;
		bin->nsects += bin->segs[seg].nsects;
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

			if (bin->segs[seg].cmdsize != sizeof (struct MACH0_(segment_command)) \
					  + (sizeof (struct MACH0_(section))*bin->segs[seg].nsects)){
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
			len = r_buf_fread_at (bin->b, off + sizeof (struct MACH0_(segment_command)),
				(ut8*)&bin->sects[sect],
#if R_BIN_MACH064
				bin->big_endian?"16c16c2L8I":"16c16c2l8i",
#else
				bin->big_endian?"16c16c9I":"16c16c9i",
#endif
				bin->nsects - sect);
			if (len < 1) {
				eprintf ("Error: read (sects)\n");
				bin->nsects = sect;
				return false;
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

	if (off > bin->size || off + sizeof (struct symtab_command) > bin->size)
		return false;
	int len = r_buf_fread_at (bin->b, off, (ut8*)&st,
		bin->big_endian?"6I":"6i", 1);
	if (len < 1) {
		eprintf ("Error: read (symtab)\n");
		return false;
	}
	bin->symtab = NULL;
	bin->nsymtab = 0;
	if (st.strsize > 0 && st.strsize < bin->size && st.nsyms > 0) {
		bin->nsymtab = st.nsyms;
		if (st.stroff > bin->size || st.stroff + st.strsize > bin->size)
			return false;
		if (!UT32_MUL (&size_sym, bin->nsymtab, sizeof (struct MACH0_(nlist))))
			return false;
		if (!size_sym)
			return false;
		if (st.symoff > bin->size || st.symoff + size_sym > bin->size)
			return false;
		if (!(bin->symstr = calloc (1, st.strsize + 2))) {
			perror ("calloc (symstr)");
			return false;
		}
		bin->symstrlen = st.strsize;
		len = r_buf_read_at (bin->b, st.stroff, (ut8*)bin->symstr,
				st.strsize);
		if (len < 1) {
			eprintf ("Error: read (symstr)\n");
			R_FREE (bin->symstr);
			return false;
		}
		if (!(bin->symtab = calloc (bin->nsymtab,
				sizeof (struct MACH0_(nlist))))) {
			perror ("calloc (symtab)");
			return false;
		}
#if R_BIN_MACH064
		len = r_buf_fread_at (bin->b, st.symoff, (ut8*)bin->symtab,
			bin->big_endian?"I2cSL":"i2csl", bin->nsymtab);
#else
		len = r_buf_fread_at (bin->b, st.symoff, (ut8*)bin->symtab,
			bin->big_endian?"I2cSI":"i2csi", bin->nsymtab);
#endif
		if (len < 1) {
			eprintf ("Error: read (nlist)\n");
			R_FREE (bin->symtab);
			return false;
		}
	}
	return true;
}

static int parse_dysymtab(struct MACH0_(obj_t)* bin, ut64 off) {
	int len;
	ut32 size_tab;

	if (off > bin->size || off + sizeof (struct dysymtab_command) > bin->size)
		return false;

	len = r_buf_fread_at(bin->b, off, (ut8*)&bin->dysymtab, bin->big_endian?"20I":"20i", 1);
	if (len < 1) {
		eprintf ("Error: read (dysymtab)\n");
		return false;
	}
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
		len = r_buf_fread_at(bin->b, bin->dysymtab.tocoff,
			(ut8*)bin->toc, bin->big_endian?"2I":"2i", bin->ntoc);
		if (len < 1) {
			eprintf ("Error: read (toc)\n");
			R_FREE (bin->toc);
			return false;
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
#if R_BIN_MACH064
		len = r_buf_fread_at (bin->b, bin->dysymtab.modtaboff,
			(ut8*)bin->modtab, bin->big_endian?"12IL":"12il", bin->nmodtab);
#else
		len = r_buf_fread_at (bin->b, bin->dysymtab.modtaboff,
			(ut8*)bin->modtab, bin->big_endian?"13I":"13i", bin->nmodtab);
#endif
		if (len == -1) {
			eprintf ("Error: read (modtab)\n");
			R_FREE (bin->modtab);
			return false;
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

		len = r_buf_fread_at (bin->b, bin->dysymtab.indirectsymoff,
				(ut8*)bin->indirectsyms, bin->big_endian?"I":"i", bin->nindirectsyms);
		if (len == -1) {
			eprintf ("Error: read (indirect syms)\n");
			R_FREE (bin->indirectsyms);
			return false;
		}
	}
	/* TODO extrefsyms, extrel, locrel */
	return true;
}

static void parse_signature(struct MACH0_(obj_t) *bin, ut64 off) {
    	int i, len;
	ut32 count, data;
	struct linkedit_data_command link = {};
    	if (off > bin->size || off + sizeof(struct linkedit_data_command) > bin->size)
	    	return;
	len = r_buf_fread_at (bin->b, off, (ut8*)&link, bin->big_endian ? "4I" : "4i", 1);
	if (len < 1) {
		eprintf ("Failed to get data while parsing LC_CODE_SIGNATURE command\n");
		return;
	}
	data = link.dataoff;
	if (data > bin->size || data + sizeof(struct super_blob_t) > bin->size)
	    	return;
	struct super_blob_t *super = (struct super_blob_t *) (bin->b->buf + data);
	count = r_read_ble32 (&super->count, little_);
	for (i = 0; i < count; ++i) {
		if ((ut8 *)(super->index + i + 1) >
		    (ut8 *)(bin->b->buf + bin->size))
			return;
		if (r_read_ble32 (&super->index[i].type, little_) == CSSLOT_ENTITLEMENTS) {
			ut32 begin = r_read_ble32 (&super->index[i].offset, little_);
			if (begin > bin->size || begin + sizeof(struct blob_t) > bin->size)
			    	return;
			struct blob_t *entitlements = (struct blob_t *) ((ut8*)super + begin);
			len = r_read_ble32 (&entitlements->length, little_) - sizeof(struct blob_t);
			if (len > bin->size || len < 1)
			    	return;
			bin->signature = calloc (1, len + 1);
			if (!bin->signature)
			    	return;
			memcpy (bin->signature, entitlements + 1, len);
			bin->signature[len] = '\0';
			return;
		}
	}
}

static int parse_thread(struct MACH0_(obj_t)* bin, struct load_command *lc, ut64 off, bool is_first_thread) {
	ut64 ptr_thread, pc = UT64_MAX, pc_offset = UT64_MAX;
	ut32 flavor, count;
	ut8 *arw_ptr = NULL;
	int arw_sz, len = 0;

	if (off > bin->size || off + sizeof (struct thread_command) > bin->size)
		return false;

	len = r_buf_fread_at (bin->b, off, (ut8*)&bin->thread,
		bin->big_endian?"2I":"2i", 1);
	if (len < 1)
		goto wrong_read;

	len = r_buf_fread_at(bin->b, off + sizeof(struct thread_command),
		(ut8*)&flavor, bin->big_endian?"1I":"1i", 1);
	if (len == -1)
		goto wrong_read;

	if (off + sizeof(struct thread_command) + sizeof(flavor) > bin->size || \
	  off + sizeof(struct thread_command) + sizeof(flavor) + sizeof (ut32) > bin->size)
		return false;

	// TODO: use count for checks
	len = r_buf_fread_at(bin->b, off + sizeof(struct thread_command) + sizeof(flavor),
		(ut8*)&count, bin->big_endian?"1I":"1i", 1);
	if (len == -1)
		goto wrong_read;

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
	ut8 *buf;
	int len;
	if (off > bin->size || off + sizeof (struct linkedit_data_command) > bin->size) {
		eprintf ("Likely overflow while parsing"
			" LC_FUNCTION_STARTS command\n");
	}
	bin->func_start = NULL;
	len = r_buf_fread_at (bin->b, off, (ut8*)&fc, bin->big_endian ? "4I" : "4i", 1);
	if (len < 1) {
		eprintf ("Failed to get data while parsing"
			" LC_FUNCTION_STARTS command\n");
	}
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

	if (off > bin->size || off + sizeof (struct dylib_command) > bin->size)
		return false;
	lib = bin->nlibs - 1;

	if (!(bin->libs = realloc (bin->libs, bin->nlibs * R_BIN_MACH0_STRING_LENGTH))) {
		perror ("realloc (libs)");
		return false;
	}
	len = r_buf_fread_at (bin->b, off, (ut8*)&dl, bin->big_endian?"6I":"6i", 1);
	if (len < 1) {
		eprintf ("Error: read (dylib)\n");
		return false;
	}

	if (off + dl.dylib.name.offset > bin->size ||\
	  off + dl.dylib.name.offset + R_BIN_MACH0_STRING_LENGTH > bin->size)
		return false;

	len = r_buf_read_at (bin->b, off+dl.dylib.name.offset, (ut8*)bin->libs[lib], R_BIN_MACH0_STRING_LENGTH);
	if (len < 1) {
		eprintf ("Error: read (dylib str)");
		return false;
	}
	return true;
}

static int init_items(struct MACH0_(obj_t)* bin) {
	struct load_command lc = {0, 0};
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
		len = r_buf_fread_at (bin->b, off, (ut8*)&lc, bin->big_endian?"2I":"2i", 1);
		if (len < 1) {
			eprintf ("Error: read (lc) at 0x%08"PFMT64x"\n", off);
			return false;
		}
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
			if (off + sizeof (struct MACH0_(encryption_info_command)) > bin->size) {
				eprintf ("encryption info out of bounds\n");
				return false;
			}
			if (r_buf_fread_at (bin->b, off, (ut8*)&eic, bin->big_endian?"5I":"5i", 1) != -1) {
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
				if (off + sizeof (struct dylinker_command) > bin->size){
					eprintf ("Warning: Cannot parse dylinker command\n");
					return false;
				}
				if (r_buf_fread_at (bin->b, off, (ut8*)&dy,
							bin->big_endian?"3I":"3i", 1) == -1) {
					eprintf ("Warning: read (LC_DYLD_INFO) at 0x%08"PFMT64x"\n", off);
				} else {
					int len = dy.cmdsize;
					char *buf = malloc (len+1);
					if (buf) {
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
			sdb_set (bin->kv, sdb_fmt (0, "mach0_cmd_%d.cmd", i), "main", 0);

			if (!is_first_thread) {
				eprintf("Error: LC_MAIN with other threads\n");
				return false;
			}
			if (off+8 > bin->size || off + sizeof (ep) > bin->size) {
				eprintf ("invalid command size for main\n");
				return false;
			}
			r_buf_fread_at (bin->b, off+8, (void*)&ep,
				bin->big_endian?"2L": "2l", 1);
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
			sdb_set (bin->kv, sdb_fmt (0, "mach0_cmd_%d.cmd", i), "dyld_info", 0);
			bin->dyld_info = malloc (sizeof(struct dyld_info_command));
			if (off + sizeof (struct dyld_info_command) > bin->size){
				eprintf ("Cannot parse dyldinfo\n");
				free (bin->dyld_info);
				return false;
			}
			if (r_buf_fread_at (bin->b, off, (ut8*)bin->dyld_info, bin->big_endian?"12I":"12i", 1) == -1) {
				free (bin->dyld_info);
				bin->dyld_info = NULL;
				eprintf ("Error: read (LC_DYLD_INFO) at 0x%08"PFMT64x"\n", off);
			}
			break;
		case LC_CODE_SIGNATURE:
			parse_signature(bin, off);
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

	if (!bin)
		return NULL;
	/* for core files */
	if (bin->nsects <1 && bin->nsegs > 0) {
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

	if (!bin->sects)
		return NULL;
	to = R_MIN (bin->nsects, 128); // limit number of sections here to avoid fuzzed bins
	if (to < 1)
		return NULL;
	if (!(sections = malloc ((bin->nsects + 1) * sizeof (struct section_t))))
		return NULL;
	for (i = 0; i < to; i++) {
		sections[i].offset = (ut64)bin->sects[i].offset;
		sections[i].addr = (ut64)bin->sects[i].addr;
		sections[i].size = (ut64)bin->sects[i].size;
		sections[i].align = bin->sects[i].align;
		sections[i].flags = bin->sects[i].flags;
		r_str_ncpy (sectname, bin->sects[i].sectname, sizeof (sectname)-1);
		// hack to support multiple sections with same name
		snprintf (segname, sizeof (segname), "%d", i); // wtf
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

static int parse_import_stub(struct MACH0_(obj_t)* bin, struct symbol_t *symbol, int idx) {
	int i, j, nsyms, stridx;
	const char *symstr;

	if (idx<0)
		return 0;
	symbol->offset = 0LL;
	symbol->addr = 0LL;
	symbol->name[0] = '\0';

	if (!bin || !bin->sects) return false;
	for (i = 0; i < bin->nsects; i++) {
		if ((bin->sects[i].flags & SECTION_TYPE) == S_SYMBOL_STUBS &&
				bin->sects[i].reserved2 > 0) {
			nsyms = (int)(bin->sects[i].size / bin->sects[i].reserved2);
			if (nsyms > bin->size) {
				eprintf ("mach0: Invalid symbol table size\n");
			}
			for (j = 0; j < nsyms; j++) {
				if (bin->sects) {
					if (bin->sects[i].reserved1 + j >= bin->nindirectsyms)
						continue;
				}
				if (bin->indirectsyms) {
					if (idx != bin->indirectsyms[bin->sects[i].reserved1 + j])
						continue;
				}
				if (idx > bin->nsymtab) {
					continue;
				}
				symbol->type = R_BIN_MACH0_SYMBOL_TYPE_LOCAL;
				symbol->offset = bin->sects[i].offset + j * bin->sects[i].reserved2;
				symbol->addr = bin->sects[i].addr + j * bin->sects[i].reserved2;
				symbol->size = 0;
				stridx = bin->symtab[idx].n_un.n_strx;
				if (stridx >= 0 && stridx < bin->symstrlen) {
					symstr = (char *)bin->symstr+stridx;
				} else {
					symstr = "???";
				}

				// Remove the extra underscore that every import seems to have in Mach-O.
				if (*symstr == '_') symstr++;

				snprintf (symbol->name, R_BIN_MACH0_STRING_LENGTH,
					"imp.%s", symstr);
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

static int inSymtab (Sdb *db, struct symbol_t *symbols, int last, const char *name, ut64 addr) {
	const char *key = sdb_fmt (0, "%s.%"PFMT64x, name, addr);
	if (sdb_const_get (db, key, NULL))
		return true;
	sdb_set (db, key, "1", 0);
	return false;
}

struct symbol_t* MACH0_(get_symbols)(struct MACH0_(obj_t)* bin) {
	const char *symstr;
	struct symbol_t *symbols;
	int from, to, i, j, s, stridx, symbols_size, symbols_count;
	Sdb *db;
	//ut64 text_base = get_text_base (bin);

	if (!bin || !bin->symtab || !bin->symstr)
		return NULL;
	/* parse symbol table */
	/* parse dynamic symbol table */
	symbols_count = (bin->dysymtab.nextdefsym + \
			bin->dysymtab.nlocalsym + \
			bin->dysymtab.nundefsym );
	symbols_count += bin->nsymtab;
	//symbols_count = bin->nsymtab;
	symbols_size = (symbols_count+1)*2 * sizeof (struct symbol_t);

	if (symbols_size < 1)
		return NULL;

	if (!(symbols = calloc (1, symbols_size)))
		return NULL;
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
		if (from == to)
			continue;
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
		if (to>0x500000) {
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
			if (bin->symtab[i].n_type & N_EXT)
				symbols[j].type = R_BIN_MACH0_SYMBOL_TYPE_EXT;
			else symbols[j].type = R_BIN_MACH0_SYMBOL_TYPE_LOCAL;
			stridx = bin->symtab[i].n_un.n_strx;
			if (stridx>=0 && stridx<bin->symstrlen)
				symstr = (char*)bin->symstr+stridx;
			else symstr = "???";
			{
				int i = 0;
				int len = 0;
				len = bin->symstrlen - stridx;
				if (len>0) {
					for (i = 0; i<len; i++) {
						if ((ut8)(symstr[i]&0xff) == 0xff || !symstr[i]) {
							len = i;
							break;
						}
					}
					char *symstr_dup = NULL;
					if (len>0) symstr_dup = r_str_ndup (symstr, len);
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
			eprintf ("Error: %s at %d\n", __FILE__,__LINE__);
			break;
		}
		if (parse_import_stub(bin, &symbols[j], i))
			symbols[j++].last = 0;
	}

#if 1
// symtab is wrongly parsed and produces dupped syms with incorrect vaddr */
	for (i=0; i < bin->nsymtab; i++) {
		struct MACH0_(nlist) *st = &bin->symtab[i];
#if 0
		eprintf ("stridx %d -> section %d type %d value = %d\n",
			st->n_un.n_strx, st->n_sect, st->n_type, st->n_value);
#endif
		stridx = st->n_un.n_strx;
		if (stridx>=0 && stridx<bin->symstrlen)
			symstr = (char*)bin->symstr+stridx;
		else symstr = "???";
		// 0 is for imports
		// 1 is for symbols
		// 2 is for func.eh (exception handlers?)
		int section = st->n_sect;
		if (section == 1 && j < symbols_count) { // text ??st->n_type == 1)
			/* is symbol */
			symbols[j].addr = st->n_value; // + text_base;
			symbols[j].offset = addr_to_offset (bin, symbols[j].addr);
			symbols[j].size = 0; /* find next symbol and crop */
			if (st->n_type & N_EXT)
				symbols[j].type = R_BIN_MACH0_SYMBOL_TYPE_EXT;
			else symbols[j].type = R_BIN_MACH0_SYMBOL_TYPE_LOCAL;
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
	if (bin->dysymtab.nundefsym<1 || bin->dysymtab.nundefsym>0xfffff) {
		return NULL;
	}
	if (!(imports = malloc ((bin->dysymtab.nundefsym + 1) * sizeof(struct import_t))))
		return NULL;
	for (i = j = 0; i < bin->dysymtab.nundefsym; i++) {
		idx = bin->dysymtab.iundefsym +i;
		if (idx<0 || idx>=bin->nsymtab) {
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
						stridx = bin->symtab[sidx].n_un.n_strx;
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
				if (entry->addr==0) // workaround for object files
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
	if ((hdr->cpusubtype & CPU_SUBTYPE_MASK) == CPU_SUBTYPE_ARM_V7K) {
		return 16;
	}
	return 32;
}

int MACH0_(is_big_endian)(struct MACH0_(obj_t)* bin) {
	bool is_ppc = bin && bin->hdr.cputype == CPU_TYPE_POWERPC64;
	if (!is_ppc) is_ppc = bin && bin->hdr.cputype == CPU_TYPE_POWERPC;
	return is_ppc;
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
	switch (hdr->cputype) {
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
	return strdup ("unknown");
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
			case CPU_SUBTYPE_ARM_V6:
				return strdup ("v6");
			case CPU_SUBTYPE_ARM_V5TEJ:
				return strdup ("v5tej");
			case CPU_SUBTYPE_ARM_XSCALE:
				return strdup ("xscale");
			case CPU_SUBTYPE_ARM_V7:
				return strdup ("v7");
			case CPU_SUBTYPE_ARM_V7F:
				return strdup ("v7f");
			case CPU_SUBTYPE_ARM_V7K:
				return strdup ("v7k");
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
	switch (hdr->filetype) {
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
	default:		 	return strdup ("Unknown");
	}
	return strdup ("Unknown");
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

	if (!(symbols = MACH0_(get_symbols) (bin)))
		return 0;
	for (i = 0; !symbols[i].last; i++)
		if (!strcmp (symbols[i].name, "_main")) {
			addr = symbols[i].addr;
			break;
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
	ut32 magic = 0;
	int len;
	struct MACH0_(mach_header) *macho_hdr = R_NEW0 (struct MACH0_(mach_header));
	int big_endian;

	if (!macho_hdr) {
		return NULL;
	}

	if (r_buf_read_at (buf, 0, (ut8*)&magic, 4) < 1) {
		eprintf ("Error: read (magic)\n");
		return false;
	}

	if (magic == MACH0_(MH_MAGIC)) {
		big_endian = false;
	} else if (magic == MACH0_(MH_CIGAM)) { 
		big_endian = true;
	} else if (magic == FAT_CIGAM) {
		big_endian = true;
	} else if (magic == 0xfeedfacf) {
		big_endian = false;
	} else {
		free (macho_hdr);
		return NULL;
	}

	len = r_buf_fread_at (buf, 0, (ut8*)macho_hdr,
#if R_BIN_MACH064
		big_endian?"8I":"8i", 1
#else
		big_endian?"7I":"7i", 1
#endif
	);

	if (len != sizeof(struct MACH0_(mach_header))) {
		free (macho_hdr);
		return NULL;
	}

	return macho_hdr;
}
