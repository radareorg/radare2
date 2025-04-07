/* radare - LGPL - Copyright 2025 - elliotnunn */

#include <r_lib.h>
#include <r_bin.h>

typedef struct {
	ut32 offset;
	ut16 target; // either section or import
	bool isimport;
} PEFReloc;

typedef struct {
	ut64 addr;
	void *unpack;
	RList/*<myreloc>*/ *relocs;
	ut32 defAddress;
	ut32 lenTotal, lenUnpack, lenDisk;
	ut32 offset;
	ut8 kind, share, align;
} PEFSection;

typedef struct {
	ut16 nsec;
	ut32 ldrsec;
	PEFSection sec[];
} RBinPEFObj;

static const char *class2string(ut8 class) {
	switch (class & 0xf) {
	case 0: return R_BIN_TYPE_FUNC_STR; // code
	case 1: return R_BIN_TYPE_OBJECT_STR; // data
	case 2: return R_BIN_TYPE_OBJECT_STR; // tvector
	case 3: return R_BIN_TYPE_SECTION_STR; // toc
	case 4: return R_BIN_TYPE_FUNC_STR; // glue
	default: return R_BIN_TYPE_UNKNOWN_STR;
	}
}

static bool pidata_getcount(const char **ptr, const char *limit, ut32 *ret) {
	*ret = 0;
	for (;;) {
		if (*ptr >= limit) return true; // fail
		ut8 byte = *(*ptr)++;
		*ret = (*ret << 7) | (byte & 0x7f);
		if (*ret & 0x80000000) return true; // unrealistically large, prevent oflow when used as int
		if ((byte & 0x80) == 0) return false; // OK
	}
}

// Do a bounds check for every single byte that is read/written,
// to guard against overflow in pointer arithmetic.
// Return nonzero on failure.
static int unpack_pidata(char *dest, size_t dlen, const char *src, size_t slen) {
	char *dlim = dest + dlen;
	const char *slim = src + slen;
	int i, j;

	while (src < slim) {
		ut8 firstbyte = *src++;
		ut8 opcode = firstbyte >> 5;
		ut32 arg = firstbyte & 0x1f;
		if (arg == 0) {
			if (pidata_getcount(&src, slim, &arg)) return 1;
		}

		if (opcode == 0) { // put zeros
			for (i=0; i<arg; i++) {
				if (dest >= dlim) return 2;
				*dest++ = 0;
			}
		} else if (opcode == 1) { // copy block
			for (i=0; i<arg; i++) {
				if (src >= slim || dest >= dlim) return 3;
				*dest++ = *src++;
			}
		} else if (opcode == 2) { // repeated block
			ut32 blockSize = arg;
			ut32 repeatCountMin1;
			if (pidata_getcount(&src, slim, &repeatCountMin1)) return 4;

			do {
				for (i=0; i<blockSize; i++) {
					if (src + i >= slim || dest >= dlim) return 5;
					*dest++ = src[i];
				}
			} while (repeatCountMin1--);
			src += blockSize;
		} else if (opcode == 3) { // interleave repeatblock with customblock
			ut32 commonSize = arg;
			ut32 customSize, repeatCount;
			if (pidata_getcount(&src, slim, &customSize)) return 6;
			if (pidata_getcount(&src, slim, &repeatCount)) return 7;

			const char *common = src;
			for (i=0; i<commonSize; i++) {
				if (src >= slim || dest >= dlim) return 8;
				*dest++ = *src++;
			}

			for (i=0; i<repeatCount; i++) {
				for (j=0; j<customSize; j++) {
					if (src >= slim || dest >= dlim) return 9;
					*dest++ = *src++;
				}
				const char *comcopy = common;
				for (j=0; j<commonSize; j++) {
					if (dest >= dlim) return 10;
					*dest++ = *comcopy++;
				}
			}
		} else if (opcode == 4) { // interleave repeatblock with zeroblock
			ut32 commonSize = arg;
			ut32 customSize, repeatCount;
			if (pidata_getcount(&src, slim, &customSize)) return 11;
			if (pidata_getcount(&src, slim, &repeatCount)) return 12;

			for (i=0; i<commonSize; i++) {
				if (dest >= dlim) return 13;
				*dest++ = 0;
			}

			for (i=0; i<repeatCount; i++) {
				for (j=0; j<customSize; j++) {
					if (src >= slim || dest >= dlim) return 14;
					*dest++ = *src++;
				}
				for (j=0; j<commonSize; j++) {
					if (dest >= dlim) return 15;
					*dest++ = 0;
				}
			}
		} else {
			return 16; // illegal opcode
		}
	}
	if (dest != dlim) return 1;
	return 0; // ok
}

static int reloc_comparator(const PEFReloc *a, const PEFReloc *b) {
	return (a->offset > b->offset) - (a->offset < b->offset);
}

static RList *do_reloc_bytecode(RBuffer *b, ut32 at, ut32 instCount) {
	RList *ret = r_list_newf((RListFree)free);
	ut32 codeA = 0, dataA = 1, rSymI = 0, rAddr = 0;
	ut32 loopInstruct = UT32_MAX;
	ut32 loopDone = 0;
	int i;

	if (0) {
		printf("           Instr     Op    Operand           codeA dataA rSymI rAddr\n");
	}

	#define dbg(name, format, ...) if (0) { \
		char buf[50]; \
		sprintf(buf, format, __VA_ARGS__); \
		printf("%05X [% 2d] %04X      %-5s %-19s %d %5d %5d   %08X\n", \
			at + 2*printpc, printpc, r_buf_read_be16_at(b, at+2*printpc), name, buf, codeA, dataA, rSymI, rAddr); \
	}

	#define PUSH_RELOC(ofs, targ, imp) { \
		PEFReloc *r = R_NEW0(PEFReloc); \
		r->offset = ofs; \
		r->target = targ; \
		r->isimport = imp; \
		r_list_append(ret, r); \
	}

	ut32 pc = 0;
	while (pc < instCount) {
		ut32 printpc = pc;
		ut16 op = r_buf_read_be16_at(b, at + 2*pc++);

		// Some instructions take a wider argument
		ut32 longop = 0;
		if (op >= 0xa000) {
			if (pc >= instCount) return 0;
			longop = ((ut32)op << 16) | r_buf_read_be16_at(b, at + 2*pc++);
		}

		if (op <= 0x3fff) {
			// RelocBySectDWithSkip (DDAT)
			ut8 skipCount = (op >> 6) & 0xff;
			ut8 relocCount = op & 0x3f;
			dbg("DDAT", "delta=%d,n=%d", skipCount*4, relocCount);

			rAddr += 4 * skipCount;
			for (i=0; i<relocCount; i++) {
				PUSH_RELOC(rAddr, dataA, false);
				rAddr += 4;
			}
		} else if (op >= 0x4000 && op <= 0x41ff) {
			// RelocBySectC (CODE)
			// DumpPEF sometimes gets rAddr wrong for large runLength!
			ut16 runLength = (op & 0x1ff) + 1;
			dbg("CODE", "cnt=%d", runLength);
			for (i=0; i<runLength; i++) {
				PUSH_RELOC(rAddr, codeA, false);
				rAddr += 4;
			}
		} else if (op >= 0x4200 && op <= 0x43ff) {
			// RelocBySectD (DATA)
			ut16 runLength = (op & 0x1ff) + 1;
			dbg("DATA", "cnt=%d", runLength);
			for (i=0; i<runLength; i++) {
				PUSH_RELOC(rAddr, dataA, false);
				rAddr += 4;
			}
		} else if (op >= 0x4400 && op <= 0x45ff) {
			// RelocTVector12 (DESC)
			ut16 runLength = (op & 0x1ff) + 1;
			dbg("DESC", "cnt=%d", runLength);
			for (i=0; i<runLength; i++) {
				PUSH_RELOC(rAddr, codeA, false);
				rAddr += 4;
				PUSH_RELOC(rAddr, dataA, false);
				rAddr += 8;
			}
		} else if (op >= 0x4600 && op <= 0x47ff) {
			// RelocTVector8 (DSC2)
			ut16 runLength = (op & 0x1ff) + 1;
			dbg("DSC2", "cnt=%d", runLength);
			for (i=0; i<runLength; i++) {
				PUSH_RELOC(rAddr, codeA, false);
				rAddr += 4;
				PUSH_RELOC(rAddr, dataA, false);
				rAddr += 4;
			}
		} else if (op >= 0x4800 && op <= 0x49ff) {
			// RelocVTable8 (VTBL)
			ut16 runLength = (op & 0x1ff) + 1;
			dbg("VTBL", "cnt=%d", runLength);
			for (i=0; i<runLength; i++) {
				PUSH_RELOC(rAddr, dataA, false);
				rAddr += 8;
			}
		} else if (op >= 0x4a00 && op <= 0x4bff) {
			// RelocImportRun (SYMR)
			ut16 runLength = (op & 0x1ff) + 1;
			dbg("SYMR", "cnt=%d", runLength);
			for (i=0; i<runLength; i++) {
				PUSH_RELOC(rAddr, rSymI, true);
				rAddr += 4;
				rSymI += 1;
			}
		} else if (op >= 0x6000 && op <= 0x61ff) {
			// RelocSmByImport (SYMB)
			ut16 index = op & 0x1ff;;
			dbg("SYMB", "idx=%d", index);
			PUSH_RELOC(rAddr, index, true);
			rAddr += 4;
			rSymI = index + 1;
		} else if (op >= 0x6200 && op <= 0x63ff) {
			// RelocSmSetSectC (CDIS)
			ut16 index = op & 0x1ff;
			dbg("CDIS", "sct=%d", index);
			codeA = index;
		} else if (op >= 0x6400 && op <= 0x65ff) {
			// RelocSmSetSectD (DTIS)
			ut16 index = op & 0x1ff;
			dbg("DTIS", "sct=%d", index);
			dataA = index;
		} else if (op >= 0x6600 && op <= 0x67ff) {
			// RelocSmBySection (SECN)
			ut16 index = op & 0x1ff;
			dbg("SECN", "sct=%d", index);
			PUSH_RELOC(rAddr, index, false);
			rAddr += 4;
		} else if (op>>12 == 0b1000) {
			// RelocIncrPosition (DELT)
			ut16 offset = (op & 0x0fff) + 1;
			dbg("DELT", "delta=%d", offset);
			rAddr += offset;
		} else if (op >= 0x9000 && op <= 0x9fff) {
			// RelocSmRepeat (RPT)
			ut8 blockCount = ((op >> 8) & 0xf) + 1;
			ut16 repeatCount = (op & 0xff) + 1;
			dbg("RPT", "i=%d,rpt=%d", blockCount, repeatCount);

			if (loopInstruct != UT32_MAX && loopInstruct != pc) return NULL; // nested loop
			loopInstruct = pc;

			if (loopDone == repeatCount) {
				loopDone = 0;
			} else {
				loopDone++;
				pc--; // rewind over "op"
				if (blockCount > pc) return NULL; // can't go back this far
				pc -= blockCount;
			}
		} else if (op >= 0xa000 && op <= 0xa3ff) {
			// RelocSetPosition (LABS)
			ut32 offset = longop & 0x3ffffff;
			dbg("LABS", "offset=%d", offset);
			rAddr = offset;
		} else if (op >= 0xa400 && op <= 0xa7ff) {
			// RelocLgByImport (LSYM)
			ut32 index = longop & 0x3ffffff;
			dbg("LSYM", "idx=%d", index);
			PUSH_RELOC(rAddr, index, true);
			rAddr += 4;
			rSymI = index + 1;
		} else if (op >= 0xb000 && op <= 0xb3ff) {
			// RelocLgRepeat (LRPT)
			ut8 blockCount = ((op >> 8) & 0xf) + 1;
			ut32 repeatCount = (longop & 0x3fffff) + 1;
			dbg("LRPT", "i=%d,rpt=%d", blockCount, repeatCount);

			if (loopInstruct != UT32_MAX && loopInstruct != pc) return NULL; // nested loop
			loopInstruct = pc;

			if (loopDone == repeatCount) {
				loopDone = 0;
			} else {
				loopDone++;
				pc -= 2; // rewind over "longop"
				if (blockCount > pc) return NULL; // can't go back this far
				pc -= blockCount;
			}
		} else if (op >= 0xb400 && op <= 0xb43f) {
			// Same as RelocSmBySection (LSEC LSECN)
			ut32 index = longop & 0x3fffff;
			dbg("LSEC", "LSECN,sct=%d", index);
			PUSH_RELOC(rAddr, index, false);
			rAddr += 4;
		} else if (op >= 0xb440 && op <= 0xb47f) {
			// Same as RelocSmSetSectC (LSEC LDIS)
			ut32 index = longop & 0x3fffff;
			dbg("LSEC", "LCDIS,sct=%d", index);
			codeA = index;
		} else if (op >= 0xb480 && op <= 0xb4bf) {
			// Same as RelocSmSetSectD (LSEC LTIS)
			ut32 index = longop & 0x3fffff;
			dbg("LSEC", "LDTIS,sct=%d", index);
			dataA = index;
		} else {
			return NULL;
		}
	}
	if (r_list_length(ret) == 0) {
		r_list_free(ret);
		return NULL;
	}
	r_list_sort(ret, (RListComparator)reloc_comparator);
	return ret;
}

static bool check(RBinFile *bf, RBuffer *b) {
	char tmp[8];
	int r = r_buf_read_at(b, 0, (ut8 *)tmp, sizeof (tmp));
	return r == sizeof (tmp) && !memcmp(tmp, "Joy!peff", sizeof (tmp));
}

static bool load(RBinFile *bf, RBuffer *buf, ut64 loadaddr) {
	if (!check(bf, buf)) return false;
	ut16 nsec = r_buf_read_be16_at(bf->buf, 32);
	RBinPEFObj *pef = bf->bo->bin_obj = calloc(1, sizeof (RBinPEFObj) + sizeof (PEFSection) * nsec);
	if (!pef) return false;
	pef->nsec = nsec;
	ut64 climb = loadaddr;
	int i;
	for (i=0; i<nsec; i++) {
		PEFSection *sec = &pef->sec[i];
		size_t offset = 40 + 28*i;
		sec->defAddress = r_buf_read_be32_at(buf, offset + 4);
		sec->lenTotal = r_buf_read_be32_at(buf, offset + 8);
		sec->lenUnpack = r_buf_read_be32_at(buf, offset + 12);
		sec->lenDisk = r_buf_read_be32_at(buf, offset + 16);
		sec->offset = r_buf_read_be32_at(buf, offset + 20);
		r_buf_read_at(buf, offset + 24, &sec->kind, 1);
		r_buf_read_at(buf, offset + 25, &sec->share, 1);
		r_buf_read_at(buf, offset + 26, &sec->align, 1);

		if (sec->kind <= 3 || sec->kind == 6) { // exists in memory
			climb += sec->align - 1;
			climb &= ~(ut64)(sec->align - 1);
			sec->addr = climb;
			climb += sec->lenTotal;
		}

		if (sec->kind == 4) pef->ldrsec = sec->offset;

		if (sec->kind == 2) { // pidata, extract now
			void *pac = malloc(sec->lenDisk);
			sec->unpack = malloc(sec->lenUnpack);
			if (!pac || !sec->unpack) return false;
			st64 n = r_buf_read_at(bf->buf, sec->offset, pac, sec->lenDisk);
			if (n != sec->lenDisk) return false;
			if (unpack_pidata(sec->unpack, sec->lenUnpack, pac, sec->lenDisk)) return false;
			free(pac);
		}
	}

	// Parse the loader section
	ut32 importedLibraryCount = r_buf_read_be32_at(bf->buf, pef->ldrsec + 24);
	ut32 totalImportedSymbolCount = r_buf_read_be32_at(bf->buf, pef->ldrsec + 28);
	ut32 relocSecCount = r_buf_read_be32_at(bf->buf, pef->ldrsec + 32);
	ut32 relocInstrOffset = r_buf_read_be32_at(bf->buf, pef->ldrsec + 36);

	for (i=0; i<relocSecCount; i++) {
		ut32 at = pef->ldrsec + 56 + 24*importedLibraryCount + 4*totalImportedSymbolCount + 12*i;
		ut16 sec = r_buf_read_be16_at(bf->buf, at);
		ut32 instCount = r_buf_read_be32_at(bf->buf, at + 4);
		ut32 firstInst = r_buf_read_be32_at(bf->buf, at + 8);

		pef->sec[sec].relocs = do_reloc_bytecode(bf->buf, pef->ldrsec + relocInstrOffset + firstInst, instCount);
	}

	return true;
}

static void destroy(RBinFile *bf) {
	RBinPEFObj *pef = bf->bo->bin_obj;
	int i;
	for (i=0; i<pef->nsec; i++) {
		free(pef->sec[i].unpack);
		r_list_free(pef->sec[i].relocs);
	}
	free(pef);
}

static RBinInfo *info(RBinFile *bf) {
	char hdr[40];
	int r = r_buf_read_at(bf->buf, 0, (ut8 *)hdr, sizeof (hdr));
	if (r != sizeof (hdr)) {
		return NULL;
	}

	RBinInfo *ret = R_NEW0 (RBinInfo);
	ret->file = strdup(bf->file);
	ret->type = strdup("PEF");
	if (!memcmp(hdr+8, "pwpc", 4)) {
		ret->arch = strdup("ppc");
		ret->machine = strdup("Power Macintosh/BeBox");
	} else if (!memcmp(hdr+8, "m68k", 4)) {
		ret->arch = strdup("m68k");
		ret->cpu = strdup("68040");
		ret->machine = strdup("Macintosh");
	}
	ret->bits = 32;
	ret->has_pi = true;
	ret->big_endian = true;
	ret->rclass = strdup("cfm");
	ret->has_va = true;
	return ret;
}

static RList *fields(RBinFile *bf) {
	RList *ret = r_list_newf((RListFree)free);
	#define ROW(nam, siz, val, fmt, cmt) \
		r_list_append (ret, r_bin_field_new (addr, addr, val, siz, nam, cmt, fmt, false));
	ut64 addr = 0;
	ROW("magic", 8, r_buf_read_be64_at(bf->buf, addr), "x", NULL); addr += 8;
	ROW("architecture", 4, r_buf_read_be32_at(bf->buf, addr), "x", NULL); addr += 4;
	ROW("formatVersion", 4, r_buf_read_be32_at(bf->buf, addr), "x", NULL); addr += 4;
	ROW("dateTimeStamp", 4, r_buf_read_be32_at(bf->buf, addr), "x", NULL); addr += 4;
	ROW("oldDefVersion", 4, r_buf_read_be32_at(bf->buf, addr), "x", NULL); addr += 4;
	ROW("oldImpVersion", 4, r_buf_read_be32_at(bf->buf, addr), "x", NULL); addr += 4;
	ROW("currentVersion", 4, r_buf_read_be32_at(bf->buf, addr), "x", NULL); addr += 4;
	ROW("sectionCount", 2, r_buf_read_be16_at(bf->buf, addr), "x", NULL); addr += 2;
	ROW("instSectionCount", 2, r_buf_read_be16_at(bf->buf, addr), "x", NULL); addr += 2;
	ROW("reserved", 2, r_buf_read_be16_at(bf->buf, addr), "x", NULL); addr += 2;
	return ret;
}

static ut64 size(RBinFile *bf) {
	RBinPEFObj *pef = bf->bo->bin_obj;
	ut64 s = 0;
	int i;
	for (i=0; i<pef->nsec; i++) {
		ut64 e = pef->sec[i].offset + pef->sec[i].lenDisk;
		if (s < e) s = e;
	}
	return s;
}

static RBinAddr *binsym(RBinFile *bf, int sym) {
	RBinPEFObj *pef = bf->bo->bin_obj;

	int n;
	if (sym == R_BIN_SYM_ENTRY || sym == R_BIN_SYM_MAIN) {
		n = 0;
	} else if (sym == R_BIN_SYM_INIT) {
		n = 1;
	} else if (sym == R_BIN_SYM_FINI) {
		n = 2;
	} else {
		return NULL;
	}

	ut32 sec = r_buf_read_be32_at(bf->buf, pef->ldrsec + n*8);
	ut32 offset = r_buf_read_be32_at(bf->buf, pef->ldrsec + n*8+4);
	if (sec < pef->nsec && offset < pef->sec[sec].addr+pef->sec[sec].lenTotal) {
		RBinAddr *ptr = R_NEW0(RBinAddr);
		ptr->vaddr = pef->sec[sec].addr + offset;
		return ptr;
	} else {
		return NULL;
	}
}

static RList *sections(RBinFile *bf) {
	RBinPEFObj *pef = bf->bo->bin_obj;
	RList *ret = r_list_newf((RListFree)r_bin_section_free);
	int i;

	for (i=0; i<pef->nsec; i++) {
		PEFSection *sec = &pef->sec[i];
		RBinSection *ptr = R_NEW0(RBinSection);
		ptr->is_segment = true;

		ptr->paddr = sec->offset;
		ptr->size = sec->lenDisk;
		ptr->vaddr = sec->addr;
		ptr->vsize = sec->lenTotal;

		ptr->type = strdup(
			sec->kind == 0 ? "text" :
			sec->kind == 1 ? "data" :
			sec->kind == 2 ? "pidata" :
			sec->kind == 3 ? "rodata" :
			sec->kind == 4 ? "loader" :
			"");
		ptr->name = strdup(ptr->type);
		ptr->is_data = sec->kind != 0;
		ptr->add = sec->kind != 4;
		ptr->perm =
			sec->kind == 0 ? R_PERM_RX : // text
			sec->kind == 1 ? R_PERM_RWX : // data
			sec->kind == 2 ? R_PERM_RWX : // pidata
			sec->kind == 3 ? R_PERM_R : // rodata
			sec->kind == 4 ? 0 : // loader
			R_PERM_RWX; // unknown

		if (sec->kind == 2) { // pidata, need to decompress
			char *muri = r_str_newf ("malloc://%"PFMT32u, sec->lenTotal); // gets zero-inited
			ptr->backing = r_io_open_nomap(bf->rbin->iob.io, muri, R_PERM_RW, 0);
			free(muri);
			if (ptr->backing != NULL) {
				r_io_desc_write(ptr->backing, sec->unpack, sec->lenUnpack);
			}

			ptr->paddr = 0;
			ptr->size = 0; // hide from R2, nothing good can come from it
		}

		r_list_append(ret, ptr);
	}
	return ret;
}

static RList *imports(RBinFile *bf) {
	RBinPEFObj *pef = bf->bo->bin_obj;
	ut32 importedLibraryCount = r_buf_read_be32_at(bf->buf, pef->ldrsec + 24);
	ut32 totalImportedSymbolCount = r_buf_read_be32_at(bf->buf, pef->ldrsec + 28);
	ut32 loaderStringsOffset = r_buf_read_be32_at(bf->buf, pef->ldrsec + 40);
	RBinImport **ary = R_NEWS(RBinImport *, totalImportedSymbolCount);
	int i, j;

	for (i=0; i<totalImportedSymbolCount; i++) {
		ary[i] = R_NEW0(RBinImport);
	}

	for (i=0; i<importedLibraryCount; i++) {
		ut32 at = pef->ldrsec + 56 + 24*i;
		ut32 libNamePtr = r_buf_read_be32_at(bf->buf, at);
		ut32 libSymCount = r_buf_read_be32_at(bf->buf, at + 12);
		ut32 firstSym = r_buf_read_be32_at(bf->buf, at + 16);

		for (j=firstSym; j<firstSym+libSymCount && j<totalImportedSymbolCount; j++) {
			at = pef->ldrsec + 56 + 24*importedLibraryCount + 4*j;
			ut8 kind = 0;
			r_buf_read_at(bf->buf, at, &kind, 1);
			ut32 symNamePtr = r_buf_read_be32_at(bf->buf, at) & 0xffffff;

			ary[j]->name = r_bin_name_new_from(r_buf_get_string(bf->buf, pef->ldrsec + loaderStringsOffset + symNamePtr));
			ary[j]->libname = r_buf_get_string(bf->buf, pef->ldrsec + loaderStringsOffset + libNamePtr);
			ary[j]->ordinal = j;
			ary[j]->type = class2string(kind);
			ary[j]->bind = (kind&0x80) ? R_BIN_BIND_WEAK_STR : R_BIN_BIND_GLOBAL_STR;
		}
	}

	RList *ret = r_list_newf((RListFree)r_bin_import_free);
	for (i=0; i<totalImportedSymbolCount; i++) {
		if (ary[i]->name != NULL) {
			r_list_append(ret, ary[i]);
		}
	}
	free(ary);
	return ret;
}

static RList *libs(RBinFile *bf) {
	RBinPEFObj *pef = bf->bo->bin_obj;
	RList *ret = r_list_newf((RListFree)free);
	ut32 importedLibraryCount = r_buf_read_be32_at(bf->buf, pef->ldrsec + 24);
	ut32 loaderStringsOffset = r_buf_read_be32_at(bf->buf, pef->ldrsec + 40);
	int i;

	for (i=0; i<importedLibraryCount; i++) {
		ut32 at = pef->ldrsec + 56 + 24*i;
		ut32 libNamePtr = r_buf_read_be32_at(bf->buf, at);
		char *name = r_buf_get_string(bf->buf, pef->ldrsec + loaderStringsOffset + libNamePtr);
		r_list_append(ret, name);
	}
	return ret;
}

void **flatlist(RList *list) {
	void **flat = R_NEWS(void *, r_list_length(list));
	RListIter *iter;
	void *ptr;
	size_t i = 0;
	r_list_foreach(list, iter, ptr) {
		flat[i++] = ptr;
	}
	return flat;
}

static RList *relocs(RBinFile *bf) {
	RBinPEFObj *pef = bf->bo->bin_obj;
	RList *ret = r_list_newf(free); // r_bin_reloc_free
	RList *importList = imports(bf); // Import linked-list
	void **importArray = flatlist(importList); // Indexable import list
	PEFReloc *r;
	RListIter *iter;
	int i;

	for (i=0; i<pef->nsec; i++) {
		r_list_foreach(pef->sec[i].relocs, iter, r) {
			RBinReloc *ptr = R_NEW0(RBinReloc);
			ptr->type = R_BIN_RELOC_32;
			ptr->additive = 1;
			ptr->vaddr = pef->sec[i].addr + r->offset;
			if (r->isimport) {
				if (r->target >= r_list_length(importList)) {
					free(ptr);
					continue;
				}
				ptr->import = r_bin_import_clone(importArray[r->target]);
			} else {
				if (r->target >= pef->nsec) {
					free(ptr);
					continue;
				}
				ptr->addend = pef->sec[r->target].addr;
			}
			r_list_append(ret, ptr);
		}
	}
	R_FREE(importArray);
	r_list_free(importList);
	return ret;
}

static RList *patch_relocs(RBinFile *bf) {
	RList *list = relocs(bf);
	RListIter *iter;
	RBinReloc *reloc;
	r_list_foreach(list, iter, reloc) {
		if (reloc->import) continue;
		RIOBind *b = &bf->rbin->iob;
		ut8 buf[4] = {};
		b->read_at(b->io, reloc->vaddr, buf, 4);
		r_write_be32(buf, r_read_be32(buf) + reloc->addend);
		b->overlay_write_at(b->io, reloc->vaddr, buf, 4);
	}
	return list;
}

static RList *symbols(RBinFile *bf) {
	RBinPEFObj *pef = bf->bo->bin_obj;
	RList *ret = r_list_newf((RListFree)r_bin_symbol_free);
	ut32 loaderStringsOffset = r_buf_read_be32_at(bf->buf, pef->ldrsec + 40);
	ut32 exportHashOffset = r_buf_read_be32_at(bf->buf, pef->ldrsec + 44);
	ut32 exportHashTablePower = r_buf_read_be32_at(bf->buf, pef->ldrsec + 48);
	ut32 exportedSymbolCount = r_buf_read_be32_at(bf->buf, pef->ldrsec + 52);
	ut32 stringLenTable = pef->ldrsec + exportHashOffset + (4<<exportHashTablePower);
	ut32 exportTable = stringLenTable + 4*exportedSymbolCount;
	int i;

	for (i=0; i<exportedSymbolCount; i++) {
		ut32 ofs = exportTable + 10*i;
		ut8 kind = 0;
		r_buf_read_at(bf->buf, ofs, &kind, 1);
		ut32 nameOfs = pef->ldrsec + loaderStringsOffset + (r_buf_read_be32_at(bf->buf, ofs) & 0xffffff);
		ut32 addr = r_buf_read_be32_at(bf->buf, ofs + 4);
		st16 index = r_buf_read_be16_at(bf->buf, ofs + 8);
		ut16 nameLen = r_buf_read_be16_at(bf->buf, stringLenTable + 4*i);
		if (index < 0 || index >= pef->nsec) continue; // re-exported func or absolute mem address, not supported

		RBinSymbol *ptr = R_NEW0(RBinSymbol);
		char *name = calloc(1, nameLen + 1);
		r_buf_read_at(bf->buf, nameOfs, (ut8*)name, nameLen);
		ptr->name = r_bin_name_new_from(name);
		ptr->vaddr = pef->sec[index].addr + addr;
		ptr->bind = R_BIN_BIND_GLOBAL_STR;
		ptr->type = class2string(kind);
		r_list_append(ret, ptr);
	}
	return ret;
}

static RList *entries(RBinFile *bf) {
	RBinPEFObj *pef = bf->bo->bin_obj;
	RList *ret = r_list_newf(free);
	static const int types[] = {
		R_BIN_ENTRY_TYPE_MAIN,
		R_BIN_ENTRY_TYPE_INIT,
		R_BIN_ENTRY_TYPE_FINI
	};
	int i;

	for (i=0; i<3; i++) {
		ut32 sec = r_buf_read_be32_at(bf->buf, pef->ldrsec + i*8);
		ut32 offset = r_buf_read_be32_at(bf->buf, pef->ldrsec + i*8+4);
		if (sec < pef->nsec && offset < pef->sec[sec].addr+pef->sec[sec].lenTotal) {
			RBinAddr *ptr = R_NEW0(RBinAddr);
			ptr->vaddr = pef->sec[sec].addr + offset;
			ptr->type = types[i];
			r_list_append(ret, ptr);
		}
	}
	return ret;
}

RBinPlugin r_bin_plugin_pef = {
	.meta = {
		.name = "pef",
		.author = "elliotnunn",
		.desc = "Vintage-Apple Preferred Executable Format bin plugin",
		.license = "LGPL-3.0-only",
	},
	.check = &check,
	.load = &load,
	.destroy = &destroy,
	.info = &info,
	.fields = &fields,
	.size = &size,
	.binsym = &binsym,
	.sections = &sections,
	.imports = &imports,
	.libs = &libs,
	.relocs = &relocs,
	.patch_relocs = &patch_relocs,
	.symbols = &symbols,
	.entries = &entries,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_pef,
	.version = R2_VERSION
};
#endif
