/* radare - LGPL - Copyright 2018 - pancake */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>
#include <ht_uu.h>
#include "../i/private.h"
#include "mach0/coresymbolication.h"

// enable debugging messages
#define D if (0)
#define R_UUID_LENGTH 33

typedef struct symbols_header_t {
	ut32 magic;
	ut32 version;
	ut8 uuid[16];
	ut32 unk0;
	ut32 unk1;
	ut32 slotsize;
	ut32 addr;
	bool valid;
	int size;
} SymbolsHeader;

typedef struct symbols_metadata_t { // 0x40
	ut32 cputype;
	ut32 subtype;
	ut32 n_segments;
	ut32 namelen;
	ut32 name;
	bool valid;
	ut32 size;
	//RList *segments;
	ut32 addr;
	int bits;
	const char *arch;
	const char *cpu;
} SymbolsMetadata;

// header starts at offset 0 and ends at offset 0x40
static SymbolsHeader parseHeader(RBuffer *buf) {
	ut8 b[64];
	SymbolsHeader sh = { 0 };
	(void)r_buf_read_at (buf, 0, b, sizeof (b));
	sh.magic = r_read_le32 (b);
	sh.version = r_read_le32 (b + 4);
	sh.valid = sh.magic == 0xff01ff02;
	int i;
	for (i = 0; i < 16; i++) {
		sh.uuid[i] = b[24 + i];
	}
	sh.unk0 = r_read_le16 (b + 0x28);
	sh.unk1 = r_read_le16 (b + 0x2c); // is slotsize + 1 :?
	sh.slotsize = r_read_le16 (b + 0x2e);
	sh.size = 0x40;
	return sh;
}

static const char *typeString(ut32 n, int *bits) {
	*bits = 32;
	if (n == 12) { // CPU_SUBTYPE_ARM_V7) {
		return "arm";
	}
	if (n == 0x0100000c) { // arm64
		*bits = 64;
		return "arm";
	}
	if (n == 0x0200000c) { // arm64-32
		//  TODO: must change bits
		*bits = 64;
		return "arm";
	}
	return "x86";
}

static const char *subtypeString(int n) {
	if (n == 9) { // CPU_SUBTYPE_ARM_V7) {
		return "armv7";
	}
	return "?";
}

// metadata section starts at offset 0x40 and ends around 0xb0 depending on filenamelength
static SymbolsMetadata parseMetadata(RBuffer *buf, int off) {
	SymbolsMetadata sm = { 0 };
	ut8 b[0x100] = { 0 };
	(void)r_buf_read_at (buf, off, b, sizeof (b));
	sm.addr = off;
	sm.cputype = r_read_le32 (b);
	sm.arch = typeString (sm.cputype, &sm.bits);
	//  eprintf ("0x%08x  cputype  0x%x -> %s\n", 0x40, sm.cputype, typeString (sm.cputype));
	// bits = (strstr (typeString (sm.cputype, &sm.bits), "64"))? 64: 32;
	sm.subtype = r_read_le32 (b + 4);
	sm.cpu = subtypeString (sm.subtype);
	//  eprintf ("0x%08x  subtype  0x%x -> %s\n", 0x44, sm.subtype, subtypeString (sm.subtype));
	sm.n_segments = r_read_le32 (b + 8);
	// int count = r_read_le32 (b + 0x48);
	sm.namelen = r_read_le32 (b + 0xc);
	// eprintf ("0x%08x  count    %d\n", 0x48, count);
	// eprintf ("0x%08x  strlen   %d\n", 0x4c, sm.namelen);
	// eprintf ("0x%08x  filename %s\n", 0x50, b + 16);
	int delta = 16;
	//sm.segments = parseSegments (buf, off + sm.namelen + delta, sm.n_segments);
	sm.size = (sm.n_segments * 32) + sm.namelen + delta;

	// hack to detect format
	ut32 nm, nm2, nm3;
	r_buf_read_at (buf, off + sm.size, (ut8 *)&nm, sizeof (nm));
	r_buf_read_at (buf, off + sm.size + 4, (ut8 *)&nm2, sizeof (nm2));
	r_buf_read_at (buf, off + sm.size + 8, (ut8 *)&nm3, sizeof (nm3));
	// eprintf ("0x%x next %x %x %x\n", off + sm.size, nm, nm2, nm3);
	if (r_read_le32 (&nm3) != 0xa1b22b1a) {
		sm.size -= 8;
		//		is64 = true;
	}
	return sm;
}

static RBinSection *bin_section_from_section(RCoreSymCacheElementSection *sect) {
	if (!sect->name) {
		return NULL;
	}
	RBinSection *s = R_NEW0 (RBinSection);
	if (!s) {
		return NULL;
	}
	s->name = r_str_ndup (sect->name, 256);
	s->size = sect->size;
	s->vsize = s->size;
	s->paddr = sect->paddr;
	s->vaddr = sect->vaddr;
	s->add = true;
	s->perm = strstr (s->name, "TEXT") ? 5 : 4;
	s->is_segment = false;
	return s;
}

static RBinSection *bin_section_from_segment(RCoreSymCacheElementSegment *seg) {
	if (!seg->name) {
		return NULL;
	}
	RBinSection *s = R_NEW0 (RBinSection);
	if (!s) {
		return NULL;
	}
	s->name = r_str_ndup (seg->name, 16);
	s->size = seg->size;
	s->vsize = seg->vsize;
	s->paddr = seg->paddr;
	s->vaddr = seg->vaddr;
	s->add = true;
	s->perm = strstr (s->name, "TEXT") ? 5 : 4;
	s->is_segment = true;
	return s;
}

static RBinSymbol *bin_symbol_from_symbol(RCoreSymCacheElement *element, RCoreSymCacheElementSymbol *s) {
	if (!s->name && !s->mangled_name) {
		return NULL;
	}
	RBinSymbol *sym = R_NEW0 (RBinSymbol);
	if (sym) {
		if (s->name && s->mangled_name) {
			sym->dname = strdup (s->name);
			sym->name = strdup (s->mangled_name);
		} else if (s->name) {
			sym->name = strdup (s->name);
		} else if (s->mangled_name) {
			sym->name = s->mangled_name;
		}
		sym->paddr = s->paddr;
		sym->vaddr = r_coresym_cache_element_pa2va (element, s->paddr);
		sym->size = s->size;
		sym->type = R_BIN_TYPE_FUNC_STR;
		sym->bind = "NONE";
	}
	return sym;
}

static RCoreSymCacheElement *parseDragons(RBinFile *bf, RBuffer *buf, int off, int bits, R_OWN char *file_name) {
	D eprintf ("Dragons at 0x%x\n", off);
	ut64 size = r_buf_size (buf);
	if (off >= size) {
		return NULL;
	}
	size -= off;
	if (!size) {
		return NULL;
	}
	ut8 *b = malloc (size);
	if (!b) {
		return NULL;
	}
	int available = r_buf_read_at (buf, off, b, size);
	if (available != size) {
		eprintf ("Warning: r_buf_read_at failed\n");
		return NULL;
	}
#if 0
	// after the list of sections, there's a bunch of unknown
	// data, brobably dwords, and then the same section list again
	// this function aims to parse it.
	0x00000138 |1a2b b2a1 0300 0000 1a2b b2a1 e055 0000| .+.......+...U..
                         n_segments ----.          .--- how many sections ?
	0x00000148 |0100 0000 ca55 0000 0400 0000 1800 0000| .....U..........
	             .---- how many symbols? 0xc7
	0x00000158 |c700 0000 0000 0000 0000 0000 0104 0000| ................
	0x00000168 |250b e803 0000 0100 0000 0000 bd55 0000| %............U..
	0x00000178 |91bb e903 e35a b42c 93a4 340a 8746 9489| .....Z.,..4..F..
	0x00000188 |0cea 4c40 0c00 0000 0900 0000 0000 0000| ..L@............
	0x00000198 |0000 0000 0000 0000 0000 0000 0000 0000| ................
	0x000001a8 |0080 0000 0000 0000 5f5f 5445 5854 0000| ........__TEXT..
	0x000001b8 |0000 0000 0000 0000 0080 0000 0000 0000| ................
	0x000001c8 |0040 0000 0000 0000 5f5f 4441 5441 0000| .@......__DATA..
	0x000001d8 |0000 0000 0000 0000 00c0 0000 0000 0000| ................
	0x000001e8 |0000 0100 0000 0000 5f5f 4c4c 564d 0000| ........__LLVM..
	0x000001f8 |0000 0000 0000 0000 00c0 0100 0000 0000| ................
	0x00000208 |00c0 0000 0000 0000 5f5f 4c49 4e4b 4544| ........__LINKED
	0x00000218 |4954 0000 0000 0000 0000 0000 d069 0000| IT...........i..
#endif
	// eprintf ("Dragon's magic:\n");
	int magicCombo = 0;
	if (!memcmp ("\x1a\x2b\xb2\xa1", b, 4)) { // 0x130  ?
		magicCombo++;
	}
	if (!memcmp ("\x1a\x2b\xb2\xa1", b + 8, 4)) {
		magicCombo++;
	}
	if (magicCombo != 2) {
		// hack for C22F7494
		available = r_buf_read_at (buf, off - 8, b, size);
		if (available != size) {
			eprintf ("Warning: r_buf_read_at failed\n");
			return NULL;
		}
		if (!memcmp ("\x1a\x2b\xb2\xa1", b, 4)) { // 0x130  ?
			off -= 8;
		} else {
			eprintf ("0x%08x  parsing error: invalid magic retry\n", off);
		}
	}
	D eprintf ("0x%08x  magic  OK\n", off);
	D {
		const int e0ss = r_read_le32 (b + 12);
		eprintf ("0x%08x  eoss   0x%x\n", off + 12, e0ss);
	}
	free (b);
	return r_coresym_cache_element_new (bf, buf, off + 16, bits, file_name);
}

static bool load_buffer(RBinFile *bf, void **bin_obj, RBuffer *buf, ut64 loadaddr, Sdb *sdb) {
#if 0
	SYMBOLS HEADER

 0	MAGIC	02ff01ff
 4	VERSION 1 (little endian)
 8      ffffffff
16      002b0000 01000000 { 0x2b00, 0x0000 }
24	UUID    16 bytes
40	2621 d85b 2100 2000 0000 0000 0000 0000
56	ffff ffff ffff ff7f 0c00 0000 0900 0000
72	0400 0000 6800 0000 2f76 6172 2f66 6f6c .... 4, 104 /// 104 length string
184
0x000000b8  5f5f 5445 5854 0000 0000 0000 0000 0000 0000 0000 0000 0000 0080 0000 0000 0000  __TEXT..........................
0x000000d8  5f5f 4441 5441 0000 0000 0000 0000 0000 0080 0000 0000 0000 0040 0000 0000 0000  __DATA...................@......
0x000000f8  5f5f 4c4c 564d 0000 0000 0000 0000 0000 00c0 0000 0000 0000 0000 0100 0000 0000  __LLVM..........................
0x00000118  5f5f 4c49 4e4b 4544 4954 0000 0000 0000 00c0 0100 0000 0000 00c0 0000 0000 0000  __LINKEDIT......................

#endif
	// 0 - magic check, version ...
	SymbolsHeader sh = parseHeader (buf);
	if (!sh.valid) {
		eprintf ("Invalid headers\n");
		return false;
	}
	SymbolsMetadata sm = parseMetadata (buf, 0x40);
	char * file_name = NULL;
	if (sm.namelen) {
		file_name = calloc (sm.namelen + 1, 1);
		if (!file_name) {
			return false;
		}
		if (r_buf_read_at (buf, 0x50, (ut8*)file_name, sm.namelen) != sm.namelen) {
			return false;
		}
	}
	RCoreSymCacheElement *element = parseDragons (bf, buf, sm.addr + sm.size, sm.bits, file_name);
	if (element) {
		*bin_obj = element;
		return true;
	}
	free (file_name);
	return false;
}

static RList *sections(RBinFile *bf) {
	RList *res = r_list_newf ((RListFree)r_bin_section_free);
	r_return_val_if_fail (res && bf->o && bf->o->bin_obj, res);
	RCoreSymCacheElement *element = bf->o->bin_obj;
	size_t i;
	for (i = 0; i < element->hdr->n_segments; i++) {
		RCoreSymCacheElementSegment *seg = &element->segments[i];
		RBinSection *s = bin_section_from_segment (seg);
		if (s) {
			r_list_append (res, s);
		}
	}
	for (i = 0; i < element->hdr->n_sections; i++) {
		RCoreSymCacheElementSection *sect = &element->sections[i];
		RBinSection *s = bin_section_from_section (sect);
		if (s) {
			r_list_append (res, s);
		}
	}
	return res;
}

static ut64 baddr(RBinFile *bf) {
	return 0LL;
}

static RBinInfo *info(RBinFile *bf) {
	SymbolsMetadata sm = parseMetadata (bf->buf, 0x40);
	RBinInfo *ret = R_NEW0 (RBinInfo);
	if (!ret) {
		return NULL;
	}
	ret->file = strdup (bf->file);
	ret->bclass = strdup ("symbols");
	ret->os = strdup ("unknown");
	ret->arch = sm.arch ? strdup (sm.arch) : NULL;
	ret->bits = sm.bits;
	ret->type = strdup ("Symbols file");
	ret->subsystem = strdup ("llvm");
	ret->has_va = true;

	return ret;
}

static bool check_buffer(RBuffer *b) {
	ut8 buf[4];
	r_buf_read_at (b, 0, buf, sizeof (buf));
	return !memcmp (buf, "\x02\xff\x01\xff", 4);
}

static RList *symbols(RBinFile *bf) {
	RList *res = r_list_newf ((RListFree)r_bin_symbol_free);
	r_return_val_if_fail (res && bf->o && bf->o->bin_obj, res);
	RCoreSymCacheElement *element = bf->o->bin_obj;
	size_t i;
	HtUU *hash = ht_uu_new0 ();
	if (!hash) {
		return res;
	}
	bool found = false;
	for (i = 0; i < element->hdr->n_lined_symbols; i++) {
		RCoreSymCacheElementSymbol *sym = (RCoreSymCacheElementSymbol *)&element->lined_symbols[i];
		ht_uu_find (hash, sym->paddr, &found);
		if (found) {
			continue;
		}
		RBinSymbol *s = bin_symbol_from_symbol (element, sym);
		if (s) {
			r_list_append (res, s);
			ht_uu_insert (hash, sym->paddr, 1);
		}
	}
	for (i = 0; i < element->hdr->n_symbols; i++) {
		RCoreSymCacheElementSymbol *sym = &element->symbols[i];
		ht_uu_find (hash, sym->paddr, &found);
		if (found) {
			continue;
		}
		RBinSymbol *s = bin_symbol_from_symbol (element, sym);
		if (s) {
			r_list_append (res, s);
		}
	}
	ht_uu_free (hash);
	return res;
}

static ut64 size(RBinFile *bf) {
	return UT64_MAX;
}

static void destroy(RBinFile *bf) {
	r_coresym_cache_element_free (bf->o->bin_obj);
}

static void header(RBinFile *bf) {
	r_return_if_fail (bf && bf->o);

	RCoreSymCacheElement *element = bf->o->bin_obj;
	if (!element) {
		return;
	}

	RBin *bin = bf->rbin;
	PrintfCallback p = bin->cb_printf;
	PJ *pj = pj_new ();
	if (!pj) {
		return;
	}

	pj_o (pj);
	pj_kn (pj, "cs_version", element->hdr->version);
	pj_kn (pj, "size", element->hdr->size);
	if (element->file_name) {
		pj_ks (pj, "name", element->file_name);
	}
	if (element->binary_version) {
		pj_ks (pj, "version", element->binary_version);
	}
	char uuidstr[R_UUID_LENGTH];
	r_hex_bin2str (element->hdr->uuid, 16, uuidstr);
	pj_ks (pj, "uuid", uuidstr);
	pj_kn (pj, "segments", element->hdr->n_segments);
	pj_kn (pj, "sections", element->hdr->n_sections);
	pj_kn (pj, "symbols", element->hdr->n_symbols);
	pj_kn (pj, "lined_symbols", element->hdr->n_lined_symbols);
	pj_kn (pj, "line_info", element->hdr->n_line_info);
	pj_end (pj);

	p ("%s\n", pj_string (pj));
	pj_free (pj);
}

RBinPlugin r_bin_plugin_symbols = {
	.name = "symbols",
	.desc = "Apple Symbols file",
	.license = "MIT",
	.load_buffer = &load_buffer,
	.check_buffer = &check_buffer,
	.symbols = &symbols,
	.sections = &sections,
	.size = &size,
	.baddr = &baddr,
	.info = &info,
	.header = &header,
	.destroy = &destroy,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_symbols,
	.version = R2_VERSION
};
#endif
