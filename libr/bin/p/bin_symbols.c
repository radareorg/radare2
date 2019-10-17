/* radare - LGPL - Copyright 2018 - pancake */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>
#include "../i/private.h"

// enable debugging messages
#define D if (0)

static bool is64 = false;
static ut64 dwordsBeginAt = UT64_MAX;
static ut64 stringsBeginAt = UT64_MAX;
static ut64 symbolsBeginAt = UT64_MAX;
// static ut64 symbolsCount = UT64_MAX;
static RList *globalSymbols = NULL;

#define SECTIONS_BEGIN 0x220
#define SEGMENTS_BEGIN 0x1b0

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

typedef struct symbols_metadata_t { // 0x40
	ut32 cputype;
	ut32 subtype;
	ut32 n_segments;
	ut32 namelen;
	ut32 name;
	bool valid;
	ut32 size;
	RList *segments;
	ut32 addr;
	int bits;
	const char *arch;
	const char *cpu;
} SymbolsMetadata;

// this is_segment concept is a bad idea imho
static RBinSection *newSection(const char *name, ut32 from, ut32 to, bool is_segment) {
	RBinSection *s = R_NEW0 (RBinSection);
	if (!s) {
		return NULL;
	}
	s->name = strdup (name);
	s->size = to - from + 1;
	s->vsize = s->size;
	s->paddr = from;
	s->vaddr = from;
	s->add = true;
	s->perm = strstr (name, "TEXT")? 5: 4;
	s->is_segment = is_segment;
	return s;
}

static RList *parseSegments(RBuffer *buf, int off, int count) {
	ut8 *b = calloc (count, 32);
	(void)r_buf_read_at (buf, off, b, count * 32);
	int x = off;
	int X = 0;
	int i;
	RList *segments = r_list_newf ((RListFree)r_bin_section_free);
	if (!segments) {
		return NULL;
	}
	// eprintf ("Segments: %d\n", count);
	for (i = 0; i < count; i++) {
		int A = r_read_le32 (b + X + 16);
		int B = r_read_le32 (b + X + 16 + 8);
		//	eprintf ("0x%08x  segment  0x%08x 0x%08x  %s\n",
		//		x, A, A + B, b + X);
		const char *cname = (const char *)(b + X);
		char *name = r_str_ndup (cname, r_str_nlen (cname, 16));
		RBinSection *section = newSection (name, A, A + B, true);
		free (name);
		r_list_append (segments, section);
		x += 32;
		X += 32;
	}
	return segments;
}

static const char *typeString(ut32 n, int *bits) {
	*bits = 32;
	if (n == 12) { // CPU_SUBTYPE_ARM_V7) {
		return "arm";
	}
	if (n == 0x0100000c) { // arm64
		*bits = 64;
		is64 = true;
		return "arm";
	}
	if (n == 0x0200000c) { // arm64-32
		//  TODO: must change bits
		is64 = false;
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
	sm.segments = parseSegments (buf, off + sm.namelen + delta, sm.n_segments);
	sm.size = (sm.n_segments * 32) + 120;

	// hack to detect format
	ut32 nm, nm2, nm3;
	r_buf_read_at (buf, off + sm.size, (ut8*)&nm, sizeof (nm));
	r_buf_read_at (buf, off + sm.size + 4, (ut8*)&nm2, sizeof (nm2));
	r_buf_read_at (buf, off + sm.size + 8, (ut8*)&nm3, sizeof (nm3));
	// eprintf ("0x%x next %x %x %x\n", off + sm.size, nm, nm2, nm3);
	if (r_read_le32 (&nm3) != 0xa1b22b1a) {
		sm.size -= 8;
		//		is64 = true;
	}
	return sm;
}

#define O(x, y) x.addr + r_offsetof (x, y)

static void printSymbolsHeader(SymbolsHeader sh) {
	// eprintf ("0x%08x  version  0x%x\n", 4, sh.version);
	eprintf ("0x%08x  uuid     ", 24);
	int i;
	for (i = 0; i < 16; i++) {
		eprintf ("%02x", sh.uuid[i]);
	}
	eprintf ("\n");
	// parse header
	// eprintf ("0x%08x  unknown  0x%x\n", 0x28, sh.unk0); //r_read_le32 (b+ 0x28));
	// eprintf ("0x%08x  unknown  0x%x\n", 0x2c, sh.unk1); //r_read_le16 (b+ 0x2c));
	// eprintf ("0x%08x  slotsize %d\n", 0x2e, sh.slotsize); // r_read_le16 (b+ 0x2e));
}

static RList *parseStrings(RBuffer *buf, int string_section, int string_section_end) {
	int sss = string_section_end + string_section;
	if (sss < 1) {
		return NULL;
	}
	char *b = calloc (1, sss);
	if (!b) {
		return NULL;
	}
	int o = 0;
	char *s = b;
	char *os = s;
	int nstrings = 0;

	int available = r_buf_read_at (buf, string_section, (ut8 *)b, sss);
	if (available != sss) {
		sss = available;
	}
	if (sss < 1) {
		eprintf ("Cannot read strings at 0x%08" PFMT64x "\n", (ut64)string_section);
		free (b);
		return NULL;
	}
	RList *res = r_list_newf ((RListFree)r_bin_string_free);
	int i;
	char *s_end = s + sss;
	for (i = 0; true; i++) {
		o = s - os;
		if (string_section + o + 8 > string_section_end) {
			break;
		}
		if (s + 4 > s_end) {
			break;
		}
		nstrings++;
		//	eprintf ("0x%08x  0x%08x %s\n", o + string_section, o, s);
		RBinString *bs = R_NEW0 (RBinString);
		if (!bs) {
			break;
		}
		bs->string = strdup (s);
		// eprintf ("%s\n", s);
		bs->vaddr = o + string_section;
		bs->paddr = o + string_section;
		bs->ordinal = i;
		bs->length = strlen (s);
		r_list_append (res, bs);
		s += bs->length + 1;
	}
	free (b);
	return res;
}

typedef struct symbols_dragons_t {
	int foo;
	ut32 addr;
	ut32 size;
	ut32 n_sections;
	ut32 n_segments;
	ut32 n_symbols;
} SymbolsDragons;

static SymbolsDragons parseDragons(RBuffer *buf, int off, int bits) {
	SymbolsDragons sd = { 0 };
	sd.addr = off;
	sd.size = 1;
	D eprintf ("Dragons at 0x%x\n", off);
	const int size = r_buf_size (buf) - off;
	if (size < 1) {
		return sd;
	}
	ut8 *b = malloc (size);
	if (!b) {
		return sd;
	}
	int available = r_buf_read_at (buf, off, b, size);
	if (available != size) {
		eprintf ("Warning: r_buf_read_at failed\n");
		return sd;
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
			return sd;
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
	sd.n_segments = r_read_le32 (b + 24);
	sd.n_sections = r_read_le32 (b + 28);
	parseSegments (buf, SEGMENTS_BEGIN, sd.n_segments);

	sd.n_symbols = r_read_le32 (b + 0x20); // depends on nsections
	if (sd.n_symbols > 1024 * 1024) {
		eprintf ("Warning: too many symbols %d, truncated to 2048\n", sd.n_symbols);
		sd.n_symbols = 2048;
	}
	sd.addr = off;
	sd.size = 0x70 - 8; // SEGMENTS_BEGIN - off;
	sd.size += sd.n_segments * 32;
	if (is64) {
		sd.size += sd.n_sections * 24;
	} else {
		sd.size += sd.n_sections * 16;
	}
	free (b);
	return sd;
}

static RBinSymbol *newSymbol(RBinString *s, ut64 addr, ut64 size) {
	RBinSymbol *sym = R_NEW0 (RBinSymbol);
	if (sym) {
		sym->name = s? s->string: NULL;
		sym->paddr = addr;
		sym->vaddr = addr;
		sym->size = size;
		sym->type = R_BIN_TYPE_FUNC_STR;
		sym->bind = "NONE";
	}
	return sym;
}

static RList *parseSections(RBuffer *b, int x, int n_sections, RList *strings) {
	// eprintf ("Sections\n");
	int buf_sz = r_buf_size (b);
	char *buf = malloc (buf_sz);
	if (!buf) {
		return NULL;
	}
	bool must_free = false;
	if (!strings) {
		strings = parseStrings (b, stringsBeginAt, buf_sz);
		if (strings) {
			must_free = true;
		}
	}
	// hack
	r_buf_read_at (b, x, (ut8 *)buf, 4);
	if (buf[0] == '_') {
		x += 16;
	}
	RList *res = r_list_newf ((RListFree)r_bin_section_free);
	int i;
	r_buf_read_at (b, x, (ut8 *)buf, buf_sz);
	int off = 0;
	for (i = 0; i < n_sections; i++) {
		off = i * 16;
		if (off + 8 >= buf_sz) {
			break;
		}
		RBinString *name = strings? r_list_get_n (strings, i): NULL;
		const char *namestr = name? name->string: "";
		ut32 A = r_read_le32 (buf + off);
		ut32 B = r_read_le32 (buf + off + 4);
		//ut32 C = r_read_le32 (buf + off + 8);
		// ut32 D = r_read_le32 (buf + off + 12);
		// eprintf ("0x%08"PFMT64x"  addr=0x%08x size=0x%08x unk=0x%08x zero=0x%08x  %s\n",
		//	(ut64)x + i + off, A, B, C, D, namestr);
		RBinSection *section = newSection (namestr, A, A + B, 0);
		r_list_append (res, section);
	}
	if (must_free) {
		r_list_free (strings);
	}
	free (buf);
	return res;
}

static RList *parseSymbols(RBuffer *buf, int x, ut64 *eof, int count) {
	// eprintf ("Symbols\n");
	const int structSize = 24; // is64? 24: 24;
	if (eof) {
		*eof = x + (count * structSize);
	}
	//eprintf ("symbols table2 count %d\n", count);
	ut8 *b = calloc (structSize, count);
	if (!b) {
		return NULL;
	}
	RList *symbols = r_list_newf (r_bin_symbol_free);
	r_buf_read_at (buf, x, b, count * structSize);
	int i;
	for (i = 0; i < count; i++) {
		int n = (i * structSize);
		const ut32 A = r_read_le32 (b + n); // offset in memory
		const ut32 B = r_read_le32 (b + n + 4); // size of the symbol
		// const ut32 C = r_read_le32 (b + n + 8); // magic number 334e4051 3ce4102 34e4020 34e4000 ...
		// const ut32 D = r_read_le32 (b + n + 12);
		// const ut32 E = r_read_le32 (b + n + 16);
		// int d = D - E;
		// eprintf ("0x%08"PFMT64x" %3d addr=0x%x size=%4d magic=0x%x %d %d d=%d\n",
		//		(ut64) n + x, i, A, B, C, D, E, d);
		r_list_append (symbols, newSymbol (NULL, A, B));
	}
	// eprintf ("0x%x\n", end_offset);
	free (b);
	return symbols;
}

static RList *filterSymbolStrings(RList *strings, int n_sections) {
	RListIter *iter;
	RBinString *s;
	RList *list = r_list_newf (NULL);
	r_list_foreach (strings, iter, s) {
		if (*s->string != '_' && !strstr (s->string, "$$")) {
			continue;
		}
		if (strchr (s->string, ' ')) {
			continue;
		}
		r_list_append (list, newSymbol (s, 0, 0));
	}
	return list;
}

// unknown data in this range
// are those relocs or references?
static void parseTable3(RBuffer *buf, int x) {
	// 0x1648 - 0x1c80
	const int dword_section = dwordsBeginAt;
	int dword_section_end = stringsBeginAt;
	int i, size = dword_section_end - dword_section;
	int min = -1;
	int max = -1;
	// eprintf ("table3 is buggy\n");
	ut8 *b = calloc (size, 1);
	if (!b) {
		return;
	}
	r_buf_read_at (buf, x, b, size);
	for (i = 0; i < size; i += 8) {
		// int o = i + dword_section;
		if (i + 4 >= size) {
			eprintf ("..skip..\n");
			continue;
		}
		int v = r_read_le32 (b + i);
		// int w = r_read_le32 (b + i + 4);
		// eprintf ("0x%08x  0x%x\t0x%x = %d\n", o, v, w, v - w);
		if (min == -1 || v < min) {
			min = v;
		}
		if (max == -1 || v > max) {
			max = v;
		}
	}
	free (b);
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
	printSymbolsHeader (sh);

	// 0x40 - contain list of segments
	SymbolsMetadata sm = parseMetadata (buf, 0x40);

	// 0x138 - 0x220        // unknown information + duplicated list of segments
	SymbolsDragons sd = parseDragons (buf, sm.addr + sm.size, sm.bits);
	// eprintf ("sections: %d\n", sd.n_sections);
	// 0x220 - 0x3a0        // table of sections

	// 0x3a0 - 0x1648       // table of dwords with -1
	// XXX this is hacky, do not hardcode
	symbolsBeginAt = sd.addr + sd.size; // is64? 0x458: 0x3a0;
	D eprintf ("Symbols at 0x%08x\n", (ut32)symbolsBeginAt);
	RList *symbols = parseSymbols (buf, symbolsBeginAt, &dwordsBeginAt, sd.n_symbols);
	D eprintf ("Dwords at 0x%08x\n", (ut32)dwordsBeginAt);
	stringsBeginAt = dwordsBeginAt + (sd.n_symbols * 8);
	D eprintf ("Strings at 0x%08x\n", (ut32)stringsBeginAt);

	// 0x1648 - 0x1c80      // table of dword pairs (unknown data)
	parseTable3 (buf, dwordsBeginAt);

	// 0x1c80 - EOF         // strings
	RList *strings = parseStrings (buf, stringsBeginAt, stringsBeginAt + r_buf_size (buf));
	// RList *secs = parseSections (buf, SECTIONS_BEGIN, sd.n_sections, strings);
	// r_list_free (secs);
	if (strings) {
		RList *symbolStrings = filterSymbolStrings (strings, sd.n_sections);
		//	eprintf ("Count strings: %d\n", r_list_length (strings));
		//	eprintf ("Symbol strings: %d\n", r_list_length (symbolStrings));
		// name the symbols
		RListIter *iter;
		RBinSymbol *sym;
		int n = 0; // sections count
		r_list_foreach (symbols, iter, sym) {
			int m = n + sd.n_sections;
			RBinString *bs = r_list_get_n (symbolStrings, m);
			if (bs) {
				sym->name = strdup (bs->string);
			} else {
				sym->name = r_str_newf ("__unnamed_%d", n);
			}
			sym->ordinal = n;
			n++;
		}
		r_list_free (strings);
		r_list_free (symbolStrings);
		globalSymbols = symbols;
	}
	return true;
}

static RList *sections(RBinFile *bf) {
	SymbolsMetadata sm = parseMetadata (bf->buf, 0x40);
	SymbolsDragons sd = parseDragons (bf->buf, sm.addr + sm.size, sm.bits);
	RList *sections = parseSections (bf->buf, SECTIONS_BEGIN - 0x18, sd.n_sections, NULL);
	RList *res = r_list_newf ((RListFree)r_bin_section_free);
	RListIter *iter;
	RBinSection *s;
	r_list_foreach (sm.segments, iter, s) {
		r_list_append (res, s);
	}
	r_list_foreach (sections, iter, s) {
		r_list_append (res, s);
	}
	r_list_free (sections);
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
	ret->arch = sm.arch? strdup (sm.arch): NULL;
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

static RList *strings(RBinFile *bf) {
	RListIter *iter;
	RList *list = r_list_newf (NULL);
	RList *strings = parseStrings (bf->buf, stringsBeginAt, r_buf_size (bf->buf));
	RBinString *s;
	// TODO do proper filter strings vs symbol filter string
	r_list_foreach (strings, iter, s) {
		if (*s->string != '_') {
			r_list_append (list, s);
		}
	}
	return list;
}

static RList *symbols(RBinFile *bf) {
	return globalSymbols;
}

static ut64 size(RBinFile *bf) {
	return UT64_MAX;
}

RBinPlugin r_bin_plugin_symbols = {
	.name = "symbols",
	.desc = "Apple Symbols file",
	.license = "MIT",
	.load_buffer = &load_buffer,
	.check_buffer = &check_buffer,
	.symbols = &symbols,
	.sections = &sections,
	.strings = strings,
	.size = &size,
	.baddr = &baddr,
	.info = &info,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_symbols,
	.version = R2_VERSION
};
#endif
