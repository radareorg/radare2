/* radare - LGPL - Copyright 2018 - pancake */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>
#include "../i/private.h"

static int bits = 32;
static ut64 dwordsBeginAt = UT64_MAX;
static ut64 stringsBeginAt = UT64_MAX;
static ut64 symbolsCount = UT64_MAX;

// seems to be always the same
#define SECTIONS_BEGIN 0x220

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
	ut32 n_sections;
	ut32 namelen;
	ut32 name;
	// array with section names?
	bool valid;
	ut32 size;
	RList *sections;
	ut32 addr;
	int bits;
	const char *arch;
	const char *cpu;
} SymbolsMetadata;

static RBinSection *newSection(const char *name, ut64 from, ut64 to) {
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
	s->perm = strstr (name, "TEXT")? 5: 6;
	return s;
}

static RList *parseSegments(RBuffer *buf, int off, int count) {
	ut8 b[0x2000] = { 0 };
	(void)r_buf_read_at (buf, off, b, sizeof (b)); // hardcoded buffers sucks
	int x = off;
	int X = 0;
	int i;
	RList *sections = r_list_newf ((RListFree)r_bin_section_free);
	if (!sections) {
		return NULL;
	}
	for (i = 0; i < count; i++) {
		int A = r_read_le32 (b + X + 16);
		int B = r_read_le32 (b + X + 16 + 8);
		eprintf ("0x%08x  section  0x%08x 0x%08x  %s\n",
			x, A, A + B, b + X);
		r_list_append (sections, newSection ((const char *)b + X, A, A + B));
		x += 32;
		X += 32;
	}
	eprintf ("\n");
	return sections;
}

static const char *typeString(int n) {
	if (n == 12) { // CPU_SUBTYPE_ARM_V7) {
		return "arm";
	}
	if (n == 0x0100000c) { // arm64
		return "arm64";
	}
	return "?";
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
	sm.arch = typeString(sm.cputype);
	//  eprintf ("0x%08x  cputype  0x%x -> %s\n", 0x40, sm.cputype, typeString (sm.cputype));
	bits = sm.bits = (strstr (typeString (sm.cputype), "64"))? 64: 32;
	sm.subtype = r_read_le32 (b + 4);
	sm.cpu = subtypeString (sm.subtype);
	//  eprintf ("0x%08x  subtype  0x%x -> %s\n", 0x44, sm.subtype, subtypeString (sm.subtype));
	sm.n_sections = r_read_le32 (b + 8);
	// int count = r_read_le32 (b + 0x48);
	sm.namelen = r_read_le32 (b + 0xc);
	// eprintf ("0x%08x  count    %d\n", 0x48, count);
	// eprintf ("0x%08x  strlen   %d\n", 0x4c, sm.namelen);
	// eprintf ("0x%08x  filename %s\n", 0x50, b + 16);
	int delta = 16;
	if (bits==64) {
		// delta = 0;
	}
	sm.sections = parseSegments (buf,
		off + sm.namelen + delta, sm.n_sections);
	sm.size = (sm.n_sections * 32) + 120;
	if (bits == 64) {
		sm.size -= 8;
	}
	return sm;
}

#define O(x, y) x.addr + r_offsetof (x, y)

static void printLine(const char *name, ut32 addr, ut32 value) {
	eprintf ("0x%08x  %s    0x%x\n", addr, name, value);
}

static void printSymbolsHeader(SymbolsHeader sh) {
	printLine ("magic", 0, sh.magic);
	eprintf ("0x%08x  version  0x%x\n", 4, sh.version);
	eprintf ("0x%08x  uuid     ", 24);
	int i;
	for (i = 0; i < 16; i++) {
		eprintf ("%02x", sh.uuid[i]);
	}
	eprintf ("\n");
	//  parse header
	// eprintf ("0x%08x  unknown  0x%x\n", 0x28, sh.unk0); //r_read_le32 (b+ 0x28));
	// eprintf ("0x%08x  unknown  0x%x\n", 0x2c, sh.unk1); //r_read_le16 (b+ 0x2c));
	// eprintf ("0x%08x  slotsize %d\n", 0x2e, sh.slotsize); // r_read_le16 (b+ 0x2e));
}

static RList *parseStrings(RBuffer *buf, int string_section, int string_section_end) {
	ut64 string_section_size = string_section_end + string_section;
	char *b = calloc (1, string_section_size);
	if (!b) {
		return NULL;
	}
	int o = 0;
	char *s = b;
	char *os = s;
	int nstrings = 0;

	int available = r_buf_read_at (buf, string_section, (ut8*)b, string_section_size);
	if (available != string_section_size) {
		string_section_size = available;
	}
	if (string_section_size < 1) {
		eprintf ("Cannot read strings at 0x%08"PFMT64x"\n", (ut64)string_section);
		free (b);
		return  NULL;
	}
	RList *res = r_list_newf ((RListFree)r_bin_string_free);
	int i;
	for (i = 0; true; i++) {
		o = s - os;
		if (string_section + o + 8 > string_section_end) {
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
} SymbolsDragons;

static SymbolsDragons parseDragons(RBuffer *buf, int off, int bits) {
	SymbolsDragons sd = { 0 };
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
	eprintf ("Dragon's magic:\n");
	if (!memcmp ("\x1a\x2b\xb2\xa1", b, 4)) {
		eprintf ("0x%08x  magic  OK\n", off);
	} else {
		eprintf ("0x%08x  parsing error: invalid magic\n", off);
	}
	const int number = r_read_le32 (b + 4); // [4] = 3
	eprintf ("0x%08x  number 0x%x\n", off + 4, number); // [8] = number
	if (!memcmp ("\x1a\x2b\xb2\xa1", b + 8, 4)) {
		eprintf ("0x%08x  magic  OK\n", off + 8);
	} else {
		eprintf ("0x%08x  parsing error: invalid magic\n", off + 8);
	}
	const int e0ss = r_read_le32 (b + 12);
	eprintf ("0x%08x  eoss   0x%x\n", off + 12, e0ss);

	sd.n_sections = r_read_le32 (b + 24); // x + 0x20); // 0xc7;
	// TODO: reuse the parseSegments code here. parseSegments (buf, 0x224);
	eprintf ("\nDragon sections %d:\n", sd.n_sections);
	int address = 0x1b0;
	if (bits == 64) {
		address -= 8;
	}
	parseSegments (buf, address, sd.n_sections);
	
	symbolsCount = r_read_le32 (b + 0x20); // depends on nsections
	eprintf ("Symbols Count %d\n", (int)symbolsCount);
#if 0
	const int rray_section = 0x1ab0; // 0x00000224; //  XXX hardcoded offset
	const int rray_section_end = rray_section + (count * 12); //  XXX hardcoded offset
	int i;
	for (i = 0; i < count; i++) {
		//	int n = rray_section + (i * 12);
		int n = (i * 12);
		const ut32 A = r_read_le32 (b + n);
		const ut32 B = r_read_le32 (b + n + 4);
		const ut32 C = r_read_le32 (b + n + 8);
		eprintf ("%3d: 0x%08" PFMT64x " 0x%08x %4d 0x%08x\n",
			i, off + n+ n, A, B, C);
		x = n;
	}
	eprintf ("%d\n", x);
#endif
	free (b);
	return sd;
}

static RBinSymbol *newSymbol (RBinString *s) {
	RBinSymbol *sym = R_NEW0 (RBinSymbol);
	if (sym) {
		sym->name = s->string;
	}
	return sym;
}

static void parseSections(RBuffer *b, int x) {
	int i, x_end = 0x3a0; // XXX hardcoded x_end
	char *buf = malloc (r_buf_size (b));
	if (!buf) {
		return;
	}
	RList *strings = parseStrings (b, stringsBeginAt, r_buf_size (b)); // XXX hardcoded offset + size
	RListIter *iter;
	RBinString *s;
	RList *list = r_list_newf (NULL);
	r_list_foreach (strings, iter, s) {
		if (*s->string == '_') {
			if (s->string[1] == '_' && s->string[2] == toupper(s->string[2])) {
				r_list_append (list, s);
			}
		}
	}
	r_buf_read_at (b, x, (ut8*)buf, sizeof (buf));
	for (i = 0; (i * 4) < (x_end - x); i += 4) {
		RBinString *name = r_list_get_n (list, (i-1)/4);
		const char *namestr = name? name->string: "";
		if (i == 0) {
			namestr = "MACH_HEADER";
		}
		eprintf ("0x%08x  addr=0x%08x size=0x%08x unk=0x%08x zero=0x%08x  %s\n",
			x + (i * 4),
			buf[i], buf[i + 1], buf[i + 2], buf[i + 3], namestr);
		// get the first nth string. those seems to be sections
	}
	r_list_free (list);
	free (buf);
}

static ut64 parseSymbols (RBuffer *buf, int x) {
	int end_offset = 0;
	ut32 count = symbolsCount; // should be 199 for the 32bit sample
	eprintf ("symbols table2 count %d\n", count);
	ut8 *b = calloc (24, count);
	if (!b) {
		return UT64_MAX;
	}
	r_buf_read_at (buf, x, b, count * 24);
	int array_section = x; // 0x000003a0;
	int i;
	const int array_section_end = array_section + (count * 24);  //  XXX hardcoded offset
	end_offset = array_section_end;
	for (i = 0; i < count; i++) {
		int n = (i * 24);
		const ut32 A = r_read_le32 (b + n); // offset in memory
		const ut32 B = r_read_le32 (b + n + 4); // size of the symbol
		const ut32 C = r_read_le32 (b + n + 8); // magic number 334e4051 3ce4102 34e4020 34e4000 ...
		const ut32 D = r_read_le32 (b + n + 12);
		const ut32 E = r_read_le32 (b + n + 16);
		int d = D - E;
		eprintf ("0x%08"PFMT64x" %3d addr=0x%x size=%4d magic=0x%x %d %d d=%d\n",
				(ut64) n + x, i, A, B, C, D, E, d);
		x = n;
	}
	eprintf ("0x%x\n", end_offset);
	free (b);
	return end_offset;
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
	ut8 *b = calloc (size, 1);
	r_buf_read_at (buf, x, b, size);
	for (i = 0; i < size; i += 8) {
		int o = i + dword_section;
		if (i + 4 >= size) {
			eprintf ("..skip..\n");
			continue;
		}
		int v = r_read_le32 (b + i);
		int w = r_read_le32 (b + i + 4);
		eprintf ("0x%08x  0x%x\t0x%x = %d\n", o, v, w, v - w);
		if (min == -1 || v < min) {
			min = v;
		}
		if (max == -1 || v > max) {
			max = v;
		}
	}
	free (b);
}

static void *load_buffer(RBinFile *bf, RBuffer *buf, ut64 loadaddr, Sdb *sdb) {
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
		return NULL;
	}
	printSymbolsHeader (sh);

	// 0x40 - contain list of segments
	SymbolsMetadata sm = parseMetadata (buf, 0x40);

	// printf ("0x%x vs 0x138\n", 0x40 + sm.size);
	int x = sm.addr + sm.size;

	// 0x138 - 0x220        // unknown information + duplicated list of segments
	SymbolsDragons sd = parseDragons (buf, x, sm.bits);
	eprintf ("sections: %d\n", sd.n_sections);
	// 0x220 - 0x3a0        // table of sections

	// 0x3a0 - 0x1648       // table of dwords with -1
	if (sm.bits == 32) {
		dwordsBeginAt = parseSymbols (buf, 0x3a0);
	} else {
		dwordsBeginAt = parseSymbols (buf, 0x458);
	}
	// skip the table3 dword pairs table
	stringsBeginAt = dwordsBeginAt + (symbolsCount * 8);

	// we need stringsBeginAt in here.. but this data is before the place we can compute this
	parseSections (buf, SECTIONS_BEGIN);

	// 0x1648 - 0x1c80      // table of dwords (unknown data)
	parseTable3 (buf, dwordsBeginAt);

	// 0x1c80 - EOF         // strings
	RList *strings = parseStrings (buf, stringsBeginAt, r_buf_size (buf));
	if (strings) {
		eprintf ("Count strings: %d\n", r_list_length (strings));
		r_list_free (strings);
	}

	return malloc (32);
}

static RList *sections(RBinFile *bf) {
	SymbolsMetadata sm = parseMetadata (bf->buf, 0x40);
	return sm.sections;
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

static bool check_bytes(const ut8 *buf, ut64 length) {
	if (buf && length >= 4) {
		if (!memcmp (buf, "\x02\xff\x01\xff", 4)) {
			return true;
		}
	}
	return false;
}

static RList *strings(RBinFile *bf) {
	RListIter *iter;
	RList *list = r_list_newf (NULL);
	RList *strings = parseStrings (bf->buf, stringsBeginAt, r_buf_size (bf->buf));
	RBinString *s;
	r_list_foreach (strings, iter, s) {
		if (*s->string != '_') {
			r_list_append (list, s);
		}
	}
	return list;
}

static RList *symbols(RBinFile *bf) {
	RListIter *iter;
	RBinString *s;
	RList *list = r_list_newf (NULL);
	RList *strings = parseStrings (bf->buf, stringsBeginAt, r_buf_size (bf->buf));
	r_list_foreach (strings, iter, s) {
		if (*s->string == '_') {
			if (s->string[1] == '_' && s->string[2] == toupper(s->string[2])) {
				continue;
			}
			r_list_append (list, newSymbol (s));
		}
	}
	return list;
}

static ut64 size(RBinFile *bf) {
	return UT64_MAX;
}

RBinPlugin r_bin_plugin_symbols = {
	.name = "symbols",
	.desc = "Apple Symbols file",
	.license = "MIT",
	.load_buffer = &load_buffer,
	.check_bytes = &check_bytes,
	.symbols = &symbols,
	.sections = &sections,
	.strings = strings,
	.size = &size,
	.info = &info,
};

#ifndef CORELIB
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_symbols,
	.version = R2_VERSION
};
#endif
