/* radare - LGPL - Copyright 2018 - pancake */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>
#include "../i/private.h"

static int bits = 32;

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
	s->perm = 7;
	return s;
}

static RList *parseSegments(RBuffer *buf, int off, int count) {
	ut8 b[0x2000] = { 0 };
	(void)r_buf_read_at (buf, off, b, sizeof (b)); // hardcoded buffers sucks
	int x = off;
	int X = 0;
	int i;
	RList *sections = r_list_newf (r_bin_section_free);
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

static SymbolsMetadata parseMetadata(RBuffer *buf, int off) {
	SymbolsMetadata sm = { 0 };
	ut8 b[0x100] = { 0 };
	(void)r_buf_read_at (buf, off, b, sizeof (b));
	sm.addr = off;
	sm.cputype = r_read_le32 (b);
	eprintf ("0x%08x  cputype  0x%x -> %s\n", 0x40, sm.cputype, typeString (sm.cputype));
	bits = sm.bits = (strstr (typeString (sm.cputype), "64"))? 64: 32;
	sm.subtype = r_read_le32 (b + 4);
	eprintf ("0x%08x  subtype  0x%x -> %s\n", 0x44, sm.subtype, subtypeString (sm.subtype));
	sm.n_sections = r_read_le32 (b + 8);
	int count = r_read_le32 (b + 0x48);
	sm.namelen = r_read_le32 (b + 0xc);
	eprintf ("0x%08x  strlen   %d\n", 0x4c, sm.namelen);
	eprintf ("0x%08x  filename %s\n", 0x50, b + 16);
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
	int x = 0;
	eprintf ("0x%08x  uuid     ", 24);
	int i;
	for (i = 0; i < 16; i++) {
		eprintf ("%02x", sh.uuid[i]);
	}
	eprintf ("\n");
	//  parse header
	eprintf ("0x%08x  unknown  0x%x\n", 0x28, sh.unk0); //r_read_le32 (b+ 0x28));
	eprintf ("0x%08x  unknown  0x%x\n", 0x2c, sh.unk1); //r_read_le16 (b+ 0x2c));
	eprintf ("0x%08x  slotsize %d\n", 0x2e, sh.slotsize); // r_read_le16 (b+ 0x2e));
}

static RList *parseStrings(RBuffer *buf, int string_section, int string_section_size) {
	const int string_section_end = string_section + string_section_size;
	char *b = malloc (string_section_size);
	if (!b) {
		return NULL;
	}
	int o = 0;
	char *s = b;
	char *os = s;
	int nstrings = 0;

	(void)r_buf_read_at (buf, string_section, b, string_section_size);
	RList *res = r_list_newf (r_bin_string_free);
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
		//
		s += strlen (s) + 1;
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

static SymbolsDragons parseDragons(RBuffer *buf, int off) {
	SymbolsDragons sd = { 0 };
	const int size = 0x8000;
	ut8 *b = malloc (size);
	if (!b) {
		return sd;
	}
	r_buf_read_at (buf, off, b, size);
#if 0
	// after the list of sections, there's a bunch of unknown
	// data, brobably dwords, and then the same section list again
	// this function aims to parse it.
	0x00000138 |1a2b b2a1 0300 0000 1a2b b2a1 e055 0000| .+.......+...U..
	0x00000148 |0100 0000 ca55 0000 0400 0000 1800 0000| .....U..........
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

#define is32 0
#if is32
//arm32
#define STRINGS_BEGIN 0x1c80
#define STRINGS_SIZE 15000
#define STRINGS_END STRINGS_BEGIN+15000
#else
//arm64
#define STRINGS_BEGIN 0x0001eb58
#define STRINGS_END 0x000610d8
#define STRINGS_SIZE STRINGS_END-STRINGS_BEGIN
#endif

static void parseSections(RBuffer *b, int x) {
	int i, x_end = 0x3a0;
	ut32 buf[STRINGS_SIZE];
	RList *strings = parseStrings (b, STRINGS_BEGIN, STRINGS_SIZE); // XXX hardcoded offset + size
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
		eprintf ("0x%08x  addr=0x%08x size=0x%08x unk=0x%08x zero=0x%08x  %s\n", x + (i * 4),
			buf[i], buf[i + 1], buf[i+2], buf[i+3], namestr);
		// get the first nth string. those seems to be sections
	}
	r_list_free (list);	
}

static void parseSymbols (RBuffer *buf, int x) {
	char countbuf[4];
	r_buf_read_at (buf, x + 0x20 - 8, &countbuf, 4);
eprintf ("x = 0x3a0 0x%x\n", x);
// 0x1648 - 0x3a0
	ut32 count = r_read_le32 (&countbuf);
	count = (0x1648 - x) / 24;
	eprintf ("symbols table2 count %d\n", count);
	ut8 *b = calloc (24, count);
	if (!b) {
		return;
	}
	r_buf_read_at (buf, x, b, count * 24);
	int array_section = x; // 0x000003a0;
	int i;
	if (1) {
		const int array_section_end = array_section + (count * 24);  //  XXX hardcoded offset
		for (i = 0; i < count; i++) {
			int n = (i * 24);
			const ut32 A = r_read_le32 (b + n); // offset in memory
			const ut32 B = r_read_le32 (b + n + 4); // size of the symbol
			const ut32 C = r_read_le32 (b + n + 8); // magic number 334e4051 3ce4102 34e4020 34e4000 ...
			const ut32 D = r_read_le32 (b + n + 12);
			const ut32 E = r_read_le32 (b + n + 16);
			int d = D - E;
			eprintf ("0x%08"PFMT64x" %3d addr=0x%x size=%4d magic=0x%x %d %d d=%d\n",
					n + x, i, A, B, C, D, E, d);
			x = n;
		}
	} else {
array_section -= 8;
		const int array_section_end = array_section + (count * 32);  //  XXX hardcoded offset
		for (i = 0; i < count; i++) {
			int n = (i * 48);
			const ut64 A = r_read_le64 (b + n); // offset in memory
			const ut64 B = r_read_le64 (b + n + 8); // size of the symbol
			const ut32 C = r_read_le32 (b + n + 16); // magic number 334e4051 3ce4102 34e4020 34e4000 ...
			const ut32 D = r_read_le32 (b + n + 20);
			const ut32 E = r_read_le32 (b + n + 24);
			int d = D - E;
			eprintf ("0x%08"PFMT64x" %3d addr=0x%08"PFMT64x" size=%4d magic=0x%x %d %d d=%d\n",
					n + x, i, A, (int)B, C, D, E, d);
			x = n;
		}
	}
	free (b);
}

// unknown data in this range
static parseTable3(RBuffer *buf, int x) {
	// 0x1648 - 0x1c80
	const int dword_section = 0x00001648;
	int dword_section_end = 0x00001c80;
	int i, size = dword_section_end - dword_section;
	int min = -1;
	int max = -1;
	ut8 *b = calloc (size, 1);
	r_buf_read_at (buf, x, b, size);
	eprintf ("--\n");
	for (i = 0; i < size; i += 4) {
		int o = i + dword_section;
		if (i + 4 >= size) {
			eprintf ("..skip..\n");
			continue;
		}
		int v = r_read_le32 (b + i);
		eprintf ("0x%08x  0x%x\n", o, v);
		if (min == -1 || v < min) {
			min = v;
		}
		if (max == -1 || v > max) {
			max = v;
		}
	}
	free (b);
	eprintf ("min %d\n", min);
	eprintf ("max %d\n", max);
	eprintf ("count %d\n", size / 4);
	eprintf ("--\n");
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

/tmp/E35AB42C-93A4-340A-8746-94890CEA4C40.symbols
Sections:
---------
0x00000000 header

0x00000220 commands/pointers/sections/headers/wtf
	0x00000220  0000 0000 d069 0000 601a 0000 0000 0000 d069 0000 ec0c 0000  .....i..`........i......
	0x00000238  5c1a 0000 0000 0000 bc76 0000 c001 0000 5a1a 0000 0000 0000  \........v......Z.......
	0x00000250  7c78 0000 7401 0000 621a 0000 0000 0000 f079 0000 4601 0000  |x..t...b........y..F...
	0x00000268  671a 0000 0000 0000 407b 0000 1c00 0000 661a 0000 0000 0000  g.......@{......f.......
	0x00000280  5c7b 0000 2b00 0000 671a 0000 0000 0000 877b 0000 df00 0000  \{..+...g........{......
	0x00000298  6e1a 0000 0000 0000 667c 0000 4500 0000 761a 0000 0000 0000  n.......f|..E...v.......
	0x000002b0  ac7c 0000 6000 0000 7e1a 0000 0000 0000 0c7d 0000 2800 0000  .|..`...~........}..(...
	0x000002c8  861a 0000 0000 0000 347d 0000 0c00 0000 8c1a 0000 0000 0000  ........4}..............
	0x000002e0  407d 0000 5400 0000 921a 0000 0000 0000 947d 0000 1400 0000  @}..T............}......
	0x000002f8  9a1a 0000 0000 0000 a87d 0000 4f02 0000 a21a 0000 0000 0000  .........}..O...........                                                                                                           0x00000310  0080 0000 a000 0000 a61a 0000 0000 0000 a080 0000 7000 0000  ....................p...
	0x00000328  ad1a 0000 0000 0000 1081 0000 a002 0000 b41a 0000 0000 0000  ........................
	0x00000340  b083 0000 0800 0000 b31a 0000 0000 0000 b883 0000 0c00 0000  ........................
	0x00000358  bb1a 0000 0000 0000 c483 0000 0c00 0000 c11a 0000 0000 0000  ........................
	0x00000370  d083 0000 6c00 0000 c91a 0000 0000 0000 4084 0000 8002 0000  ....l...........@.......
	0x00000388  c71a 0000 0000 0000 00c0 0000 bce3 0000 c41a 0000 0000 0000  ........................
0x000003a0 ffffd array table
	0x000003a0  d069 0000 c403 0000 5140 4e33 051b 0000 c41a 0000 ffff ffff  .i......Q@N3............
		0x69d0 0x3c4 0x334e4051 0x1b05 0x1ac4
	0x000003b8  946d 0000 3a00 0000 5140 4e33 711b 0000 211b 0000 ffff ffff  .m..:...Q@N3q...!.......
		0x6d94 0x3a 0x334e4051
	0x000003d0  ce6d 0000 6400 0000 5140 4e33 ed1b 0000 861b 0000 ffff ffff  .m..d...Q@N3............
0x00001648  nonffd table of independent dwords :?

0x00001c80 strings

0x138
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
	SymbolsDragons sd = parseDragons (buf, x);
	// 0x220 - 0x3a0        // table of sections
	parseSections (buf, 0x220);

	// 0x3a0 - 0x1648       // table of dwords with -1
	if (bits == 32) {
		parseSymbols (buf, 0x3a0);
	} else {
		parseSymbols (buf, 0x458);
	}

	// 0x1648 - 0x1c80      // table of dwords (unknown data)
	// parseTable3 (buf, 0x1648);

	// 0x1c80 - EOF         // strings
	RList *strings = parseStrings (buf, STRINGS_BEGIN, STRINGS_SIZE); // XXX hardcoded offset + size
	eprintf ("Count strings: %d\n", r_list_length (strings));
	r_list_free (strings);

	return malloc (32);
}

static RList *sections(RBinFile *bf) {
	SymbolsMetadata sm = parseMetadata (bf->buf, 0x40);
	eprintf ("--- %d\n", r_list_length (sm.sections));
	return sm.sections;
}

static RBinInfo *info(RBinFile *bf) {
	RBinInfo *ret = R_NEW0 (RBinInfo);
	if (!ret) {
		return NULL;
	}
	ret->file = strdup (bf->file);
	ret->bclass = strdup ("symbols");
	ret->os = strdup ("unknown");
	ret->arch = strdup ("arm");
	ret->bits = 64; // 32
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
	// XXX hardcoded offset + size
	RList *strings = parseStrings (bf->buf, STRINGS_BEGIN, STRINGS_SIZE);
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
	// XXX hardcoded offset + size
	RList *strings = parseStrings (bf->buf, STRINGS_BEGIN, STRINGS_SIZE);
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
