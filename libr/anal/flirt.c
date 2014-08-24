/* radare - LGPL - Copyright 2014 - TheLemonMan, jfrankowski */
/* original cpp code from Rheax <rheaxmascot@gmail.com> */
/* more information on flirt https://www.hex-rays.com/products/ida/tech/flirt/in_depth.shtml */

#include <r_types.h>
#include <r_lib.h>
#include <r_cmd.h>
#include <r_sign.h>

/*arch flags*/
#define IDASIG__ARCH__80X86						0x00
#define IDASIG__ARCH__Z80						0x01
#define IDASIG__ARCH__INTEL_860					0x02
#define IDASIG__ARCH__8051						0x03
#define IDASIG__ARCH__TMS320C5X					0x04
#define IDASIG__ARCH__6502						0x05
#define IDASIG__ARCH__PDP11						0x06
#define IDASIG__ARCH__MOTOROLA_680X0			0x07
#define IDASIG__ARCH__JAVA						0x08
#define IDASIG__ARCH__MOTOROLA_68XX				0x09
#define IDASIG__ARCH__SGS_THOMSON_ST7			0x0A
#define IDASIG__ARCH__MOTOROLA_68HC12			0x0B
#define IDASIG__ARCH__MIPS						0x0C
#define IDASIG__ARCH__ADVANCED_RISC				0x0D
#define IDASIG__ARCH__TMS320C6X					0x0E
#define IDASIG__ARCH__POWERPC					0x0F
#define IDASIG__ARCH__INTEL_80196				0x10
#define IDASIG__ARCH__Z8						0x11
#define IDASIG__ARCH__HITACHI_SH				0x12
#define IDASIG__ARCH__MSVS_DOT_NET				0x13
#define IDASIG__ARCH__ATMEL_8_BIT_RISC			0x14
#define IDASIG__ARCH__HITACHI_H8_300_H8_2000	0x15
#define IDASIG__ARCH__MICROCHIP_PIC				0x16
#define IDASIG__ARCH__SPARC						0x17
#define IDASIG__ARCH__DEC_ALPHA					0x18
#define IDASIG__ARCH__HP_PA_RISC				0x19
#define IDASIG__ARCH__HITACHI_H8_500			0x1A
#define IDASIG__ARCH__TASKING_TRICORE			0x1B
#define IDASIG__ARCH__MOTOROLA_DSP5600X			0x1C
#define IDASIG__ARCH__SIEMENS_C166				0x1D
#define IDASIG__ARCH__SGS_THOMSON_ST20			0x1E
#define IDASIG__ARCH__INTEL_ITANIUM_IA64		0x1F
#define IDASIG__ARCH__INTEL_I960				0x20
#define IDASIG__ARCH__FUJITSU_F2MC_16			0x21
#define IDASIG__ARCH__TMS320C54XX				0x22
#define IDASIG__ARCH__TMS320C55XX				0x23
#define IDASIG__ARCH__TRIMEDIA					0x24
#define IDASIG__ARCH__MITSUBISH_32_BIT_RISC		0x25
#define IDASIG__ARCH__NEC_78K0					0x26
#define IDASIG__ARCH__NEC_78K0S					0x27
#define IDASIG__ARCH__MITSUBISHI_8_BIT			0x28
#define IDASIG__ARCH__MITSIBUSHI_16_BIT			0x29
#define IDASIG__ARCH__ST9PLUS					0x2A
#define IDASIG__ARCH__FUJITSU_FR				0x2B
#define IDASIG__ARCH__MOTOROLA_68HC16			0x2C
#define IDASIG__ARCH__MITSUBISHI_7900			0x2D

/*file_types flags*/
#define IDASIG__FILE__DOS_EXE_OLD				0x00000001
#define IDASIG__FILE__DOS_COM_OLD				0x00000002
#define IDASIG__FILE__BIN						0x00000004
#define IDASIG__FILE__DOSDRV					0x00000008
#define IDASIG__FILE__NE						0x00000010
#define IDASIG__FILE__INTELHEX					0x00000020
#define IDASIG__FILE__MOSHEX					0x00000040
#define IDASIG__FILE__LX						0x00000080
#define IDASIG__FILE__LE						0x00000100
#define IDASIG__FILE__NLM						0x00000200
#define IDASIG__FILE__COFF						0x00000400
#define IDASIG__FILE__PE						0x00000800
#define IDASIG__FILE__OMF						0x00001000
#define IDASIG__FILE__SREC						0x00002000
#define IDASIG__FILE__ZIP						0x00004000
#define IDASIG__FILE__OMFLIB					0x00008000
#define IDASIG__FILE__AR						0x00010000
#define IDASIG__FILE__LOADER					0x00020000
#define IDASIG__FILE__ELF						0x00040000
#define IDASIG__FILE__W32RUN					0x00080000
#define IDASIG__FILE__AOUT						0x00100000
#define IDASIG__FILE__PILOT						0x00200000
#define IDASIG__FILE__DOS_EXE					0x00400000
#define IDASIG__FILE__AIXAR						0x00800000

/*os_types flags*/
#define IDASIG__OS__MSDOS						0x01
#define IDASIG__OS__WIN							0x02
#define IDASIG__OS__OS2							0x04
#define IDASIG__OS__NETWARE						0x08
#define IDASIG__OS__UNIX						0x10

/*app types flags*/
#define IDASIG__APP__CONSOLE					0x0001
#define IDASIG__APP__GRAPHICS					0x0002
#define IDASIG__APP__EXE						0x0004
#define IDASIG__APP__DLL						0x0008
#define IDASIG__APP__DRV						0x0010
#define IDASIG__APP__SINGLE_THREADED			0x0020
#define IDASIG__APP__MULTI_THREADED				0x0040
#define IDASIG__APP__16_BIT						0x0080
#define IDASIG__APP__32_BIT						0x0100
#define IDASIG__APP__64_BIT						0x0200

/*feature flags*/
#define IDASIG__FEATURE__STARTUP				0x01
#define IDASIG__FEATURE__CTYPE_CRC				0x02
#define IDASIG__FEATURE__2BYTE_CTYPE			0x04
#define IDASIG__FEATURE__ALT_CTYPE_CRC			0x08
#define IDASIG__FEATURE__COMPRESSED				0x10

typedef struct idasig_v5_t {
	ut8  magic[6]; /* should be set to IDASGN */
	ut8  version;  /*from 5 to 9*/
	ut8  arch;
	ut32 file_types;
	ut16 os_types;
	ut16 app_types;
	ut16 features;
	ut16 old_n_functions;
	ut16 crc16;
	ut8  ctype[12];
	ut8  library_name_len;
	ut16 crc_;
} idasig_v5_t;

typedef struct idasig_v6_v7_t {
	ut32 n_functions;
} idasig_v6_v7_t;

typedef struct idasig_v8_v9_t {
	ut16 pattern_size;
} idasig_v8_v9_t;

/* newer header only add fields, that's why we'll always read a v5 header first */

/*
arch             : target architecture
file_types       : files where we expect to find the functions (exe, coff, ...)
os_types         : os where we expect to find the functions
app_types        : applications in which we expect to find the functions
features         : signature file features
old_n_functions  : number of functions
crc16            : certainly crc16 of the tree
ctype[12]        :
library_name_len : length of the library name, which is right after the header
crc_             : unknown field
n_functions      : number of functions
pattern_size     : size of the leading bytes pattern
*/

#define READ_BYTE_ERR(name, b) if( (name = read_byte(b)) < 0 ) { goto buf_err_exit; }

static ut8 read_byte (RBuffer *b) {
	/*returns a negative value on error, else it returns the read byte*/
	ut8 r;
	if ( r_buf_read_at(b, b->cur, &r, 1) != 1 ) {
		eprintf("Couldn't read from the buffer any further\n");
		exit(-1);
	}

	return r;
}

static ut16 read_short (RBuffer *b) {
	ut16 r = (read_byte(b) << 8) + read_byte(b);
	return r;
}

static ut32 read_word (RBuffer *b) {
	ut32 r = (read_short(b) << 16) + read_short(b);
	return r;
}

static ut32 read_shift (RBuffer *b) {
	ut32 r = read_byte(b);
	if ( r & 0x80 )
		return ((r & 0x7f) << 8) + read_byte(b);

	return r;
}

static ut32 r_flirt_explode_mask (RBuffer *b) {
	ut32 r = read_byte(b);

	if ((r & 0x80) != 0x80)
		return r;

	if ((r & 0xc0) != 0xc0)
		return ((r & 0x7f) << 8) + read_byte(b);

	if ((r & 0xe0) != 0xe0)
		return ((r & 0x3f) << 24) + (read_byte(b) << 16) + read_short(b);

	return read_word(b);
}

#define R_FLIRT_NAME_MAX 1024

typedef struct RFlirtName {
	char name[R_FLIRT_NAME_MAX];
	ut32 offset;
} RFlirtName;

typedef struct RFlirtSubLeaf {
	ut16 check_off;
	ut8  check_val;
	ut8  flags;
	RList *names_list;
} RFlirtSubLeaf;

typedef struct RFlirtLeaf {
	RList *sub_list;
	ut32 crc_len;
	ut32 crc_val;
} RFlirtLeaf;

typedef struct RFlirtNode {
	RList *child_list;
	RList *leaf_list;
	ut32 length;
	ut8 *match;
	ut64 mask;
	ut8 *maskp;
} RFlirtNode;


#define POLY 0x8408
unsigned short crc16(const unsigned char *data_p, size_t length) {
	unsigned char i;
	unsigned int data;

	if ( length == 0 )
		return 0;
	unsigned int crc = 0xFFFF;
	do
	{
		data = *data_p++;
		for ( i=0; i < 8; i++ )
		{
			if ( (crc ^ data) & 1 )
				crc = (crc >> 1) ^ POLY;
			else
				crc >>= 1;
			data >>= 1;
		}
	} while ( --length != 0 );

	crc = ~crc;
	data = crc;
	crc = (crc << 8) | ((data >> 8) & 0xff);
	return (unsigned short)(crc);
}

/*static int decompress (ut8 *buf, int buf_size, ut8 **out, int *out_size) {*/
	/*z_stream *stream = R_NEW0(z_stream);*/
	/*int wbits, dec_size = buf_size * 2;*/
	/*ut8 *dec_buf = malloc(dec_size);*/
	/**out = NULL;*/
	/**out_size = 0;*/
	/*if (!stream || !dec_buf)*/
		/*goto err_exit;*/
	/*[> Check for zlib header <]*/
	/*if (buf[0] == 0x78 && buf[1] == 0x9C)*/
		/*wbits = MAX_WBITS;*/
	/*else*/
		/*wbits = -MAX_WBITS;*/
	/*if (inflateInit2(stream, wbits) != Z_OK)*/
		/*goto err_exit;*/
	/*stream->next_in = buf;*/
	/*stream->avail_in = buf_size;*/
	/*stream->next_out = dec_buf;*/
	/*stream->avail_out = dec_size;*/
	/*int ret, size;*/
	/*for (;;) {*/
		/*ret = inflate(stream, Z_FINISH);*/
		/*switch (ret) {*/
			/*case Z_STREAM_END:*/
				/**out = dec_buf;*/
				/**out_size = stream->next_out - dec_buf;*/
				/*inflateEnd(stream);*/
				/*free(stream);*/
				/*return R_TRUE;*/
			/*case Z_BUF_ERROR:*/
				/*size = stream->next_out - dec_buf;*/
				/*dec_size *= 2;*/
				/*dec_buf = realloc(dec_buf, dec_size);*/
				/*if (!dec_buf)*/
					/*goto err_exit;*/
				/*stream->next_out = dec_buf + size;*/
				/*stream->avail_out = dec_size - size;*/
				/*break;*/
			/*default:*/
				/*eprintf("Unhandled zlib error! (%i)\n", ret);*/
				/*goto err_exit;*/
		/*}*/
	/*}*/
/*err_exit:*/
	/*inflateEnd(stream);*/
	/*free(stream);*/
	/*free(dec_buf);*/
	/**out = NULL;*/
	/**out_size = 0;*/
	/*return R_FALSE;*/
/*}*/


static int node_match (const ut8 *buf, const ut64 buf_size, const RFlirtNode *node) {
	int i;
	if (node->length > buf_size)
		return R_FALSE;
	for (i = 0; i < node->length; i++) {
		if ((node->match[i]&node->maskp[i]) != (buf[i]&node->maskp[i]))
			return R_FALSE;
	}

	return R_TRUE;
}

static void node_print_pattern (const RAnal * anal, const RFlirtNode *node) {
	int i;
	ut64 cur;
	cur = 1ULL << (node->length - 1);
	for (i = 0; i < node->length; i++) {
		if (node->mask&cur)
			anal->printf("..");
		else
			anal->printf("%02X", node->match[i]);
		cur >>= 1;
	}
	anal->printf("\n");
}

static void subleaf_free (RFlirtSubLeaf *sub) {
	r_list_free(sub->names_list);
}

static void leaf_free (RFlirtLeaf *leaf) {
	leaf->sub_list->free = subleaf_free;
	r_list_free(leaf->sub_list);
}

static void node_free (RFlirtNode *node) {
	free(node->maskp);
	free(node->match);

	if (node->leaf_list) {
		node->leaf_list->free = leaf_free;
		r_list_free(node->leaf_list);
	}

	if (node->child_list) {
		node->child_list->free = node_free;
		r_list_free(node->child_list);
	}
}

static void node_print (const RAnal *anal, RFlirtNode *node, const int indent) {
	int i;
	RListIter *it;
	RFlirtLeaf *leaf;

	if (!node)
		return;

	for (i = 0; i < indent; i++) anal->printf("\t");
	node_print_pattern(anal, node);

	r_list_foreach(node->leaf_list, it, leaf) {
		RListIter *it;
		RFlirtSubLeaf *sub;
		for (i = 0; i < indent; i++) anal->printf("\t");
		anal->printf("crc16 : %04x (%x)\n", leaf->crc_val, leaf->crc_len);
		r_list_foreach(leaf->sub_list, it, sub) {
			RListIter *it;
			RFlirtName *name;
			anal->printf("flags : %x\n", sub->flags);
			if (sub->flags & 1)
				anal->printf("check @ %02x = %02x\n", sub->check_off, sub->check_val);
			r_list_foreach(sub->names_list, it, name) {
				for (i = 0; i < indent + 1; i++) anal->printf("\t");
				anal->printf("> %s @ %x\n", name->name, name->offset);
			}
		}
	}

	RFlirtNode *child;
	r_list_foreach(node->child_list, it, child) {
		node_print(anal, child, indent + 1);
	}
}

static void node_match_buf (const RAnal *anal, const ut64 off, const ut8 *buf, unsigned long buf_size, RFlirtNode *node) {
	RListIter *it1, *it2, *it3;
	RFlirtNode *c;
	RFlirtLeaf *l;
	RFlirtSubLeaf *s;
	ut64 pos;

	int debug = R_FALSE;

	for (pos = off; pos < buf_size; ) {
		if (node_match(buf + pos, buf_size - pos, node)) {
			if (pos >= 0x2554 && pos <= 0x2598) {
				/*anal->printf("bingo? %x\n", pos);*/
				node_print (anal, node, -1);
				debug = R_TRUE;
			}
			pos += node->length;

			r_list_foreach(node->child_list, it1, c)
				node_match_buf(anal, pos, buf, buf_size, c);

			if (node->leaf_list) {
				r_list_foreach(node->leaf_list, it2, l) {
					if (l->crc_len) {
						const ut16 crc = crc16(buf + pos, l->crc_len);
						anal->printf("crc : %04X CALC : %04X\n", l->crc_val, crc);
						if (crc != l->crc_val)
							continue;
					}

					r_list_foreach(l->sub_list, it3, s) {
						if (debug)
							anal->printf("check (%x) %x = %x\n", pos, pos + s->check_off, s->check_val);
						if ((s->flags & 1) && buf[pos + s->check_off + 2] != s->check_val) {
							anal->printf("discard (%02x != %02x)\n", buf[pos + s->check_off], s->check_val);
							continue;
						}
						anal->printf("pass!\n");
						anal->printf("end?\n");
					}
				}
				/*return;*/
			}
		} else
			pos += 1;
	}
}

static void parse_leaf (const RAnal *anal, RBuffer *b, RFlirtNode *node) {
	ut32 flags, off;
	int i;

	node->leaf_list = r_list_new();
	do {
		RFlirtLeaf *leaf = R_NEW0(RFlirtLeaf);
		leaf->sub_list = r_list_new();

		leaf->crc_len = read_byte(b);
		leaf->crc_val = read_short(b);

		r_list_append(node->leaf_list, leaf);
		do {
			RFlirtSubLeaf *sub = R_NEW0(RFlirtSubLeaf);
			sub->names_list = r_list_new();
			r_list_append(leaf->sub_list, sub);

			ut32 length = read_shift(b); // certainly useless

			off = 0;
			do {
				RFlirtName *name = R_NEW0(RFlirtName);
				off += read_shift(b);
				name->offset = off;
				ut8 ch = read_byte(b);
				if (ch < 0x20)
					ch = read_byte(b);
				for (i = 0; ch >= 0x20; i++) {
					if (i > R_FLIRT_NAME_MAX) {
						anal->printf("Function name too long\n");
						// TODO:FIXME
						return;
					}
					name->name[i] = (char)ch;
					ch = read_byte(b);
				}
				if (ch == 0x0a) {
					/*name->name[i++] = (char)ch;*/
					ch = read_byte(b);
				}
				name->name[i] = '\0';
				anal->printf("name %s (%x)\n", name, ch);
				flags = ch;
				r_list_append(sub->names_list, name);
			} while(flags & 0x01);

			if (flags & 0x02) {
				sub->flags |= 1;
				anal->printf("bbpos %x\n", b->cur);
				sub->check_off = read_shift(b);
				/*sub->check_off = read_short(b)&0xff;*/
				sub->check_val = read_byte(b);
			}

			if (flags & 0x04) {
				sub->flags |= 2;
				/*ut32 a = read_shift(b);*/
				ut32 a = read_short(b);
				ut32 p = read_byte(b);
				if (!p)
					p = read_shift(b);
				b->cur += p;
			}
		} while(flags & 0x08); // more terminal nodes
	} while(flags & 0x10); // more hash entries
}

static void parse_tree (const RAnal *anal, RBuffer *b, RFlirtNode *root_node) {
	int tree_nodes;
	int i, j;
	ut64 bitmap;

	tree_nodes = read_shift(b);

	if (!tree_nodes)
		return parse_leaf(anal, b, root_node);

	root_node->child_list = r_list_new();

	/*for (i = 0; i < tree_nodes; i++) {*/
	for (i = 0; i < tree_nodes; ++i) {
		RFlirtNode *node = R_NEW0(RFlirtNode);
		node->length = read_byte(b);

		if (node->length < 0x10)
			node->mask = read_shift(b);
		else if (node->length <= 0x20)
			node->mask = r_flirt_explode_mask(b);
		else if (node->length <= 0x40)
			node->mask = ((ut64)r_flirt_explode_mask(b) << 32)+ r_flirt_explode_mask(b);

		bitmap = 1ULL << (node->length - 1);

		node->match = malloc(node->length);
		node->maskp = malloc(node->length);

		/*for (j = 0; bitmap ; j++, bitmap >>= 1) {*/
		for (j = 0; j < node->length ; ++j, bitmap >>= 1) {
			node->maskp[j] = (node->mask&bitmap) ? 0x00 : 0xff;
			node->match[j] = (node->mask&bitmap) ? 0x00 : read_byte(b);
		}
		r_list_append(root_node->child_list, node);

		parse_tree(anal, b, node);
	}
}

#define ARCHSTR(define, str) if (arch == define) return str;
#define FLAGSTR(flag, str)\
if(flags & flag) {if(strlen(str) > 0) ret = r_str_concat(ret, " "); ret = r_str_concat(ret, str);}
static const char * flirt_arch_str(ut8 arch) {
	ARCHSTR(IDASIG__ARCH__80X86, "80X86");
	ARCHSTR(IDASIG__ARCH__Z80, "Z80");
	ARCHSTR(IDASIG__ARCH__INTEL_860, "INTEL_860");
	ARCHSTR(IDASIG__ARCH__8051, "8051");
	ARCHSTR(IDASIG__ARCH__TMS320C5X, "TMS320C5X");
	ARCHSTR(IDASIG__ARCH__6502, "6502");
	ARCHSTR(IDASIG__ARCH__PDP11, "PDP11");
	ARCHSTR(IDASIG__ARCH__MOTOROLA_680X0, "MOTOROLA_680X0");
	ARCHSTR(IDASIG__ARCH__JAVA, "JAVA");
	ARCHSTR(IDASIG__ARCH__MOTOROLA_68XX, "MOTOROLA_68XX");
	ARCHSTR(IDASIG__ARCH__SGS_THOMSON_ST7, "SGS_THOMSON_ST7");
	ARCHSTR(IDASIG__ARCH__MOTOROLA_68HC12, "MOTOROLA_68HC12");
	ARCHSTR(IDASIG__ARCH__MIPS, "MIPS");
	ARCHSTR(IDASIG__ARCH__ADVANCED_RISC, "ADVANCED_RISC");
	ARCHSTR(IDASIG__ARCH__TMS320C6X, "TMS320C6X");
	ARCHSTR(IDASIG__ARCH__POWERPC, "POWERPC");
	ARCHSTR(IDASIG__ARCH__INTEL_80196, "INTEL_80196");
	ARCHSTR(IDASIG__ARCH__Z8, "Z8");
	ARCHSTR(IDASIG__ARCH__HITACHI_SH, "HITACHI_SH");
	ARCHSTR(IDASIG__ARCH__MSVS_DOT_NET, "MSVS_DOT_NET");
	ARCHSTR(IDASIG__ARCH__ATMEL_8_BIT_RISC, "ATMEL_8_BIT_RISC");
	ARCHSTR(IDASIG__ARCH__HITACHI_H8_300_H8_2000, "HITACHI_H8_300_H8_2000");
	ARCHSTR(IDASIG__ARCH__MICROCHIP_PIC, "MICROCHIP_PIC");
	ARCHSTR(IDASIG__ARCH__SPARC, "SPARC");
	ARCHSTR(IDASIG__ARCH__DEC_ALPHA, "DEC_ALPHA");
	ARCHSTR(IDASIG__ARCH__HP_PA_RISC, "HP_PA_RISC");
	ARCHSTR(IDASIG__ARCH__HITACHI_H8_500, "HITACHI_H8_500");
	ARCHSTR(IDASIG__ARCH__TASKING_TRICORE, "TASKING_TRICORE");
	ARCHSTR(IDASIG__ARCH__MOTOROLA_DSP5600X, "MOTOROLA_DSP5600X");
	ARCHSTR(IDASIG__ARCH__SIEMENS_C166, "SIEMENS_C166");
	ARCHSTR(IDASIG__ARCH__SGS_THOMSON_ST20, "SGS_THOMSON_ST20");
	ARCHSTR(IDASIG__ARCH__INTEL_ITANIUM_IA64, "INTEL_ITANIUM_IA64");
	ARCHSTR(IDASIG__ARCH__INTEL_I960, "INTEL_I960");
	ARCHSTR(IDASIG__ARCH__FUJITSU_F2MC_16, "FUJITSU_F2MC_16");
	ARCHSTR(IDASIG__ARCH__TMS320C54XX, "TMS320C54XX");
	ARCHSTR(IDASIG__ARCH__TMS320C55XX, "TMS320C55XX");
	ARCHSTR(IDASIG__ARCH__TRIMEDIA, "TRIMEDIA");
	ARCHSTR(IDASIG__ARCH__MITSUBISH_32_BIT_RISC, "MITSUBISH_BIT_RISC");
	ARCHSTR(IDASIG__ARCH__NEC_78K0, "NEC_78K0");
	ARCHSTR(IDASIG__ARCH__NEC_78K0S, "NEC_78K0S");
	ARCHSTR(IDASIG__ARCH__MITSUBISHI_8_BIT, "MITSUBISHI_8_BIT");
	ARCHSTR(IDASIG__ARCH__MITSIBUSHI_16_BIT, "MITSIBUSHI_16_BIT");
	ARCHSTR(IDASIG__ARCH__ST9PLUS, "ST9PLUS");
	ARCHSTR(IDASIG__ARCH__FUJITSU_FR, "FUJITSU_FR");
	ARCHSTR(IDASIG__ARCH__MOTOROLA_68HC16, "MOTOROLA_68HC16");
	ARCHSTR(IDASIG__ARCH__MITSUBISHI_7900, "MITSUBISHI_7900");

	return "UNKNOWN";
}

static const char * flirt_file_types_str(ut32 flags) {
	char *ret = NULL;

	FLAGSTR(IDASIG__FILE__DOS_EXE_OLD, "DOS_EXE_OLD");
	FLAGSTR(IDASIG__FILE__DOS_COM_OLD, "DOS_COM_OLD");
	FLAGSTR(IDASIG__FILE__BIN, "BIN");
	FLAGSTR(IDASIG__FILE__DOSDRV, "DOSDRV");
	FLAGSTR(IDASIG__FILE__NE, "NE");
	FLAGSTR(IDASIG__FILE__INTELHEX, "INTELHEX");
	FLAGSTR(IDASIG__FILE__MOSHEX, "MOSHEX");
	FLAGSTR(IDASIG__FILE__LX, "LX");
	FLAGSTR(IDASIG__FILE__LE, "LE");
	FLAGSTR(IDASIG__FILE__NLM, "NLM");
	FLAGSTR(IDASIG__FILE__COFF, "COFF");
	FLAGSTR(IDASIG__FILE__PE, "PE");
	FLAGSTR(IDASIG__FILE__OMF, "OMF");
	FLAGSTR(IDASIG__FILE__SREC, "SREC");
	FLAGSTR(IDASIG__FILE__ZIP, "ZIP");
	FLAGSTR(IDASIG__FILE__OMFLIB, "OMFLIB");
	FLAGSTR(IDASIG__FILE__AR, "AR");
	FLAGSTR(IDASIG__FILE__LOADER, "LOADER");
	FLAGSTR(IDASIG__FILE__ELF, "ELF");
	FLAGSTR(IDASIG__FILE__W32RUN, "W32RUN");
	FLAGSTR(IDASIG__FILE__AOUT, "AOUT");
	FLAGSTR(IDASIG__FILE__PILOT, "PILOT");
	FLAGSTR(IDASIG__FILE__DOS_EXE, "EXE");
	FLAGSTR(IDASIG__FILE__AIXAR, "AIXAR");

	return ret;
}

static const char * flirt_os_types_str(ut16 flags) {
	char *ret = NULL;

	FLAGSTR(IDASIG__OS__MSDOS, "MSDOS");
	FLAGSTR(IDASIG__OS__WIN, "WIN");
	FLAGSTR(IDASIG__OS__OS2, "OS2");
	FLAGSTR(IDASIG__OS__NETWARE, "NETWARE");
	FLAGSTR(IDASIG__OS__UNIX, "UNIX");

	return ret;
}

static const char * flirt_app_types_str(ut16 flags) {
	char *ret = NULL;

	FLAGSTR(IDASIG__APP__CONSOLE, "CONSOLE");
	FLAGSTR(IDASIG__APP__GRAPHICS, "GRAPHICS");
	FLAGSTR(IDASIG__APP__EXE, "EXE");
	FLAGSTR(IDASIG__APP__DLL, "DLL");
	FLAGSTR(IDASIG__APP__DRV, "DRV");
	FLAGSTR(IDASIG__APP__SINGLE_THREADED, "SINGLE_THREADED");
	FLAGSTR(IDASIG__APP__MULTI_THREADED, "MULTI_THREADED");
	FLAGSTR(IDASIG__APP__16_BIT, "16_BIT");
	FLAGSTR(IDASIG__APP__32_BIT, "32_BIT");
	FLAGSTR(IDASIG__APP__64_BIT, "64_BIT");

	return ret;
}

static const char * flirt_feature_str(ut16 flags) {
	char *ret = NULL;

	FLAGSTR(IDASIG__FEATURE__STARTUP, "STARTUP");
	FLAGSTR(IDASIG__FEATURE__CTYPE_CRC, "CTYPE_CRC");
	FLAGSTR(IDASIG__FEATURE__2BYTE_CTYPE, "2BYTE_CTYPE");
	FLAGSTR(IDASIG__FEATURE__ALT_CTYPE_CRC, "ALT_CTYPE_CRC");
	FLAGSTR(IDASIG__FEATURE__COMPRESSED, "COMPRESSED");

	return ret;
}

static void print_header(idasig_v5_t *header) {
	eprintf("magic: %s\n", header->magic);
	eprintf("version: %d\n", header->version);
	/*eprintf("arch: %s\n", flirt_arch_str(header->arch));*/
	eprintf("arch: %s\n", flirt_arch_str(header->arch));
	eprintf("file_types: %s\n", flirt_file_types_str(header->file_types));
	eprintf("os_types: %s\n", flirt_os_types_str(header->os_types));
	eprintf("app_types: %s\n", flirt_app_types_str(header->app_types));
	eprintf("features: %s\n", flirt_feature_str(header->features));
	eprintf("old_n_functions: %04x\n", header->old_n_functions);
	eprintf("crc16: %04x\n", header->crc16);
	eprintf("ctype: %s\n", header->ctype);
	eprintf("library_name_len: %d\n", header->library_name_len);
	eprintf("crc_: %04x\n", header->crc_);
}

static int parse_header(RBuffer *buf, idasig_v5_t *header) {
	/*if( r_buf_read_at(buf,  0, header->magic, sizeof(header->magic)) != sizeof(header->magic) )*/
		/*return R_FALSE;*/
	/*if( r_buf_read_at(buf, -1, &header->version, sizeof(header->version)) != sizeof(header->version) )*/
		/*return R_FALSE;*/
	if( r_buf_read_at(buf, buf->cur, &header->arch, sizeof(header->arch)) != sizeof(header->arch) )
		return R_FALSE;
	if( r_buf_read_at(buf, buf->cur, &header->file_types, sizeof(header->file_types)) != sizeof(header->file_types) )
		return R_FALSE;
	if( r_buf_read_at(buf, buf->cur, &header->os_types, sizeof(header->os_types)) != sizeof(header->os_types) )
		return R_FALSE;
	if( r_buf_read_at(buf, buf->cur, &header->app_types, sizeof(header->app_types)) != sizeof(header->app_types) )
		return R_FALSE;
	if( r_buf_read_at(buf, buf->cur, &header->features, sizeof(header->features)) != sizeof(header->features) )
		return R_FALSE;
	if( r_buf_read_at(buf, buf->cur, &header->old_n_functions, sizeof(header->old_n_functions)) != sizeof(header->old_n_functions) )
		return R_FALSE;
	if( r_buf_read_at(buf, buf->cur, &header->crc16, sizeof(header->crc16)) != sizeof(header->crc16) )
		return R_FALSE;
	if( r_buf_read_at(buf, buf->cur, header->ctype, sizeof(header->ctype)) != sizeof(header->ctype) )
		return R_FALSE;
	if( r_buf_read_at(buf, buf->cur, &header->library_name_len, sizeof(header->library_name_len)) != sizeof(header->library_name_len) )
		return R_FALSE;
	if( r_buf_read_at(buf, buf->cur, &header->crc_, sizeof(header->crc_)) != sizeof(header->crc_) )
		return R_FALSE;

	return R_TRUE;
}

static int parse_v6_v7_header(RBuffer *buf, idasig_v6_v7_t *header) {
	if(r_buf_read_at(buf, buf->cur, &header->n_functions, sizeof(header->n_functions)) != sizeof(header->n_functions))
		return R_FALSE;

	return R_TRUE;
}

static int parse_v8_v9_header(RBuffer *buf, idasig_v8_v9_t *header) {
	if(r_buf_read_at(buf, buf->cur, &header->pattern_size, sizeof(header->pattern_size)) != sizeof(header->pattern_size))
		return R_FALSE;

	return R_TRUE;
}

R_API int r_sign_is_flirt (RBuffer *buf) {
	/*if buf is a flirt signature, return signature version, otherwise return false*/

	idasig_v5_t *header = R_NEW0(idasig_v5_t);
	if( r_buf_read_at(buf, buf->cur, header->magic, sizeof(header->magic)) != sizeof(header->magic) )
		return R_FALSE;

	if (memcmp(header->magic, "IDASGN", 6))
		return R_FALSE;

	if( r_buf_read_at(buf, buf->cur, &header->version, sizeof(header->version)) != sizeof(header->version) )
		return R_FALSE;

	return header->version;
}

R_API int r_sign_flirt_parse (const RAnal *anal, RBuffer *buf_to_scan, RBuffer *flirt_buf) {
	int version;
	ut8 *name;
	ut8 *buf, *decompressed_buf;
	RBuffer *r_buf;
	int size, decompressed_size;
	idasig_v5_t * header;
	idasig_v6_v7_t *v6_v7;
	idasig_v8_v9_t *v8_v9;

	if (! (version = r_sign_is_flirt(flirt_buf)) ) {
		goto err_exit;
	}

	if ( version < 5 || version > 9 ) {
		anal->printf("Unsupported flirt signature version\n");
		goto err_exit;
	}

	if (! (header = R_NEW0(idasig_v5_t)))
		goto err_exit;

	parse_header(flirt_buf, header);

	if ( version >= 6 ) {
		if (! (v6_v7 = R_NEW0(idasig_v6_v7_t)) ) goto err_exit;
		if (! parse_v6_v7_header(flirt_buf, v6_v7) ) goto err_exit;

		if ( version >= 8 ) {
			if (! (v8_v9 = R_NEW0(idasig_v8_v9_t)) ) goto err_exit;
			if (! parse_v8_v9_header(flirt_buf, v8_v9) ) goto err_exit;
		}
	}

	name = malloc(header->library_name_len + 1);
	if (!name)
		goto err_exit;

	if (r_buf_read_at(flirt_buf, flirt_buf->cur, name, header->library_name_len) != header->library_name_len)
		goto err_exit;
	name[header->library_name_len] = '\0';

	eprintf("Name: %s\n", name);
	print_header(header);

	size = r_buf_size(flirt_buf) - flirt_buf->cur;
	buf = malloc(size);
	if (r_buf_read_at(flirt_buf, flirt_buf->cur, buf, size) != size)
		goto err_exit;

	if (header->features & IDASIG__FEATURE__COMPRESSED) {
		/*if (! (decompressed_buf = r_gunzip(buf, size, &decompressed_size))) {*/
		if (! r_zip_decompress(buf, size, &decompressed_buf, &decompressed_size)){
			eprintf("Decompressing failed.\n");
			goto err_exit;
		}

		free(buf);
		buf = decompressed_buf;
		size = decompressed_size;
	}

	RFlirtNode *node = R_NEW0(RFlirtNode);
	node->child_list = r_list_new();
	r_buf = r_buf_new();
	r_buf->buf = buf;
	r_buf->length = size;
	parse_tree(anal, r_buf, node);
	/*node_print(node, -1);*/

	RListIter *it;
	RFlirtNode *n;
	r_list_foreach(node->child_list, it, n) {
		node_match_buf(anal, 0L, buf, size, n);
	}

	node_free(node);
	free(buf);
	r_buf_free(buf_to_scan);
	r_buf_free(flirt_buf);
	free(header);
	free(name);
	return R_TRUE;

err_exit:
	eprintf("We encountered an error while parsing the file. Sorry.\n");
	r_buf_free(buf_to_scan);
	r_buf_free(flirt_buf);
	free(header);
	free(name);
	return R_FALSE;
}
