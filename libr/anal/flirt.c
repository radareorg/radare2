/* radare - LGPL - Copyright 2014-2024 - jfrankowski, pancake */
/* credits to IDA for the flirt tech */
/* original cpp code from Rheax <rheaxmascot@gmail.com> */
/* thanks LemonBoy for the improved research on rheax original work */
/* more information on flirt https://www.hex-rays.com/products/ida/tech/flirt/in_depth.shtml */

#define R_LOG_ORIGIN "anal.flirt"

#include <r_lib.h>
#include <r_sign.h>

#define DEBUG 0

/*
Flirt file format
=================
High level layout:
After the v5 header, there might be two more header fields depending of the version.
If version == 6 or version == 7, there is one more header field.
If version == 8 or version == 9, there is two more header field.
See idasig_v* structs for their description.
Next there is the non null terminated library name of library_name_len length.
Next see Parsing below.

Endianness:
All multi bytes values are stored in little endian form in the headers.
For the rest of the file they are stored in big endian form.

Parsing:
- described headers
- library name, not null terminated, length of library_name_len.

parse_tree (cf. parse_tree):
- read number of initial root nodes: 1 byte if strictly inferior to 127 otherwise 2 bytes,
stored in big endian mode, and the most significant bit isnt used. cf. read_multiple_bytes().
if 0, this is a leaf, goto leaf (cf. parse_leaf). else continue parsing (cf. parse_tree).

	- for number of root node do:
	 - read node length, one unsigned byte (the pattern size in this node) (cf. read_node_length)
	 - read node variant mask (bit array) (cf. read_node_variant_mask):
	  - if node length < 0x10 read up to two bytes. cf. read_max_2_bytes
	  - if node length < 0x20 read up to five bytes. cf. read_multiple_bytes
	 - read non-variant bytes (cf. read_node_bytes)
	 - goto parse_tree

	leaf (cf. parse_leaf):
	- read crc length, 1 byte
	- read crc value, 2 bytes
	module:
	 - read total module length:
	  - if version >= 9 read up to five bytes, cf. read_multiple_bytes
	  - else read up to two bytes, cf. read_max_2_bytes
	 - read module public functions (cf. read_module_public_functions):
	 same crc:
	  - public function name:
	     - read function offset:
	       if version >= 9 read up to five bytes, cf. read_multiple_bytes
	       else read up to two bytes, cf. read_max_2_bytes
	     - if current byte < 0x20, read it : this is a function flag, see IDASIG_FUNCTION* defines
	     - read function name until current byte < 0x20
	     - read parsing flag, 1 byte
	     - if flag & IDASIG__PARSE__MORE_PUBLIC_NAMES: goto public function name
	     - if flag & IDASIG__PARSE__READ_TAIL_BYTES, read tail bytes, cf. read_module_tail_bytes:
	       - if version >= 8: read number of tail bytes, else suppose one
	       - for number of tail bytes do:
		 - read tail byte offset:
		   if version >= 9 read up to five bytes, cf. read_multiple_bytes
		   else read up to two bytes, cf. read_max_2_bytes
		 - read tail byte value, one byte

	     - if flag & IDASIG__PARSE__READ_REFERENCED_FUNCTIONS, read referenced functions, cf. read_module_referenced_functions:
	       - if version >= 8: read number of referenced functions, else suppose one
	       - for number of referenced functions do:
		 - read referenced function offset:
		   if version >= 9 read up to five bytes, cf. read_multiple_bytes
		   else read up to two bytes, cf. read_max_2_bytes
		 - read referenced function name length, one byte:
		   - if name length == 0, read length up to five bytes, cf. read_multiple_bytes
		 - for name length, read name chars:
		   - if name is null terminated, it means the offset is negative

	     - if flag & IDASIG__PARSE__MORE_MODULES_WITH_SAME_CRC, goto same crc, read function with same crc
	     - if flag & IDASIG__PARSE__MORE_MODULES, goto module, to read another module

More Information
-----------------
Function flags:
- local functions ((l) with dumpsig) which are static ones.
- collision functions ((!) with dumpsig) are the result of an unresolved collision.

Tail bytes:
When two modules have the same pattern, and same crc, flirt tries to identify
a byte which is different in all the same modules.
Their offset is from the first byte after the crc.
They appear as "(XXXX: XX)" in dumpsig output

Referenced functions:
When two modules have the same pattern, and same crc, and are identical in
non-variant bytes, they only differ by the functions they call. These functions are
"referenced functions". They need to be identified first before the module can be
identified.
The offset is from the start of the function to the referenced function name.
They appear as "(REF XXXX: NAME)" in dumpsig output
*/

/* arch flags */
#define IDASIG__ARCH__386        0       // Intel 80x86
#define IDASIG__ARCH__Z80        1       // 8085, Z80
#define IDASIG__ARCH__I860       2       // Intel 860
#define IDASIG__ARCH__8051       3       // 8051
#define IDASIG__ARCH__TMS        4       // Texas Instruments TMS320C5x
#define IDASIG__ARCH__6502       5       // 6502
#define IDASIG__ARCH__PDP        6       // PDP11
#define IDASIG__ARCH__68K        7       // Motoroal 680x0
#define IDASIG__ARCH__JAVA       8       // Java
#define IDASIG__ARCH__6800       9       // Motorola 68xx
#define IDASIG__ARCH__ST7        10      // SGS-Thomson ST7
#define IDASIG__ARCH__MC6812     11      // Motorola 68HC12
#define IDASIG__ARCH__MIPS       12      // MIPS
#define IDASIG__ARCH__ARM        13      // Advanced RISC Machines
#define IDASIG__ARCH__TMSC6      14      // Texas Instruments TMS320C6x
#define IDASIG__ARCH__PPC        15      // PowerPC
#define IDASIG__ARCH__80196      16      // Intel 80196
#define IDASIG__ARCH__Z8         17      // Z8
#define IDASIG__ARCH__SH         18      // Renesas (formerly Hitachi) SuperH
#define IDASIG__ARCH__NET        19      // Microsoft Visual Studio.Net
#define IDASIG__ARCH__AVR        20      // Atmel 8-bit RISC processor(s)
#define IDASIG__ARCH__H8         21      // Hitachi H8/300, H8/2000
#define IDASIG__ARCH__PIC        22      // Microchip's PIC
#define IDASIG__ARCH__SPARC      23      // SPARC
#define IDASIG__ARCH__ALPHA      24      // DEC Alpha
#define IDASIG__ARCH__HPPA       25      // Hewlett-Packard PA-RISC
#define IDASIG__ARCH__H8500      26      // Hitachi H8/500
#define IDASIG__ARCH__TRICORE    27      // Tasking Tricore
#define IDASIG__ARCH__DSP56K     28      // Motorola DSP5600x
#define IDASIG__ARCH__C166       29      // Siemens C166 family
#define IDASIG__ARCH__ST20       30      // SGS-Thomson ST20
#define IDASIG__ARCH__IA64       31      // Intel Itanium IA64
#define IDASIG__ARCH__I960       32      // Intel 960
#define IDASIG__ARCH__F2MC       33      // Fujistu F2MC-16
#define IDASIG__ARCH__TMS320C54  34      // Texas Instruments TMS320C54xx
#define IDASIG__ARCH__TMS320C55  35      // Texas Instruments TMS320C55xx
#define IDASIG__ARCH__TRIMEDIA   36      // Trimedia
#define IDASIG__ARCH__M32R       37      // Mitsubishi 32bit RISC
#define IDASIG__ARCH__NEC_78K0   38      // NEC 78K0
#define IDASIG__ARCH__NEC_78K0S  39      // NEC 78K0S
#define IDASIG__ARCH__M740       40      // Mitsubishi 8bit
#define IDASIG__ARCH__M7700      41      // Mitsubishi 16bit
#define IDASIG__ARCH__ST9        42      // ST9+
#define IDASIG__ARCH__FR         43      // Fujitsu FR Family
#define IDASIG__ARCH__MC6816     44      // Motorola 68HC16
#define IDASIG__ARCH__M7900      45      // Mitsubishi 7900
#define IDASIG__ARCH__TMS320C3   46      // Texas Instruments TMS320C3
#define IDASIG__ARCH__KR1878     47      // Angstrem KR1878
#define IDASIG__ARCH__AD218X     48      // Analog Devices ADSP 218X
#define IDASIG__ARCH__OAKDSP     49      // Atmel OAK DSP
#define IDASIG__ARCH__TLCS900    50      // Toshiba TLCS-900
#define IDASIG__ARCH__C39        51      // Rockwell C39
#define IDASIG__ARCH__CR16       52      // NSC CR16
#define IDASIG__ARCH__MN102L00   53      // Panasonic MN10200
#define IDASIG__ARCH__TMS320C1X  54      // Texas Instruments TMS320C1x
#define IDASIG__ARCH__NEC_V850X  55      // NEC V850 and V850ES/E1/E2
#define IDASIG__ARCH__SCR_ADPT   56      // Processor module adapter for processor modules written in scripting languages
#define IDASIG__ARCH__EBC        57      // EFI Bytecode
#define IDASIG__ARCH__MSP430     58      // Texas Instruments MSP430
#define IDASIG__ARCH__SPU        59      // Cell Broadband Engine Synergistic Processor Unit
#define IDASIG__ARCH__DALVIK     60      // Android Dalvik Virtual Machine

/*file_types flags*/
#define IDASIG__FILE__DOS_EXE_OLD    0x00000001
#define IDASIG__FILE__DOS_COM_OLD    0x00000002
#define IDASIG__FILE__BIN            0x00000004
#define IDASIG__FILE__DOSDRV         0x00000008
#define IDASIG__FILE__NE             0x00000010
#define IDASIG__FILE__INTELHEX       0x00000020
#define IDASIG__FILE__MOSHEX         0x00000040
#define IDASIG__FILE__LX             0x00000080
#define IDASIG__FILE__LE             0x00000100
#define IDASIG__FILE__NLM            0x00000200
#define IDASIG__FILE__COFF           0x00000400
#define IDASIG__FILE__PE             0x00000800
#define IDASIG__FILE__OMF            0x00001000
#define IDASIG__FILE__SREC           0x00002000
#define IDASIG__FILE__ZIP            0x00004000
#define IDASIG__FILE__OMFLIB         0x00008000
#define IDASIG__FILE__AR             0x00010000
#define IDASIG__FILE__LOADER         0x00020000
#define IDASIG__FILE__ELF            0x00040000
#define IDASIG__FILE__W32RUN         0x00080000
#define IDASIG__FILE__AOUT           0x00100000
#define IDASIG__FILE__PILOT          0x00200000
#define IDASIG__FILE__DOS_EXE        0x00400000
#define IDASIG__FILE__DOS_COM        0x00800000
#define IDASIG__FILE__AIXAR          0x01000000

/*os_types flags*/
#define IDASIG__OS__MSDOS      0x01
#define IDASIG__OS__WIN        0x02
#define IDASIG__OS__OS2        0x04
#define IDASIG__OS__NETWARE    0x08
#define IDASIG__OS__UNIX       0x10
#define IDASIG__OS__OTHER      0x20

/*app types flags*/
#define IDASIG__APP__CONSOLE            0x0001
#define IDASIG__APP__GRAPHICS           0x0002
#define IDASIG__APP__EXE                0x0004
#define IDASIG__APP__DLL                0x0008
#define IDASIG__APP__DRV                0x0010
#define IDASIG__APP__SINGLE_THREADED    0x0020
#define IDASIG__APP__MULTI_THREADED     0x0040
#define IDASIG__APP__16_BIT             0x0080
#define IDASIG__APP__32_BIT             0x0100
#define IDASIG__APP__64_BIT             0x0200

/*feature flags*/
#define IDASIG__FEATURE__STARTUP          0x01
#define IDASIG__FEATURE__CTYPE_CRC        0x02
#define IDASIG__FEATURE__2BYTE_CTYPE      0x04
#define IDASIG__FEATURE__ALT_CTYPE_CRC    0x08
#define IDASIG__FEATURE__COMPRESSED       0x10

/*parsing flags*/
#define IDASIG__PARSE__MORE_PUBLIC_NAMES            0x01
#define IDASIG__PARSE__READ_TAIL_BYTES              0x02
#define IDASIG__PARSE__READ_REFERENCED_FUNCTIONS    0x04
#define IDASIG__PARSE__MORE_MODULES_WITH_SAME_CRC   0x08
#define IDASIG__PARSE__MORE_MODULES                 0x10

/*functions flags*/
#define IDASIG__FUNCTION__LOCAL                     0x02 // describes a static function
#define IDASIG__FUNCTION__UNRESOLVED_COLLISION      0x08 // describes a collision that wasn't resolved

R_PACKED(
typedef struct idasig_v5_t {
/* newer header only add fields, that's why we'll always read a v5 header first */
	ut8 magic[6];  /* should be set to IDASGN */
	ut8 version;   /*from 5 to 9*/
	ut8 arch;
	ut32 file_types;
	ut16 os_types;
	ut16 app_types;
	ut16 features;
	ut16 old_n_functions;
	ut16 crc16;
	ut8 ctype[12];  // XXX: how to use it
	ut8 library_name_len;
	ut16 ctypes_crc16;
}) idasig_v5_t;

R_PACKED(
typedef struct idasig_v6_v7_t {
	ut32 n_functions;
}) idasig_v6_v7_t;

R_PACKED(
typedef struct idasig_v8_v9_t {
	ut16 pattern_size;
}) idasig_v8_v9_t;

R_PACKED(
typedef struct idasig_v10_t {
	ut16 unknown;
}) idasig_v10_t;

/* newer header only add fields, that's why we'll always read a v5 header first */
#if 0
arch             : target architecture
file_types       : files where we expect to find the functions (exe, coff, ...)
os_types         : os where we expect to find the functions
app_types        : applications in which we expect to find the functions
features         : signature file features
old_n_functions  : number of functions
crc16            : certainly crc16 of the tree
ctype[12]        : unknown field
library_name_len : length of the library name, which is right after the header
ctypes_crc16     : unknown field
n_functions      : number of functions
pattern_size     : number of the leading pattern bytes
#endif

#define R_FLIRT_NAME_MAX 1024

typedef struct RFlirtTailByte {
	ut16 offset; // from pattern_size + crc_length
	ut8 value;
} RFlirtTailByte;

typedef struct RFlirtFunction {
	char name[R_FLIRT_NAME_MAX];
	ut16 offset; // function offset from the module start
	ut8 negative_offset; // true if offset is negative, for referenced functions
	ut8 is_local; // true if function is static
	ut8 is_collision; // true if was an unresolved collision
} RFlirtFunction;

typedef struct RFlirtModule {
	ut32 crc_length;
	ut32 crc16; // crc16 of the module after the pattern bytes
	// until but not including the first variant byte
	// this is a custom crc16
	ut16 length; // total length of the module, should < 0x8000
	RList *public_functions;
	RList *tail_bytes;
	RList *referenced_functions;
} RFlirtModule;

typedef struct {
	ut8 version;
	const RAnal *anal;
	int header_size;
	RBuffer *b;
	// this is ugly, but we can't afford to change the return size of read_byte
	bool buf_eof;
	bool buf_err;
} RFlirt;

typedef struct RFlirtNode {
	RList *child_list;
	RList *module_list;
	ut32 length; // length of the pattern
	ut64 variant_mask; // this is the mask that will define variant bytes in ut8 *pattern_bytes
	ut8 *pattern_bytes; // holds the pattern bytes of the signature
	ut8 *variant_bool_array; // bool array, if true, byte in pattern_bytes is a variant byte
} RFlirtNode;

// This is from flair tools flair/crc16.cpp
#define POLY ((ut32)0x8408)
ut16 crc16(const ut8 *data_p, size_t length) {
	ut8 i;
	ut32 data;
	ut32 crc = 0xFFFF;

	if (length == 0) {
		return 0;
	}
	do {
		data = *data_p++;
		for (i = 0; i < 8; i++) {
			if ((crc ^ data) & 1) {
				crc = (crc >> 1) ^ POLY;
			} else {
				crc >>= 1;
			}
			data >>= 1;
		}
	} while (--length > 0);

	crc = ~crc;
	data = crc;
	crc = (crc << 8) | ((data >> 8) & 0xff);
	return (ut16) (crc);
}

static ut8 read_byte(RFlirt *f) {
	ut8 r = 0;
	if (f->buf_eof || f->buf_err) {
		return 0;
	}
	int length = r_buf_read (f->b, &r, 1);
	if (length != 1) {
		r = 0;
		if (length == -1) {
			f->buf_err = true;
		} else if (length == 0) {
			f->buf_eof = true;
		}
	}
	return r;
}

static ut16 read_short(RFlirt *f) {
	ut16 r = read_byte (f);
	r <<= 8;
	r += read_byte (f);
	return r;
}

static ut32 read_word(RFlirt *f) {
	ut32 r = read_short (f);
	r <<= 16;
	r += read_short (f);
	return r;
}

static ut16 read_max_2_bytes(RFlirt *f) {
	const ut16 r = read_byte (f);
	return (r & 0x80) ? ((r & 0x7f) << 8) + read_byte (f) : r;
}

static ut32 read_multiple_bytes(RFlirt *f) {
	ut32 r = read_byte (f);
	if ((r & 0x80) != 0x80) {
		return r;
	}
	if ((r & 0xc0) != 0xc0) {
		return ((r & 0x7f) << 8) + read_byte (f);
	}
	if ((r & 0xe0) != 0xe0) {
		r = ((r & 0x3f) << 24) + (((ut32)read_byte (f)) << 16);
		r += read_short (f);
		return r;
	}
	return read_word (f);
}

static void module_free(RFlirtModule *module) {
	if (!module) {
		return;
	}
	if (module->public_functions) {
		module->public_functions->free = (RListFree) free;
		r_list_free (module->public_functions);
	}
	if (module->tail_bytes) {
		module->tail_bytes->free = (RListFree) free;
		r_list_free (module->tail_bytes);
	}
	if (module->referenced_functions) {
		module->referenced_functions->free = (RListFree) free;
		r_list_free (module->referenced_functions);
	}
	free (module);
}

static void node_free(RFlirtNode *node) {
	if (!node) {
		return;
	}
	free (node->variant_bool_array);
	free (node->pattern_bytes);
	if (node->module_list) {
		node->module_list->free = (RListFree)module_free;
		r_list_free (node->module_list);
	}
	if (node->child_list) {
		node->child_list->free = (RListFree) node_free;
		r_list_free (node->child_list);
	}
	free (node);
}

static void print_module(const RAnal *anal, const RFlirtModule *module) {
	RListIter *pub_func_it, *ref_func_it, *tail_byte_it;
	RFlirtFunction *func, *ref_func;
	RFlirtTailByte *tail_byte;

	anal->cb_printf ("%02X %04X %04X ", module->crc_length, module->crc16, module->length);
	r_list_foreach (module->public_functions, pub_func_it, func) {
		if (func->is_local || func->is_collision) {
			anal->cb_printf ("(");
			if (func->is_local) {
				anal->cb_printf ("l");
			}
			if (func->is_collision) {
				anal->cb_printf ("!");
			}
			anal->cb_printf (")");
		}
		anal->cb_printf ("%04X:%s", func->offset, func->name);
		if (pub_func_it->n) {
			anal->cb_printf (" ");
		}
	}
	if (module->tail_bytes) {
		r_list_foreach (module->tail_bytes, tail_byte_it, tail_byte) {
			anal->cb_printf (" (%04X: %02X)", tail_byte->offset, tail_byte->value);
		}
	}
	if (module->referenced_functions) {
		anal->cb_printf (" (REF ");
		r_list_foreach (module->referenced_functions, ref_func_it, ref_func) {
			anal->cb_printf ("%04X: %s", ref_func->offset, ref_func->name);
			if (ref_func_it->n) {
				anal->cb_printf (" ");
			}
		}
		anal->cb_printf (")");
	}
	anal->cb_printf ("\n");
}


static void print_node_pattern(const RAnal *anal, const RFlirtNode *node) {
	int i;
	for (i = 0; i < node->length; i++) {
		if (node->variant_bool_array[i]) {
			anal->cb_printf ("..");
		} else {
			anal->cb_printf ("%02X", node->pattern_bytes[i]);
		}
	}
	anal->cb_printf (":\n");
}

static void print_indentation(const RAnal *anal, int indent) {
	anal->cb_printf ("%s", r_str_pad (' ', indent));
}

static void print_node(const RAnal *anal, const RFlirtNode *node, int indent) {
	/*Prints a signature node. The output is similar to dumpsig*/
	int i;
	RListIter *child_it, *module_it;
	RFlirtNode *child;
	RFlirtModule *module;

	if (node->pattern_bytes) { // avoid printing the root node
		print_indentation (anal, indent);
		print_node_pattern (anal, node);
	}
	if (node->child_list) {
		r_list_foreach (node->child_list, child_it, child) {
			print_node (anal, child, indent + 1);
		}
	} else if (node->module_list) {
		i = 0;
		r_list_foreach (node->module_list, module_it, module) {
			print_indentation (anal, indent + 1);
			anal->cb_printf ("%d. ", i);
			print_module (anal, module);
			i++;
		}
	}
}

static bool module_match_buffer(RAnal *anal, const RFlirtModule *module, ut8 *b, ut64 address, ut32 buf_size) {
	/* Returns true if module matches b, according to the signatures infos.
	* Return false otherwise.
	* The buffer starts from the first byte after the pattern */
	RFlirtFunction *flirt_func;
	RAnalFunction *next_module_function;
	RListIter *tail_byte_it, *flirt_func_it;
	RFlirtTailByte *tail_byte;

	if (32 + module->crc_length < buf_size && module->crc16 != crc16 (b + 32, module->crc_length)) {
		return false;
	}
	if (module->tail_bytes) {
		r_list_foreach (module->tail_bytes, tail_byte_it, tail_byte) {
			if (32 + module->crc_length + tail_byte->offset < buf_size && b[32 + module->crc_length + tail_byte->offset] != tail_byte->value) {
				return false;
			}
		}
	}

	// TODO referenced functions
	r_list_foreach (module->public_functions, flirt_func_it, flirt_func) {
		// Once the first module function is found, we need to go through the module->public_functions
		// list to identify the others. See flirt doc for more information

		next_module_function = r_anal_get_function_at ((RAnal *) anal, address + flirt_func->offset);
		if (next_module_function) {
			char *name;
			int name_offs = 0;
			ut32 next_module_function_size;

			// get function size from flirt signature
			ut64 flirt_fcn_size = module->length - flirt_func->offset;
			RFlirtFunction *next_flirt_func;
			RListIter *next_flirt_func_it = flirt_func_it->n;
			while (next_flirt_func_it) {
				next_flirt_func = next_flirt_func_it->data;
				if (!next_flirt_func->is_local && !next_flirt_func->negative_offset) {
					flirt_fcn_size = next_flirt_func->offset - flirt_func->offset;
					break;
				}
				next_flirt_func_it = next_flirt_func_it->n;
			}
			// resize function if needed
			next_module_function_size = r_anal_function_linear_size (next_module_function);
			if (next_module_function_size < flirt_fcn_size) {
				RListIter *iter;
				RListIter *iter_tmp;
				RAnalFunction *fcn;
				r_list_foreach_safe (anal->fcns, iter, iter_tmp, fcn) {
					if (fcn != next_module_function &&
							fcn->addr >= next_module_function->addr + next_module_function_size &&
							fcn->addr < next_module_function->addr + flirt_fcn_size) {
						RListIter *iter_bb;
						RAnalBlock *block;
						r_list_foreach (fcn->bbs, iter_bb, block) {
							r_anal_function_add_block (next_module_function, block);
						}
						next_module_function->ninstr += fcn->ninstr;
						r_anal_function_delete (fcn);
					}
				}
				r_anal_function_resize (next_module_function, flirt_fcn_size);
				next_module_function_size = r_anal_function_linear_size (next_module_function);
				r_anal_trim_jmprefs ((RAnal *)anal, next_module_function);
			}

			while (flirt_func->name[name_offs] == '?') { // skip '?' chars
				name_offs++;
			}
			if (!flirt_func->name[name_offs]) {
				continue;
			}
			name = r_name_filter_dup (flirt_func->name + name_offs);
			free (next_module_function->name);
			next_module_function->name = r_str_newf ("flirt.%s", name);
			anal->flb.set (anal->flb.f, next_module_function->name,
				next_module_function->addr, next_module_function_size);
			anal->cb_printf ("Found %s\n", next_module_function->name);
			free (name);
		}
	}
	return true;
}

/* Returns true if b matches the pattern in node. */
/* Returns false otherwise. */
static bool node_pattern_match(const RFlirtNode *node, ut8 *b, int buf_size) {
	int i;
	if (buf_size < node->length) {
		return false;
	}
	for (i = 0; i < node->length; i++) {
		if (!node->variant_bool_array[i]) {
			if (i < node->length && node->pattern_bytes[i] != b[i]) {
				return false;
			}
		}
	}
	return true;
}

static bool node_match_buffer(RAnal *anal, const RFlirtNode *node, ut8 *b, ut64 address, ut32 buf_size, ut32 buf_idx) {
	RListIter *node_child_it, *module_it;
	RFlirtNode *child;
	RFlirtModule *module;

	if (node_pattern_match (node, b + buf_idx, buf_size - buf_idx)) {
		if (node->child_list) {
			r_list_foreach (node->child_list, node_child_it, child) {
				if (node_match_buffer (anal, child, b, address, buf_size, buf_idx + node->length)) {
					return true;
				}
			}
		} else if (node->module_list) {
			r_list_foreach (node->module_list, module_it, module) {
				if (module_match_buffer (anal, module, b, address, buf_size)) {
					return true;
				}
			}
		}
	}
	return false;
}

static bool node_match_functions(RAnal *anal, const RFlirtNode *root_node) {
	/* Tries to find matching functions between the signature infos in root_node
	* and the analyzed functions in anal
	* Returns false on error. */

	if (r_list_length (anal->fcns) == 0) {
		R_LOG_INFO ("Nothing to do when no functions have been analyzed. Try running `aa`");
		return false;
	}

	anal->flb.push_fs (anal->flb.f, "flirt");
	RListIter *it_func;
	RAnalFunction *func;
	r_list_foreach (anal->fcns, it_func, func) {
		ut64 func_size = r_anal_function_linear_size (func);
		ut8 *func_buf = malloc (func_size);
		if (!func_buf) {
			continue;
		}
		if (!anal->iob.read_at (anal->iob.io, func->addr, func_buf, (int)func_size)) {
			R_LOG_WARN ("Couldn't read function %s at 0x%"PFMT64x, func->name, func->addr);
			free (func_buf);
			continue;
		}
		RListIter *node_child_it;
		RFlirtNode *child;
		r_list_foreach (root_node->child_list, node_child_it, child) {
			if (node_match_buffer (anal, child, func_buf, func->addr, func_size, 0)) {
				break;
			}
		}
		free (func_buf);
	}
	anal->flb.pop_fs (anal->flb.f);

	return true;
}

// parses a module tail bytes, returns false on parsing error
static ut8 read_module_tail_bytes(RFlirt *f, RFlirtModule *module) {
	int i;
	ut8 number_of_tail_bytes = 1;
	RFlirtTailByte *tail_byte = NULL;
	if (!(module->tail_bytes = r_list_newf ((RListFree) free))) {
		goto beach;
	}

	if (f->version >= 8) { // this counter was introduced in version 8
		number_of_tail_bytes = read_byte (f); // XXX are we sure it's not read_multiple_bytes?
		if (f->buf_eof || f->buf_err) {
			goto beach;
		}
	}
	for (i = 0; i < number_of_tail_bytes; i++) {
		tail_byte = R_NEW0 (RFlirtTailByte);
		if (!tail_byte) {
			return false;
		}
		if (f->version >= 9) {
			// /!\ XXX don't trust ./zipsig output because it will write a version 9 header, but keep the old version offsets
			tail_byte->offset = read_multiple_bytes (f);
			if (f->buf_eof || f->buf_err) {
				goto beach;
			}
		} else {
			tail_byte->offset = read_max_2_bytes (f);
			if (f->buf_eof || f->buf_err) {
				goto beach;
			}
		}
		tail_byte->value = read_byte (f);
		if (f->buf_eof || f->buf_err) {
			goto beach;
		}
		r_list_append (module->tail_bytes, tail_byte);
		R_LOG_DEBUG ("READ TAIL BYTE: %04X: %02X", tail_byte->offset, tail_byte->value);
	}

	return true;

beach:
	free (tail_byte);
	r_list_free (module->tail_bytes);
	module->tail_bytes = NULL;
	return false;
}

// parses a module referenced functions, returns false on parsing error
static ut8 read_module_referenced_functions(RFlirt *f, RFlirtModule *module) {
	int i, j;
	ut8 number_of_referenced_functions;
	ut32 ref_function_name_length;
	RFlirtFunction *ref_function = NULL;

	module->referenced_functions = r_list_new ();

	if (f->version >= 8) { // this counter was introduced in version 8
		number_of_referenced_functions = read_byte (f); // XXX are we sure it's not read_multiple_bytes?
		if (f->buf_eof || f->buf_err) {
			goto beach;
		}
	} else { // suppose there's only one
		number_of_referenced_functions = 1;
	}

	for (i = 0; i < number_of_referenced_functions; i++) {
		ref_function = R_NEW0 (RFlirtFunction);
		if (!ref_function) {
			goto beach;
		}
		if (f->version >= 9) {
			ref_function->offset = read_multiple_bytes (f);
			if (f->buf_eof || f->buf_err) {
				goto beach;
			}
		} else {
			ref_function->offset = read_max_2_bytes (f);
			if (f->buf_eof || f->buf_err) {
				goto beach;
			}
		}
		ref_function_name_length = read_byte (f);
		if (f->buf_eof || f->buf_err) {
			goto beach;
		}
		if (!ref_function_name_length) {
			// not sure why it's not read_multiple_bytes() in the first place
			ref_function_name_length = read_multiple_bytes (f); // XXX might be read_max_2_bytes, need more data
			if (f->buf_eof || f->buf_err) {
				goto beach;
			}
		}
		if ((int) ref_function_name_length < 0 || ref_function_name_length >= R_FLIRT_NAME_MAX) {
			goto beach;
		}
		for (j = 0; j < ref_function_name_length; j++) {
			ref_function->name[j] = read_byte (f);
			if (f->buf_eof || f->buf_err) {
				goto beach;
			}
		}
		if (!ref_function->name[ref_function_name_length]) {
			// if the last byte of the name is 0, it means the offset is negative
			ref_function->negative_offset = true;
		} else {
			ref_function->name[ref_function_name_length] = '\0';
		}
		r_list_append (module->referenced_functions, ref_function);
		R_LOG_DEBUG ("(REF: %04X: %s)", ref_function->offset, ref_function->name);
	}

	return true;

beach:
	module->referenced_functions = NULL;
	free (ref_function);
	return false;
}

// Reads and set the public functions names and offsets associated within a module, returns false on parsing error
static ut8 read_module_public_functions(RFlirt *f, RFlirtModule *module, ut8 *flags) {
	int i;
	ut16 offset = 0;
	ut8 current_byte;

	module->public_functions = r_list_new ();
	RFlirtFunction *function = NULL;

	do {
		if (f->version >= 9) {   // seems like version 9 introduced some larger offsets
			offset += read_multiple_bytes (f); // offsets are dependent of the previous ones
			if (f->buf_eof || f->buf_err) {
				goto beach;
			}
		} else {
			offset += read_max_2_bytes (f); // offsets are dependent of the previous ones
			if (f->buf_eof || f->buf_err) {
				goto beach;
			}
		}
		function = R_NEW0 (RFlirtFunction);
		function->offset = offset;

		current_byte = read_byte (f);
		if (f->buf_eof || f->buf_err) {
			goto beach;
		}
		if (current_byte < 0x20) {
			if (current_byte & IDASIG__FUNCTION__LOCAL) { // static function
				function->is_local = true;
			}
			if (current_byte & IDASIG__FUNCTION__UNRESOLVED_COLLISION) {
				// unresolved collision (happens in *.exc while creating .sig from .pat)
				function->is_collision = true;
			}
#if DEBUG
			if (current_byte & 0x01 || current_byte & 0x04) { // appears as 'd' or '?' in dumpsig
				R_LOG_DEBUG ("Investigate public name: %02X @ %04X", current_byte, r_buf_tell (f->b) + f->header_size);
			}
#endif
			current_byte = read_byte (f);
			if (f->buf_eof || f->buf_err) {
				goto beach;
			}
		}

		for (i = 0; current_byte >= 0x20 && i < R_FLIRT_NAME_MAX; i++) {
			function->name[i] = current_byte;
			current_byte = read_byte (f);
			if (f->buf_eof || f->buf_err) {
				goto beach;
			}
		}

		if (i == R_FLIRT_NAME_MAX) {
			R_LOG_INFO ("Function name too long");
			function->name[R_FLIRT_NAME_MAX - 1] = '\0';
		} else {
			function->name[i] = '\0';
		}
		R_LOG_ERROR ("%04X:%s ", function->offset, function->name);
		*flags = current_byte;
		r_list_append (module->public_functions, function);
	} while (*flags & IDASIG__PARSE__MORE_PUBLIC_NAMES);
#if DEBUG
	eprintf ("\n");
#endif
	return true;

beach:
	free (function);
	return false;
}

// parses a signature leaf: modules with same leading pattern, returns false on parsing error
static bool parse_leaf(RFlirt *f, RFlirtNode *node) {
	ut8 flags = 0;
	RFlirtModule *module = NULL;

	node->module_list = r_list_new ();
	do { // loop for all modules having the same prefix
		ut8 crc_length = read_byte (f);
		if (f->buf_eof || f->buf_err) {
			goto beach;
		}
		ut16 crc16 = read_short (f);
		if (f->buf_eof || f->buf_err) {
			goto beach;
		}
		do { // loop for all modules having the same crc
			module = R_NEW0 (RFlirtModule);
			if (!module) {
				goto beach;
			}
			module->crc_length = crc_length;
			module->crc16 = crc16;
			if (f->version >= 9) { // seems like version 9 introduced some larger length
				/*/!\ XXX don't trust ./zipsig output because it will write a version 9 header, but keep the old version offsets*/
				module->length = read_multiple_bytes (f); // should be < 0x8000
				if (f->buf_eof || f->buf_err) {
					goto beach;
				}
			} else {
				module->length = read_max_2_bytes (f); // should be < 0x8000
				if (f->buf_eof || f->buf_err) {
					goto beach;
				}
			}
			R_LOG_DEBUG ("module_length: %04X", module->length);

			if (!read_module_public_functions (f, module, &flags)) {
				goto beach;
			}

			if (flags & IDASIG__PARSE__READ_TAIL_BYTES) { // we need to read some tail bytes because in this leaf we have functions with same crc
				if (!read_module_tail_bytes (f, module)) {
					goto beach;
				}
			}
			if (flags & IDASIG__PARSE__READ_REFERENCED_FUNCTIONS) { // we need to read some referenced functions
				if (!read_module_referenced_functions (f, module)) {
					goto beach;
				}
			}
			r_list_append (node->module_list, module);
		} while (flags & IDASIG__PARSE__MORE_MODULES_WITH_SAME_CRC);
	} while (flags & IDASIG__PARSE__MORE_MODULES); // same prefix but different crc

	return true;

beach:
	module_free (module);
	return false;
}

static bool read_node_length(RFlirt *f, RFlirtNode *node) {
	node->length = read_byte (f);
	if (f->buf_eof || f->buf_err) {
		return false;
	}
	R_LOG_DEBUG ("flirt node length: %02X", node->length);
	return true;
}

static bool read_node_variant_mask(RFlirt *f, RFlirtNode *node) {
	// Reads and sets a node's variant bytes mask. This mask is then used to
	// read the non-variant bytes following, returns false on parsing error
	if (node->length < 16) {
		node->variant_mask = read_max_2_bytes (f);
	} else if (node->length <= 32) {
		node->variant_mask = read_multiple_bytes (f);
	} else if (node->length <= 64) { // it shouldn't be more than 64 bits
		node->variant_mask = (((ut64)read_multiple_bytes (f)) << 32) + read_multiple_bytes (f);
	}
	return (!f->buf_eof && !f->buf_err);
}

// Reads the node bytes, and also sets the variant bytes in variant_bool_array, returns false on parsing error
static bool read_node_bytes(RFlirt *f, RFlirtNode *node) {
	int i;
	if ((int) node->length < 0) {
		return false;
	}
	if (node->length > 63) {
		R_LOG_ERROR ("Invalid flirt node size %d", node->length);
		return false;
	}
	ut64 current_mask_bit = 1ULL << (node->length - 1);
	if (!(node->pattern_bytes = malloc (node->length))) {
		return false;
	}
	if (!(node->variant_bool_array = malloc (node->length))) {
		return false;
	}
	for (i = 0; i < node->length; i++, current_mask_bit >>= 1) {
		node->variant_bool_array[i] = (bool)(node->variant_mask & current_mask_bit);
		if (node->variant_mask & current_mask_bit) {
			node->pattern_bytes[i] = 0;
		} else {
			node->pattern_bytes[i] = read_byte (f);
			if (f->buf_eof || f->buf_err) {
				return false;
			}
		}
	}
	return true;
}

// parse a signature pattern tree or sub-tree, returns false on parsing error
static bool parse_tree(RFlirt *f, RFlirtNode *root_node) {
	RFlirtNode *node = NULL;
	int i, tree_nodes = read_multiple_bytes (f);
	if (f->buf_eof || f->buf_err) {
		R_LOG_ERROR ("eof");
		return false;
	}
	if (tree_nodes == 0) {
		// if there's no tree nodes remaining, that means we are on the leaf
		return parse_leaf (f, root_node);
	}
	root_node->child_list = r_list_new ();
	for (i = 0; i < tree_nodes; i++) {
		node = R_NEW0 (RFlirtNode);
		if (!node) {
			goto beach;
		}
		if (!read_node_length (f, node)) {
			goto beach;
		}
		if (!read_node_variant_mask (f, node)) {
			goto beach;
		}
		if (!read_node_bytes (f, node)) {
			goto beach;
		}
		r_list_append (root_node->child_list, node);
		if (!parse_tree (f, node)) {
			R_LOG_DEBUG ("flirst child node parsing fails");
			goto beach;
		}
	}
	return true;
beach:
	r_list_free (root_node->child_list);
	root_node->child_list = NULL;
	node_free (node);
	return false;
}

#if DEBUG

#define PRINT_ARCH(define, str) if (arch == define) { eprintf (" %s", str); return; }
static void print_arch(ut8 arch) {
	PRINT_ARCH (IDASIG__ARCH__386, "386");
	PRINT_ARCH (IDASIG__ARCH__Z80, "Z80");
	PRINT_ARCH (IDASIG__ARCH__I860, "I860");
	PRINT_ARCH (IDASIG__ARCH__8051, "8051");
	PRINT_ARCH (IDASIG__ARCH__TMS, "TMS");
	PRINT_ARCH (IDASIG__ARCH__6502, "6502");
	PRINT_ARCH (IDASIG__ARCH__PDP, "PDP");
	PRINT_ARCH (IDASIG__ARCH__68K, "68K");
	PRINT_ARCH (IDASIG__ARCH__JAVA, "JAVA");
	PRINT_ARCH (IDASIG__ARCH__6800, "6800");
	PRINT_ARCH (IDASIG__ARCH__ST7, "ST7");
	PRINT_ARCH (IDASIG__ARCH__MC6812, "MC6812");
	PRINT_ARCH (IDASIG__ARCH__MIPS, "MIPS");
	PRINT_ARCH (IDASIG__ARCH__ARM, "ARM");
	PRINT_ARCH (IDASIG__ARCH__TMSC6, "TMSC6");
	PRINT_ARCH (IDASIG__ARCH__PPC, "PPC");
	PRINT_ARCH (IDASIG__ARCH__80196, "80196");
	PRINT_ARCH (IDASIG__ARCH__Z8, "Z8");
	PRINT_ARCH (IDASIG__ARCH__SH, "SH");
	PRINT_ARCH (IDASIG__ARCH__NET, "NET");
	PRINT_ARCH (IDASIG__ARCH__AVR, "AVR");
	PRINT_ARCH (IDASIG__ARCH__H8, "H8");
	PRINT_ARCH (IDASIG__ARCH__PIC, "PIC");
	PRINT_ARCH (IDASIG__ARCH__SPARC, "SPARC");
	PRINT_ARCH (IDASIG__ARCH__ALPHA, "ALPHA");
	PRINT_ARCH (IDASIG__ARCH__HPPA, "HPPA");
	PRINT_ARCH (IDASIG__ARCH__H8500, "H8500");
	PRINT_ARCH (IDASIG__ARCH__TRICORE, "TRICORE");
	PRINT_ARCH (IDASIG__ARCH__DSP56K, "DSP56K");
	PRINT_ARCH (IDASIG__ARCH__C166, "C166");
	PRINT_ARCH (IDASIG__ARCH__ST20, "ST20");
	PRINT_ARCH (IDASIG__ARCH__IA64, "IA64");
	PRINT_ARCH (IDASIG__ARCH__I960, "I960");
	PRINT_ARCH (IDASIG__ARCH__F2MC, "F2MC");
	PRINT_ARCH (IDASIG__ARCH__TMS320C54, "TMS320C54");
	PRINT_ARCH (IDASIG__ARCH__TMS320C55, "TMS320C55");
	PRINT_ARCH (IDASIG__ARCH__TRIMEDIA, "TRIMEDIA");
	PRINT_ARCH (IDASIG__ARCH__M32R, "M32R");
	PRINT_ARCH (IDASIG__ARCH__NEC_78K0, "NEC_78K0");
	PRINT_ARCH (IDASIG__ARCH__NEC_78K0S, "NEC_78K0S");
	PRINT_ARCH (IDASIG__ARCH__M740, "M740");
	PRINT_ARCH (IDASIG__ARCH__M7700, "M7700");
	PRINT_ARCH (IDASIG__ARCH__ST9, "ST9");
	PRINT_ARCH (IDASIG__ARCH__FR, "FR");
	PRINT_ARCH (IDASIG__ARCH__MC6816, "MC6816");
	PRINT_ARCH (IDASIG__ARCH__M7900, "M7900");
	PRINT_ARCH (IDASIG__ARCH__TMS320C3, "TMS320C3");
	PRINT_ARCH (IDASIG__ARCH__KR1878, "KR1878");
	PRINT_ARCH (IDASIG__ARCH__AD218X, "AD218X");
	PRINT_ARCH (IDASIG__ARCH__OAKDSP, "OAKDSP");
	PRINT_ARCH (IDASIG__ARCH__TLCS900, "TLCS900");
	PRINT_ARCH (IDASIG__ARCH__C39, "C39");
	PRINT_ARCH (IDASIG__ARCH__CR16, "CR16");
	PRINT_ARCH (IDASIG__ARCH__MN102L00, "MN102L00");
	PRINT_ARCH (IDASIG__ARCH__TMS320C1X, "TMS320C1X");
	PRINT_ARCH (IDASIG__ARCH__NEC_V850X, "NEC_V850X");
	PRINT_ARCH (IDASIG__ARCH__SCR_ADPT, "SCR_ADPT");
	PRINT_ARCH (IDASIG__ARCH__EBC, "EBC");
	PRINT_ARCH (IDASIG__ARCH__MSP430, "MSP430");
	PRINT_ARCH (IDASIG__ARCH__SPU, "SPU");
	PRINT_ARCH (IDASIG__ARCH__DALVIK, "DALVIK");
}

#define PRINT_FLAG(define, str) if (flags & define) { eprintf (" %s", str); }
static void print_file_types(ut32 flags) {
	PRINT_FLAG (IDASIG__FILE__DOS_EXE_OLD, "DOS_EXE_OLD");
	PRINT_FLAG (IDASIG__FILE__DOS_COM_OLD, "DOS_COM_OLD");
	PRINT_FLAG (IDASIG__FILE__BIN, "BIN");
	PRINT_FLAG (IDASIG__FILE__DOSDRV, "DOSDRV");
	PRINT_FLAG (IDASIG__FILE__NE, "NE");
	PRINT_FLAG (IDASIG__FILE__INTELHEX, "INTELHEX");
	PRINT_FLAG (IDASIG__FILE__MOSHEX, "MOSHEX");
	PRINT_FLAG (IDASIG__FILE__LX, "LX");
	PRINT_FLAG (IDASIG__FILE__LE, "LE");
	PRINT_FLAG (IDASIG__FILE__NLM, "NLM");
	PRINT_FLAG (IDASIG__FILE__COFF, "COFF");
	PRINT_FLAG (IDASIG__FILE__PE, "PE");
	PRINT_FLAG (IDASIG__FILE__OMF, "OMF");
	PRINT_FLAG (IDASIG__FILE__SREC, "SREC");
	PRINT_FLAG (IDASIG__FILE__ZIP, "ZIP");
	PRINT_FLAG (IDASIG__FILE__OMFLIB, "OMFLIB");
	PRINT_FLAG (IDASIG__FILE__AR, "AR");
	PRINT_FLAG (IDASIG__FILE__LOADER, "LOADER");
	PRINT_FLAG (IDASIG__FILE__ELF, "ELF");
	PRINT_FLAG (IDASIG__FILE__W32RUN, "W32RUN");
	PRINT_FLAG (IDASIG__FILE__AOUT, "AOUT");
	PRINT_FLAG (IDASIG__FILE__PILOT, "PILOT");
	PRINT_FLAG (IDASIG__FILE__DOS_EXE, "EXE");
	PRINT_FLAG (IDASIG__FILE__AIXAR, "AIXAR");
}

static void print_os_types(ut16 flags) {
	PRINT_FLAG (IDASIG__OS__MSDOS, "MSDOS");
	PRINT_FLAG (IDASIG__OS__WIN, "WIN");
	PRINT_FLAG (IDASIG__OS__OS2, "OS2");
	PRINT_FLAG (IDASIG__OS__NETWARE, "NETWARE");
	PRINT_FLAG (IDASIG__OS__UNIX, "UNIX");
}

static void print_app_types(ut16 flags) {
	PRINT_FLAG (IDASIG__APP__CONSOLE, "CONSOLE");
	PRINT_FLAG (IDASIG__APP__GRAPHICS, "GRAPHICS");
	PRINT_FLAG (IDASIG__APP__EXE, "EXE");
	PRINT_FLAG (IDASIG__APP__DLL, "DLL");
	PRINT_FLAG (IDASIG__APP__DRV, "DRV");
	PRINT_FLAG (IDASIG__APP__SINGLE_THREADED, "SINGLE_THREADED");
	PRINT_FLAG (IDASIG__APP__MULTI_THREADED, "MULTI_THREADED");
	PRINT_FLAG (IDASIG__APP__16_BIT, "16_BIT");
	PRINT_FLAG (IDASIG__APP__32_BIT, "32_BIT");
	PRINT_FLAG (IDASIG__APP__64_BIT, "64_BIT");
}

static void print_features(ut16 flags) {
	PRINT_FLAG (IDASIG__FEATURE__STARTUP, "STARTUP");
	PRINT_FLAG (IDASIG__FEATURE__CTYPE_CRC, "CTYPE_CRC");
	PRINT_FLAG (IDASIG__FEATURE__2BYTE_CTYPE, "2BYTE_CTYPE");
	PRINT_FLAG (IDASIG__FEATURE__ALT_CTYPE_CRC, "ALT_CTYPE_CRC");
	PRINT_FLAG (IDASIG__FEATURE__COMPRESSED, "COMPRESSED");
}

static void print_header(idasig_v5_t *header) {
	// eprintf("magic: %s\n", header->magic);
	eprintf ("version: %d\n", header->version);
	eprintf ("arch:"); print_arch (header->arch); eprintf ("\n");
	eprintf ("file_types:"); print_file_types (header->file_types); eprintf ("\n");
	eprintf ("os_types:"); print_os_types (header->os_types); eprintf ("\n");
	eprintf ("app_types:"); print_app_types (header->app_types); eprintf ("\n");
	eprintf ("features:"); print_features (header->features); eprintf ("\n");
	eprintf ("old_n_functions: %04x\n", header->old_n_functions);
	eprintf ("crc16: %04x\n", header->crc16);
	eprintf ("ctype: %s\n", header->ctype);
	eprintf ("library_name_len: %d\n", header->library_name_len);
	eprintf ("ctypes_crc16: %04x\n", header->ctypes_crc16);
}
#endif

static idasig_v5_t *parse_header(RFlirt *f) {
	idasig_v5_t *header = R_NEW0 (idasig_v5_t);
	if (!header) {
		return NULL;
	}
	RBuffer *buf = f->b;
	if (r_buf_fread (buf, (ut8 *)header, "8ci5s13cs", 1) != sizeof (idasig_v5_t)) {
		free (header);
		return NULL;
	}
	return header;
}

static idasig_v6_v7_t *parse_v6_v7_header(RFlirt *f) {
	idasig_v6_v7_t *header = R_NEW0 (idasig_v6_v7_t);
	if (!header) {
		return NULL;
	}
	RBuffer *buf = f->b;
	if (r_buf_fread (buf, (ut8 *)header, "i", 1) != sizeof (idasig_v6_v7_t)) {
		free (header);
		return NULL;
	}
	return header;
}

static idasig_v8_v9_t *parse_v8_v9_header(RFlirt *f) {
	idasig_v8_v9_t *header = R_NEW0 (idasig_v8_v9_t);
	if (!header) {
		return NULL;
	}
	RBuffer *buf = f->b;
	if (r_buf_fread (buf, (ut8 *)header, "s", 1) != sizeof (idasig_v8_v9_t)) {
		free (header);
		return NULL;
	}
	return header;
}

static idasig_v10_t *parse_v10_header(RFlirt *f) {
	idasig_v10_t *header = R_NEW0 (idasig_v10_t);
	if (!header) {
		return NULL;
	}
	RBuffer *buf = f->b;
	if (r_buf_fread (buf, (ut8 *)header, "s", 1) != sizeof (idasig_v10_t)) {
		free (header);
		return NULL;
	}
	return header;
}

static RFlirtNode *flirt_parse(RFlirt *f) {
	char *name = NULL;
	idasig_v5_t *header = NULL;
	ut8 *buf = NULL;
	int decompressed_size = 0;
	RFlirtNode *node = NULL;
	RFlirtNode *ret = NULL;

	// TODO: remove as its implicit with rbuffer imho
	f->buf_eof = false;
	f->buf_err = false;

	int version = r_sign_is_flirt (f->b);
	if (version < 1) {
		R_LOG_ERROR ("Invalid flirt version");
		goto beach;
	}
	f->version = version;
	if (version < 5 || version > 10) {
		R_LOG_ERROR ("Unsupported flirt signature version");
		goto beach;
	}

	r_buf_seek (f->b, 0, R_BUF_SET);
	header = parse_header (f);
	if (!header) {
		R_LOG_ERROR ("Cannot parse flirt header");
		goto beach;
	}
	if (version >= 6) {
		idasig_v6_v7_t *v6_v7 = parse_v6_v7_header (f);
		if (!v6_v7) {
			R_LOG_ERROR ("Cannot parse v6/v7 header");
			goto beach;
		}
		free (v6_v7);
		if (version >= 8) {
			idasig_v8_v9_t *v8_v9 = parse_v8_v9_header (f);
			if (!v8_v9) {
				R_LOG_ERROR ("Cannot parse v8/v9 header");
				goto beach;
			}
			if (version >= 10) {
				idasig_v10_t *v10 = parse_v10_header (f);
				if (!v10) {
					R_LOG_ERROR ("Cannot parse v10 header");
					goto beach;
				}
				free (v10);
			}
			free (v8_v9);
		}
	}

	name = malloc (header->library_name_len + 1);
	if (!name) {
		goto beach;
	}

	if (r_buf_read (f->b, (ut8*)name, header->library_name_len) != header->library_name_len) {
		goto beach;
	}

	name[header->library_name_len] = '\0';

	R_LOG_DEBUG ("Loading %s", name);
#if DEBUG
	print_header (header);
#endif
	f->header_size = r_buf_tell (f->b);

	int size = r_buf_size (f->b) - r_buf_tell (f->b);
	if (size < 1 || !(buf = malloc (size))) {
		R_LOG_ERROR ("Invalid remaining size");
		goto beach;
	}
	if (r_buf_read (f->b, buf, size) != size) {
		goto beach;
	}

	if (header->features & IDASIG__FEATURE__COMPRESSED) {
		ut8 *dbuf = NULL;
		if (version == 5 || version == 6) {
			dbuf = r_inflate_raw (buf, size, NULL, &decompressed_size);
		} else if (version >= 7) {
			dbuf = r_inflate (buf, size, NULL, &decompressed_size);
		} else {
			R_LOG_ERROR ("FLIRT signatures version %d is not supported", version);
			goto beach;
		}
		if (!dbuf) {
			R_LOG_ERROR ("FLIRT Decompression failed");
			goto beach;
		}
		R_FREE (buf);
		buf = dbuf;
		size = decompressed_size;
	}

	if (!(node = R_NEW0 (RFlirtNode))) {
		goto beach;
	}
	f->buf_eof = false;
	f->buf_err = false;
	r_buf_free (f->b);
	f->b = r_buf_new_with_pointers (buf, size, false);
	// DEBUG r_file_dump ("sig_dump", f->b, size, false);
	if (parse_tree (f, node)) {
		ret = node;
	} else {
		R_LOG_ERROR ("flirt parse tree error");
		free (node);
	}
beach:
	free (buf);
	r_buf_free (f->b);
	f->b = NULL;
	free (header);
	free (name);
	return ret;
}

// if buf is a flirt signature, returns signature version, or zero
R_API int r_sign_is_flirt(RBuffer *buf) {
	R_RETURN_VAL_IF_FAIL (buf, 0);
	int ret = 0;
	idasig_v5_t *header = R_NEW0 (idasig_v5_t);
	if (!header) {
		goto beach;
	}
	if (r_buf_read (buf, header->magic, sizeof (header->magic)) != sizeof (header->magic)) {
		goto beach;
	}
	if (strncmp ((const char *) header->magic, "IDASGN", 6)) {
		goto beach;
	}
	if (r_buf_read (buf, (ut8*)&header->version, sizeof (header->version)) != sizeof (header->version)) {
		goto beach;
	}
	ret = header->version;
beach:
	free (header);
	return ret;
}

static inline RFlirt *flirt_new(const RAnal *anal, RBuffer *flirt_buf) {
	RFlirt *f = R_NEW0 (RFlirt);
	if (f) {
		f->anal = anal;
		f->b = flirt_buf;
	}
	return f;
}

static inline void flirt_free(RFlirt *f) {
	if (f) {
		r_buf_free (f->b);
		free (f);
	}
}

// dump a flirt signature content on screen
R_API void r_sign_flirt_dump(const RAnal *anal, const char *flirt_file) {
	RBuffer *flirt_buf = r_buf_new_from_file (flirt_file);
	if (!flirt_buf) {
		R_LOG_ERROR ("Can't slurp %s", flirt_file);
		return;
	}
	RFlirt *f = flirt_new (anal, flirt_buf);
	RFlirtNode *node = flirt_parse (f);
	if (node) {
		print_node (anal, node, -1);
		node_free (node);
	} else {
		R_LOG_ERROR ("We encountered a problem while parsing the file");
	}
	flirt_free (f);
}

// parses a flirt signature file and scan the currently opened file with it
R_API void r_sign_flirt_scan(RAnal *anal, const char *flirt_file) {
	RBuffer *flirt_buf = r_buf_new_from_file (flirt_file);
	if (!flirt_buf) {
		R_LOG_ERROR ("Can't slurp %s", flirt_file);
		return;
	}
	RFlirt *f = flirt_new (anal, flirt_buf);
	RFlirtNode *node = flirt_parse (f);
	if (node) {
		if (!node_match_functions (anal, node)) {
			R_LOG_ERROR ("scanning file %s", flirt_file);
		}
		node_free (node);
	} else {
		R_LOG_ERROR ("We encountered an error while parsing the file %s", flirt_file);
	}
	flirt_free (f);
}
