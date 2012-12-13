/* radare - LGPL - Copyright 2007-2012 - pancake */
#include <r_types.h>

#define USHORT(x,y) ((unsigned short)(x[y+1]|(x[y]<<8)))
#define UINT(x,y) ((unsigned int)((x[y]<<24)|(x[y+1]<<16)|(x[y+2]<<8)|x[y+3]))

#define R_BIN_JAVA_MAXSTR 256

#define R_BIN_JAVA_USHORT(x,y) ((unsigned short)((0xff&x[y+1]|((x[y]&0xff)<<8)) & 0xffff))
#define R_BIN_JAVA_UINT(x,y) ((unsigned int)(((x[y]&0xff)<<24)|((x[y+1]&0xff)<<16)|((x[y+2]&0xff)<<8)|(x[y+3]&0xff)))
#define R_BIN_JAVA_SWAPUSHORT(x) ((unsigned short)((x<<8)|((x>>8)&0x00FF)))

enum {
	R_BIN_JAVA_TYPE_FIELD,
	R_BIN_JAVA_TYPE_CODE,
	R_BIN_JAVA_TYPE_LINENUM,
	R_BIN_JAVA_TYPE_CONST
};

typedef struct r_bin_java_classfile_t {
	ut8 cafebabe[4];
	ut8 minor[2];
	ut8 major[2];
	unsigned short cp_count;
} RBinJavaClass;

typedef struct r_bin_java_classfile2_t {
	unsigned short access_flags;
	unsigned short this_class;
	unsigned short super_class;
} RBinJavaClass2;

typedef struct r_bin_java_cp_item_t {
	int tag;
	char name[32];
	char *value;
	ut8 bytes[5];
	unsigned short length;
	unsigned short ord;
	unsigned short off;
} RBinJavaCpItem;

typedef struct r_bin_java_constant_t {
	char *name;
	int tag;
	int len;
} RBinJavaConstant;
struct r_bin_java_attr_code_t {
	unsigned short max_stack;
	unsigned short max_locals;
	unsigned short code_length;
	unsigned short code_offset;
	unsigned int exception_table_length;
	unsigned short start_pc;
	unsigned short end_pc;
	unsigned short handler_pc;
	unsigned short catch_type;
};

struct r_bin_java_attr_linenum_t {
	unsigned int table_length;
	unsigned short start_pc;
	unsigned short line_number;
};

struct r_bin_java_attr_t {
	int type;
	char *name;
	unsigned short name_idx;
	unsigned int length;
	union {
		struct r_bin_java_attr_code_t code;
		struct r_bin_java_attr_linenum_t linenum;
		unsigned short const_value_idx;
	} info;
	struct r_bin_java_attr_t *attributes;
};

struct r_bin_java_fm_t {
	unsigned short flags;
	char *name;
	unsigned short name_idx;
	char *descriptor;
	unsigned short descriptor_idx;
	unsigned short attr_count;
	struct r_bin_java_attr_t *attributes;
};

typedef struct r_bin_java_lines_t {
	int count;
	int *addr;
	int *line;
} RBinJavaLines;

typedef struct r_bin_java_obj_t {
	struct r_bin_java_classfile_t cf;
	struct r_bin_java_classfile2_t cf2;
	struct r_bin_java_cp_item_t *cp_items;
	ut32 fields_count;
	struct r_bin_java_fm_t *fields;
	ut32 methods_count;
	struct r_bin_java_fm_t *methods;
	int size;
	const char* file;
	RBinJavaLines lines;
	struct r_buf_t*b;
	int midx;
	int fsym;
	int fsymsz;
} RBinJavaObj;

typedef struct r_bin_java_sym_t {
	char name[R_BIN_JAVA_MAXSTR];
	ut64 offset; // XXX: ut64 is too much
	ut64 size;
	int last;
} RBinJavaSymbol;

typedef struct r_bin_java_str_t {
	char str[R_BIN_JAVA_MAXSTR];
	ut64 offset;
	ut64 ordinal;
	ut64 size;
	int last;
} RBinJavaString;

char* r_bin_java_get_version(struct r_bin_java_obj_t* bin);
ut64 r_bin_java_get_entrypoint(struct r_bin_java_obj_t* bin);
ut64 r_bin_java_get_main(struct r_bin_java_obj_t* bin);
struct r_bin_java_sym_t* r_bin_java_get_symbols(struct r_bin_java_obj_t* bin);
struct r_bin_java_str_t* r_bin_java_get_strings(struct r_bin_java_obj_t* bin);
void* r_bin_java_free(struct r_bin_java_obj_t* bin);
struct r_bin_java_obj_t* r_bin_java_new(const char* file);
struct r_bin_java_obj_t* r_bin_java_new_buf(struct r_buf_t *buf);
