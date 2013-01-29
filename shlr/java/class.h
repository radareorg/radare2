/* radare - LGPL - Copyright 2007-2013 - pancake */

#ifndef _INCLUDE_JAVA_CLASS_H_
#define _INCLUDE_JAVA_CLASS_H_

#include <r_types.h>

#define USHORT(x,y) ((ut16)(x[y+1]|(x[y]<<8)))
#define UINT(x,y) ((ut32)((x[y]<<24)|(x[y+1]<<16)|(x[y+2]<<8)|x[y+3]))

#define R_BIN_JAVA_MAXSTR 256

#define R_BIN_JAVA_USHORT(x,y) ((ut16)(((0xff&x[y+1])|((x[y]&0xff)<<8)) & 0xffff))
#define R_BIN_JAVA_UINT(x,y) ((ut32)(((x[y]&0xff)<<24)|((x[y+1]&0xff)<<16)|((x[y+2]&0xff)<<8)|(x[y+3]&0xff)))
#define R_BIN_JAVA_SWAPUSHORT(x) ((ut16)((x<<8)|((x>>8)&0x00FF)))

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
	ut16 cp_count;
} RBinJavaClass;

typedef struct r_bin_java_classfile2_t {
	ut16 access_flags;
	ut16 this_class;
	ut16 super_class;
} RBinJavaClass2;

typedef struct r_bin_java_cp_item_t {
	int tag;
	char name[32];
	char *value;
	ut8 bytes[5];
	ut16 length;
	ut16 ord;
	ut16 off;
} RBinJavaCpItem;

typedef struct r_bin_java_constant_t {
	char *name;
	int tag;
	int len;
} RBinJavaConstant;

struct r_bin_java_attr_code_t {
	ut16 max_stack;
	ut16 max_locals;
	ut16 code_length;
	ut16 code_offset;
	ut32 exception_table_length;
	ut16 start_pc;
	ut16 end_pc;
	ut16 handler_pc;
	ut16 catch_type;
};

struct r_bin_java_attr_linenum_t {
	ut32 table_length;
	ut16 start_pc;
	ut16 line_number;
};

struct r_bin_java_attr_t {
	int type;
	char *name;
	ut16 name_idx;
	ut32 length;
	union {
		struct r_bin_java_attr_code_t code;
		struct r_bin_java_attr_linenum_t linenum;
		ut16 const_value_idx;
	} info;
	struct r_bin_java_attr_t *attributes;
};

struct r_bin_java_fm_t {
	ut16 flags;
	char *name;
	ut16 name_idx;
	char *descriptor;
	ut16 descriptor_idx;
	ut16 attr_count;
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
	struct r_buf_t* b;
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

char* r_bin_java_get_version(RBinJavaObj* bin);
ut64 r_bin_java_get_entrypoint(RBinJavaObj* bin);
ut64 r_bin_java_get_main(RBinJavaObj* bin);
RBinJavaSymbol* r_bin_java_get_symbols(RBinJavaObj* bin);
RBinJavaString* r_bin_java_get_strings(RBinJavaObj* bin);
void* r_bin_java_free(RBinJavaObj* bin);
RBinJavaObj* r_bin_java_new(const char* file);
RBinJavaObj* r_bin_java_new_buf(struct r_buf_t * buf);

#endif
