#include <r_types.h>

#define R_BIN_JAVA_MAXSTR 256

#define R_BIN_JAVA_USHORT(x,y) (unsigned short)(x[y+1]|(x[y]<<8))
#define R_BIN_JAVA_UINT(x,y) (unsigned int) ((x[y]<<24)|(x[y+1]<<16)|(x[y+2]<<8)|x[y+3])

enum {
	R_BIN_JAVA_TYPE_FIELD,
	R_BIN_JAVA_TYPE_CODE,
	R_BIN_JAVA_TYPE_LINENUM,
	R_BIN_JAVA_TYPE_CONST
};

struct r_bin_java_classfile_t {
	u8 cafebabe[4];
	u8 minor[2];
	u8 major[2];
	unsigned short cp_count;
};

struct r_bin_java_classfile2_t {
	unsigned short access_flags;
	unsigned short this_class;
	unsigned short super_class;
};

struct r_bin_java_cp_item_t {
	int tag;
	char name[32];
	char *value;
	u8 bytes[5];
	unsigned short length;
	unsigned short ord;
	unsigned short off;
};

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

struct r_bin_java_t {
    const char* file;
	int fd;
	struct r_bin_java_classfile_t cf;
	struct r_bin_java_classfile2_t cf2;
	struct r_bin_java_cp_item_t *cp_items;
	unsigned int fields_count;
	struct r_bin_java_fm_t *fields;
	unsigned int methods_count;
	struct r_bin_java_fm_t *methods;
};

struct r_bin_java_sym_t {
	u64 offset;
	u64 size;
	char name[R_BIN_JAVA_MAXSTR];
};

struct r_bin_java_str_t {
	u64 offset;
	u64 ordinal;
	u64 size;
	char str[R_BIN_JAVA_MAXSTR];
};

int r_bin_java_open(struct r_bin_java_t *bin, const char *file);
int r_bin_java_close(struct r_bin_java_t *bin);
int r_bin_java_get_version(struct r_bin_java_t *bin, char *version);
u64 r_bin_java_get_entrypoint(struct r_bin_java_t *bin);
int r_bin_java_get_symbols(struct r_bin_java_t *bin, struct r_bin_java_sym_t *sym);
int r_bin_java_get_symbols_count(struct r_bin_java_t *bin);
int r_bin_java_get_strings(struct r_bin_java_t *bin, struct r_bin_java_str_t *str);
int r_bin_java_get_strings_count(struct r_bin_java_t *bin);
