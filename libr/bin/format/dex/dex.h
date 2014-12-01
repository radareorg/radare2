#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>

#define R_BIN_DEX_MAXSTR 256

#pragma pack(4)
struct dex_header_t {
	ut8 magic[8];
	ut32 checksum;
	ut8 signature[20];
	ut32 size;
	ut32 header_size;
	ut32 endian;
	ut32 linksection_size;
	ut32 linksection_offset;
	ut32 map_offset;
	ut32 strings_size;
	ut32 strings_offset;
	ut32 types_size;
	ut32 types_offset;
	ut32 prototypes_size;
	ut32 prototypes_offset;
	ut32 fields_size;
	ut32 fields_offset;
	ut32 method_size;
	ut32 method_offset;
	ut32 class_size;
	ut32 class_offset;
	ut32 data_size;
	ut32 data_offset;
};

#pragma pack(4)
struct dex_proto_t {
	ut32 shorty_id;
	ut32 return_type_id;
	ut32 params_id;
};

struct dex_type_t {
	ut32 descriptor_id;
};

#pragma pack(4)
struct dex_field_t {
	ut16 class_id;
	ut16 type_id;
	ut32 name_id;
};

#if 0
struct dex_method_t {
	ut8 class_id;
	ut8 proto_id;
	ut32 name_id;
};
#endif
#pragma pack(1)
typedef struct dex_method_t {
        ut16 class_id;
        ut16 proto_id;
        ut32 name_id;
} RBinDexMethod;

#pragma pack(1)
typedef struct dex_class_t {
	ut32 class_id; // index into typeids
	ut32 access_flags;
	ut32 super_class;
	ut32 interfaces_offset;
	ut32 source_file;
	ut32 anotations_offset;
	ut32 class_data_offset;
	ut32 static_values_offset;
} RBinDexClass;

typedef struct r_bin_dex_obj_t {
	int size;
	const char *file;
	struct r_buf_t *b;
	struct dex_header_t header;
	ut32 *strings;
	struct dex_class_t *classes;
	struct dex_method_t *methods;
	struct dex_type_t *types;
	struct dex_field_t *fields;
	RList *methods_list;
	RList *imports_list;
	ut64 code_from;
	ut64 code_to;
	Sdb *kv;
} RBinDexObj;

struct r_bin_dex_str_t {
	char str[R_BIN_DEX_MAXSTR];
	ut64 offset;
	ut64 ordinal;
	int size;
	int last;
};

char* r_bin_dex_get_version(struct r_bin_dex_obj_t* bin);
struct r_bin_dex_obj_t *r_bin_dex_new_buf(struct r_buf_t *buf);
struct r_bin_dex_str_t *r_bin_dex_get_strings (struct r_bin_dex_obj_t* bin);

int dex_read_uleb128 (const ut8 *ptr);
int dex_read_sleb128 (const char *ptr);
int dex_uleb128_len (const ut8 *ptr);
