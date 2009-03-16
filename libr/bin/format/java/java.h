#include <r_types.h>

#define R_BIN_JAVA_MAXSTR 256

#define USHORT(x,y) (unsigned short)(x[y+1]|(x[y]<<8))
#define UINT(x,y) (unsigned int) ((x[y]<<24)|(x[y+1]<<16)|(x[y+2]<<8)|x[y+3])

struct r_bin_java_classfile_t {
	unsigned char cafebabe[4];
	unsigned char minor[2];
	unsigned char major[2];
	unsigned short cp_count;
};

struct r_bin_java_classfile2_t {
	unsigned short access_flags;
	unsigned short this_class;
	unsigned short super_class;
};

struct r_bin_java_cp_item_t {
	int tag;
	char name[255];
	char *value;
	unsigned char bytes[5];
	u64 off;
};

struct r_bin_java_fields_t {
	int flags;
	int name_ndx;
	int descriptor_ndx;
	struct r_bin_java_attribute_t *atributes;
}

typedef struct r_bin_java_t {
    const char* file;
	FILE fd;
	struct classfile cf;
	struct classfile2 cf2;
	struct r_bin_java_cp_item_t *cp_items;
	struct r_bin_java_field_t *fields;
	struct r_bin_java_method_t *methods;
};


