#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>

#define R_BIN_ZIMG_MAXSTR 256

struct zimg_header_t {
	ut8 magic[8];
	ut32 filler[6];
	ut8 arm_magic[4];
	ut32 kernel_start;
	ut32 kernel_end;
};

typedef struct r_bin_zimg_obj_t {
	int size;
	const char *file;
	RBuffer *b;
	struct zimg_header_t header;
	ut32 *strings;
	RList *methods_list;
	RList *imports_list;
	ut64 code_from;
	ut64 code_to;
	Sdb *kv;
} RBinZimgObj;

struct r_bin_zimg_str_t {
	char str[R_BIN_ZIMG_MAXSTR];
	ut64 offset;
	ut64 ordinal;
	int size;
	int last;
};

struct r_bin_zimg_obj_t *r_bin_zimg_new_buf(RBuffer *buf);
struct r_bin_zimg_str_t *r_bin_zimg_get_strings (struct r_bin_zimg_obj_t *bin);
