/* radare - LGPL - Copyright 2013 xvilka */

#include <r_types.h>
#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>

#ifndef _INCLUDE_R_BIN_TE_H_
#define _INCLUDE_R_BIN_TE_H_

#define R_BIN_TE_SCN_IS_SHAREABLE(x)       x & TE_IMAGE_SCN_MEM_SHARED
#define R_BIN_TE_SCN_IS_EXECUTABLE(x)      x & TE_IMAGE_SCN_MEM_EXECUTE
#define R_BIN_TE_SCN_IS_READABLE(x)        x & TE_IMAGE_SCN_MEM_READ
#define R_BIN_TE_SCN_IS_WRITABLE(x)        x & TE_IMAGE_SCN_MEM_WRITE

struct r_bin_te_section_t {
	ut8  name[TE_IMAGE_SIZEOF_NAME];
	ut64 size;
	ut64 vsize;
	ut64 vaddr;
	ut64 paddr;
	ut64 flags;
	int last;
};

struct r_bin_te_string_t {
	char string[TE_STRING_LENGTH];
	ut64 vaddr;
	ut64 paddr;
	ut64 size;
	char type;
	int last;
};

struct r_bin_te_obj_t {
	TE_image_file_header *header;
	TE_image_section_header *section_header;
	int size;
	int endian;
	const char* file;
	struct r_buf_t* b;
	Sdb *kv;
};

char* r_bin_te_get_arch(struct r_bin_te_obj_t* bin);
RBinAddr* r_bin_te_get_entrypoint(struct r_bin_te_obj_t* bin);
ut64 r_bin_te_get_main_paddr(struct r_bin_te_obj_t *bin);
ut64 r_bin_te_get_image_base(struct r_bin_te_obj_t* bin);
int r_bin_te_get_image_size(struct r_bin_te_obj_t* bin);
char* r_bin_te_get_machine(struct r_bin_te_obj_t* bin);
int r_bin_te_get_bits(struct r_bin_te_obj_t* bin);
char* r_bin_te_get_os(struct r_bin_te_obj_t* bin);
struct r_bin_te_section_t* r_bin_te_get_sections(struct r_bin_te_obj_t* bin);
char* r_bin_te_get_subsystem(struct r_bin_te_obj_t* bin);
void* r_bin_te_free(struct r_bin_te_obj_t* bin);
struct r_bin_te_obj_t* r_bin_te_new(const char* file);
struct r_bin_te_obj_t* r_bin_te_new_buf(struct r_buf_t *buf);

#endif
