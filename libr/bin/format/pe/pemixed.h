#include <r_types.h>
#include "pe.h"

#define SUB_BIN_DOS 0
#define SUB_BIN_NATIVE 1
#define SUB_BIN_NET 2

#ifndef _INCLUDE_R_BIN_PEMIXED_H_
#define _INCLUDE_R_BIN_PEMIXED_H_

struct r_bin_pemixed_obj_t {
	const char* file;
	int size;
	struct PE_(r_bin_pe_obj_t)* sub_bin_dos;
	struct PE_(r_bin_pe_obj_t)* sub_bin_native;
	struct PE_(r_bin_pe_obj_t)* sub_bin_net;
	
	RBuffer* b;
};

// static int r_bin_pemixed_init(struct r_bin_pemixed_obj_t* bin, struct PE_(r_bin_pe_obj_t)* pe_bin);
struct PE_(r_bin_pe_obj_t)* r_bin_pemixed_init_dos(struct PE_(r_bin_pe_obj_t)* pe_bin);
struct PE_(r_bin_pe_obj_t)* r_bin_pemixed_init_native(struct PE_(r_bin_pe_obj_t)* pe_bin);
struct PE_(r_bin_pe_obj_t)* r_bin_pemixed_extract(struct r_bin_pemixed_obj_t* bin, int sub_bin);
// static bool check_il_only(ut32 flags);
void* r_bin_pemixed_free(struct r_bin_pemixed_obj_t* bin);
struct r_bin_pemixed_obj_t * r_bin_pemixed_from_bytes_new(const ut8* buf, ut64 size);

#endif
