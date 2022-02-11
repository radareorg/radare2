#ifndef _INCLUDE_R_BIN_PEMIXED_H_
#define _INCLUDE_R_BIN_PEMIXED_H_

#include <r_types.h>
#include "pe.h"

#define SUB_BIN_DOS 0
#define SUB_BIN_NATIVE 1
#define SUB_BIN_NET 2

typedef struct r_bin_pemixed_obj_t {
	const char* file;
	int size;
	RBinPEObj* sub_bin_dos;
	RBinPEObj* sub_bin_native;
	RBinPEObj* sub_bin_net;
	RBuffer* b;
} RBinPEMixed;

RBinPEObj *r_bin_pemixed_init_dos(RBinPEObj* pe);
RBinPEObj* r_bin_pemixed_init_native(RBinPEObj* pe);
RBinPEObj* r_bin_pemixed_extract(RBinPEMixed* pemixed, int sub_bin);
void* r_bin_pemixed_free(RBinPEMixed *pemixed);
RBinPEMixed *r_bin_pemixed_from_bytes_new(const ut8* buf, ut64 size);

#endif
