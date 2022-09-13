#ifndef R2_BPLIST_H
#define R2_BPLIST_H

#ifdef __cplusplus
extern "C" {
#endif

#include <r_util.h>
#include <r_util/pj.h>

typedef struct r_bplist_t {
	const char* data;
	ut64 size;
	ut64 num_objects;
	ut8 ref_size;
	ut8 offset_size;
	const char* offset_table;
	PJ *pj;
} RBPlist;

R_API bool r_bplist_parse(PJ *pj, const ut8 *data, size_t data_len);

#ifdef __cplusplus
}
#endif

#endif
