#ifndef R_BASE_TYPES_H
#define R_BASE_TYPES_H

#include "r_util.h"

#ifdef __cplusplus
extern "C" {
#endif

R_IPI void enum_type_fini(void *e, void *user);
R_IPI void struct_type_fini(void *e, void *user);
R_IPI void union_type_fini(void *e, void *user);

#ifdef __cplusplus
}
#endif
#endif R_BASE_TYPES_H