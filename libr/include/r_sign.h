#ifndef R2_SIGN_H
#define R2_SIGN_H

#include <r_types.h>
#include <r_anal.h>
#include <r_util.h>
#include <r_list.h>

#ifdef __cplusplus
extern "C" {
#endif

R_LIB_VERSION_HEADER(r_sign);

#define R_SIGN_KEY_MAXSZ 1024
#define R_SIGN_VAL_MAXSZ 10240

enum {
	R_SIGN_EXACT = 'e',  // Exact match
	R_SIGN_ANAL  = 'a',  // Anal
	R_SIGN_METR  = 'm',  // Function metrics
};

/* signature struct */
typedef struct r_sign_item_t {
	char *name;
	int space;
	int type;
	int size;
	ut8 *bytes;
	ut8 *mask;
} RSignItem;

typedef int (*RSignForeachCallback)(void *user, RSignItem *it);

#ifdef R_API
R_API bool r_sign_add(RAnal *a, int type, const char *name, ut64 size, const ut8 *bytes, const ut8 *mask);
R_API bool r_sign_add_anal(RAnal *a, const char *name, ut64 size, const ut8 *bytes);
R_API bool r_sign_delete(RAnal *a, const char *name);
R_API void r_sign_list(RAnal *a, int format);
R_API void r_sign_foreach(RAnal *a, RSignForeachCallback cb, void *user);
R_API void r_sign_item_free(void *_item);
#endif

#ifdef __cplusplus
}
#endif

#endif
