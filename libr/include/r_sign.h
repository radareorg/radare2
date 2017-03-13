#ifndef R2_SIGN_H
#define R2_SIGN_H

#include <r_types.h>
#include <r_anal.h>
#include <r_search.h>

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

typedef struct r_sign_item_t {
	char *name;
	int space;
	int type;
	int size;
	ut8 *bytes;
	ut8 *mask;
} RSignItem;

typedef int (*RSignForeachCallback)(RSignItem *it, void *user);
typedef int (*RSignSearchCallback)(RSearchKeyword *kw, RSignItem *it, ut64 addr, void *user);

typedef struct r_sign_search_t {
	RSearch *search;
	RList *items;
	RSignSearchCallback cb;
	void *user;
} RSignSearch;

#ifdef R_API
R_API bool r_sign_add(RAnal *a, int type, const char *name, ut64 size, const ut8 *bytes, const ut8 *mask);
R_API bool r_sign_add_anal(RAnal *a, const char *name, ut64 size, const ut8 *bytes);
R_API bool r_sign_delete(RAnal *a, const char *name);
R_API void r_sign_list(RAnal *a, int format);

R_API int r_sign_space_count_for(RAnal *a, int idx);
R_API void r_sign_space_unset_for(RAnal *a, int idx);

R_API bool r_sign_foreach(RAnal *a, RSignForeachCallback cb, void *user);

R_API RSignSearch *r_sign_search_new();
R_API void r_sign_search_free(RSignSearch *ss);
R_API void r_sign_search_init(RAnal *a, RSignSearch *ss, RSignSearchCallback cb, void *user);
R_API int r_sign_search_update(RAnal *a, RSignSearch *ss, ut64 *at, const ut8 *buf, int len);

R_API RSignItem *r_sign_item_dup(RSignItem *it);
R_API void r_sign_item_free(void *_item);

R_API int r_sign_is_flirt(RBuffer *buf);
R_API void r_sign_flirt_dump(const RAnal *anal, const char *flirt_file);
R_API void r_sign_flirt_scan(const RAnal *anal, const char *flirt_file);
#endif

#ifdef __cplusplus
}
#endif

#endif
