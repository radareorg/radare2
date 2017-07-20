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
	R_SIGN_BYTES  = 'b', // bytes pattern
	R_SIGN_ANAL   = 'a', // bytes pattern (anal mask)
	R_SIGN_GRAPH  = 'g', // graph metrics
	R_SIGN_OFFSET = 'o', // offset
	R_SIGN_REFS   = 'r', // references
};

typedef struct r_sign_graph_t {
	int cc;
	int nbbs;
	int edges;
	int ebbs;
} RSignGraph;

typedef struct r_sign_bytes_t {
	int size;
	ut8 *bytes;
	ut8 *mask;
} RSignBytes;

typedef struct r_sign_item_t {
	char *name;
	int space;

	RSignBytes *bytes;
	RSignGraph *graph;
	ut64 offset;
	RList *refs;
} RSignItem;

typedef int (*RSignForeachCallback)(RSignItem *it, void *user);
typedef int (*RSignSearchCallback)(RSignItem *it, RSearchKeyword *kw, ut64 addr, void *user);
typedef int (*RSignGraphMatchCallback)(RSignItem *it, RAnalFunction *fcn, void *user);
typedef int (*RSignOffsetMatchCallback)(RSignItem *it, RAnalFunction *fcn, void *user);
typedef int (*RSignRefsMatchCallback)(RSignItem *it, RAnalFunction *fcn, void *user);

typedef struct r_sign_search_t {
	RSearch *search;
	RList *items;
	RSignSearchCallback cb;
	void *user;
} RSignSearch;

#ifdef R_API
R_API bool r_sign_add_bytes(RAnal *a, const char *name, ut64 size, const ut8 *bytes, const ut8 *mask);
R_API bool r_sign_add_anal(RAnal *a, const char *name, ut64 size, const ut8 *bytes, ut64 at);
R_API bool r_sign_add_graph(RAnal *a, const char *name, RSignGraph graph);
R_API bool r_sign_add_offset(RAnal *a, const char *name, ut64 offset);
R_API bool r_sign_add_refs(RAnal *a, const char *name, RList *refs);
R_API bool r_sign_delete(RAnal *a, const char *name);
R_API void r_sign_list(RAnal *a, int format);

R_API bool r_sign_foreach(RAnal *a, RSignForeachCallback cb, void *user);

R_API RSignSearch *r_sign_search_new(void);
R_API void r_sign_search_free(RSignSearch *ss);
R_API void r_sign_search_init(RAnal *a, RSignSearch *ss, int minsz, RSignSearchCallback cb, void *user);
R_API int r_sign_search_update(RAnal *a, RSignSearch *ss, ut64 *at, const ut8 *buf, int len);
R_API bool r_sign_match_graph(RAnal *a, RAnalFunction *fcn, int mincc, RSignGraphMatchCallback cb, void *user);
R_API bool r_sign_match_offset(RAnal *a, RAnalFunction *fcn, RSignOffsetMatchCallback cb, void *user);
R_API bool r_sign_match_refs(RAnal *a, RAnalFunction *fcn, RSignRefsMatchCallback cb, void *user);

R_API bool r_sign_load(RAnal *a, const char *file);
R_API char *r_sign_path(RAnal *a, const char *file);
R_API bool r_sign_save(RAnal *a, const char *file);

R_API RSignItem *r_sign_item_new(void);
R_API RSignItem *r_sign_item_dup(RSignItem *it);
R_API void r_sign_item_free(RSignItem *item);

R_API RList *r_sign_fcn_refs(RAnal *a, RAnalFunction *fcn);

// TODO
R_API int r_sign_is_flirt(RBuffer *buf);
R_API void r_sign_flirt_dump(const RAnal *anal, const char *flirt_file);
R_API void r_sign_flirt_scan(const RAnal *anal, const char *flirt_file);
#endif

#ifdef __cplusplus
}
#endif

#endif
