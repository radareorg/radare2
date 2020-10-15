#ifndef R2_SIGN_H
#define R2_SIGN_H

#include <r_types.h>
#include <r_anal.h>
#include <r_search.h>

#ifdef __cplusplus
extern "C" {
#endif

R_LIB_VERSION_HEADER(r_sign);

// XXX those limits should go away
#define R_SIGN_KEY_MAXSZ 1024
#define R_SIGN_VAL_MAXSZ 10240

#define ZIGN_HASH "sha256"
#define R_ZIGN_HASH R_HASH_SHA256

typedef enum {
	R_SIGN_BYTES     = 'b', // bytes pattern
	R_SIGN_BYTES_MASK= 'm', // bytes pattern
	R_SIGN_BYTES_SIZE= 's', // bytes pattern
	R_SIGN_ANAL      = 'a', // bytes pattern (anal mask) // wtf ?
	R_SIGN_COMMENT   = 'c', // comment
	R_SIGN_GRAPH     = 'g', // graph metrics
	R_SIGN_OFFSET    = 'o', // addr
	R_SIGN_NAME      = 'n', // real name
	R_SIGN_REFS      = 'r', // references
	R_SIGN_XREFS     = 'x', // xrefs
	R_SIGN_VARS      = 'v', // variables
	R_SIGN_TYPES     = 't', // types
	R_SIGN_BBHASH    = 'h', // basic block hash
} RSignType;

typedef struct r_sign_graph_t {
	int cc;
	int nbbs;
	int edges;
	int ebbs;
	int bbsum;
} RSignGraph;

typedef struct r_sign_bytes_t {
	int size;
	ut8 *bytes;
	ut8 *mask;
} RSignBytes;

typedef struct r_sign_hash_t {
	char *bbhash;
} RSignHash;

typedef struct r_sign_item_t {
	char *name;
	char *realname;
	char *comment;
	const RSpace *space;

	RSignBytes *bytes;
	RSignGraph *graph;
	ut64 addr;
	RList *refs;
	RList *xrefs;
	RList *vars;
	RList *types;
	RSignHash *hash;
} RSignItem;

typedef int (*RSignForeachCallback)(RSignItem *it, void *user);
typedef int (*RSignSearchCallback)(RSignItem *it, RSearchKeyword *kw, ut64 addr, void *user);
typedef int (*RSignMatchCallback)(RSignItem *it, RAnalFunction *fcn, RSignType type, bool seen, void *user);

typedef struct r_sign_search_met {
	/* types is an 0 terminated array of RSignTypes that are going to be
	 * searched for. Valid types are: graph, offset, refs, bbhash, types, vars
	 */
	RSignType types[7];
	int mincc; // min complexity for graph search
	RAnal *anal;
	void *user; // user data for callback function
	RSignMatchCallback cb;
	RAnalFunction *fcn;
} RSignSearchMetrics;

typedef struct r_sign_search_t {
	RSearch *search;
	RList *items;
	RSignSearchCallback cb;
	void *user;
} RSignSearch;

typedef struct r_sign_options_t {
	double bytes_diff_threshold;
	double graph_diff_threshold;
} RSignOptions;

typedef struct {
	double score;
	double bscore;
	double gscore;
	RSignItem *item;
} RSignCloseMatch;

#ifdef R_API
R_API bool r_sign_add_bytes(RAnal *a, const char *name, ut64 size, const ut8 *bytes, const ut8 *mask);
R_API bool r_sign_add_anal(RAnal *a, const char *name, ut64 size, const ut8 *bytes, ut64 at);
R_API bool r_sign_add_graph(RAnal *a, const char *name, RSignGraph graph);
R_API bool r_sign_addto_item(RAnal *a, RSignItem *it, RAnalFunction *fcn, RSignType type);
R_API bool r_sign_add_addr(RAnal *a, const char *name, ut64 addr);
R_API bool r_sign_add_name(RAnal *a, const char *name, const char *realname);
R_API bool r_sign_add_comment(RAnal *a, const char *name, const char *comment);
R_API bool r_sign_add_refs(RAnal *a, const char *name, RList *refs);
R_API bool r_sign_add_xrefs(RAnal *a, const char *name, RList *xrefs);
R_API bool r_sign_add_vars(RAnal *a, const char *name, RList *vars);
R_API bool r_sign_add_types(RAnal *a, const char *name, RList *vars);
R_API bool r_sign_delete(RAnal *a, const char *name);
R_API void r_sign_list(RAnal *a, int format);
R_API RList *r_sign_get_list(RAnal *a);
R_API bool r_sign_add_hash(RAnal *a, const char *name, int type, const char *val, int len);
R_API bool r_sign_add_bb_hash(RAnal *a, RAnalFunction *fcn, const char *name);
R_API char *r_sign_calc_bbhash(RAnal *a, RAnalFunction *fcn);
R_API bool r_sign_deserialize(RAnal *a, RSignItem *it, const char *k, const char *v);
R_API RSignItem *r_sign_get_item(RAnal *a, const char *name);
R_API bool r_sign_add_item(RAnal *a, RSignItem *it);

R_API bool r_sign_foreach(RAnal *a, RSignForeachCallback cb, void *user);

R_API RSignSearch *r_sign_search_new(void);
R_API void r_sign_search_free(RSignSearch *ss);
R_API void r_sign_search_init(RAnal *a, RSignSearch *ss, int minsz, RSignSearchCallback cb, void *user);
R_API int r_sign_search_update(RAnal *a, RSignSearch *ss, ut64 *at, const ut8 *buf, int len);
R_API int r_sign_fcn_match_metrics(RSignSearchMetrics *sm);

R_API bool r_sign_load(RAnal *a, const char *file);
R_API bool r_sign_load_gz(RAnal *a, const char *filename);
R_API char *r_sign_path(RAnal *a, const char *file);
R_API bool r_sign_save(RAnal *a, const char *file);

R_API RSignItem *r_sign_item_new(void);
R_API void r_sign_item_free(RSignItem *item);
R_API void r_sign_graph_free(RSignGraph *graph);
R_API void r_sign_bytes_free(RSignBytes *bytes);

R_API RList *r_sign_fcn_refs(RAnal *a, RAnalFunction *fcn);
R_API RList *r_sign_fcn_xrefs(RAnal *a, RAnalFunction *fcn);
R_API RList *r_sign_fcn_vars(RAnal *a, RAnalFunction *fcn);
R_API RList *r_sign_fcn_types(RAnal *a, RAnalFunction *fcn);

R_API int r_sign_is_flirt(RBuffer *buf);
R_API void r_sign_flirt_dump(const RAnal *anal, const char *flirt_file);
R_API void r_sign_flirt_scan(RAnal *anal, const char *flirt_file);

R_API RList *r_sign_find_closest_sig(RAnal *a, RSignItem *it, int count, double score_threshold);
R_API RList *r_sign_find_closest_fcn(RAnal *a, RSignItem *it, int count, double score_threshold);
R_API void r_sign_close_match_free(RSignCloseMatch *match);
R_API bool r_sign_diff(RAnal *a, RSignOptions *options, const char *other_space_name);
R_API bool r_sign_diff_by_name(RAnal *a, RSignOptions *options, const char *other_space_name, bool not_matching);

R_API RSignOptions *r_sign_options_new(const char *bytes_thresh, const char *graph_thresh);
R_API void r_sign_options_free(RSignOptions *options);
#endif

#ifdef __cplusplus
}
#endif

#endif
