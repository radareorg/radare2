#ifndef _INCLUDE_R_SEARCH_H_
#define _INCLUDE_R_SEARCH_H_

#include "r_types.h"
#include "r_util.h"
#include "list.h"

enum {
	R_SEARCH_KEYWORD,
	R_SEARCH_REGEXP,
	R_SEARCH_PATTERN,
	R_SEARCH_STRING,
	R_SEARCH_XREFS,
	R_SEARCH_AES
};

typedef struct r_search_kw_t {
	char keyword[128];
	char binmask[128];
	ut8 bin_keyword[128];
	ut8 bin_binmask[128];
	ut32 keyword_length;
	ut32 binmask_length;
	ut32 idx; // searching purposes
	void *data;
	int count;
	int kwidx;
	struct list_head list;
} RSearchKeyword;

typedef struct r_search_hit_t {
	RSearchKeyword *kw;
	ut64 addr;
} RSearchHit;

typedef int (*RSearchCallback)(struct r_search_kw_t *kw, void *user, ut64 where);

typedef struct r_search_t {
	int n_kws;
	int mode;
	ut32 pattern_size;
	ut32 string_min; /* min number of matches */
	ut32 string_max; /* max number of matches */
	void *user; /* user data */
	RSearchCallback callback;
	RList *hits;
	RMemoryPool *pool;
	//struct r_search_binparse_t *bp;
	//TODO RList *kws; // TODO: Use r_search_kw_new ()
	struct list_head kws; //r_search_hw_t kws;
} RSearch;

#ifdef R_API

#define R_SEARCH_AES_BOX_SIZE 31

R_API RSearch *r_search_new(int mode);
R_API int r_search_set_mode(RSearch *s, int mode);
R_API int r_search_init(RSearch *s, int mode);
R_API RSearch *r_search_free(RSearch *s);

/* keyword management */
R_API int r_search_update(RSearch *s, ut64 *from, const ut8 *buf, long len);
R_API int r_search_update_i(RSearch *s, ut64 from, const ut8 *buf, long len);

/* */
R_API int r_search_kw_add(RSearch *s, const char *kw, const char *bm);
R_API int r_search_kw_add_hex(RSearch *s, const char *kw, const char *bm);
R_API int r_search_kw_add_bin(RSearch *s, const ut8 *kw, int kw_len, const ut8 *bm, int bm_len);
// TODO: Must be RList
R_API struct r_search_kw_t *r_search_kw_list(RSearch *s);
R_API void r_search_reset(RSearch *s);
R_API void r_search_kw_reset(RSearch *s);

R_API int r_search_range_add(RSearch *s, ut64 from, ut64 to);
R_API int r_search_range_set(RSearch *s, ut64 from, ut64 to);
R_API int r_search_range_reset(RSearch *s);
R_API int r_search_set_blocksize(RSearch *s, ut32 bsize);

// TODO: this is internal API?
R_API int r_search_mybinparse_update(RSearch *s, ut64 from, const ut8 *buf, int len);
R_API int r_search_aes_update(RSearch *s, ut64 from, const ut8 *buf, int len);
R_API int r_search_strings_update(RSearch *s, ut64 from, const char *buf, int len, int enc);
R_API int r_search_regexp_update(RSearch *s, ut64 from, const ut8 *buf, int len);
R_API int r_search_xrefs_update(RSearch *s, ut64 from, const ut8 *buf, int len);
R_API int r_search_hit_new(RSearch *s, RSearchKeyword *kw, ut64 addr);

/* pattern search */
R_API int r_search_pattern(RSearch *s, ut32 size);
R_API int r_search_strings(RSearch *s, ut32 min, ut32 max);
//R_API int r_search_set_callback(RSearch *s, int (*callback)(struct r_search_kw_t *, void *, ut64), void *user);
R_API void r_search_set_callback(RSearch *s, RSearchCallback(callback), void *user);
R_API int r_search_begin(RSearch *s);
#endif
#endif
