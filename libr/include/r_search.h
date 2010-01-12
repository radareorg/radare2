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

#define R_SEARCH_AES_BOX_SIZE 31

/* search api */

typedef struct r_search_kw_t {
	char keyword[128];
	char binmask[128];
	ut8 bin_keyword[128];
	ut8 bin_binmask[128];
	ut32 keyword_length;
	ut32 binmask_length;
	ut32 idx; // searching purposes
	int count;
	int kwidx;
	struct list_head list;
} rSearchKeyword;

typedef struct r_search_hit_t {
	ut64 addr;
	struct r_search_kw_t *kw;
	int len;
	struct list_head list;
} rSearchHit;


typedef int (*rSearchCallback)(struct r_search_kw_t *kw, void *user, ut64 where);

typedef struct r_search_t {
	int n_kws;
	int mode;
	ut32 pattern_size;
	ut32 string_min; /* min number of matches */
	ut32 string_max; /* max number of matches */
	void *user; /* user data */
	//int (*callback)(struct r_search_kw_t *kw, void *user, ut64 where);
	rSearchCallback(callback);
	//struct r_search_binparse_t *bp;
	struct list_head kws; //r_search_hw_t kws;
	struct list_head hits; //r_search_hit_t hits;
} rSearch;

#ifdef R_API
R_API struct r_search_t *r_search_new(int mode);
R_API int r_search_set_mode(struct r_search_t *s, int mode);
R_API int r_search_init(struct r_search_t *s, int mode);
R_API struct r_search_t *r_search_free(struct r_search_t *s);

/* keyword management */
R_API int r_search_update(struct r_search_t *s, ut64 *from, const ut8 *buf, long len);
R_API int r_search_update_i(struct r_search_t *s, ut64 from, const ut8 *buf, long len);

/* */
R_API int r_search_kw_add(struct r_search_t *s, const char *kw, const char *bm);
R_API int r_search_kw_add_hex(struct r_search_t *s, const char *kw, const char *bm);
R_API int r_search_kw_add_bin(struct r_search_t *s, const ut8 *kw, int kw_len, const ut8 *bm, int bm_len);
R_API struct r_search_kw_t *r_search_kw_list(struct r_search_t *s);
R_API int r_search_reset(struct r_search_t *s);
R_API int r_search_kw_reset(struct r_search_t *s);

R_API int r_search_range_add(struct r_search_t *s, ut64 from, ut64 to);
R_API int r_search_range_set(struct r_search_t *s, ut64 from, ut64 to);
R_API int r_search_range_reset(struct r_search_t *s);
R_API int r_search_set_blocksize(struct r_search_t *s, ut32 bsize);

// TODO: this is internal API?
R_API int r_search_mybinparse_update(struct r_search_t *s, ut64 from, const ut8 *buf, int len);
R_API int r_search_aes_update(struct r_search_t *s, ut64 from, const ut8 *buf, int len);
R_API int r_search_strings_update(struct r_search_t *s, ut64 from, const ut8 *buf, int len, int enc);
R_API int r_search_regexp_update(struct r_search_t *s, ut64 from, const ut8 *buf, int len);
R_API int r_search_xrefs_update(struct r_search_t *s, ut64 from, const ut8 *buf, int len);

/* pattern search */
R_API int r_search_pattern(struct r_search_t *s, ut32 size);
R_API int r_search_strings(struct r_search_t *s, ut32 min, ut32 max);
//R_API int r_search_set_callback(struct r_search_t *s, int (*callback)(struct r_search_kw_t *, void *, ut64), void *user);
R_API int r_search_set_callback(struct r_search_t *s, rSearchCallback(callback), void *user);
R_API int r_search_begin(struct r_search_t *s);
#endif

#endif
