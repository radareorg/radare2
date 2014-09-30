#ifndef R2_SEARCH_H
#define R2_SEARCH_H

#include <r_types.h>
#include <r_util.h>
#include <r_list.h>
#include <r_io.h>

#ifdef __cplusplus
extern "C" {
#endif

R_LIB_VERSION_HEADER(r_search);

enum {
	R_SEARCH_KEYWORD,
	R_SEARCH_REGEXP,
	R_SEARCH_PATTERN,
	R_SEARCH_STRING,
	R_SEARCH_XREFS,
	R_SEARCH_AES,
	R_SEARCH_DELTAKEY,
	R_SEARCH_LAST
};

#define R_SEARCH_DISTANCE_MAX 10

#define R_SEARCH_KEYWORD_TYPE_BINARY 'i'
#define R_SEARCH_KEYWORD_TYPE_STRING 's'

typedef struct r_search_keyword_t {
	ut8 *bin_keyword;
	ut8 *bin_binmask;
	ut32 keyword_length;
	ut32 binmask_length;
	ut32 idx[R_SEARCH_DISTANCE_MAX]; // searching purposes
	int distance;
	void const *data;
	int count;
	int kwidx;
	int icase; // ignore case
	int type;
	ut64 last; // last hit hint
} RSearchKeyword;

typedef struct r_search_hit_t {
	RSearchKeyword *kw;
	ut64 addr;
} RSearchHit;

typedef int (*RSearchUpdate)(void *s, ut64 from, const ut8 *buf, int len);
typedef int (*RSearchCallback)(RSearchKeyword *kw, void *user, ut64 where);

typedef struct r_search_t {
	int n_kws;
	int mode;
	ut32 pattern_size;
	ut32 string_min; /* min number of matches */
	ut32 string_max; /* max number of matches */
	void *user; /* user data */
	RSearchCallback callback;
	RList *hits;
	int nhits;
	RMemoryPool *pool;
	int distance;
	int inverse;
	int contiguous;
	int align;
	RSearchUpdate update;
	RList *kws; // TODO: Use r_search_kw_new ()
	RIOBind iob;
	char bckwrds;
} RSearch;

#ifdef R_API

#define R_SEARCH_AES_BOX_SIZE 31

R_API RSearch *r_search_new(int mode);
R_API int r_search_set_mode(RSearch *s, int mode);
R_API RSearch *r_search_free(RSearch *s);

/* keyword management */
R_API RList *r_search_find(RSearch *s, ut64 addr, const ut8 *buf, int len);
R_API int r_search_update(RSearch *s, ut64 *from, const ut8 *buf, long len);
R_API int r_search_update_i(RSearch *s, ut64 from, const ut8 *buf, long len);

R_API void r_search_keyword_free (RSearchKeyword *kw);
R_API RSearchKeyword* r_search_keyword_new(const ut8 *kw, int kwlen, const ut8 *bm, int bmlen, const char *data);
R_API RSearchKeyword* r_search_keyword_new_str(const char *kw, const char *bm, const char *data, int icase);
R_API RSearchKeyword* r_search_keyword_new_hex(const char *kwstr, const char *bmstr, const char *data);
R_API RSearchKeyword* r_search_keyword_new_hexmask(const char *kwstr, const char *data);
R_API RSearchKeyword *r_search_keyword_new_regexp (const char *str, const char *data);

R_API int r_search_kw_add(RSearch *s, RSearchKeyword *kw);
R_API void r_search_reset(RSearch *s, int mode);
R_API void r_search_kw_reset(RSearch *s);

R_API int r_search_range_add(RSearch *s, ut64 from, ut64 to);
R_API int r_search_range_set(RSearch *s, ut64 from, ut64 to);
R_API int r_search_range_reset(RSearch *s);
R_API int r_search_set_blocksize(RSearch *s, ut32 bsize);

R_API int r_search_bmh(const RSearchKeyword *kw, const ut64 from, const ut8 *buf, const int len, ut64 *out);

// TODO: is this an internal API?
R_API int r_search_mybinparse_update(void *s, ut64 from, const ut8 *buf, int len);
R_API int r_search_aes_update(void *s, ut64 from, const ut8 *buf, int len);
R_API int r_search_rsa_update(void *s, ut64 from, const ut8 *buf, int len);
R_API int r_search_deltakey_update(void *s, ut64 from, const ut8 *buf, int len);
R_API int r_search_strings_update(void *s, ut64 from, const ut8 *buf, int len);
R_API int r_search_regexp_update(void *s, ut64 from, const ut8 *buf, int len);
R_API int r_search_xrefs_update(void *s, ut64 from, const ut8 *buf, int len);
R_API int r_search_hit_new(RSearch *s, RSearchKeyword *kw, ut64 addr);
R_API void r_search_set_distance(RSearch *s, int dist);
R_API int r_search_strings(RSearch *s, ut32 min, ut32 max);
R_API int r_search_set_string_limits(RSearch *s, ut32 min, ut32 max); // WTF dupped?
//R_API int r_search_set_callback(RSearch *s, int (*callback)(struct r_search_kw_t *, void *, ut64), void *user);
R_API void r_search_set_callback(RSearch *s, RSearchCallback(callback), void *user);
R_API int r_search_begin(RSearch *s);

/* pattern search */
R_API void r_search_pattern_size(RSearch *s, int size);
R_API int r_search_pattern(RSearch *s, ut64 from, ut64 to);

#ifdef __cplusplus
}
#endif

#endif
#endif
