/* radare - LGPL - Copyright 2008-2016 - pancake */

#ifndef R2_UTIL_H
#define R2_UTIL_H

#include <r_types.h>
#include <r_diff.h>
#include <btree.h>
#include <r_regex.h>
#include <r_list.h> // radare linked list
#include <r_flist.h> // radare fixed pointer array iterators
#include <list.h> // kernel linked list
#include <r_th.h>
#include <dirent.h>
#include <sys/time.h>
#if 0
#include <r_util/r_big.h>
#endif
#include <r_util/r_bitmap.h>
#include <r_util/r_utf8.h>
#include <r_util/r_debruijn.h>
#include <r_util/r_des.h>
#include <r_util/r_file.h>
#include <r_util/r_num.h>
#include <r_util/r_graph.h>
#include <r_util/r_range.h>
#include <r_util/r_sandbox.h>
#include <r_util/r_spaces.h>
#include <r_util/r_str.h>
#include <r_util/r_strpool.h>
#include <r_util/r_sys.h>
#include <r_util/r_tree.h>
#include <r_util/r_uleb128.h>
#if __UNIX__
#include <signal.h>
#endif
#ifdef HAVE_LIB_GMP
#include <gmp.h>
#endif
#if HAVE_LIB_SSL
#include <openssl/bn.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

R_LIB_VERSION_HEADER(r_util);


// TODO: use lowercase here?
#define R_REFCTR_CLASS int refctr;void (*ref_free)(x)
#define R_REFCTR_INIT(x,y) x->refctr=0;x->ref_free=y
#define R_REFCTR_REF(x) x->refctr++
#define R_REFCTR_UNREF(x) if (--x->refctr<=0) x->ref_free(x)

#define R_STATIC_ASSERT(x) switch (0) {case 0: case (x):;}

#if 0
typedef struct {
	R_REFCTR_CLASS;
} Foo;

Foo *r_foo_new () {
	Foo *f = R_NEW(Foo)
	R_REFCTR_INIT (f, r_foo_free);
	...
	return f;
}
Foo *foo = r_foo_new (Foo)
R_REFCTR_REF (foo)
R_REFCTR_UNREF (foo)
#endif

/* empty classes */
typedef struct { } RSystem;
//typedef struct { } RStr;
typedef struct { } RLog;
#define RStr char*

typedef int (*RStrRangeCallback) (void *, int);

typedef struct r_mem_pool_t {
	ut8 **nodes;
	int ncount;
	int npool;
	//
	int nodesize;
	int poolsize;
	int poolcount;
} RMemoryPool;

typedef struct r_mem_pool_factory_t {
	int limit;
	RMemoryPool **pools;
} RPoolFactory;

/* copied from RIOCache */
typedef struct r_buf_cache_t {
        ut64 from;
        ut64 to;
        int size;
        ut8 *data;
        ut8 *odata;
        int written;
} RBufferSparse;

typedef struct r_buf_t {
	ut8 *buf;
	ut64 length;
	st64 cur;
	ut64 base;
	RMmap *mmap;
	bool empty;
	bool ro; // read-only
	int fd;
	RList *sparse;
} RBuffer;

/* r_cache */

typedef struct r_cache_t {
	ut64 base;
	ut8 *buf;
	ut64 len;
} RCache;

typedef struct r_prof_t {
	struct timeval begin;
	double result;
} RProfile;

/* bitsize */
enum {
	R_SYS_BITS_8 = 1,
	R_SYS_BITS_16 = 2,
	R_SYS_BITS_32 = 4,
	R_SYS_BITS_64 = 8,
};

#include "ht.h"

/* r_mixed */

#define RMIXED_MAXKEYS 256
typedef struct r_mixed_data_t {
	int size;
	union {
		RHashTable *ht;
		RHashTable64 *ht64;
	} hash;
} RMixedData;

typedef struct r_mixed_t {
	RList *list;
	RMixedData *keys[RMIXED_MAXKEYS];
	ut64 state[RMIXED_MAXKEYS]; // used by change_(begin|end)
} RMixed;


/* TODO : THIS IS FROM See libr/anal/fcnstore.c for refactoring info */
typedef struct r_list_range_t {
	RHashTable64 *h;
	RList *l;
	//RListComparator c;
} RListRange;

/* stack api */
typedef struct r_stack_t {
	void **elems;
	unsigned int n_elems;
	int top;
} RStack;

/* queue api */
typedef struct r_queue_t {
	void **elems;
	unsigned int capacity;
	unsigned int front;
	int rear;
	unsigned int size;
} RQueue;


#ifdef R_API
R_API RStack *r_stack_new (unsigned int n);
R_API void r_stack_free (RStack *s);
R_API int r_stack_push (RStack *s, void *el);
R_API void *r_stack_pop (RStack *s);
R_API int r_stack_is_empty (RStack *s);
R_API unsigned int r_stack_size (RStack *s);

R_API RQueue *r_queue_new (int n);
R_API void r_queue_free (RQueue *q);
R_API int r_queue_enqueue (RQueue *q, void *el);
R_API void *r_queue_dequeue (RQueue *q);
R_API int r_queue_is_empty (RQueue *q);

// TODO: find better names and write vapis
#define ut8p_b(x) ((x)[0])
#define ut8p_bw(x) ((x)[0]|((x)[1]<<8))
#define ut8p_bd(x) ((x)[0]|((x)[1]<<8)|((x)[2]<<16)|((x)[3]<<24))
#define ut8p_bq(x) ((x)[0]|((x)[1]<<8)|((x)[2]<<16)|((x)[3]<<24)|((x)[4]<<32)|((x)[5]<<40)|((x)[6]<<48)|((x)[7]<<56))
#define ut8p_lw(x) ((x)[1]|((x)[0]<<8))
#define ut8p_ld(x) ((x)[3]|((x)[2]<<8)|((x)[1]<<16)|((x)[0]<<24))
#define ut8p_lq(x) ((x)[7]|((x)[6]<<8)|((x)[5]<<16)|((x)[4]<<24)|((x)[3]<<32)|((x)[2]<<40)|((x)[1]<<48)|((x)[0]<<56))

#define R_BUF_CUR UT64_MAX
/* constructors */
R_API RBuffer *r_buf_new(void);
R_API RBuffer *r_buf_new_with_bytes(const ut8* bytes, ut64 len);
R_API RBuffer *r_buf_new_with_pointers (const ut8 *bytes, ut64 len);
R_API RBuffer *r_buf_new_with_buf(RBuffer *b);
R_API RBuffer *r_buf_new_file(const char *file);
R_API RBuffer *r_buf_new_slurp (const char *file);
R_API RBuffer *r_buf_mmap (const char *file, int flags);
R_API RBuffer *r_buf_new_sparse();
/* methods */
R_API int r_buf_set_bits(RBuffer *b, int bitoff, int bitsize, ut64 value);
R_API int r_buf_set_bytes(RBuffer *b, const ut8 *buf, ut64 length);
R_API int r_buf_append_string(RBuffer *b, const char *str);
R_API bool r_buf_append_buf(RBuffer *b, RBuffer *a);
R_API bool r_buf_append_bytes(RBuffer *b, const ut8 *buf, int length);
R_API bool r_buf_append_nbytes(RBuffer *b, int length);
R_API bool r_buf_append_ut32(RBuffer *b, ut32 n);
R_API bool r_buf_append_ut64(RBuffer *b, ut64 n);
R_API bool r_buf_append_ut16(RBuffer *b, ut16 n);
R_API bool r_buf_prepend_bytes(RBuffer *b, const ut8 *buf, int length);
R_API char *r_buf_to_string(RBuffer *b);
R_API ut8 *r_buf_get_at(RBuffer *b, ut64 addr, int *len);
#define r_buf_read(a,b,c) r_buf_read_at(a,R_BUF_CUR,b,c)
#define r_buf_write(a,b,c) r_buf_write_at(a,R_BUF_CUR,b,c)
R_API int r_buf_read_at(RBuffer *b, ut64 addr, ut8 *buf, int len);
R_API int r_buf_seek (RBuffer *b, st64 addr, int whence);
R_API int r_buf_fread_at(RBuffer *b, ut64 addr, ut8 *buf, const char *fmt, int n);
R_API int r_buf_write_at(RBuffer *b, ut64 addr, const ut8 *buf, int len);
R_API int r_buf_fwrite_at (RBuffer *b, ut64 addr, ut8 *buf, const char *fmt, int n);
R_API void r_buf_free(RBuffer *b);
R_API char *r_buf_free_to_string (RBuffer *b);
R_API const ut8 *r_buf_buffer (RBuffer *b);
R_API ut64 r_buf_size (RBuffer *b);

R_API ut64 r_mem_get_num(const ut8 *b, int size);

/* MEMORY POOL */
R_API RMemoryPool* r_mem_pool_deinit(RMemoryPool *pool);
R_API RMemoryPool *r_mem_pool_new(int nodesize, int poolsize, int poolcount);
R_API RMemoryPool *r_mem_pool_free(RMemoryPool *pool);
R_API void* r_mem_pool_alloc(RMemoryPool *pool);

/* FACTORY POOL */
R_API RPoolFactory *r_poolfactory_instance(void);
R_API void r_poolfactory_init (int limit);
R_API RPoolFactory* r_poolfactory_new(int limit);
R_API void *r_poolfactory_alloc(RPoolFactory *pf, int nodesize);
R_API void r_poolfactory_stats(RPoolFactory *pf);
R_API void r_poolfactory_free(RPoolFactory *pf);

R_API int r_mem_count(const ut8 **addr);
R_API RCache* r_cache_new(void);
R_API void r_cache_free(RCache *c);
R_API const ut8* r_cache_get(RCache *c, ut64 addr, int *len);
R_API int r_cache_set(RCache *c, ut64 addr, const ut8 *buf, int len);
R_API void r_cache_flush (RCache *c);

R_API void r_prof_start(RProfile *p);
R_API double r_prof_end(RProfile *p);

R_API void *r_mem_dup (void *s, int l);
R_API void r_mem_reverse(ut8 *b, int l);
R_API int r_mem_protect(void *ptr, int size, const char *prot);
R_API int r_mem_set_num (ut8 *dest, int dest_size, ut64 num);
R_API int r_mem_eq(ut8 *a, ut8 *b, int len);
R_API void r_mem_copybits(ut8 *dst, const ut8 *src, int bits);
R_API void r_mem_copyloop (ut8 *dest, const ut8 *orig, int dsize, int osize);
R_API void r_mem_swaporcopy (ut8 *dest, const ut8 *src, int len, bool big_endian);
R_API void r_mem_swapendian (ut8 *dest, const ut8 *orig, int size);
R_API int r_mem_cmp_mask (const ut8 *dest, const ut8 *orig, const ut8 *mask, int len);
R_API const ut8 *r_mem_mem (const ut8 *haystack, int hlen, const ut8 *needle, int nlen);
R_API const ut8 *r_mem_mem_aligned(const ut8 *haystack, int hlen, const ut8 *needle, int nlen, int align);

/* TODO ..use as uppercase maybe? they are macros! */
#define strnull(x) (!x||!*x)
#define iswhitechar(x) ((x)==' '||(x)=='\t'||(x)=='\n'||(x)=='\r')
#define iswhitespace(x) ((x)==' '||(x)=='\t')
#define isseparator(x) ((x)==' '||(x)=='\t'||(x)=='\n'||(x)=='\r'||(x)==' '|| \
		(x)==','||(x)==';'||(x)==':'||(x)=='['||(x)==']'|| \
		(x)=='('||(x)==')'||(x)=='{'||(x)=='}')
#define ishexchar(x) ((x>='0'&&x<='9') ||  (x>='a'&&x<='f') ||  (x>='A'&&x<='F'))

R_API int r_name_check(const char *name);
R_API int r_name_filter(char *name, int len);
R_API char *r_name_filter2(const char *name);
R_API int r_name_validate_char(const char ch);

R_API int r_base64_encode(char *bout, const ut8 *bin, int len);
R_API int r_base64_decode(ut8 *bout, const char *bin, int len);
R_API ut8 *r_base64_decode_dyn(const char *in, int len);
R_API char *r_base64_encode_dyn(const char *str, int len);

R_API int r_base91_encode(char *bout, const ut8 *bin, int len);
R_API int r_base91_decode(ut8 *bout, const char *bin, int len);

R_API char *r_punycode_encode(const char*src, int srclen, int *dstlen);
R_API char *r_punycode_decode(const char *src, int srclen, int *dstlen);

R_API int r_hex_pair2bin(const char *arg);
R_API int r_hex_str2binmask(const char *in, ut8 *out, ut8 *mask);
R_API int r_hex_str2bin(const char *in, ut8 *out);
R_API int r_hex_bin2str(const ut8 *in, int len, char *out);
R_API char *r_hex_bin2strdup(const ut8 *in, int len);
R_API int r_hex_to_byte(ut8 *val, ut8 c);
R_API int r_hex_str_is_valid(const char * s);
R_API st64 r_hex_bin_truncate(ut64 in, int n);

/* LOG */
R_API void r_log_msg(const char *str);
R_API void r_log_error(const char *str);
R_API void r_log_file(const char *str);
R_API void r_log_progress(const char *str, int percent);

/*swap*/
static inline ut16 r_swap_ut16(ut16 val) {
    return (val << 8) | (val >> 8 );
}

static inline st16 r_swap_st16(st16 val) {
    val = ((val << 8) & 0xFF00FF00 ) | ((val >> 8) & 0xFF00FF );
    return (val << 16) | (val >> 16);
}

static inline ut32 r_swap_ut32(ut32 val) {
    val = ((val << 8) & 0xFF00FF00 ) | ((val >> 8) & 0xFF00FF );
    return (val << 16) | (val >> 16);
}

static inline st32 r_swap_st32(st32 val) {
    val = ((val << 8) & 0xFF00FF00) | ((val >> 8) & 0xFF00FF );
    return (val << 16) | ((val >> 16) & 0xFFFF);
}


static inline ut64 r_swap_ut64(ut64 val) {
    val = ((val << 8) & 0xFF00FF00FF00FF00ULL ) | ((val >> 8) & 0x00FF00FF00FF00FFULL );
    val = ((val << 16) & 0xFFFF0000FFFF0000ULL ) | ((val >> 16) & 0x0000FFFF0000FFFFULL );
    return (val << 32) | (val >> 32);
}

static inline st64 r_swap_st64(st64 val) {
    val = ((val << 8) & 0xFF00FF00FF00FF00ULL ) | ((val >> 8) & 0x00FF00FF00FF00FFULL );
    val = ((val << 16) & 0xFFFF0000FFFF0000ULL ) | ((val >> 16) & 0x0000FFFF0000FFFFULL );
    return (val << 32) | ((val >> 32) & 0xFFFFFFFFULL);
}
#endif

/* constr */
typedef struct r_constr_t {
	char *b;
	int l;
	int i;
} RConstr;

R_API RConstr* r_constr_new(int size);
R_API void r_constr_free(RConstr *c);
R_API const char *r_constr_get(RConstr *c, const char *str);
R_API const char *r_constr_append(RConstr *c, const char *str);
R_API const char *r_constr_add(RConstr *c, const char *str);

typedef struct r_strht_t {
	RStrpool *sp;
	RHashTable *ht;
	RList *ls;
} RStrHT;

R_API RStrHT *r_strht_new(void);
R_API void r_strht_free(RStrHT *s);
R_API const char *r_strht_get(RStrHT *s, const char *key);
R_API int r_strht_set(RStrHT *s, const char *key, const char *val);
R_API void r_strht_clear(RStrHT *s);
R_API void r_strht_del(RStrHT *s, const char *key);
R_API int r_is_heap(void *p);

typedef struct {
	int len;
	char *ptr;
	int ptrlen;
	char buf[64];
} RStrBuf;

#define R_STRBUF_SAFEGET(sb) (r_strbuf_get (sb) == NULL ? "" : r_strbuf_get (sb))
R_API RStrBuf *r_strbuf_new(const char *s);
R_API bool r_strbuf_set(RStrBuf *sb, const char *s);
R_API bool r_strbuf_setf(RStrBuf *sb, const char *fmt, ...);
R_API int r_strbuf_append(RStrBuf *sb, const char *s);
R_API int r_strbuf_appendf(RStrBuf *sb, const char *fmt, ...);
R_API char *r_strbuf_get(RStrBuf *sb);
R_API char *r_strbuf_drain(RStrBuf *sb);
R_API void r_strbuf_free(RStrBuf *sb);
R_API void r_strbuf_fini(RStrBuf *sb);
R_API void r_strbuf_init(RStrBuf *sb);

R_API int r_util_lines_getline(ut64 *lines_cache, int lines_cache_sz, ut64 off);

/* Some "secured" functions, to do basic operation (mul, sub, add...) on integers */
static inline int UT64_ADD(ut64 *r, ut64 a, ut64 b) {
	if(UT64_MAX - a < b)
		return 0;
	if(r != NULL)
		*r = a + b;
	return 1;
}

static inline int UT64_MUL(ut64 *r, ut64 a, ut64 b) {
	if(a && UT64_MAX / a < b)
		return 0;
	if(r != NULL)
		*r = a * b;
	return 1;
}

static inline int UT64_SUB(ut64 *r, ut64 a, ut64 b) {
	if(b > a)
		return 0;
	if(r != NULL)
		*r = a - b;
	return 1;
}

static inline int UT32_ADD(ut32 *r, ut32 a, ut32 b) {
	if(UT32_MAX - a < b)
		return 0;
	if(r != NULL)
		*r = a + b;
	return 1;
}

static inline int UT32_MUL(ut32 *r, ut32 a, ut32 b) {
	if(a && UT32_MAX / a < b)
		return 0;
	if(r != NULL)
		*r = a * b;
	return 1;
}

static inline int UT32_SUB(ut32 *r, ut32 a, ut32 b) {
	if(b > a)
		return 0;
	if(r != NULL)
		*r = a - b;
	return 1;
}

static inline int UT16_ADD(ut16 *r, ut16 a, ut16 b) {
	if(UT16_MAX - a < b)
		return 0;
	if(r != NULL)
		*r = a + b;
	return 1;
}

static inline int UT16_MUL(ut16 *r, ut16 a, ut16 b) {
	if(a && UT16_MAX / a < b)
		return 0;
	if(r != NULL)
		*r = a * b;
	return 1;
}

static inline int UT16_SUB(ut16 *r, ut16 a, ut16 b) {
	if(b > a)
		return 0;
	if(r != NULL)
		*r = a - b;
	return 1;
}

static inline int UT8_ADD(ut8 *r, ut8 a, ut8 b) {
	if(UT8_MAX - a < b)
		return 0;
	if(r != NULL)
		*r = a + b;
	return 1;
}

static inline int UT8_MUL(ut8 *r, ut8 a, ut8 b) {
	if(a && UT8_MAX / a < b)
		return 0;
	if(r != NULL)
		*r = a * b;
	return 1;
}

static inline int UT8_SUB(ut8 *r, ut8 a, ut8 b) {
	if(b > a)
		return 0;
	if(r != NULL)
		*r = a - b;
	return 1;
}

#ifdef __cplusplus
}
#endif

#endif
