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
#include <r_util/r_base64.h>
#include <r_util/r_base91.h>
#include <r_util/r_buf.h>
#include <r_util/r_bitmap.h>
#include <r_util/r_constr.h>
#include <r_util/r_debruijn.h>
#include <r_util/r_cache.h>
#include <r_util/r_des.h>
#include <r_util/r_file.h>
#include <r_util/r_hex.h>
#include <r_util/r_log.h>
#include <r_util/r_mem.h>
#include <r_util/r_mixed.h>
#include <r_util/r_name.h>
#include <r_util/r_num.h>
#include <r_util/r_graph.h>
#include <r_util/r_pool.h>
#include <r_util/r_punycode.h>
#include <r_util/r_queue.h>
#include <r_util/r_range.h>
#include <r_util/r_sandbox.h>
#include <r_util/r_spaces.h>
#include <r_util/r_stack.h>
#include <r_util/r_str.h>
#include <r_util/r_strbuf.h>
#include <r_util/r_strht.h>
#include <r_util/r_strpool.h>
#include <r_util/r_sys.h>
#include <r_util/r_tree.h>
#include <r_util/r_uleb128.h>
#include <r_util/r_utf8.h>
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

/* TODO : THIS IS FROM See libr/anal/fcnstore.c for refactoring info */
typedef struct r_list_range_t {
	RHashTable64 *h;
	RList *l;
	//RListComparator c;
} RListRange;

#ifdef R_API

// TODO: find better names and write vapis
#define ut8p_b(x) ((x)[0])
#define ut8p_bw(x) ((x)[0]|((x)[1]<<8))
#define ut8p_bd(x) ((x)[0]|((x)[1]<<8)|((x)[2]<<16)|((x)[3]<<24))
#define ut8p_bq(x) ((x)[0]|((x)[1]<<8)|((x)[2]<<16)|((x)[3]<<24)|((x)[4]<<32)|((x)[5]<<40)|((x)[6]<<48)|((x)[7]<<56))
#define ut8p_lw(x) ((x)[1]|((x)[0]<<8))
#define ut8p_ld(x) ((x)[3]|((x)[2]<<8)|((x)[1]<<16)|((x)[0]<<24))
#define ut8p_lq(x) ((x)[7]|((x)[6]<<8)|((x)[5]<<16)|((x)[4]<<24)|((x)[3]<<32)|((x)[2]<<40)|((x)[1]<<48)|((x)[0]<<56))

/* TODO ..use as uppercase maybe? they are macros! */
#define strnull(x) (!x||!*x)
#define iswhitechar(x) ((x)==' '||(x)=='\t'||(x)=='\n'||(x)=='\r')
#define iswhitespace(x) ((x)==' '||(x)=='\t')
#define isseparator(x) ((x)==' '||(x)=='\t'||(x)=='\n'||(x)=='\r'||(x)==' '|| \
		(x)==','||(x)==';'||(x)==':'||(x)=='['||(x)==']'|| \
		(x)=='('||(x)==')'||(x)=='{'||(x)=='}')
#define ishexchar(x) ((x>='0'&&x<='9') ||  (x>='a'&&x<='f') ||  (x>='A'&&x<='F'))

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
