/* radare - LGPL - Copyright 2008-2014 - pancake */

#ifndef R2_UTIL_H
#define R2_UTIL_H

#include <r_types.h>
#include <btree.h>
#include <r_regex.h>
#include <r_list.h> // radare linked list
#include <r_flist.h> // radare fixed pointer array iterators
#include <list.h> // kernel linked list
#include <r_th.h>
#include <r_lib.h>
#include <dirent.h>
#include <sys/time.h>
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

typedef struct r_mmap_t {
	ut8 *buf;
	ut64 base;
	int len;
	int fd;
	int rw;
#if __WINDOWS__
	HANDLE fh;
	HANDLE fm;
#endif
} RMmap;

typedef struct r_buf_t {
	ut8 *buf;
	int length;
	st64 cur;
	ut64 base;
	RMmap *mmap;
	ut8 empty;
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

/* numbers */
#define R_NUMCALC_STRSZ 4096

typedef struct {
	double d;
	ut64 n;
} RNumCalcValue;

typedef enum {
	RNCNAME, RNCNUMBER, RNCEND, RNCINC, RNCDEC,
	RNCPLUS='+', RNCMINUS='-', RNCMUL='*', RNCDIV='/', RNCMOD='%',
	//RNCXOR='^', RNCOR='|', RNCAND='&',
	RNCNEG='~', RNCAND='&', RNCORR='|', RNCXOR='^',
	RNCPRINT=';', RNCASSIGN='=', RNCLEFTP='(', RNCRIGHTP=')'
} RNumCalcToken;

typedef struct r_num_calc_t {
	RNumCalcToken curr_tok;
	RNumCalcValue number_value;
	char string_value[R_NUMCALC_STRSZ];
	int errors;
	char oc;
	const char *calc_err;
	int calc_i;
	const char *calc_buf;
	int calc_len;
} RNumCalc;


typedef struct r_num_t {
	ut64 (*callback)(struct r_num_t *userptr, const char *str, int *ok);
//	RNumCallback callback;
	ut64 value;
	double fvalue;
	void *userptr;
	int dbz; /// division by zero happened
	RNumCalc nc;
} RNum;

typedef ut64 (*RNumCallback)(struct r_num_t *self, const char *str, int *ok);

typedef struct r_range_item_t {
	ut64 fr;
	ut64 to;
	ut8 *data;
	int datalen;
} RRangeItem;

typedef struct r_range_t {
	int count;
	int changed;
	RList *ranges;
} RRange;

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

/* graph api */
typedef struct r_graph_node_t {
	RList *parents; // <RGraphNode>
	RList *children; // <RGraphNode>
	ut64 addr;
	void *data;
	int refs;
	RListFree free;
} RGraphNode;

typedef struct r_graph_t {
	RList *path; // <RGraphNode>
	RGraphNode *root;
	RList *roots; // <RGraphNode>
	RListIter *cur; // ->data = RGraphNode*
	RList *nodes; // <RGraphNode>
	PrintfCallback printf;
	int level;
} RGraph;

#ifdef R_API
R_API RGraphNode *r_graph_node_new (ut64 addr, void *data);
R_API void r_graph_node_free (RGraphNode *n);
R_API void r_graph_traverse(RGraph *t);
R_API RGraph * r_graph_new ();
R_API void r_graph_free (RGraph* t);
R_API RGraphNode* r_graph_get_current (RGraph *t, ut64 addr);
R_API RGraphNode* r_graph_get_node (RGraph *t, ut64 addr, boolt c);
R_API void r_graph_reset (RGraph *t);
R_API void r_graph_add (RGraph *t, ut64 from, ut64 addr, void *data);
R_API void r_graph_plant(RGraph *t);
R_API void r_graph_push (RGraph *t, ut64 addr, void *data);
R_API RGraphNode* r_graph_pop(RGraph *t);

R_API boolt r_file_truncate (const char *filename, ut64 newsize);
R_API ut64 r_file_size(const char *str);
R_API char *r_file_root(const char *root, const char *path);
R_API boolt r_file_is_directory(const char *str);
R_API boolt r_file_is_regular(const char *str);
R_API RMmap *r_file_mmap (const char *file, boolt rw, ut64 base);
R_API int r_file_mmap_read (const char *file, ut64 addr, ut8 *buf, int len);
R_API int r_file_mmap_write(const char *file, ut64 addr, const ut8 *buf, int len);
R_API void r_file_mmap_free (RMmap *m);

// TODO: find better names and write vapis
#define ut8p_b(x) ((x)[0])
#define ut8p_bw(x) ((x)[0]|((x)[1]<<8))
#define ut8p_bd(x) ((x)[0]|((x)[1]<<8)|((x)[2]<<16)|((x)[3]<<24))
#define ut8p_bq(x) ((x)[0]|((x)[1]<<8)|((x)[2]<<16)|((x)[3]<<24)|((x)[4]<<32)|((x)[5]<<40)|((x)[6]<<48)|((x)[7]<<56))
#define ut8p_lw(x) ((x)[1]|((x)[0]<<8))
#define ut8p_ld(x) ((x)[3]|((x)[2]<<8)|((x)[1]<<16)|((x)[0]<<24))
#define ut8p_lq(x) ((x)[7]|((x)[6]<<8)|((x)[5]<<16)|((x)[4]<<24)|((x)[3]<<32)|((x)[2]<<40)|((x)[1]<<48)|((x)[0]<<56))

R_API RNum *r_num_new(RNumCallback cb, void *ptr);
R_API void r_num_free(RNum *num);
R_API char *r_num_units(char *buf, ut64 num);
R_API int r_num_conditional(RNum *num, const char *str);
R_API ut64 r_num_calc (RNum *num, const char *str, const char **err);
R_API const char *r_num_calc_index (RNum *num, const char *p);
R_API ut64 r_num_chs (int cylinder, int head, int sector, int sectorsize);
R_API int r_num_is_valid_input(RNum *num, const char *input_value);
R_API ut64 r_num_get_input_value(RNum *num, const char *input_value);
R_API char* r_num_as_string(RNum *___, ut64 n);

#define R_BUF_CUR UT64_MAX
R_API RBuffer *r_buf_new();
R_API RBuffer *r_buf_new_with_bytes(const ut8* bytes, ut64 len);
R_API RBuffer *r_buf_file (const char *file);
R_API RBuffer *r_buf_mmap (const char *file, int flags);
R_API int r_buf_set_bits(RBuffer *b, int bitoff, int bitsize, ut64 value);
R_API int r_buf_set_bytes(RBuffer *b, const ut8 *buf, int length);
R_API int r_buf_append_string(RBuffer *b, const char *str);
R_API int r_buf_append_buf(RBuffer *b, RBuffer *a);
R_API int r_buf_append_bytes(RBuffer *b, const ut8 *buf, int length);
R_API int r_buf_append_nbytes(RBuffer *b, int length);
R_API int r_buf_append_ut32(RBuffer *b, ut32 n);
R_API int r_buf_append_ut64(RBuffer *b, ut64 n);
R_API int r_buf_append_ut16(RBuffer *b, ut16 n);
R_API int r_buf_prepend_bytes(RBuffer *b, const ut8 *buf, int length);
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

R_API ut64 r_mem_get_num(const ut8 *b, int size, int endian);

/* MEMORY POOL */
R_API RMemoryPool* r_mem_pool_deinit(RMemoryPool *pool);
R_API RMemoryPool *r_mem_pool_new(int nodesize, int poolsize, int poolcount);
R_API RMemoryPool *r_mem_pool_free(RMemoryPool *pool);
R_API void* r_mem_pool_alloc(RMemoryPool *pool);

/* FACTORY POOL */
R_API RPoolFactory *r_poolfactory_instance();
R_API void r_poolfactory_init (int limit);
R_API RPoolFactory* r_poolfactory_new(int limit);
R_API void *r_poolfactory_alloc(RPoolFactory *pf, int nodesize);
R_API void r_poolfactory_stats(RPoolFactory *pf);
R_API void r_poolfactory_free(RPoolFactory *pf);

R_API int r_mem_count(const ut8 **addr);
R_API RCache* r_cache_new();
R_API void r_cache_free(RCache *c);
R_API const ut8* r_cache_get(RCache *c, ut64 addr, int *len);
R_API int r_cache_set(RCache *c, ut64 addr, const ut8 *buf, int len);
R_API void r_cache_flush (RCache *c);

R_API void r_prof_start(RProfile *p);
R_API double r_prof_end(RProfile *p);

R_API void *r_mem_dup (void *s, int l);
R_API int r_mem_protect(void *ptr, int size, const char *prot);
R_API int r_mem_set_num (ut8 *dest, int dest_size, ut64 num, int endian);
R_API int r_mem_eq(ut8 *a, ut8 *b, int len);
R_API void r_mem_copybits(ut8 *dst, const ut8 *src, int bits);
R_API void r_mem_copyloop (ut8 *dest, const ut8 *orig, int dsize, int osize);
R_API void r_mem_copyendian (ut8 *dest, const ut8 *orig, int size, int endian);
R_API int r_mem_cmp_mask (const ut8 *dest, const ut8 *orig, const ut8 *mask, int len);
R_API const ut8 *r_mem_mem (const ut8 *haystack, int hlen, const ut8 *needle, int nlen);

#define r_num_abs(x) x>0?x:-x
R_API void r_num_minmax_swap(ut64 *a, ut64 *b);
R_API void r_num_minmax_swap_i(int *a, int *b); // XXX this can be a cpp macro :??
R_API ut64 r_num_math(RNum *num, const char *str);
R_API ut64 r_num_get(RNum *num, const char *str);
R_API int r_num_to_bits(char *out, ut64 num);
R_API int r_num_to_trits(char *out, ut64 num);	//Rename this please
R_API int r_num_rand(int max);
R_API void r_num_irand();
R_API ut16 r_num_ntohs (ut16 foo);
R_API int r_is_valid_input_num_value(RNum *num, const char *input_value);
R_API ut64 r_get_input_num_value(RNum *num, const char *input_value);


/* TODO ..use as uppercase maybe? they are macros! */
#define strnull(x) (!x||!*x)
#define iswhitechar(x) ((x)==' '||(x)=='\t'||(x)=='\n'||(x)=='\r')
#define iswhitespace(x) ((x)==' '||(x)=='\t')
#define isseparator(x) ((x)==' '||(x)=='\t'||(x)=='\n'||(x)=='\r'||(x)==' '|| \
		(x)==','||(x)==';'||(x)==':'||(x)=='['||(x)==']'|| \
		(x)=='('||(x)==')'||(x)=='{'||(x)=='}')
#define ishexchar(x) ((x>='0'&&x<='9') ||  (x>='a'&&x<='f') ||  (x>='A'&&x<='F')) {

R_API int r_name_check(const char *name);
R_API int r_name_filter(char *name, int len);
R_API char *r_name_filter2(const char *name);

R_API void r_base64_encode(ut8 *bout, const ut8 *bin, int len);
R_API int r_base64_decode(ut8 *bout, const char *bin, int len);

/* strings */
static inline void r_str_rmch (char *s, char ch) {
	for (;*s; s++) {
		if (*s==ch)
			memmove (s, s+1, strlen (s));
	}
}
#define r_str_array(x,y) ((y>=0 && y<(sizeof(x)/sizeof(*x)))?x[y]:"")
R_API const char *r_str_rchr(const char *base, const char *p, int ch);
R_API const char *r_str_closer_chr (const char *b, const char *s);
R_API int r_str_bounds(const char *str, int *h);
R_API char *r_str_crop(const char *str, int x, int y, int w, int h);
R_API int r_str_len_utf8 (const char *s);
R_API int r_str_len_utf8char (const char *s, int left);
R_API void r_str_filter_zeroline(char *str, int len);
R_API int r_str_write (int fd, const char *b);
R_API void r_str_ncpy(char *dst, const char *src, int n);
R_API void r_str_sanitize(char *c);
R_API const char *r_str_casestr(const char *a, const char *b);
R_API const char *r_str_lastbut (const char *s, char ch, const char *but);
R_API int r_str_split(char *str, char ch);
R_API char* r_str_replace(char *str, const char *key, const char *val, int g);
#define r_str_cpy(x,y) memmove(x,y,strlen(y)+1);
R_API int r_str_bits (char *strout, const ut8 *buf, int len, const char *bitz);
R_API ut64 r_str_bits_from_string(const char *buf, const char *bitz);
R_API int r_str_rwx(const char *str);
R_API int r_str_replace_char (char *s, int a, int b);
R_API const char *r_str_rwx_i(int rwx);
R_API void r_str_writef(int fd, const char *fmt, ...);
R_API char **r_str_argv(const char *str, int *_argc);
R_API void r_str_argv_free(char **argv);
R_API char *r_str_new(char *str);
R_API char *r_str_newf(const char *fmt, ...);
R_API const char *r_str_bool(int b);
R_API const char *r_str_ansi_chrn(const char *str, int n);
R_API int r_str_ansi_len(const char *str);
R_API int r_str_ansi_filter(char *str, int len);
R_API int r_str_word_count(const char *string);
R_API int r_str_char_count(const char *string, char ch);
R_API char *r_str_word_get0set(char *stra, int stralen, int idx, const char *newstr, int *newlen);
R_API int r_str_word_set0(char *str);
R_API const char *r_str_word_get0(const char *str, int idx);
R_API char *r_str_word_get_first(const char *string);
R_API char *r_str_chop(char *str);
R_API const char *r_str_chop_ro(const char *str);
R_API char *r_str_trim(char *str);
R_API char *r_str_trim_head(char *str);
R_API const char *r_str_trim_const(const char *str);
R_API char *r_str_trim_tail(char *str);
R_API char *r_str_trim_head_tail(char *str);
R_API ut32 r_str_hash(const char *str);
R_API ut64 r_str_hash64(const char *str);
R_API char *r_str_clean(char *str);
R_API int r_str_nstr(char *from, char *to, int size);
R_API const char *r_str_lchr(const char *str, char chr);
R_API int r_str_nchr(const char *str, char chr);
R_API char *r_str_ichr(char *str, char chr);
R_API int r_str_ccmp(const char *dst, const char *orig, int ch);
R_API int r_str_cmp(const char *dst, const char *orig, int len);
R_API int r_str_ccpy(char *dst, char *orig, int ch);
R_API const char *r_str_get(const char *str);
R_API char *r_str_ndup(const char *ptr, int len);
R_API char *r_str_dup(char *ptr, const char *string);
R_API void *r_str_free(void *ptr);
R_API int r_str_inject(char *begin, char *end, char *str, int maxlen);
R_API int r_str_delta(char *p, char a, char b);
R_API void r_str_filter(char *str, int len);
R_API const char * r_str_tok (const char *str1, const char b, size_t len);

R_API int r_str_re_match(const char *str, const char *reg);
R_API int r_str_re_replace(const char *str, const char *reg, const char *sub);
R_API int r_str_unescape(char *buf);
R_API char *r_str_escape(const char *buf);
R_API char *r_str_escape_dot(const char *buf);
R_API void r_str_uri_decode(char *buf);
R_API char *r_str_uri_encode (const char *buf);
R_API char *r_str_home(const char *str);
R_API int r_str_nlen (const char *s, int n);
R_API int r_wstr_clen (const char *s);
R_API char *r_str_prefix(char *ptr, const char *string);
R_API char *r_str_prefix_all (char *s, const char *pfx);
R_API char *r_str_concat(char *ptr, const char *string);
R_API char *r_str_concatf(char *ptr, const char *fmt, ...);
R_API char *r_str_concatch(char *x, char y);
R_API void r_str_case(char *str, int up);
R_API void r_str_chop_path (char *s);
R_API ut8 r_str_contains_macro(const char *input_value);
R_API void r_str_truncate_cmd(char *string);

R_API char *r_hex_from_c(const char *code);
R_API int r_str_glob (const char *str, const char *glob);
R_API int r_str_binstr2bin(const char *str, ut8 *out, int outlen);
R_API int r_hex_pair2bin(const char *arg);
R_API int r_hex_str2binmask(const char *in, ut8 *out, ut8 *mask);
R_API int r_hex_str2bin(const char *in, ut8 *out);
R_API int r_hex_bin2str(const ut8 *in, int len, char *out);
R_API char *r_hex_bin2strdup(const ut8 *in, int len);
R_API int r_hex_to_byte(ut8 *val, ut8 c);
R_API st64 r_hex_bin_truncate (ut64 in, int n);

R_API int r_file_chmod (const char *file, const char *mod, int recursive);
R_API char *r_file_temp (const char *prefix);
R_API char *r_file_path(const char *bin);
R_API const char *r_file_basename (const char *path);
R_API char *r_file_dirname (const char *path);
R_API char *r_file_abspath(const char *file);
R_API ut8 *r_inflate(const ut8 *src, int srcLen, int *dstLen);
R_API ut8 *r_file_gzslurp(const char *str, int *outlen, int origonfail);
R_API char *r_stdin_slurp (int *sz);
R_API char *r_file_slurp(const char *str, int *usz);
//R_API char *r_file_slurp_range(const char *str, ut64 off, ut64 sz);
R_API char *r_file_slurp_range(const char *str, ut64 off, int sz, int *osz);
R_API char *r_file_slurp_random_line(const char *file);
R_API ut8 *r_file_slurp_hexpairs(const char *str, int *usz);
R_API boolt r_file_dump(const char *file, const ut8 *buf, int len);
R_API boolt r_file_rm(const char *file);
R_API boolt r_file_rmrf(const char *file);
R_API boolt r_file_exists(const char *str);
R_API boolt r_file_fexists(const char *fmt, ...);
R_API char *r_file_slurp_line(const char *file, int line, int context);
R_API int r_file_mkstemp(const char *prefix, char **oname);
R_API char *r_file_tmpdir();

#define ON_WINDOWS_OS 0xA
#define ON_NIX_OS 0xB

R_API int r_what_os_am_i ();


R_API ut64 r_sys_now();
R_API int r_sys_stop ();
R_API char *r_sys_pid_to_path(int pid);
R_API int r_sys_run(const ut8 *buf, int len);
R_API int r_sys_getpid();
R_API int r_sys_crash_handler(const char *cmd);
R_API const char *r_sys_arch_str(int arch);
R_API int r_sys_arch_id(const char *arch);
R_API RList *r_sys_dir(const char *path);
R_API void r_sys_perror(const char *fun);
#if __WINDOWS__
#define r_sys_mkdir(x) (CreateDirectory(x,NULL)!=0)
#define r_sys_mkdir_failed() (GetLastError () != ERROR_ALREADY_EXISTS)
#else
#define r_sys_mkdir(x) (mkdir(x,0755)!=-1)
#define r_sys_mkdir_failed() (errno != EEXIST)
#endif
R_API int r_sys_rmkdir(const char *dir);
R_API int r_sys_sleep(int secs);
R_API int r_sys_usleep(int usecs);
R_API char *r_sys_getenv(const char *key);
R_API int r_sys_setenv(const char *key, const char *value);
R_API char *r_sys_whoami (char *buf);
R_API char *r_sys_getdir();
R_API int r_sys_chdir(const char *s);
R_API int r_sys_cmd_str_full(const char *cmd, const char *input, char **output, int *len, char **sterr);
#if __WINDOWS__
R_API char *r_sys_cmd_str_w32(const char *cmd);
#endif
R_API int r_sys_truncate(const char *file, int sz);
R_API int r_sys_cmd(const char *cmd);
R_API int r_sys_cmdbg(const char *cmd);
R_API int r_sys_cmdf (const char *fmt, ...);
R_API char *r_sys_cmd_str(const char *cmd, const char *input, int *len);
R_API char *r_sys_cmd_strf(const char *cmd, ...);
//#define r_sys_cmd_str(cmd, input, len) r_sys_cmd_str_full(cmd, input, len, 0)
R_API void r_sys_backtrace(void);

/* utf8 */
typedef wchar_t RRune;
R_API int r_utf8_encode (ut8 *ptr, const RRune  ch);
R_API int r_utf8_decode (const ut8 *ptr, int ptrlen, RRune *ch);
R_API int r_utf8_encode_str (const RRune *str, ut8 *dst, const int dst_length);
R_API int r_utf8_size (const ut8 *ptr);
R_API int r_utf8_strlen (const ut8 *str);
R_API int r_isprint (const RRune c);

/* LOG */
R_API void r_log_msg(const char *str);
R_API void r_log_error(const char *str);
R_API void r_log_file(const char *str);
R_API void r_log_progress(const char *str, int percent);

/* Ranges */
R_API RRange *r_range_new();
R_API RRange *r_range_new_from_string(const char *string);
R_API RRange *r_range_free(RRange *r);
R_API RRangeItem *r_range_item_get(RRange *r, ut64 addr);
R_API ut64 r_range_size(RRange *r);
R_API int r_range_add_from_string(RRange *rgs, const char *string);
R_API RRangeItem *r_range_add(RRange *rgs, ut64 from, ut64 to, int rw);
R_API int r_range_sub(RRange *rgs, ut64 from, ut64 to);
R_API void r_range_merge(RRange *rgs, RRange *r);
R_API int r_range_contains(RRange *rgs, ut64 addr);
R_API int r_range_sort(RRange *rgs);
R_API void r_range_percent(RRange *rgs);
R_API int r_range_list(RRange *rgs, int rad);
R_API int r_range_get_n(RRange *rgs, int n, ut64 *from, ut64 *to);
R_API RRange *r_range_inverse(RRange *rgs, ut64 from, ut64 to, int flags);
R_API int r_range_overlap(ut64 a0, ut64 a1, ut64 b0, ut64 b1, int *d);

#if 0
/* big */
#if HAVE_LIB_GMP
#define RNumBig mpz_t
#elif HAVE_LIB_SSL
#define RNumBig BIGNUM
#else
#define	R_BIG_SIZE 10000
typedef struct r_num_big_t {
	char dgts[R_BIG_SIZE];
	int sign, last;
} RNumBig;
#endif

R_API RNumBig *r_big_new(RNumBig *b);
R_API void r_big_free(RNumBig *b);
R_API void r_big_sub(RNumBig *a, RNumBig *b, RNumBig *c);
R_API void r_big_print(RNumBig *n);
R_API void r_big_set(RNumBig *a, RNumBig *b);
R_API void r_big_set_st(RNumBig *n, int v);
R_API void r_big_set_st64(RNumBig *n, st64 v);
R_API void r_big_set_str(RNumBig *n, const char *str);
R_API void r_big_add (RNumBig *c, RNumBig *a, RNumBig *b);
R_API void r_big_sub(RNumBig *c, RNumBig *a, RNumBig *b);
R_API int r_big_cmp(RNumBig *a, RNumBig *b);
R_API int r_big_cmp_st(RNumBig *n, int v);
R_API void r_big_shift(RNumBig *n, int d);
R_API void r_big_mul (RNumBig *c, RNumBig *a, RNumBig *b);
R_API void r_big_mul_ut (RNumBig *c, RNumBig *a, ut32 b);
R_API void r_big_div(RNumBig *c, RNumBig *a, RNumBig *b);
R_API void r_big_div_ut(RNumBig *a, RNumBig *b, ut32 c);
R_API int r_big_divisible_ut(RNumBig *n, ut32 v);
R_API void r_big_mod(RNumBig *c, RNumBig *a, RNumBig *b);
#endif

/* uleb */
R_API const ut8 *r_uleb128 (const ut8 *data, int datalen, ut64 *v);
R_API const ut8 *r_leb128 (const ut8 *data, st64 *v);
#endif

/* constr */
typedef struct r_constr_t {
	char *b;
	int l;
	int i;
} RConstr;

R_API RConstr* r_constr_new (int size);
R_API void r_constr_free (RConstr *c);
R_API const char *r_constr_get (RConstr *c, const char *str);
R_API const char *r_constr_append (RConstr *c, const char *str);
R_API const char *r_constr_add (RConstr *c, const char *str);

/* sandbox */
R_API DIR* r_sandbox_opendir (const char *path);
R_API int r_sandbox_enable (int e);
R_API int r_sandbox_disable (int e);
R_API int r_sandbox_system (const char *x, int fork);
R_API int r_sandbox_creat (const char *path, int mode);
R_API int r_sandbox_open (const char *path, int mode, int perm);
R_API FILE *r_sandbox_fopen (const char *path, const char *mode);
R_API int r_sandbox_chdir (const char *path);
R_API int r_sandbox_check_path (const char *path);
R_API int r_sandbox_kill(int pid, int sig);

/* derbuijn.c */
R_API char* r_debruijn_pattern(int size, int start, const char* charset);
R_API int r_debruijn_offset(ut64 value, int guest_endian);

/* strpool */
#define R_STRPOOL_INC 1024

typedef struct {
	char *str;
	int len;
	int size;
} RStrpool;

R_API RStrpool* r_strpool_new (int sz);
R_API char *r_strpool_alloc (RStrpool *p, int l);
R_API int r_strpool_append(RStrpool *p, const char *s);
R_API void r_strpool_free (RStrpool *p);
R_API int r_strpool_fit(RStrpool *p);
R_API char *r_strpool_get(RStrpool *p, int index);
R_API char *r_strpool_get_i(RStrpool *p, int index);
R_API int r_strpool_get_index(RStrpool *p, const char *s);
R_API char *r_strpool_next(RStrpool *p, int index);
R_API char *r_strpool_slice (RStrpool *p, int index);
R_API char *r_strpool_empty (RStrpool *p);

typedef struct r_strht_t {
	RStrpool *sp;
	RHashTable *ht;
	RList *ls;
} RStrHT;

R_API RStrHT *r_strht_new();
R_API void r_strht_free(RStrHT *s);
R_API const char *r_strht_get(RStrHT *s, const char *key);
R_API int r_strht_set(RStrHT *s, const char *key, const char *val);
R_API void r_strht_clear(RStrHT *s);
R_API void r_strht_del(RStrHT *s, const char *key);
R_API int r_is_heap (void *p);

typedef struct {
	int len;
	char *ptr;
	char buf[64];
} RStrBuf;

#define R_STRBUF_SAFEGET(sb) (r_strbuf_get (sb) == NULL ? "" : r_strbuf_get (sb))
R_API RStrBuf *r_strbuf_new(const char *s);
R_API int r_strbuf_set(RStrBuf *sb, const char *s);
R_API int r_strbuf_setf(RStrBuf *sb, const char *fmt, ...);
R_API int r_strbuf_append(RStrBuf *sb, const char *s);
R_API int r_strbuf_appendf(RStrBuf *sb, const char *fmt, ...);
R_API char *r_strbuf_get(RStrBuf *sb);
R_API void r_strbuf_free(RStrBuf *sb);
R_API void r_strbuf_fini(RStrBuf *sb);
R_API void r_strbuf_init(RStrBuf *sb);

R_API char **r_sys_get_environ ();
R_API void r_sys_set_environ (char **e);


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
