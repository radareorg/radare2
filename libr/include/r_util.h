#ifndef _INCLUDE_UTIL_R_
#define _INCLUDE_UTIL_R_

#include <r_types.h>
#include <btree.h>
#include <r_list.h> // radare linked list
#include <r_flist.h> // radare fixed pointer array iterators
#include <list.h> // kernel linked list
/* profiling */
#include <sys/time.h>
#ifdef HAVE_LIB_GMP
#include <gmp.h>
#endif
#if HAVE_LIB_SSL
#include <openssl/bn.h>
#endif

/* empty classes */
typedef struct { } RSystem;
//typedef struct { } RStr;
typedef struct { } RLog;
#define RStr char*

typedef struct r_mem_pool_t {
	ut8 **nodes;
	int ncount;
	int npool;
	//
	int nodesize;
	int poolsize;
	int poolcount;
} RMemoryPool;

typedef struct r_buf_t {
	ut8 *buf;
	int length;
	int cur;
	ut64 base;
} RBuffer;

/* r_cache */
// TOTHINK: move into a separated library?
typedef struct r_cache_item_t {
	ut64 addr;
	char *str;
	struct list_head list;
} RCacheItem;

typedef struct r_cache_t {
	ut64 start;
	ut64 end;
	struct list_head items;
} RCache;

typedef struct r_prof_t {
	struct timeval begin;
	double result;
} RProfile;

/* numbers */
typedef struct r_num_t {
	ut64 (*callback)(struct r_num_t *userptr, const char *str, int *ok);
//	RNumCallback callback;
	ut64 value;
	void *userptr;
} RNum;
typedef ut64 (*RNumCallback)(RNum *self, const char *str, int *ok);

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

typedef struct r_mmap_t {
	ut8 *buf;
	int len;
	int fd;
	int rw;
#if __WINDOWS__
	HANDLE fh;
	HANDLE fm;
#endif
} RMmap;

/* bitsize */
enum {
	R_SYS_BITS_8 = 1,
	R_SYS_BITS_16 = 2,
	R_SYS_BITS_32 = 4,
	R_SYS_BITS_64 = 8,
};


/** hashtable **/
typedef struct r_hashtable_entry_t {
	ut32 hash;
	void *data;
} RHashTableEntry;

typedef struct r_hashtable_t {
	RHashTableEntry *table;
	ut32 size;
	ut32 rehash;
	ut32 max_entries;
	ut32 size_index;
	ut32 entries;
	ut32 deleted_entries;
} RHashTable;

typedef struct r_hashtable64_entry_t {
	ut64 hash;
	void *data;
} RHashTable64Entry;

typedef struct r_hashtable64_t {
	RHashTable64Entry *table;
	ut64 size;
	ut64 rehash;
	ut64 max_entries;
	ut64 size_index;
	ut64 entries;
	ut64 deleted_entries;
} RHashTable64;

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


#ifdef R_API

R_API RMmap *r_file_mmap (const char *file, boolt rw);
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

#define R_BUF_CUR -1
R_API RBuffer *r_buf_new();
R_API int r_buf_set_bits(RBuffer *b, int bitoff, int bitsize, ut64 value);
R_API int r_buf_set_bytes(RBuffer *b, ut8 *buf, int length);
R_API int r_buf_append_bytes(RBuffer *b, const ut8 *buf, int length);
R_API int r_buf_prepend_bytes(RBuffer *b, const ut8 *buf, int length);
R_API char *r_buf_to_string(RBuffer *b);
R_API int r_buf_read_at(RBuffer *b, ut64 addr, ut8 *buf, int len);
R_API int r_buf_fread_at(RBuffer *b, ut64 addr, ut8 *buf, const char *fmt, int n);
R_API int r_buf_write_at(RBuffer *b, ut64 addr, const ut8 *buf, int len);
R_API int r_buf_fwrite_at (RBuffer *b, ut64 addr, ut8 *buf, const char *fmt, int n);
R_API void r_buf_free(RBuffer *b);

R_API struct r_mem_pool_t* r_mem_pool_deinit(struct r_mem_pool_t *pool);
R_API struct r_mem_pool_t *r_mem_pool_new(int nodesize, int poolsize, int poolcount);
R_API struct r_mem_pool_t *r_mem_pool_free(struct r_mem_pool_t *pool);
R_API void* r_mem_pool_alloc(struct r_mem_pool_t *pool);
R_API int r_mem_count(const ut8 **addr);
R_API RCache* r_cache_new();
R_API void r_cache_free(struct r_cache_t *c);
R_API char *r_cache_get(struct r_cache_t *c, ut64 addr);
R_API int r_cache_set(struct r_cache_t *c, ut64 addr, char *str);
R_API int r_cache_validate(struct r_cache_t *c, ut64 from, ut64 to);
R_API int r_cache_invalidate(struct r_cache_t *c, ut64 from, ut64 to);

R_API void r_prof_start(struct r_prof_t *p);
R_API double r_prof_end(struct r_prof_t *p);

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
R_API ut64 r_num_math(struct r_num_t *num, const char *str);
R_API ut64 r_num_get(struct r_num_t *num, const char *str);
R_API int r_num_to_bits(char *out, ut64 num);
R_API int r_num_rand(int max);
R_API void r_num_irand();

/* TODO ..use as uppercase maybe? they are macros! */
#define R_BETWEEN(x,y,z) (((x)>=(y)) && ((x)<=(z)))
#define r_offsetof(type, member) ((unsigned long) &((type*)0)->member)
#define strnull(x) (!x||!*x)
#define iswhitechar(x) ((x)==' '||(x)=='\t'||(x)=='\n'||(x)=='\r')
#define iswhitespace(x) ((x)==' '||(x)=='\t')
#define isseparator(x) ((x)==' '||(x)=='\t'||(x)=='\n'||(x)=='\r'||(x)==' '|| \
		(x)==','||(x)==';'||(x)==':'||(x)=='['||(x)==']'|| \
		(x)=='('||(x)==')'||(x)=='{'||(x)=='}')
#define ishexchar(x) ((x>='0'&&x<='9') ||  (x>='a'&&x<='f') ||  (x>='A'&&x<='F')) {

R_API void r_base64_encode(ut8 *bout, const ut8 *bin, int len);
R_API int r_base64_decode(ut8 *bout, const ut8 *bin, int len);
/* strings */
#define r_str_write(x,y) write (x, y, strlen(y))
R_API int r_str_bits (char *strout, const ut8 *buf, int len, const char *bitz);
R_API int r_str_rwx(const char *str);
R_API void r_str_subchr (char *s, int a, int b);
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
R_API int r_str_word_set0(char *str);
R_API char *r_str_word_get0(char *str, int idx);
R_API char *r_str_word_get_first(const char *string);
R_API char *r_str_chop(char *str);
R_API const char *r_str_chop_ro(const char *str);
R_API char *r_str_trim(char *str);
R_API char *r_str_trim_head(char *str);
R_API char *r_str_trim_tail(char *str);
R_API char *r_str_trim_head_tail(char *str);
R_API ut32 r_str_hash(const char *str);
R_API ut64 r_str_hash64(const char *str);
R_API char *r_str_clean(char *str);
R_API int r_str_nstr(char *from, char *to, int size);
R_API char *r_str_lchr(char *str, char chr);
R_API int r_str_nchr(const char *str, char chr);
R_API char *r_str_ichr(char *str, char chr);
R_API int r_str_ccmp(const char *dst, const char *orig, int ch);
R_API int r_str_cmp(const char *dst, const char *orig, int len);
R_API int r_str_ccpy(char *dst, char *orig, int ch);
R_API const char *r_str_get(const char *str);
R_API char *r_str_dup(char *ptr, const char *string);
R_API char *r_str_dup_printf(const char *fmt, ...);
R_API void *r_str_free(void *ptr);
R_API int r_str_inject(char *begin, char *end, char *str, int maxlen);
R_API int r_str_delta(char *p, char a, char b);
R_API void r_str_filter(char *str, int len);

R_API int r_str_re_match(const char *str, const char *reg);
R_API int r_str_re_replace(const char *str, const char *reg, const char *sub);
R_API char *r_str_sub(char *string, char *pat, char *rep, int global);
R_API int r_str_escape(char *buf);
R_API char *r_str_unscape(char *buf);
R_API char *r_str_home(const char *str);
R_API char *r_str_concat(char *ptr, const char *string);
R_API char *r_str_concatf(char *ptr, const char *fmt, ...);
R_API char *r_str_concatch(char *x, char y);
R_API void r_str_case(char *str, int up);
R_API void r_str_chop_path (char *s);

R_API int r_str_glob (const char *str, const char *glob);
R_API int r_str_binstr2bin(const char *str, ut8 *out, int outlen);
R_API int r_hex_pair2bin(const char *arg);
R_API int r_hex_str2binmask(const char *in, ut8 *out, ut8 *mask);
R_API int r_hex_str2bin(const char *in, ut8 *out);
R_API int r_hex_bin2str(const ut8 *in, int len, char *out);
R_API char *r_hex_bin2strdup(const ut8 *in, int len);
R_API int r_hex_to_byte(ut8 *val, ut8 c);
R_API st64 r_hex_bin_truncate (ut64 in, int n);

R_API char *r_file_temp (const char *prefix);
R_API char *r_file_path(const char *bin);
R_API const char *r_file_basename (const char *path);
R_API char *r_file_abspath(const char *file);
R_API char *r_file_slurp(const char *str, int *usz);
//R_API char *r_file_slurp_range(const char *str, ut64 off, ut64 sz);
R_API char *r_file_slurp_range(const char *str, ut64 off, int sz, int *osz);
R_API char *r_file_slurp_random_line(const char *file);
R_API ut8 *r_file_slurp_hexpairs(const char *str, int *usz);
R_API boolt r_file_dump(const char *file, const ut8 *buf, int len);
R_API boolt r_file_rm(const char *file);
R_API boolt r_file_exist(const char *str);
R_API char *r_file_slurp_line(const char *file, int line, int context);
R_API int r_file_mkstemp(const char *prefix, char **oname);
R_API const char *r_file_tmpdir();

R_API ut64 r_sys_now();
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
R_API const char *r_sys_getenv(const char *key);
R_API int r_sys_setenv(const char *key, const char *value);
R_API char *r_sys_getcwd();
R_API char *r_sys_cmd_str_full(const char *cmd, const char *input, int *len, char **sterr);
#if __WINDOWS__
R_API char *r_sys_cmd_str_w32(const char *cmd);
#endif
R_API int r_sys_cmd(const char *cmd);
R_API int r_sys_cmdf (const char *fmt, ...);
R_API char *r_sys_cmd_str(const char *cmd, const char *input, int *len);
R_API char *r_sys_cmd_strf(const char *cmd, ...);
//#define r_sys_cmd_str(cmd, input, len) r_sys_cmd_str_full(cmd, input, len, 0)
R_API void r_sys_backtrace(void);
R_API int r_alloca_init();
R_API ut8 *r_alloca_bytes(int len);
R_API char *r_alloca_str(const char *str);
R_API int r_alloca_ret_i(int n);

/* LOG */
R_API void r_log_msg(const char *str);
R_API void r_log_error(const char *str);
R_API void r_log_file(const char *str);
R_API void r_log_progress(const char *str, int percent);

/* Ranges */
R_API RRange *r_range_new();
R_API RRange *r_range_new_from_string(const char *string);
R_API RRange *r_range_free(RRange *r);
R_API struct r_range_item_t *r_range_item_get(RRange *r, ut64 addr);
R_API ut64 r_range_size(RRange *r);
R_API int r_range_add_from_string(RRange *rgs, const char *string);
R_API struct r_range_item_t *r_range_add(RRange *rgs, ut64 from, ut64 to, int rw);
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


R_API RHashTable* r_hashtable_new(void);
R_API void r_hashtable_free(RHashTable *ht);
R_API void *r_hashtable_lookup(RHashTable *ht, ut32 hash);
R_API boolt r_hashtable_insert(RHashTable *ht, ut32 hash, void *data);
R_API void r_hashtable_remove(RHashTable *ht, ut32 hash);

R_API RHashTable64* r_hashtable64_new(void);
R_API void r_hashtable64_free(RHashTable64 *ht);
R_API void *r_hashtable64_lookup(RHashTable64 *ht, ut64 hash);
R_API boolt r_hashtable64_insert(RHashTable64 *ht, ut64 hash, void *data);
R_API void r_hashtable64_remove(RHashTable64 *ht, ut64 hash);
#endif

#endif
