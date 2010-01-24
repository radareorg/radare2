#ifndef _INCLUDE_UTIL_R_
#define _INCLUDE_UTIL_R_

#include "r_types.h"
#include <btree.h>
#include "r_list.h" // radare linked list
#include "r_array.h" // radare fixed pointer array iterators
#include "list.h" // kernel linked list
/* profiling */
#include <sys/time.h>

/* pool */
typedef struct r_mem_pool_t {
	void **nodes;
	int ncount;
	int npool;
	//
	int nodesize;
	int poolsize;
	int poolcount;
} rMemPool;

/* buf */
typedef struct r_buf_t {
	ut8 *buf;
	int length;
	int cur;
	ut64 base;
} rBuffer;

/* r_cache */
// TOTHINK: move into a separated library?
typedef struct r_cache_item_t {
	ut64 addr;
	char *str;
	struct list_head list;
} rCacheItem;

typedef struct r_cache_t {
	ut64 start;
	ut64 end;
	struct list_head items;
} rCache;

typedef struct r_prof_t {
	struct timeval begin;
	double result;
} rProf;

/* numbers */
typedef struct r_num_t {
	ut64 (*callback)(void *userptr, const char *str, int *ok);
	ut64 value;
	void *userptr;
} rNum;
typedef ut64 (*rNumCallback)(rNum *self, const char *str, int *ok);

#ifdef R_API
R_API struct r_num_t *r_num_new(rNumCallback *cb, void *ptr);

#define R_BUF_CUR -1
R_API struct r_buf_t *r_buf_init(struct r_buf_t *b);
R_API struct r_buf_t *r_buf_new();
R_API int r_buf_set_bits(struct r_buf_t *b, int bitoff, int bitsize, ut64 value);
R_API int r_buf_set_bytes(struct r_buf_t *b, ut8 *buf, int length);
R_API int r_buf_read_at(struct r_buf_t *b, ut64 addr, ut8 *buf, int len);
R_API int r_buf_fread_at(struct r_buf_t *b, ut64 addr, ut8 *buf, const char *fmt, int n);
R_API int r_buf_write_at(struct r_buf_t *b, ut64 addr, const ut8 *buf, int len);
R_API void r_buf_free(struct r_buf_t *b);

R_API struct r_mem_pool_t* r_mem_pool_deinit(struct r_mem_pool_t *pool);
R_API struct r_mem_pool_t* r_mem_pool_init(struct r_mem_pool_t *pool, int nodesize, int poolsize, int poolcount);
R_API struct r_mem_pool_t *r_mem_pool_new(int nodesize, int poolsize, int poolcount);
R_API struct r_mem_pool_t *r_mem_pool_free(struct r_mem_pool_t *pool);
R_API void* r_mem_pool_alloc(struct r_mem_pool_t *pool);
R_API int r_mem_count(ut8 **addr);
R_API void r_cache_init(struct r_cache_t *lang);
R_API rCache* r_cache_new();
R_API void r_cache_free(struct r_cache_t *c);
R_API char *r_cache_get(struct r_cache_t *c, ut64 addr);
R_API int r_cache_set(struct r_cache_t *c, ut64 addr, char *str);
R_API int r_cache_validate(struct r_cache_t *c, ut64 from, ut64 to);
R_API int r_cache_invalidate(struct r_cache_t *c, ut64 from, ut64 to);

R_API void r_prof_start(struct r_prof_t *p);
R_API double r_prof_end(struct r_prof_t *p);

/* memory */
R_API void r_mem_copybits(ut8 *dst, const ut8 *src, int bits);
R_API void r_mem_copyloop (ut8 *dest, const ut8 *orig, int dsize, int osize);
R_API void r_mem_copyendian (ut8 *dest, const ut8 *orig, int size, int endian);
R_API int r_mem_cmp_mask(const ut8 *dest, const ut8 *orig, const ut8 *mask, int len);
R_API const ut8 *r_mem_mem(const ut8 *haystack, int hlen, const ut8 *needle, int nlen);

R_API void r_num_minmax_swap(ut64 *a, ut64 *b);
R_API void r_num_minmax_swap_i(int *a, int *b); // XXX this can be a cpp macro :??
R_API ut64 r_num_math(struct r_num_t *num, const char *str);
R_API ut64 r_num_get(struct r_num_t *num, const char *str);
R_API void r_num_init(struct r_num_t *num);

/* strings */

#define r_offsetof(type, member) ((unsigned long) &((type*)0)->member)

/* TODO ..use as uppercase maybe? they are macros! */
#define strnull(x) (!x||!*x)
#define iswhitechar(x) (x==' '||x=='\t'||x=='\n'||x=='\r')
#define iswhitespace(x) (x==' '||x=='\t')
#define isseparator(x) (x==' '||x=='\t'||x=='\n'||x=='\r'||x==' '|| \
		x==','||x==';'||x==':'||x=='['||x==']'||x=='('||x==')'||x=='{'||x=='}')
#define ishexchar(x) ((x>='0'&&x<='9') ||  (x>='a'&&x<='f') ||  (x>='A'&&x<='F')) {

/* stabilized */
R_API const char *r_str_bool(int b);
R_API const char *r_str_ansi_chrn(const char *str, int n);
R_API int r_str_ansi_len(const char *str);
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
R_API int r_str_hash(const char *str);
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

R_API int r_str_re_match(const char *str, const char *reg);
R_API int r_str_re_replace(const char *str, const char *reg, const char *sub);
R_API char *r_str_sub(char *string, char *pat, char *rep, int global);
R_API int r_str_escape(char *buf);
R_API char *r_str_home(const char *str);
R_API char *r_str_concat(char *ptr, const char *string);
R_API char *r_str_concatf(char *ptr, const char *fmt, ...);
R_API inline void r_str_concatch(char *x, char y);

/* hex */
R_API int r_hex_pair2bin(const char *arg);
R_API int r_hex_str2bin(const char *in, ut8 *out);
R_API int r_hex_bin2str(const ut8 *in, int len, char *out);
R_API char *r_hex_bin2strdup(const ut8 *in, int len);
R_API int r_hex_to_byte(ut8 *val, ut8 c);

/* file */
R_API char *r_file_path(const char *bin);
R_API char *r_file_slurp(const char *str, int *usz);
R_API char *r_file_slurp_range(const char *str, ut64 off, ut64 sz);
R_API char *r_file_slurp_random_line(const char *file);
R_API ut8 *r_file_slurp_hexpairs(const char *str, int *usz);
R_API int r_file_dump(const char *file, const ut8 *buf, int len);
R_API int r_file_rm(const char *file);
R_API int r_file_exist(const char *str);
R_API char *r_file_slurp_line(const char *file, int line, int context);

R_API int r_sys_sleep(int secs);
R_API int r_sys_usleep(int usecs);
R_API const char *r_sys_getenv(const char *key);
R_API int r_sys_setenv(const char *key, const char *value, int ow);
R_API char *r_sys_cmd_str_full(const char *cmd, const char *input, int *len, char **sterr);
#define r_sys_cmd_str(cmd, input, len) r_sys_cmd_str_full(cmd, input, len, 0)
R_API int r_alloca_init();
R_API ut8 *r_alloca_bytes(int len);
R_API char *r_alloca_str(const char *str);
R_API int r_alloca_ret_i(int n);
#endif

#endif
