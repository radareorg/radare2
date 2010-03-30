#ifndef _INCLUDE_UTIL_R_
#define _INCLUDE_UTIL_R_

#include <r_types.h>
#include <btree.h>
#include <r_list.h> // radare linked list
#include <r_flist.h> // radare fixed pointer array iterators
#include <list.h> // kernel linked list
/* profiling */
#include <sys/time.h>

/* empty classes */
typedef struct { } RSystem;
typedef struct { } RStr;
typedef struct { } RLog;

typedef struct r_mem_pool_t {
	void **nodes;
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
	ut64 (*callback)(void *userptr, const char *str, int *ok);
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
	struct list_head list;
} RRangeItem;

typedef struct r_range_t {
	int count;
	int changed;
	struct list_head ranges;
} RRange;

#ifdef R_API
/* bitsize */
enum {
	R_SYS_BITS_8 = 1,
	R_SYS_BITS_16 = 2,
	R_SYS_BITS_32 = 4,
	R_SYS_BITS_64 = 8,
};

/* arch */
// TODO: This must deprecate DEFAULT_ARCH??
#if __i386__
#define R_SYS_ARCH "x86"
#define R_SYS_BITS R_SYS_BITS_32
#elif __x86_64__
#define R_SYS_ARCH "x86"
#define R_SYS_BITS (R_SYS_BITS_32 | R_SYS_BITS_64)
#elif __POWERPC__
#define R_SYS_ARCH "powerpc"
#define R_SYS_BITS R_SYS_BITS_32
#elif __arm__
#define R_SYS_ARCH "arm"
#define R_SYS_BITS R_SYS_BITS_32
#elif __sparc__
#define R_SYS_ARCH "sparc"
#define R_SYS_BITS R_SYS_BITS_32
#elif __mips__
#define R_SYS_ARCH "mips"
#define R_SYS_BITS R_SYS_BITS_32
#else
#define R_SYS_ARCH "unknown"
#define R_SYS_BITS R_SYS_BITS_32
#endif

/* os */
#if __APPLE__
#define R_SYS_OS "darwin"
#elif __linux__
#define R_SYS_OS "linux"
#elif __WIN32__ || __CYGWIN__ || MINGW32
#define R_SYS_OS "windows"
#elif __NetBSD__ 
#define R_SYS_OS "netbsd"
#elif __OpenBSD__
#define R_SYS_OS "openbsd"
#elif __FreeBSD__
#define R_SYS_OS "freebsd"
#else
#define R_SYS_OS "unknown"
#endif

/* endian */
#if LIL_ENDIAN
#define R_SYS_ENDIAN "little"
#else
#define R_SYS_ENDIAN "big"
#endif

R_API RNum *r_num_new(RNumCallback cb, void *ptr);

#define R_BUF_CUR -1
R_API RBuffer *r_buf_init(RBuffer *b);
R_API RBuffer *r_buf_new();
R_API int r_buf_set_bits(RBuffer *b, int bitoff, int bitsize, ut64 value);
R_API int r_buf_set_bytes(RBuffer *b, ut8 *buf, int length);
R_API int r_buf_read_at(RBuffer *b, ut64 addr, ut8 *buf, int len);
R_API int r_buf_fread_at(RBuffer *b, ut64 addr, ut8 *buf, const char *fmt, int n);
R_API int r_buf_write_at(RBuffer *b, ut64 addr, const ut8 *buf, int len);
R_API int r_buf_fwrite_at (RBuffer *b, ut64 addr, ut8 *buf, const char *fmt, int n);
R_API void r_buf_free(RBuffer *b);

R_API struct r_mem_pool_t* r_mem_pool_deinit(struct r_mem_pool_t *pool);
R_API struct r_mem_pool_t* r_mem_pool_init(struct r_mem_pool_t *pool, int nodesize, int poolsize, int poolcount);
R_API struct r_mem_pool_t *r_mem_pool_new(int nodesize, int poolsize, int poolcount);
R_API struct r_mem_pool_t *r_mem_pool_free(struct r_mem_pool_t *pool);
R_API void* r_mem_pool_alloc(struct r_mem_pool_t *pool);
R_API int r_mem_count(ut8 **addr);
R_API void r_cache_init(struct r_cache_t *lang);
R_API RCache* r_cache_new();
R_API void r_cache_free(struct r_cache_t *c);
R_API char *r_cache_get(struct r_cache_t *c, ut64 addr);
R_API int r_cache_set(struct r_cache_t *c, ut64 addr, char *str);
R_API int r_cache_validate(struct r_cache_t *c, ut64 from, ut64 to);
R_API int r_cache_invalidate(struct r_cache_t *c, ut64 from, ut64 to);

R_API void r_prof_start(struct r_prof_t *p);
R_API double r_prof_end(struct r_prof_t *p);

R_API void r_mem_copybits(ut8 *dst, const ut8 *src, int bits);
R_API void r_mem_copyloop (ut8 *dest, const ut8 *orig, int dsize, int osize);
R_API void r_mem_copyendian (ut8 *dest, const ut8 *orig, int size, int endian);
R_API int r_mem_cmp_mask(const ut8 *dest, const ut8 *orig, const ut8 *mask, int len);
R_API const ut8 *r_mem_mem(const ut8 *haystack, int hlen, const ut8 *needle, int nlen);

#define r_num_abs(x) x>0?x:-x
R_API void r_num_minmax_swap(ut64 *a, ut64 *b);
R_API void r_num_minmax_swap_i(int *a, int *b); // XXX this can be a cpp macro :??
R_API ut64 r_num_math(struct r_num_t *num, const char *str);
R_API ut64 r_num_get(struct r_num_t *num, const char *str);
R_API void r_num_init(struct r_num_t *num);

/* TODO ..use as uppercase maybe? they are macros! */
#define r_offsetof(type, member) ((unsigned long) &((type*)0)->member)
#define strnull(x) (!x||!*x)
#define iswhitechar(x) (x==' '||x=='\t'||x=='\n'||x=='\r')
#define iswhitespace(x) (x==' '||x=='\t')
#define isseparator(x) (x==' '||x=='\t'||x=='\n'||x=='\r'||x==' '|| \
	x==','||x==';'||x==':'||x=='['||x==']'||x=='('||x==')'||x=='{'||x=='}')
#define ishexchar(x) ((x>='0'&&x<='9') ||  (x>='a'&&x<='f') ||  (x>='A'&&x<='F')) {

/* strings */
#define r_str_write(x,y) write (x, y, strlen(y))
R_API int r_str_writef(int fd, const char *fmt, ...);
R_API char **r_str_argv(const char *str, int *_argc);
R_API void r_str_argv_free(char **argv);
R_API char *r_str_new(char *str);
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
R_API void r_str_filter(char *str, int len);

R_API int r_str_re_match(const char *str, const char *reg);
R_API int r_str_re_replace(const char *str, const char *reg, const char *sub);
R_API char *r_str_sub(char *string, char *pat, char *rep, int global);
R_API int r_str_escape(char *buf);
R_API char *r_str_home(const char *str);
R_API char *r_str_concat(char *ptr, const char *string);
R_API char *r_str_concatf(char *ptr, const char *fmt, ...);
R_API void r_str_concatch(char *x, char y);
R_API void r_str_case(char *str, int up);

R_API int r_hex_pair2bin(const char *arg);
R_API int r_hex_str2bin(const char *in, ut8 *out);
R_API int r_hex_bin2str(const ut8 *in, int len, char *out);
R_API char *r_hex_bin2strdup(const ut8 *in, int len);
R_API int r_hex_to_byte(ut8 *val, ut8 c);

R_API char *r_file_path(const char *bin);
R_API const char *r_file_basename (const char *path);
R_API const char *r_file_abspath(const char *file);
R_API char *r_file_slurp(const char *str, int *usz);
R_API char *r_file_slurp_range(const char *str, ut64 off, ut64 sz);
R_API char *r_file_slurp_random_line(const char *file);
R_API ut8 *r_file_slurp_hexpairs(const char *str, int *usz);
R_API int r_file_dump(const char *file, const ut8 *buf, int len);
R_API int r_file_rm(const char *file);
R_API int r_file_exist(const char *str);
R_API char *r_file_slurp_line(const char *file, int line, int context);

R_API ut64 r_sys_now();
R_API int r_sys_mkdir(const char *dir);
R_API int r_sys_sleep(int secs);
R_API int r_sys_usleep(int usecs);
R_API const char *r_sys_getenv(const char *key);
R_API int r_sys_setenv(const char *key, const char *value, int ow);
R_API char *r_sys_getcwd();
R_API char *r_sys_cmd_str_full(const char *cmd, const char *input, int *len, char **sterr);
R_API int r_sys_cmd(const char *cmd);
R_API char *r_sys_cmd_str(const char *cmd, const char *input, int *len);
//#define r_sys_cmd_str(cmd, input, len) r_sys_cmd_str_full(cmd, input, len, 0)
R_API int r_alloca_init();
R_API ut8 *r_alloca_bytes(int len);
R_API char *r_alloca_str(const char *str);
R_API int r_alloca_ret_i(int n);

/* LOG */
R_API int r_log_msg(const char *str);
R_API int r_log_error(const char *str);
R_API int r_log_progress(const char *str, int percent);

/* Ranges */
R_API int r_range_init(struct r_range_t *r);
R_API RRange *r_range_new();
R_API RRange *r_range_new_from_string(const char *string);
R_API RRange *r_range_free(RRange *r);
R_API struct r_range_item_t *r_range_item_get(RRange *r, ut64 addr);
R_API ut64 r_range_size(RRange *r);
R_API int r_range_add_from_string(RRange *rgs, const char *string);
R_API struct r_range_item_t *r_range_add(RRange *rgs, ut64 from, ut64 to, int rw);
R_API int r_range_sub(RRange *rgs, ut64 from, ut64 to);
R_API int r_range_merge(RRange *rgs, RRange *r);
R_API int r_range_contains(RRange *rgs, ut64 addr);
R_API int r_range_sort(RRange *rgs);
R_API void r_range_percent(RRange *rgs);
R_API int r_range_list(RRange *rgs, int rad);
R_API int r_range_get_n(RRange *rgs, int n, ut64 *from, ut64 *to);
R_API RRange *r_range_inverse(RRange *rgs, ut64 from, ut64 to, int flags);
R_API int r_range_overlap(ut64 a0, ut64 a1, ut64 b0, ut64 b1, int *d);
#endif

#endif
