#ifndef R_STR_H
#define R_STR_H

#include "r_str_util.h"
#include <r_list.h>
#include <r_vec.h>
#include <r_types_base.h>
#include <stdarg.h>
#include <wchar.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
	R_STRING_ENC_LATIN1 = 'a',
	R_STRING_ENC_UTF8 = '8',
	R_STRING_ENC_UTF16LE = 'u',
	R_STRING_ENC_UTF32LE = 'U',
	R_STRING_ENC_UTF16BE = 'b',
	R_STRING_ENC_UTF32BE = 'B',
	R_STRING_ENC_GUESS = 'g',
} RStrEnc;

typedef struct {
	char *str;
	char buf[64]; // 20s vs 11s - 2x faster if string fits in buffer
	int len;
	char *ptr;
	bool weak;
} RString;

// string split using rvec
typedef struct {
	ut16 from;
	ut16 to;
} RStringSlice;

R_VEC_TYPE (RVecStringSlice, RStringSlice);


typedef int (*RStrRangeCallback) (void *, int);

// can be replaced with RString
#define r_strf_buffer(s) char strbuf[s]
#define r_strf_var(n,s,f, ...) char n[s]; snprintf (n, s, f, __VA_ARGS__);
#define r_strf(s,...) (snprintf (strbuf, sizeof (strbuf), s, __VA_ARGS__)? strbuf: strbuf)
#define r_str_var(n,s,f) char n[s]; r_str_ncpy (n, f, s);

typedef struct r_charset_rune_t {
	ut8 *ch;
	ut8 *hx;
	struct r_charset_rune_t *left;
	struct r_charset_rune_t *right;
} RCharsetRune;

typedef struct r_charset_t {
	bool loaded;
	Sdb *db;
	Sdb *db_char_to_hex;
	RCharsetRune *custom_charset;
	size_t encode_maxkeylen;
	size_t decode_maxkeylen;
} RCharset;

#define R_STR_ISEMPTY(x) (!(x) || !*(x))
#define R_STR_ISNOTEMPTY(x) ((x) && *(x))
// XXX must deprecate
#define R_STR_DUP(x) (((x) != NULL) ? strdup ((x)) : NULL)
#define r_str_array(x,y) ((y >= 0 && y < (sizeof (x) / sizeof (*(x))))?(x)[(y)]: "")
R_API RCharset *r_charset_new(void);
R_API void r_charset_free(RCharset *charset);
R_API RCharsetRune *r_charset_rune_new(const ut8 *ch, const ut8 *hx);
R_API void r_charset_rune_free(RCharsetRune *rcr);
R_API size_t r_charset_encode_str(RCharset *rc, ut8 *out, size_t out_len, const ut8 *in, size_t in_len);
R_API size_t r_charset_decode_str(RCharset *rc, ut8 *out, size_t out_len, const ut8 *in, size_t in_len);
R_API bool r_charset_open(RCharset *c, const char *cs);
R_API bool r_charset_use(RCharset *c, const char *cf);
R_API RList *r_charset_list(RCharset *c);
R_API void r_charset_close(RCharset *c);
R_API RCharsetRune *add_rune(RCharsetRune *rcsr, const ut8 *ch, const ut8 *hx);
R_API RCharsetRune *search_from_hex(RCharsetRune *rcsr, const ut8 *hx);
R_API RCharsetRune *search_from_char(RCharsetRune *rcsr, const ut8 *ch);

// str
R_API char *r_str_repeat(const char *ch, int sz);
R_API const char *r_str_pad(const char ch, int len);
R_API const char *r_str_rstr(const char *base, const char *p);
R_API const char *r_strstr_ansi(const char *a, const char *b);
R_API const char *r_str_rchr(const char *base, const char *p, int ch);
R_API const char *r_str_nchr(const char *str, char chr, int maxlen);
R_API const char *r_str_closer_chr(const char *b, const char *s);
R_API int r_str_bounds(const char *str, int *h);
R_API bool r_str_eq(const char *s1, const char *s2);
R_API bool r_str_eqi(const char *s1, const char *s2);
R_API char *r_str_crop(const char *str, unsigned int x, unsigned int y, unsigned int x2, unsigned int y2);
R_API char *r_str_scale(const char *r, int w, int h);
R_API bool r_str_range_in(const char *r, ut64 addr);
R_API int r_str_size(const char *s, int *rows);
R_API size_t r_str_len_utf8(const char *s);
R_API size_t r_str_len_utf8_ansi(const char *str);
R_API size_t r_str_len_utf8char(const char *s, int left);
R_API size_t r_str_utf8_charsize(const char *str);
R_API size_t r_str_utf8_charsize_prev(const char *str, int prev_len);
R_API size_t r_str_utf8_charsize_last(const char *str);
R_API void r_str_filter_zeroline(char *str, int len);
R_API size_t r_str_utf8_codepoint(const char *s, size_t left);
R_API bool r_str_char_fullwidth(const char *s, size_t left);
R_API int r_str_write(int fd, const char *b);
R_API void r_str_sanitize(char *c);
R_API char *r_str_sanitize_sdb_key(const char *s);
R_API const char *r_str_casestr(const char *a, const char *b);
R_API const char *r_str_firstbut(const char *s, char ch, const char *but);
R_API const char *r_str_firstbut_escape(const char *s, char ch, const char *but);
R_API const char *r_str_lastbut(const char *s, char ch, const char *but);
R_API int r_str_split(char *str, char ch);
R_API char *r_str_slice(const char *str, RStringSlice s);
R_API const char *r_str_asciitable(void);

R_API RVecStringSlice *r_str_split_vec(const char *str, const char *c, int n);
R_API RList *r_str_split_list(char *str, const char *c, int n);
R_API RList *r_str_split_duplist(const char *str, const char *c, bool trim);
R_API size_t *r_str_split_lines(char *str, size_t *count);
R_API R_MUSTUSE char* r_str_replace(char *str, const char *key, const char *val, int g);
R_API R_MUSTUSE char* r_str_replace_all(char *str, const char *key, const char *val);
R_API R_MUSTUSE char *r_str_replace_icase(char *str, const char *key, const char *val, int g, int keep_case);
R_API void r_str_replace_in(char *str, ut32 sz, const char *key, const char *val, int g);
R_API R_MUSTUSE char* r_str_replace_thunked(char *str, char *clean, int *thunk, int clen, const char *key, const char *val, int g);
R_API R_MUSTUSE char* r_str_replace_thunked(char *str, char *clean, int *thunk, int clen, const char *key, const char *val, int g);
#define r_str_cpy(x,y) memmove ((x), (y), strlen (y) + 1);
#define r_str_cat(x,y) memmove ((x) + strlen (x), (y), strlen (y) + 1);
R_API int r_str_bits(char *strout, const ut8 *buf, int len, const char *bitz);
R_API int r_str_bits64(char *strout, ut64 in);
R_API ut64 r_str_bits_from_string(const char *buf, const char *bitz);
R_API int r_str_rwx(const char *str);
R_API int r_str_replace_ch(char *s, char a, char b, bool g);
R_API int r_str_replace_char(char *s, int a, int b);
R_API int r_str_replace_char_once(char *s, int a, int b);
R_API void r_str_remove_char(char *str, char c);
R_API const char *r_str_rwx_i(int rwx);
R_API int r_str_fmtargs(const char *fmt);
R_API char *r_str_arg_escape(const char *arg);
R_API int r_str_arg_unescape(char *arg);
R_API char **r_str_argv(const char *str, int *_argc);
R_API void r_str_argv_free(char **argv);
R_API char *r_str_new(const char *str);
R_API void r_str_fixspaces(char *str);
R_API int r_snprintf(char *string, int len, const char *fmt, ...) R_PRINTF_CHECK(3, 4);
R_API bool r_str_is_ascii(const char *str);
R_API char *r_str_nextword(char *s, char ch);
R_API bool r_str_is_printable(const char *str);
R_API bool r_str_is_printable_limited(const char *str, int size);
R_API bool r_str_is_printable_incl_newlines(const char *str);
R_API char *r_str_appendlen(char *ptr, const char *string, int slen);
R_API char *r_str_newf(const char *fmt, ...) R_PRINTF_CHECK(1, 2);
R_API char *r_str_newvf(const char *fmt, va_list ap);
R_API int r_str_distance(const char *a, const char *b);
R_API char *r_str_newlen(const char *str, int len);
R_API const char *r_str_sysbits(const int v);
R_API char *r_str_trunc_ellipsis(const char *str, int len);
R_API const char *r_str_bool(bool b);
R_API bool r_str_is_true(const char *s);
R_API bool r_str_is_false(const char *s);
R_API bool r_str_is_bool(const char *val);
R_API const char *r_str_ansi_chrn(const char *str, size_t n);
R_API size_t r_str_ansi_strip(char *str);
R_API size_t r_str_ansi_len(const char *str);
R_API size_t r_str_ansi_nlen(const char *str, size_t len);
R_API int r_str_ansi_trim(char *str, int str_len, int n);
R_API int r_str_ansi_filter(char *str, char **out, int **cposs, int len);
R_API char *r_str_ansi_resetbg(const char *str, const char *bgcolor);
R_API char *r_str_ansi_crop(const char *str, unsigned int x, unsigned int y, unsigned int x2, unsigned int y2);
R_API int r_str_word_count(const char *string);
R_API size_t r_str_char_count(const char *string, char ch);
R_API char *r_str_word_get0set(char *stra, int stralen, int idx, const char *newstr, int *newlen);
// R_UNUSED R_API char *r_str_insert(char *src, int pos, const char *str);
R_API int r_str_word_set0(char *str);
R_API int r_str_word_set0_stack(char *str);
R_API const char *r_str_word_get0(const char *str, int idx);
R_API char *r_str_word_get_first(const char *string);
R_API void r_str_trim(char *str);
R_API void r_str_trim_emptylines(char *str);
R_API int r_str_ntrim(char *str, int n);
R_API char *r_str_wrap(const char *str, int w);
R_API char *r_str_trim_dup(const char *str);
R_API char *r_str_trim_ndup(const char *str, size_t n);
R_API char *r_str_trim_lines(char *str);
R_API void r_str_trim_head(char *str);
R_API const char *r_str_trim_head_ro(const char *str);
R_API const char *r_str_trim_head_wp(const char *str);
R_API void r_str_trim_tail(char *str);
R_API void r_str_trim_args(char *str);
R_API ut32 r_str_hash(const char *str);
R_API ut64 r_str_hash64(const char *str);
R_API char *r_str_trim_nc(char *str);
R_API const char *r_str_nstr(const char *from, const char *to, int size);
R_API const char *r_str_lchr(const char *str, char chr);
R_API const char *r_sub_str_lchr(const char *str, int start, int end, char chr);
R_API const char *r_sub_str_rchr(const char *str, int start, int end, char chr);
R_API char *r_str_ichr(char *str, char chr);
R_API bool r_str_ccmp(const char *dst, const char *orig, int ch);
R_API bool r_str_cmp_list(const char *list, const char *item, char sep);
R_API int r_str_casecmp(const char *dst, const char *orig);
R_API int r_str_ncasecmp(const char *dst, const char *orig, size_t n);
R_API const char *r_str_get(const char *str);
R_API const char *r_str_get_fail(const char *str, const char *failstr);
R_API const char *r_str_getf(const char *str);
R_API char *r_str_ndup(const char *ptr, int len);
R_API int r_str_inject(char *begin, char *end, char *str, int maxlen);
R_API int r_str_delta(char *p, char a, char b);
R_API void r_str_filter(char *str, int len);
R_API const char *r_str_tok(const char *str1, const char b, size_t len);
R_API char *r_str_tok_next(char *s);

R_API char *r_str_tok_r(char *str, const char *delim, char **save_ptr);
R_API wchar_t *r_str_mb_to_wc(const char *buf);
R_API char *r_str_wc_to_mb(const wchar_t *buf);
R_API wchar_t *r_str_mb_to_wc_l(const char *buf, int len);
R_API char *r_str_wc_to_mb_l(const wchar_t *buf, int len);
R_API const char *r_str_str_xy(const char *s, const char *word, const char *prev, int *x, int *y);

typedef void(*str_operation)(char *c);

R_API int r_str_do_until_token(str_operation op, char *str, const char tok);

R_API void r_str_reverse(char *str);
R_API int r_str_re_match(const char *str, const char *reg);
R_API int r_str_re_replace(const char *str, const char *reg, const char *sub);
R_API int r_str_path_unescape(char *path);
R_API char *r_str_path_escape(const char *path);
R_API int r_str_unescape(char *buf);
R_API char *r_str_sanitize_r2(const char *buf);
R_API char *r_str_escape_raw(const ut8 *buf, int sz);
R_API char *r_str_escape(const char *buf);
R_API char *r_str_escape_sh(const char *buf);
R_API char *r_str_escape_sql(const char *buf);
R_API char *r_str_escape_dot(const char *buf);
R_API char *r_str_escape_latin1(const char *buf, bool show_asciidot, bool esc_bslash, bool colors);
R_API char *r_str_escape_utf8(const char *buf, bool show_asciidot, bool esc_bslash);
R_API char *r_str_escape_utf8_keep_printable(const char *buf, bool show_asciidot, bool esc_bslash); // like escape_utf8 but leaves valid \uXXXX chars directly in utf-8
R_API char *r_str_escape_utf16le(const char *buf, int buf_size, bool show_asciidot, bool esc_bslash);
R_API char *r_str_escape_utf32le(const char *buf, int buf_size, bool show_asciidot, bool esc_bslash);
R_API char *r_str_escape_utf16be(const char *buf, int buf_size, bool show_asciidot, bool esc_bslash);
R_API char *r_str_escape_utf32be(const char *buf, int buf_size, bool show_asciidot, bool esc_bslash);
R_API void r_str_byte_escape(const char *p, char **dst, int dot_nl, bool default_dot, bool esc_bslash);
R_API char *r_str_format_msvc_argv(size_t argc, const char **argv);
R_API void r_str_uri_decode(char *buf);
R_API char *r_str_uri_encode(const char *buf);
R_API char *r_str_utf16_decode(const ut8 *s, int len);
R_API int r_str_utf16_to_utf8(ut8 *dst, int len_dst, const ut8 *src, int len_src, int little_endian);
R_API char *r_str_utf16_encode(const char *s, int len);
R_API char *r_str_escape_utf8_for_json(const char *s, int len);
R_API char *r_str_escape_utf8_for_json_strip(const char *buf, int buf_size);
R_API char *r_str_encoded_json(const char *buf, int buf_size, int encoding);
R_API R_MUSTUSE char *r_str_r2_prefix(const char *str);
R_API size_t r_str_nlen(const char *s, int n);
R_API size_t r_str_nlen_w(const char *s, int n);
R_API size_t r_wstr_clen(const char *s);
R_API char *r_str_prepend(char *ptr, const char *string);
R_API char *r_str_prefix_all(const char *s, const char *pfx);
R_API char *r_str_append(char *ptr, const char *string);
R_API char *r_str_append_owned(char *ptr, char *string);
R_API char *r_str_appendf(char *ptr, const char *fmt, ...) R_PRINTF_CHECK(2, 3);
R_API char *r_str_appendch(char *x, char y);
R_API void r_str_case(char *str, bool up);
R_API void r_str_trim_path(char *s);
R_API ut8 r_str_contains_macro(const char *input_value);
R_API void r_str_truncate_cmd(char *string);
R_API bool r_str_glob(const char *str, const char *glob);
R_API char *r_str_between(const char *str, const char *prefix, const char *suffix);
#undef r_str_startswith
static inline size_t r_str_ncpy(char *dst, const char *src, size_t n) {
	size_t i;

	// do not do anything if n is 0
	if (n == 0) {
		return 0;
	}

	n--;
	for (i = 0; src[i] && n > 0; i++, n--) {
		dst[i] = src[i];
	}
	dst[i] = 0;
	return i;
}
R_API bool r_str_startswith(const char *str, const char *needle);
R_UNUSED static inline bool r_str_startswith_inline(const char *str, const char *needle) {
	if (!str || !needle) {
		return false;
	}
	return !strncmp (str, needle, strlen (needle));
}
#define r_str_startswith r_str_startswith_inline
R_UNUSED static const char *r_str_skip_prefix(const char *str, const char *prefix) {
	if (r_str_startswith (str, prefix)) {
		str += strlen (prefix);
	}
	return str;
}
R_API bool r_str_endswith(const char *str, const char *needle);
R_API bool r_str_isnumber(const char *str);
R_API const char *r_str_last(const char *in, const char *ch);
R_API char* r_str_highlight(char *str, const char *word, const char *color, const char *color_reset);
R_API char *r_qrcode_gen(const ut8 *text, int len, bool utf8, bool inverted);
R_API char *r_str_from_ut64(ut64 val);
R_API void r_str_stripLine(char *str, const char *key);
R_API char *r_str_list_join(RList *str, const char *sep);
R_API char *r_str_array_join(const char **a, size_t n, const char *sep);

R_API const char *r_str_sep(const char *base, const char *sep);
R_API const char *r_str_rsep(const char *base, const char *p, const char *sep);
R_API char *r_str_donut(int size);
R_API char *r_str_version(const char *program);
R_API char *r_str_ss(const char* msg, const char *nl, int cs);

R_API char *r_str_after(char *s, char c);
R_API int r_str_printf(R_NONNULL char *buffer, size_t buffer_size, R_NONNULL const char *format, ...);
  /// __attribute__ ((format (printf, 3, 4)));
R_API int r_str_scanf(R_NONNULL const char *buffer, R_NONNULL const char *format, ...);
  /// __attribute__ ((format (scanf, 2, 3)));

// rstr

R_API char *r_string_get(const RString *s, int *len);
R_API RString r_string_new(const char *is, int len);
R_API void r_string_free(RString *s);
R_API RString r_string_from(const char *is, int len);
R_API void r_string_unweak(RString *a);
R_API void r_string_trim(RString *s);
R_API R_WIP RString r_string_newf(const char *fmt, ...);
R_API bool r_string_append(RString *a, const char *s);
R_API void r_string_appendf(RString *a, const char *fmt, ...);

#ifdef __cplusplus
}
#endif

#endif //  R_STR_H
