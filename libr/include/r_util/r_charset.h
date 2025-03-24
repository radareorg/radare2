#ifndef R_UTIL_CHARSET_H
#define R_UTIL_CHARSET_H

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

R_API RCharset *r_charset_new(void);
R_API void r_charset_free(RCharset *charset);
R_API RCharsetRune *r_charset_rune_new(const ut8 *ch, const ut8 *hx);
R_API void r_charset_rune_free(RCharsetRune *rcr);
R_API size_t r_charset_encode_str(RCharset *rc, ut8 *out, size_t out_len, const ut8 *in, size_t in_len, bool early_exit);
R_API size_t r_charset_decode_str(RCharset *rc, ut8 *out, size_t out_len, const ut8 *in, size_t in_len);
R_API bool r_charset_open(RCharset *c, const char *cs);
R_API bool r_charset_use(RCharset *c, const char *cf);
R_API RList *r_charset_list(RCharset *c);
R_API void r_charset_close(RCharset *c);
R_API RCharsetRune *add_rune(RCharsetRune *rcsr, const ut8 *ch, const ut8 *hx);
R_API RCharsetRune *search_from_hex(RCharsetRune *rcsr, const ut8 *hx);
R_API RCharsetRune *search_from_char(RCharsetRune *rcsr, const ut8 *ch);

#endif
