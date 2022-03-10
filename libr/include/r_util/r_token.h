#ifndef R2_UTIL_TOKEN_H
#define R2_UTIL_TOKEN_H

typedef enum {
	R_TOKEN_NONE,
	R_TOKEN_INT,
	R_TOKEN_FLOAT,
	R_TOKEN_WORD,
	R_TOKEN_HASH,
	R_TOKEN_STRING,
	R_TOKEN_COMMENT,
	R_TOKEN_MATH,
	R_TOKEN_GROUP,
	R_TOKEN_BEGIN,
	R_TOKEN_END
} RTokenType;

typedef bool (*RTokenizerCallback)(void *tok);

typedef struct r_tokenizer_t {
	bool hex;
	bool escape;
	const char *buf;
	char ch;
	size_t begin;
	int indent;
	size_t end;
	RTokenType type;
	RTokenizerCallback cb;
	void *user;
} RTokenizer;

R_API char *r_str_tokenize_json(const char *buf);
R_API RTokenizer *r_tokenizer_new(void);
R_API void r_str_tokenize(const char *buf, RTokenizerCallback cb, void *user);

#endif
