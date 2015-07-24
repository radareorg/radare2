#ifndef _INCLUDE_RANGSTR_H_
#define _INCLUDE_RANGSTR_H_

#include <sys/types.h>

#define RangstrType unsigned short

typedef struct {
	int type;
	int next;
	size_t f, t;
	const char *p;
} Rangstr;

void rangstr_print (Rangstr *s);
Rangstr rangstr_new (const char *s);
Rangstr rangstr_null(void);
int rangstr_int (Rangstr *s);
char *rangstr_dup (Rangstr *rs);
Rangstr rangstr_news (const char *s, RangstrType *res, int i);
int rangstr_cmp (Rangstr *a, Rangstr *b);
const char *rangstr_str (Rangstr* rs);
int rangstr_length (Rangstr* rs);
int rangstr_find (Rangstr* rs, char ch);

#endif
