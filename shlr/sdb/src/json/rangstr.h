#ifndef _INCLUDE_RANGSTR_H_
#define _INCLUDE_RANGSTR_H_

#include <sys/types.h>
#include "../types.h"

#define RangstrType unsigned int

typedef struct {
	int type;
	int next;
	size_t f, t;
	const char *p;
} Rangstr;

#if 0
SDB_IPI void rangstr_print (Rangstr *s);
SDB_IPI Rangstr rangstr_new (const char *s);
SDB_IPI Rangstr rangstr_null(void);
SDB_IPI int rangstr_int (Rangstr *s);
SDB_IPI char *rangstr_dup (Rangstr *rs);
SDB_IPI Rangstr rangstr_news (const char *s, RangstrType *res, int i);
SDB_IPI int rangstr_cmp (Rangstr *a, Rangstr *b);
SDB_IPI const char *rangstr_str (Rangstr* rs);
SDB_IPI int rangstr_length (Rangstr* rs);
SDB_IPI int rangstr_find (Rangstr* rs, char ch);
#endif

#endif
