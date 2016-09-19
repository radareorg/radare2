#ifndef R_STRHT_H
#define R_STRHT_H
#include <r_list.h>
#include <r_util/r_strpool.h>
#include "ht.h"

typedef struct r_strht_t {
	RStrpool *sp;
	RHashTable *ht;
	RList *ls;
} RStrHT;

R_API RStrHT *r_strht_new(void);
R_API void r_strht_free(RStrHT *s);
R_API const char *r_strht_get(RStrHT *s, const char *key);
R_API int r_strht_set(RStrHT *s, const char *key, const char *val);
R_API void r_strht_clear(RStrHT *s);
R_API void r_strht_del(RStrHT *s, const char *key);
R_API int r_is_heap(void *p);
#endif //  R_STRHT_H
