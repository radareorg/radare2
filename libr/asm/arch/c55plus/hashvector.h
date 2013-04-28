#ifndef HASHVECTOR_H
#define HASHVECTOR_H

#include <r_types.h>

typedef struct {
	st32 code;
	st32 (*hash_func)(st32 A1, st32 A2);
} HASHCODE_ENTRY_T;

#endif
