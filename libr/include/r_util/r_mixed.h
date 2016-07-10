#ifndef R_MIXED_H
#define R_MIXED_H
#include <r_list.h>
#include "ht.h"

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


#endif //  R_MIXED_H
