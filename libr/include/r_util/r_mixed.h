#ifndef R_MIXED_H
#define R_MIXED_H
#include <r_list.h>
#include <sdb.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RMIXED_MAXKEYS 256
typedef struct r_mixed_data_t {
	int size;
	union {
		SdbHt *ht;
		SdbHt *ht64;
	} hash;
} RMixedData;

typedef struct r_mixed_t {
	RList *list;
	RMixedData *keys[RMIXED_MAXKEYS];
	ut64 state[RMIXED_MAXKEYS]; // used by change_(begin|end)
} RMixed;

#ifdef __cplusplus
}
#endif

#endif //  R_MIXED_H
