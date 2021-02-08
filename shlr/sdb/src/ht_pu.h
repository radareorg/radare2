#ifndef SDB_HT_PU_H
#define SDB_HT_PU_H

/*
 * This header provides an hashtable HtPU that has void* as key and ut64 as
 * value. The API functions starts with "ht_pu_" and the types starts with "HtPU".
 */
#define HT_TYPE 4
#include "ht_inc.h"

SDB_API HtName_(Ht)* Ht_(new0)(void);
#undef HT_TYPE

#endif
