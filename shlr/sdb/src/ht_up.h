#ifndef SDB_HT_UP_H
#define SDB_HT_UP_H

/*
 * This header provides an hashtable HtUP that has ut64 as key and void* as
 * value. The API functions starts with "ht_up_" and the types starts with "HtUP".
 */
#undef HT_TYPE
#define HT_TYPE 2
#include "ht_inc.h"
#include "sdbht.h"

SDB_API HtName_(Ht)* Ht_(new0)(void);
SDB_API HtName_(Ht)* Ht_(new)(HT_(DupValue) valdup, HT_(KvFreeFunc) pair_free, HT_(CalcSizeV) valueSize);
SDB_API HtName_(Ht)* Ht_(new_size)(ut32 initial_size, HT_(DupValue) valdup, HT_(KvFreeFunc) pair_free, HT_(CalcSizeV) valueSize);
#undef HT_TYPE

#endif
