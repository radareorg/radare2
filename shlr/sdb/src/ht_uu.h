#ifndef SDB_HT_H_
#define SDB_HT_H_

/*
 * This header provides an hashtable Ht that has ut64 as key and ut64 as
 * value. The API functions starts with "ht_" and the types starts with "Ht".
 */
#undef HT_TYPE
#define HT_TYPE 3
#include "ht_inc.h"
#include "sdbht.h"

SDB_API HtName_(Ht)* Ht_(new0)(void);

#endif
