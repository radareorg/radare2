#ifndef R2_HASHTABLE_H
#define R2_HASHTABLE_H

#include <r_types.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct r_htable_iter_t {
  char *key;
  void *data;
  struct r_htable_iter_t *next;
}RHTableIter;

typedef struct r_htable_t {
  RHTableIter **table;
  size_t length;
}RHTable;

RHTable *r_htable_new (size_t size);
void r_htable_clear (RHTable *htable);
void r_htable_free (RHTable *htable);
bool r_htable_add (RHTable *htable, char *key, void *value);
bool r_htable_add_uint64 (RHTable *htable, ut64 key, void *value);
void *r_htable_get (RHTable *htable, char *key);
void *r_htable_get_uint64 (RHTable *htable, ut64 key);
RHTableIter *r_htable_entry_new (char *key, void *value);

#ifdef __cplusplus
}
#endif

#endif
