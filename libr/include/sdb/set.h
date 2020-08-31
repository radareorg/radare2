#ifndef SDB_SET_H
#define SDB_SET_H

#include "ht_pp.h"
#include "ht_up.h"

typedef HtPP SetP;

SDB_API SetP *set_p_new(void);
SDB_API void set_p_add(SetP *p, void *u);
SDB_API bool set_p_contains(SetP *s, void *u);
SDB_API void set_p_delete(SetP *s, void *u);
SDB_API void set_p_free(SetP *p);

typedef HtUP SetU;

SDB_API SetU *set_u_new(void);
SDB_API void set_u_add(SetU *p, ut64 u);
SDB_API bool set_u_contains(SetU *s, ut64 u);
SDB_API void set_u_delete(SetU *s, ut64 u);
SDB_API void set_u_free(SetU *p);

#endif
