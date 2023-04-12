/* radare - LGPL - Copyright 2017 - wargio */

#ifndef LIBPS_H
#define LIBPS_H
#include <r_types.h>

typedef struct {
    ut32 value;
    ut16 type;
} ppcps_field_t;

typedef struct {
    const char* name;
    ppcps_field_t operands[6];
    int n;
    int op;
    ut32 anal_op;
} ppcps_t;

bool libps_decode(ut32 data, ppcps_t* ps);
void libps_snprint(char* str, int size, ut64 addr, ppcps_t* instr);

#endif /* LIBPS_H */

