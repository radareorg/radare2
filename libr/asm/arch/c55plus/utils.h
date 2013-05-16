#ifndef UUTILS_H
#define UUTILS_H

#include <r_types.h>
#define C55PLUS_DEBUG 0

st8 *strcat_dup(st8 *s1, st8 *s2, st32 n_free);
st8 *get_hex_str(ut32 hex_num);

#endif
