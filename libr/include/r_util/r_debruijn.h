/* radare - LGPL - Copyright 2014 - crowell */

#ifndef R_DEBRUIJN_H
#define R_DEBRUIJN_H

#include <r_types.h>

// For information about the algorithm, see Joe Sawada and Frank Ruskey, "An
// Efficient Algorithm for Generating Necklaces with Fixed Density"

// Generate a cyclic pattern of desired size, and charset, return with starting
// offset of start.
// The returned string is malloced, and it is the responsibility of the caller
// to free the memory.
R_API char* r_debruijn_pattern(int size, int start, const char* charset);


// Finds the offset of a given value in a cyclic pattern of an integer.
R_API int r_debruijn_offset(ut64 value, bool is_big_endian);

#endif // R_DEBRUIJN_H
