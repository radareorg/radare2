#ifndef R2_HEAP_JEMALLOC_H
#define R2_HEAP_JEMALLOC_H

#include "r_jemalloc/internal/jemalloc_internal.h"

#define INC_HEAP32 1
#include "r_heap_jemalloc.h"
#undef INC_HEAP32
#endif

#undef GH
#undef GHT
#undef GHT_MAX

#if INC_HEAP32
#define GH(x) x##_32
#define GHT ut32
#define GHT_MAX UT32_MAX
#else
#define GH(x) x##_64
#define GHT ut64
#define GHT_MAX UT64_MAX
#endif

#define PRINTF_A(color, fmt , ...) r_cons_printf (color fmt Color_RESET, __VA_ARGS__)
#define PRINTF_YA(fmt, ...) PRINTF_A (Color_YELLOW, fmt, __VA_ARGS__)
#define PRINTF_GA(fmt, ...) PRINTF_A (Color_GREEN, fmt, __VA_ARGS__)
#define PRINTF_BA(fmt, ...) PRINTF_A (Color_BLUE, fmt, __VA_ARGS__)
#define PRINTF_RA(fmt, ...) PRINTF_A (Color_RED, fmt, __VA_ARGS__)

#define PRINT_A(color, msg) r_cons_print (color msg Color_RESET)
#define PRINT_YA(msg) PRINT_A (Color_YELLOW, msg)
#define PRINT_GA(msg) PRINT_A (Color_GREEN, msg)
#define PRINT_BA(msg) PRINT_A (Color_BLUE, msg)
#define PRINT_RA(msg) PRINT_A (Color_RED, msg)
