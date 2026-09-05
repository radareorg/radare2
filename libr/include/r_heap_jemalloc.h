#ifndef R2_HEAP_JEMALLOC_H
#define R2_HEAP_JEMALLOC_H

#ifdef __cplusplus
extern "C" {
#endif

#define INC_HEAP32 1
#undef INC_HEAP32

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

#ifdef __cplusplus
}
#endif

#endif
