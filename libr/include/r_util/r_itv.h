#ifndef R_INTERVAL_H
#define R_INTERVAL_H

#include <r_types.h>

#ifdef __cplusplus
extern "C" {
#endif

// An interval in 64-bit address space which is aware of address space wraparound
// Precondition: 0 <= size < 2**64 and addr + size <= 2**64
typedef struct r_interval_t {
	// public:
	ut64 addr;
	ut64 size;
} RInterval;

typedef RInterval r_itv_t;

#define R_ITV_BEGIN(x) r_itv_begin(x->itv)
static inline ut64 r_itv_begin(RInterval itv) {
	return itv.addr;
}

#define R_ITV_SIZE(x) r_itv_size(x->itv)
static inline ut64 r_itv_size(RInterval itv) {
	return itv.size;
}

// Returns the right endpoint address (not included)
#define R_ITV_END(x) r_itv_end(x->itv)
static inline ut64 r_itv_end(RInterval itv) {
	return itv.addr + itv.size;
}

// Returns true if itv contained addr
#define R_ITV_CONTAIN(x,y) r_itv_contain(x->itv, y)
static inline bool r_itv_contain(RInterval itv, ut64 addr) {
	ut64 end = itv.addr + itv.size;
	return itv.addr <= addr && (!end || addr < end);
}

// Returns true if x is a subset of itv
#define R_ITV_INCLUDE(x,y) r_itv_include(x->itv, y)
static inline bool r_itv_include(RInterval itv, RInterval x) {
	ut64 end = itv.addr + itv.size;
	return itv.addr <= x.addr && (!end || (x.addr + x.size && x.addr + x.size <= end));
}

// Returns true if itv and x overlap (implying they are non-empty)
#define R_ITV_OVERLAP(x,y) r_itv_overlap(x->itv, y)
static inline bool r_itv_overlap(RInterval itv, RInterval x) {
	ut64 end = itv.addr + itv.size, end1 = x.addr + x.size;
	return (!end1 || itv.addr < end1) && (!end || x.addr < end);
}

#define R_ITV_OVERLAP2(x,y,z) r_itv_overlap2(x->itv, y, z)
static inline bool r_itv_overlap2(RInterval itv, ut64 addr, ut64 size) {
	RInterval rai = {addr, size};
	return r_itv_overlap (itv, rai);
}

// Precondition: itv and x overlap
// Returns the intersection of itv and x
#define R_ITV_INTERSECT(x,y) r_itv_intersect((RInterval)x->itv, (RInterval)y)
static inline RInterval r_itv_intersect(RInterval itv, RInterval x) {
	ut64 addr = R_MAX (itv.addr, x.addr);
	ut64 end = R_MIN (itv.addr + itv.size - 1, x.addr + x.size - 1) + 1;
	RInterval rai = {addr, end - addr};
	return rai;
}

#ifdef __cplusplus
}
#endif

#endif  // R_INTERVAL_H
