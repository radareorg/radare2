#ifndef R_ADDR_INTERVAL_H
#define R_ADDR_INTERVAL_H

#include <r_types.h>

// An interval in 64-bit address space which is aware of address space wraparound
// Precondition: 0 <= size < 2**64 and addr + size <= 2**64
typedef struct r_addr_interval_t {
	// public:
	ut64 addr;
	ut64 size;
} RAddrInterval;

// Returns true if itv contained addr
static inline bool r_itv_contain(RAddrInterval itv, ut64 addr) {
	ut64 end = itv.addr + itv.size;
	return itv.addr <= addr && (!end || addr < end);
}

// Returns true if x is a subset of itv
static inline bool r_itv_include(RAddrInterval itv, RAddrInterval x) {
	ut64 end = itv.addr + itv.size;
	return itv.addr <= x.addr && (!end || (x.addr + x.size && x.addr + x.size <= end));
}

// Returns true if itv and x overlap (implying they are non-empty)
static inline bool r_itv_overlap(RAddrInterval itv, RAddrInterval x) {
	ut64 end = itv.addr + itv.size, end1 = x.addr + x.size;
	return (!end1 || itv.addr < end1) && (!end || x.addr < end);
}

static inline bool r_itv_overlap2(RAddrInterval itv, ut64 addr, ut64 size) {
	return r_itv_overlap (itv, (RAddrInterval){addr, size});
}

// Precondition: itv and x overlap
// Returns the intersection of itv and x
static inline RAddrInterval r_itv_intersect(RAddrInterval itv, RAddrInterval x) {
	ut64 addr = R_MIN (itv.addr, x.addr),
			end = R_MIN (itv.addr + itv.size - 1, x.addr + x.size - 1) + 1;
	return (RAddrInterval){addr, end - addr};
}

#endif  // R_ADDR_INTERVAL_H
