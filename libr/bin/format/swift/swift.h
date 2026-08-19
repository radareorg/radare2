#ifndef R2_BIN_SWIFT_H
#define R2_BIN_SWIFT_H

#include <r_bin.h>
#include <sdb/ht_uu.h>

// container-independent loader for the swift5_* type metadata sections.
// the owning bin plugin provides virtual address reads and pointer-slot
// resolution (relocs/binds); everything else is common swift ABI logic
typedef struct r_bin_swift_loader_t {
	RBinFile *bf;
	void *user;
	// read len bytes at a virtual address, returns the amount read
	int (*read_at)(void *user, ut64 va, ut8 *buf, int len);
	// resolve a pointer-sized slot: return an owned symbol name (external
	// descriptor) or fill *target with the pointed descriptor address
	char *(*slot)(void *user, ut64 va, ut64 *target);
	// symbols used to name vtable methods and attach members to types
	RVecRBinSymbol *symbols;
	// internal state
	HtUP *symbols_ht;
	HtPP *mangled_ht;
	// type context descriptor vaddr -> type metadata vaddr, used to read the
	// static field-offset vector for fixed-layout structs
	HtUU *meta_by_desc;
	int depth;
} RBinSwiftLoader;

R_IPI void r_bin_swift_load_classes(RBinSwiftLoader *ld, RList *out, ut64 types_va, ut64 types_size, ut64 protos_va, ut64 protos_size, int limit);

#endif
