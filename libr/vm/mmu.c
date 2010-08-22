/* radare - LGPL - Copyright 2008-2010 pancake<nopcode.org> */

#include "r_vm.h"

R_API int r_vm_mmu_read(RVm *vm, ut64 off, ut8 *data, int len) {
	if (vm->iob.read_at)
		return vm->iob.read_at (vm->iob.io, off, data, len);
	return -1;
}

R_API int r_vm_mmu_write(RVm *vm, ut64 off, ut8 *data, int len) {
	if (vm->use_mmu_cache && vm->iob.write_at)
		return vm->iob.write_at (vm->iob.io, off, data, len);
	return -1;
}
