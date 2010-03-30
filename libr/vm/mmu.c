/* radare - LGPL - Copyright 2008-2010 pancake<nopcode.org> */

#include "r_vm.h"

R_API int r_vm_mmu_cache_write(RVm *vm, ut64 addr, ut8 *buf, int len) {
	RVmChange *ch = R_NEW(RVmChange);
	ch->from = addr;
	ch->to = addr + len;
	ch->data = (ut8*)malloc(len);
	memcpy (ch->data, buf, len);
	list_add_tail (&(ch->list), &vm->mmu_cache);
	return 0;
}

R_API int r_vm_mmu_cache_read(RVm *vm, ut64 addr, ut8 *buf, int len) {
	RVmChange *c;
	struct list_head *pos;

	// TODO: support for unaligned and partial accesses
	list_for_each(pos, &vm->mmu_cache) {
		c = list_entry (pos, RVmChange, list);
		if (addr >= c->from && addr+len <= c->to) {
			memcpy (buf, c->data, len);
			// XXX THIS IS BUGGY
			return 1;
		}
	}
	return 0;
}

// XXX: Use ioBind here..
R_API void r_vm_mmu_set_io(RVm *vm,
	int (*read)(void *user, ut64 addr, ut8 *buf, int len),
	int (*write)(void *user, ut64 addr, ut8 *buf, int len),
	void *user)
{
	vm->read = read;
	vm->write = write;
	vm->user = user;
}

R_API int r_vm_mmu_read(RVm *vm, ut64 off, ut8 *data, int len) {
	if (!vm->realio && r_vm_mmu_cache_read(vm, off, data, len))
		return len;
	if (vm->read)
		return vm->read(vm->user, off, data, len);
	return -1;
}

R_API int r_vm_mmu_write(RVm *vm, ut64 off, ut8 *data, int len) {
	if (!vm->realio)
		return r_vm_mmu_cache_write(vm, off, data, len);
	// XXX: callback for write-at should be userdefined
	if (vm->write)
		return vm->write(vm->user, off, data, len);
	return -1;
}

int r_vm_mmu_real(RVm *vm, int set) {
	return vm->realio = set;
}
