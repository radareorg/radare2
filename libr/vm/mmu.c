/* radare - LGPL - Copyright 2008-2009 pancake<nopcode.org> */

#include "r_vm.h"

int r_vm_mmu_cache_write(struct r_vm_t *vm, ut64 addr, ut8 *buf, int len)
{
	struct r_vm_change_t *ch = MALLOC_STRUCT(struct r_vm_change_t);
	ch->from = addr;
	ch->to = addr + len;
	ch->data = (ut8*)malloc(len);
	memcpy(ch->data, buf, len);
	list_add_tail(&(ch->list), &vm->mmu_cache);
	return 0;
}

int r_vm_mmu_cache_read(struct r_vm_t *vm, ut64 addr, ut8 *buf, int len)
{
	struct r_vm_change_t *c;
	struct list_head *pos;

	// TODO: support for unaligned and partial accesses
	list_for_each(pos, &vm->mmu_cache) {
		c = list_entry(pos, struct r_vm_change_t, list);
		if (addr >= c->from && addr+len <= c->to) {
			memcpy(buf, c->data, len);
			return 1;
		}
	}
	return 0;
}

int r_vm_mmu_read(struct r_vm_t *vm, ut64 off, ut8 *data, int len)
{
	if (!vm->realio && r_vm_mmu_cache_read(vm, off, data, len))
		return len;
	return r_io_read_at(vm, off, data, len);
}

int r_vm_mmu_write(struct r_vm_t *vm, ut64 off, ut8 *data, int len)
{
	if (!vm->realio)
		return r_vm_mmu_cache_write(vm, off, data, len);
	fprintf(stderr, "vm_mmu_write!\n");
	// XXX: callback for write-at should be userdefined
	return r_io_write_at(vm, off, data, len);
}

int r_vm_mmu_real(struct r_vm_t *vm, int set)
{
	return vm->realio = set;
}
