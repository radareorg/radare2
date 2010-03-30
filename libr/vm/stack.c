/* radare - LGPL - Copyright 2008-2009 pancake<nopcode.org> */

#include "r_vm.h"
#include "list.h"

void r_vm_stack_push(struct r_vm_t *vm, ut64 _val) {
	// XXX determine size of stack here
	// XXX do not write while emulating zomfg
	// XXX we need a way to define the size of registers to grow/shrink the stack properly
	ut32 val = _val;
	r_vm_reg_set(vm, vm->cpu.sp, r_vm_reg_get(vm, vm->cpu.sp)+4);
	r_vm_mmu_write(vm, r_vm_reg_get(vm, vm->cpu.sp), (void *)&val, 4);
}

void r_vm_stack_pop(struct r_vm_t *vm, const char *reg) {
	ut32 val = 0;
	if (r_vm_mmu_read(vm, r_vm_reg_get(vm, vm->cpu.sp), (void *)&val, 4))
		return;
	r_vm_mmu_read(vm, r_vm_reg_get(vm, vm->cpu.sp), (void *)&val, 4);
	r_vm_reg_set(vm, reg, val);
	r_vm_reg_set(vm, vm->cpu.sp, r_vm_reg_get(vm, vm->cpu.sp)-4);
}
