/* radare - LGPL - Copyright 2008-2010 pancake<nopcode.org> */

#include "r_vm.h"
#include "list.h"

R_API void r_vm_stack_push(RVm *vm, ut64 _val) {
	// XXX determine size of stack here
	// XXX do not write while emulating zomfg
	// XXX we need a way to define the size of registers to grow/shrink the stack properly
	ut32 val = _val;
	r_vm_reg_set(vm, vm->cpu.sp, r_vm_reg_get(vm, vm->cpu.sp)+4);
	r_vm_mmu_write(vm, r_vm_reg_get(vm, vm->cpu.sp), (void *)&val, 4);
}

R_API void r_vm_stack_pop(RVm *vm, const char *reg) {
	ut32 val = 0;
	if (r_vm_mmu_read(vm, r_vm_reg_get(vm, vm->cpu.sp), (void *)&val, 4))
		return;
	r_vm_mmu_read(vm, r_vm_reg_get(vm, vm->cpu.sp), (void *)&val, 4);
	r_vm_reg_set(vm, reg, val);
	r_vm_reg_set(vm, vm->cpu.sp, r_vm_reg_get(vm, vm->cpu.sp)-4);
}
