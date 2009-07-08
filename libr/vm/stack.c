/* radare - LGPL - Copyright 2008-2009 pancake<nopcode.org> */

#include "r_vm.h"
#include "list.h"

void r_vm_stack_push(struct r_vm_t *vm, ut64 _val)
{
	// XXX determine size of stack here
	// XXX do not write while emulating zomfg
	ut32 val = _val;
	vm_reg_set(vm, vm_cpu.sp, vm_reg_get(vm, vm_cpu.sp)+4);
	vm_mmu_write(vm, vm_reg_get(vm, vm_cpu.sp), &val, 4);
}

void r_vm_stack_pop(struct r_vm_t *vm, const char *reg)
{
	ut32 val = 0;
	if (vm_mmu_read(vm_reg_get(vm, vm->cpu.sp), &val, 4))
		return;
//printf("POP (%s)\n", reg);
	vm_mmu_read(vm, vm_reg_get(vm, vm->cpu.sp), &val, 4);
	vm_reg_set(vm, reg, val);
	vm_reg_set(vm_cpu.sp, vm_reg_get(vm, vm->cpu.sp)-4);
}
