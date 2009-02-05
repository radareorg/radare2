/* radare - LGPL - Copyright 2008-2009 pancake<nopcode.org> */

#include "r_vm.h"

void r_vm_setup_flags(struct r_vm_t *vm, const char *zf)
{
	vm->cpu.zf = strdup(zf);
}

void r_vm_setup_cpu(struct r_vm_t *vm, const char *eip, const char *esp, const char *ebp)
{
	vm->cpu.pc = strdup(eip);
	vm->cpu.sp = strdup(esp);
	vm->cpu.bp = strdup(ebp);
}

void r_vm_setup_fastcall(struct r_vm_t *vm, const char *eax, const char *ebx, const char *ecx, const char *edx)
{
	vm->cpu.a0 = strdup(eax);
	vm->cpu.a1 = strdup(ebx);
	vm->cpu.a2 = strdup(ecx);
	vm->cpu.a3 = strdup(edx);
}

void r_vm_setup_ret(struct r_vm_t *vm, const char *eax)
{
	vm->cpu.ret = strdup(eax);
}
