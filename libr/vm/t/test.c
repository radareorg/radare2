#include <r_vm.h>

int main() {
	RVm *vm = r_vm_new ();
	//r_vm_eval (vm, "eax=33");
	r_vm_op_eval (vm, "mov eax, 33");
	printf ("eax=0x%llx\n", r_vm_reg_get (vm, "eax"));
	return 0;
}
