#include "r_vm.h"
#include "list.h"

int r_vm_op_list(struct r_vm_t *vm)
{
	struct list_head *pos;

	printf("Oplist:\n");
	list_for_each(pos, &vm->ops) {
		struct r_vm_op_t *o = list_entry(pos, struct r_vm_op_t, list);
		printf(" %s = %s\n", o->opcode, o->code);
	}
	return 0;
}

int r_vm_cmd_op_help()
{
	printf("avo [op] [expr]\n"
	" \"avo call [esp]=eip+$$$,esp=esp+4,eip=$1\n"
	" \"avo jmp eip=$1\n"
	" \"avo mov $1=$2\n"
	"Note: The prefix '\"' quotes the command and does not parses pipes and so\n");
	return 0;
}

