/* radare - LGPL - Copyright 2008-2009 pancake<nopcode.org> */

#include "r_vm.h"

static char *unkreg = "(unk)";

/* static */
static struct r_vm_reg_type r_vm_reg_types[] = {
	{ R_VMREG_BIT, "bit" },
	{ R_VMREG_INT64, "int64" },
	{ R_VMREG_INT32, "int32" },
	{ R_VMREG_INT16, "int16" },
	{ R_VMREG_INT8, "int8" },
	{ R_VMREG_FLOAT32, "float32" },
	{ R_VMREG_FLOAT64, "float64" },
	{ 0, NULL }
};

void r_vm_reg_type_list()
{
	struct r_vm_reg_type *p = r_vm_reg_types;
	while(p) {
		if (p->str==NULL)
			break;
		printf(" .%s\n", p->str);
		p++;
	}
}

const char *r_vm_reg_type(int type)
{
	struct r_vm_reg_type *p = r_vm_reg_types;
	while(p) {
		if (p->type == type)
			return p->str;
		p++;
	}
	return unkreg;
}

const int r_vm_reg_type_i(const char *str)
{
	struct r_vm_reg_type *p = r_vm_reg_types;
	while(p) {
		if (!strcmp(str, p->str))
			return p->type;
		p++;
	}
	return -1;
}

int r_vm_reg_del(struct r_vm_t *vm, const char *name)
{
	struct list_head *pos;

	list_for_each(pos, &vm->regs) {
		struct r_vm_reg_t *r = list_entry(pos, struct r_vm_reg_t, list);
		if (!strcmp(name, r->name)) {
			list_del(&r->list);
			return 0;
		}
	}
	return 1;
}

int r_vm_reg_set(struct r_vm_t *vm, const char *name, ut64 value)
{
	struct list_head *pos;

	list_for_each(pos, &vm->regs) {
		struct r_vm_reg_t *r = list_entry(pos, struct r_vm_reg_t, list);
		if (!strcmp(name, r->name)) {
			r->value = value;
			if (vm->rec == NULL && r->set != NULL) {
				vm->rec = r;
				r_vm_eval(vm, r->set);
				vm->rec = NULL;
			}
			return 1;
		}
	}
	return 0;
}

int r_vm_reg_alias_list(struct r_vm_t *vm)
{
	struct r_vm_reg_t *reg;
	struct list_head *pos;
	int len,space;

	printf("Register alias:\n");
	list_for_each(pos, &vm->regs) {
		reg= list_entry(pos, struct r_vm_reg_t, list);
		if (reg->get == NULL && reg->set == NULL)
			continue;
		len = strlen(reg->name)+1;
		printf("%s:", reg->name);
		if (len>=R_VM_ALEN) {
			space = R_VM_ALEN;
			printf("\n");
		} else space = R_VM_ALEN-len;
		printf("%*cget = %s\n%*cset = %s\n",
			space, ' ', reg->get, R_VM_ALEN,' ', reg->set);
	}
	return 0;
}

int r_vm_reg_alias(struct r_vm_t *vm, const char *name, const char *get, const char *set)
{
	struct r_vm_reg_t *reg;
	struct list_head *pos;

	list_for_each(pos, &vm->regs) {
		reg = list_entry(pos, struct r_vm_reg_t, list);
		if (!strcmp(name, reg->name)) {
			free(reg->get);
			reg->get = NULL;
			if (get) reg->get = strdup(get);

			free(reg->set);
			reg->set = NULL;
			if (set) reg->set = strdup(set);
			return 1;
		}
	}
	fprintf(stderr, "Register '%s' not defined.\n", name);
	return 0;
}

int r_vm_cmd_reg(struct r_vm_t *vm, const char *_str)
{
	char *str, *ptr;
	int len;

	len = strlen(_str)+1;
	str = alloca(len);
	memcpy(str, _str, len);

	if (str==NULL ||str[0]=='\0') {
		/* show all registers */
		r_vm_print(vm, -1);
	} else {
		switch(str[0]) {
		case 'a':
			if (str[1]==' ') {
				char *get,*set;
				get = strchr(str+2, ' ');
				if (get) {
					get[0]='\0';
					get = get+1;
					set = strchr(get, ' ');
					if (set) {
						set[0]='\0';
						set = set +1;
						r_vm_reg_alias(vm, str+2, get, set);
					}
				}
			} else r_vm_reg_alias_list(vm);
			break;
		case 't':
			r_vm_reg_type_list(vm);
			break;
		case '+':
			// add register
			// avr+ eax int32
			for(str=str+1;str&&*str==' ';str=str+1);
			ptr = strchr(str, ' ');
			if (ptr) {
				ptr[0]='\0';
				r_vm_reg_add(vm, str, r_vm_reg_type_i(ptr+1), 0);
			} else r_vm_reg_add(vm, str, R_VMREG_INT32, 0);
			break;
		case '-':
			// rm register
			// avr- eax
			// avr-*
			for(str=str+1;str&&*str==' ';str=str+1);
			if (str[0]=='*')
				INIT_LIST_HEAD(&vm->regs); // XXX Memory leak
			else r_vm_reg_del(vm, str);
			break;
		default:
			for(;str&&*str==' ';str=str+1);
			ptr = strchr(str, '=');
			if (ptr) {
				//vm_eval(str);
				r_vm_op_eval(vm, str);
	#if 0
				/* set register value */
				ptr[0]='\0';
				vm_eval_eq(str, ptr+1);
				ptr[0]='=';
	#endif
			} else {
				if (*str=='.') {
					r_vm_print(vm, r_vm_reg_type_i(str+1));
				} else {
					/* show single registers */
					printf("%s = 0x%08llx\n", str, vm_reg_get(str));
				}
			}
		}
	}
	return 0;
}
