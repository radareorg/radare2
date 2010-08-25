/* radare - LGPL - Copyright 2008-2010 pancake<nopcode.org> */

#include "r_vm.h"

/* TODO: use r_reg here..instead of reimplement the fucking same all the time */
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

R_API void r_vm_reg_type_list() {
	struct r_vm_reg_type *p = r_vm_reg_types;
	while (p && p->str) {
		if (p->str==NULL)
			break;
		printf(" .%s\n", p->str);
		p++;
	}
}

R_API const char *r_vm_reg_type(int type) {
	struct r_vm_reg_type *p = r_vm_reg_types;
	while (p && p->str) {
		if (p->type == type)
			return p->str;
		p++;
	}
	return unkreg;
}

R_API int r_vm_reg_type_i(const char *str) {
	struct r_vm_reg_type *p = r_vm_reg_types;
	while (p && p->str) {
		if (!strcmp(str, p->str))
			return p->type;
		p++;
	}
	return -1;
}

R_API int r_vm_reg_del(struct r_vm_t *vm, const char *name) {
	struct list_head *pos;

	list_for_each(pos, &vm->regs) {
		struct r_vm_reg_t *r = list_entry(pos, struct r_vm_reg_t, list);
		if (!strcmp(name, r->name)) {
			list_del(&r->list);
			return R_FALSE;
		}
	}
	return R_TRUE;
}

R_API int r_vm_reg_set(struct r_vm_t *vm, const char *name, ut64 value) {
	struct list_head *pos;
	if (name)
	list_for_each(pos, &vm->regs) {
		struct r_vm_reg_t *r = list_entry(pos, struct r_vm_reg_t, list);
		if (!strcmp(name, r->name)) {
			r->value = value;
			if (vm->rec == NULL && r->set != NULL) {
				vm->rec = r;
				r_vm_eval(vm, r->set);
				vm->rec = NULL;
			}
			return R_TRUE;
		}
	}
	return R_FALSE;
}

R_API int r_vm_reg_alias_list(struct r_vm_t *vm) {
	struct r_vm_reg_t *reg;
	struct list_head *pos;
	int len,space;

	eprintf ("Register alias:\n");
	list_for_each (pos, &vm->regs) {
		reg= list_entry (pos, struct r_vm_reg_t, list);
		if (reg->get == NULL && reg->set == NULL)
			continue;
		len = strlen(reg->name)+1;
		printf("%s:", reg->name);
		if (len>=R_VM_ALEN) {
			space = R_VM_ALEN;
			printf("\n");
		} else space = R_VM_ALEN-len;
		eprintf ("%*cget = %s\n%*cset = %s\n",
			space, ' ', reg->get, R_VM_ALEN,' ', reg->set);
	}
	return 0;
}

R_API int r_vm_reg_alias(struct r_vm_t *vm, const char *name, const char *get, const char *set) {
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
	eprintf ("Register '%s' not defined.\n", name);
	return 0;
}

R_API int r_vm_cmd_eval(RVm *vm, const char *cmd) {
	char *next;
	do {
		next = strchr (cmd,'\n');
		if (next) {
			*next=0;
			next++;
		}
		if (strlen(cmd)>2 && !memcmp (cmd, "av", 2))
			r_vm_cmd_reg (vm, cmd+2);
		cmd = next;
	} while (next);
	return R_TRUE;
}

R_API int r_vm_cmd_reg(struct r_vm_t *vm, const char *_str) {
	char *str, *ptr;
	int len;

	len = strlen (_str)+1;
	str = alloca (len);
	memcpy (str, _str, len);

	if (str==NULL || str[0]=='\0') {
		/* show all registers */
		r_vm_print (vm, -1);
		return 0;
	}
	if (str[0]=='o') {
		r_vm_cmd_op (vm, str+2);
		return 0;
	}
	strcpy(str, str+1);
	switch(str[0]) {
	case 'r':
		r_vm_setup_ret (vm, str+2);
		break;
	case 'c':
		{
		char *sp, *bp, *pc = str+2;
		sp = strchr(pc, ' ');
		if (!sp) return 0;
		*sp=0;sp++;
		bp = strchr(sp, ' ');
		if (!sp) return 0;
		*bp=0;bp++;
		r_vm_setup_cpu (vm, pc, sp, bp);
		}
		break;
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
	case 'f':
		r_vm_setup_flags(vm, str+2);
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
				eprintf("%s = 0x%08"PFMT64x"\n", str, r_vm_reg_get(vm, str));
			}
		}
	}
	return 0;
}

R_API ut64 r_vm_reg_get(struct r_vm_t *vm, const char *name) {
	struct list_head *pos;
	int len;
	if (!name)
		return 0LL;
	len = strlen(name);
	if (name[len-1]==']')
		len--;

	list_for_each (pos, &vm->regs) {
		RVmReg *r = list_entry(pos, struct r_vm_reg_t, list);
		if (!strncmp (name, r->name, len)) {
			if (vm->rec==NULL && r->get != NULL) {
				vm->rec = r;
				r_vm_eval(vm, r->get);
				//vm_op_eval(r->get);
				vm->rec = NULL;
				return r->value;
			}
			return r->value;
		}
	}
	return -1LL;
}
