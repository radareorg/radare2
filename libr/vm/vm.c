/* radare - LGPL - Copyright 2008-2010 pancake<nopcode.org> */

#include "r_vm.h"

/* TODO: move into r_vm_t */
int vm_arch = -1;

static ut64 r_vm_get_value(struct r_vm_t *vm, const char *str) {
	ut64 ret = 0LL;
	for (;*str&&*str==' ';str=str+1);

	if (str[0]=='$' && str[1]=='$') {
#if TODO
		struct aop_t aop;
		char w[32];
		if (str[2]=='$') { // $$$
			ret = r_vm_reg_get(vm, vm->cpu.pc);
			arch_aop(ret , config.block,&aop);
			return aop.length;
		} else // $$
			return config.seek;
#endif
	}

	if (str[0]=='0' && str[1]=='x')
		sscanf(str, "0x%"PFMT64x"", &ret);
	else
	if (str[0]>='0' && str[0]<='9')
		sscanf(str, "%"PFMT64d"", &ret);
	else ret = r_vm_reg_get(vm, str);
	return ret;
}

static ut64 r_vm_get_math(struct r_vm_t *vm, const char *str) {
	int len;
	char *p,*a;

	len = strlen(str)+1;
	p = alloca(len);
	memcpy(p, str, len);
	a = strchr(p,'+');
	if (a) {
		*a='\0';
		return r_vm_get_value(vm, p) + r_vm_get_value(vm, a+1);
	}
	a = strchr(p,'-');
	if (a) {
		*a='\0';
		return r_vm_get_value(vm, p) - r_vm_get_value(vm, a+1);
	}
	a = strchr(p,'*');
	if (a) {
		*a='\0';
		return r_vm_get_value(vm, p) * r_vm_get_value(vm, a+1);
	}
	a = strchr(p,'/');
	if (a) {
		*a='\0';
		return r_vm_get_value(vm, p) / r_vm_get_value(vm, a+1);
	}
	a = strchr(p,'&');
	if (a) {
		*a='\0';
		return r_vm_get_value(vm, p) & r_vm_get_value(vm, a+1);
	}
	a = strchr(p,'|');
	if (a) {
		*a='\0';
		return r_vm_get_value(vm, p) | r_vm_get_value(vm, a+1);
	}
	a = strchr(p,'^');
	if (a) {
		*a='\0';
		return r_vm_get_value(vm, p) ^ r_vm_get_value(vm, a+1);
	}
	a = strchr(p,'%');
	if (a) {
		*a='\0';
		return r_vm_get_value(vm, p) % r_vm_get_value(vm, a+1);
	}
	a = strchr(p,'>');
	if (a) {
		*a='\0';
		return r_vm_get_value(vm, p) >> r_vm_get_value(vm, a+1);
	}
	a = strchr(p,'<');
	if (a) {
		*a='\0';
		return r_vm_get_value(vm, p) << r_vm_get_value(vm, a+1);
	}
	return r_vm_get_value(vm, p);
}

R_API void r_vm_print(struct r_vm_t *vm, int type) {
	struct list_head *pos;

	if (type == -2)
		printf("fs vm\n");

	list_for_each (pos, &vm->regs) {
		struct r_vm_reg_t *r = list_entry(pos, struct r_vm_reg_t, list);
		if (type == -2) {
			printf("f vm.%s @ 0x%08"PFMT64x"\n", r->name, r->value);
		} else {
			if (type == -1 || type == r->type)
			printf(".%s\t%s = 0x%08"PFMT64x"\n",
				r_vm_reg_type(r->type), r->name,
				(r->get!=NULL)?r_vm_reg_get(vm, r->name):r->value);
		}
	}

	if (type == -2)
		printf ("fs *\n");
}

R_API int r_vm_reg_add(struct r_vm_t *vm, const char *name, int type, ut64 value) {
	RVmReg *r = (RVmReg*)malloc (sizeof (RVmReg));
	if (r == NULL)
		return 0;
	strncpy (r->name, name, 15);
	r->type = type;
	r->value = value;
	r->get = NULL;
	r->set = NULL;
	list_add_tail (&(r->list), &vm->regs);
	return 1;
}

R_API ut64 r_vm_reg_get(struct r_vm_t *vm, const char *name) {
	struct list_head *pos;
	int len = strlen(name);
	if (name[len-1]==']')
		len--;

	list_for_each(pos, &vm->regs) {
		struct r_vm_reg_t *r = list_entry(pos, struct r_vm_reg_t, list);
		if (!strncmp(name, r->name, len)) {
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

R_API int r_vm_import(struct r_vm_t *vm, int in_vm) {
	struct list_head *pos;

	eprintf ("Importing register values\n");
	list_for_each(pos, &vm->regs) {
		struct r_vm_reg_t *r = list_entry(pos, struct r_vm_reg_t, list);
		if (in_vm) {
			char name[64];
			snprintf(name, 63, "vm.%s", r->name);
			r->value = r_num_get(NULL, name); // XXX doesnt work for eflags and so
		} else r->value = r_num_get(NULL, r->name); // XXX doesnt work for eflags and so
	}
	return 0;
}

R_API void r_vm_cpu_call(struct r_vm_t *vm, ut64 addr) {
	/* x86 style */
	r_vm_stack_push (vm, r_vm_reg_get(vm, vm->cpu.pc));
	r_vm_reg_set (vm, vm->cpu.pc, addr);
	// XXX this should be the next instruction after pc (we need insn length here)
}

R_API int r_vm_init(struct r_vm_t *vm, int init) {
#if 0
	if (config.arch != vm_arch)
		init = 1;
#endif
	if (init) {
		INIT_LIST_HEAD(&vm->mmu_cache);
		INIT_LIST_HEAD(&vm->regs);
		INIT_LIST_HEAD(&vm->ops);
		memset(&vm->cpu, '\0', sizeof(struct r_vm_cpu_t));
	}

	//vm_mmu_real(vm, config_get_i("vm.realio"));
	/* vm_dbg_arch_x86_nregs */
	/* XXX: this is hardcoded ..should be moved outside or as in plugins */
	switch (1) { //config.arch) {
#if 0
	case ARCH_X86_64:
		vm_reg_add("rax", R_VMREG_INT64, 0);
		vm_reg_add("rbx", R_VMREG_INT64, 0);
		vm_reg_add("rcx", R_VMREG_INT64, 0);
		vm_reg_add("rdx", R_VMREG_INT64, 0);
		vm_reg_add("rdi", R_VMREG_INT64, 0);
		vm_reg_add("rsi", R_VMREG_INT64, 0);
		vm_reg_add("rip", R_VMREG_INT64, 0);
	case ARCH_X86:
#endif
	default:
		//fprintf(stderr,"R_VM: Initialized\n");
		r_vm_op_add(vm,"mov", "$1=$2");
		r_vm_op_add(vm,"lea", "$1=$2");
		r_vm_op_add(vm,"add", "$1=$1+$2");
		r_vm_op_add(vm,"sub", "$1=$1-$2");
		r_vm_op_add(vm,"jmp", "eip=$1");
		r_vm_op_add(vm,"push", "esp=esp-4,[esp]=$1");
		r_vm_op_add(vm,"pop", "$1=[esp],esp=esp+4");
		r_vm_op_add(vm,"call", "esp=esp-4,[esp]=eip+$$$,eip=$1");
		r_vm_op_add(vm,"ret", "eip=[esp],esp=esp+4");

		r_vm_reg_add(vm,"eax", R_VMREG_INT32, 0);
		r_vm_reg_add(vm,"ax", R_VMREG_INT16, 0);
		r_vm_reg_alias(vm, "ax","ax=eax&0xffff", "eax=eax>16,eax=eax<16,eax=eax|ax");
		r_vm_reg_add(vm,"al", R_VMREG_INT8, 0);
		r_vm_reg_alias(vm, "al","al=eax&0xff", "al=al&0xff,eax=eax>16,eax=eax<16,eax=eax|al");
		r_vm_reg_add(vm,"ah", R_VMREG_INT8, 0);
		r_vm_reg_alias(vm, "ah","ah=eax&0xff00,ah=ah>8", "eax=eax&0xFFFF00ff,ah=ah<8,eax=eax|ah,ah=ah>8");
		r_vm_reg_add(vm,"ebx", R_VMREG_INT32, 0);
		r_vm_reg_add(vm,"ecx", R_VMREG_INT32, 0);
		r_vm_reg_add(vm,"edx", R_VMREG_INT32, 0);
		r_vm_reg_add(vm,"esi", R_VMREG_INT32, 0);
		r_vm_reg_add(vm,"edi", R_VMREG_INT32, 0);
		r_vm_reg_add(vm,"eip", R_VMREG_INT32, 0);
		r_vm_reg_add(vm,"esp", R_VMREG_INT32, 0);
		r_vm_reg_add(vm,"ebp", R_VMREG_INT32, 0);
		r_vm_reg_add(vm,"zf",  R_VMREG_BIT, 0);
		r_vm_reg_add(vm,"cf",  R_VMREG_BIT, 0); // ...

		r_vm_setup_cpu(vm, "eip", "esp", "ebp");
		r_vm_setup_flags(vm, "zf");
		//vm_setup_call("[ebp-4]", "[ebp-8]", "[ebp-12]", "edx");
		r_vm_setup_fastcall(vm, "eax", "ebx", "ecx", "edx");
		//vm_setup_loop("ecx");
		//vm_setup_copy("esi", "edi");
		r_vm_setup_ret(vm, "eax");
		// TODO: do the same for fpregs and mmregs
#if 0
		if (init) // XXX
			r_vm_arch_x86_init(vm);
#endif
		break;
#if 0
	case ARCH_MIPS:
#if 0
		vm_nregs    = vm_arch_mips_nregs;
		vm_regs     = vm_arch_mips_regs;
		vm_regs_str = vm_arch_mips_regs_str;
#endif
		// TODO: do the same for fpregs and mmregs
		if (init)
			vm_arch_mips_init();
		break;
		//vm_regs = NULL;
#endif
	}
	return 0;
}

R_API int r_vm_eval_cmp(RVm *vm, const char *str) {
	int len;
	char *p, *ptr;

	for (;*str==' ';str=str+1);
	len = strlen (str)+1;
	ptr = alloca(len);
	memcpy (ptr, str, len);
	p = strchr (ptr, ',');
	if (!p) p = strchr (ptr, ' ');
	if (p) {
		r_vm_reg_set (vm, vm->cpu.zf,(r_vm_get_math(vm, ptr)-r_vm_get_math(vm, p+1)));
		p='\0';
		return 0;
	}
	return 1;
}

R_API int r_vm_eval_eq(RVm *vm, const char *str, const char *val) {
	char *p;
	ut8 buf[64];
	ut64 _int8  = 0;
	ut16 _int16 = 0;
	ut32 _int32 = 0;
	ut64 _int64 = 0;
	for(;*str==' ';str=str+1);
	for(;*val==' ';val=val+1);

	if (*str=='[') {
		// USE MMU
		// [foo] = 33, [reg] = 33
		if (*val=='[') {
			// [0x804800] = [0x30480]
			ut64 off = r_vm_get_math(vm, val+1);
			p = strchr(val+1,':');
			if (p) {
				int size = atoi(val+1);
				off = r_vm_get_math(vm, p+1);
				switch(size) {
				case 8:
					r_vm_mmu_read(vm, off, buf, 1);
					r_vm_mmu_write(vm, off, buf, 1);
					break;
				case 16:
					r_vm_mmu_read(vm, off, buf, 2);
					r_vm_mmu_write(vm, off, buf, 2);
					break;
				case 64:
					r_vm_mmu_read(vm, off, buf, 8);
					r_vm_mmu_write(vm, off, buf, 8);
					break;
				default:
					r_vm_mmu_read(vm, off, buf, 4);
					r_vm_mmu_write(vm, off, buf, 4);
				}
			} else {
				r_vm_mmu_read(vm, off, (ut8*)&_int32, 4);
				//off = r_vm_get_math(val);
				r_vm_mmu_write(vm, off, (void*)&_int32, 4);
			}
		} else {
			// [0x804800] = eax
			// use ssssskcvtgvmu
			ut64 off = r_vm_get_math(vm, str+1);
			// XXX support 64 bits here
			ut32 v = (ut32)r_vm_get_math(vm, val); // TODO control endian
			p = strchr(str+1,':');
			fprintf(stderr,"   ;==> [0x%08"PFMT64x"] = %x  ((%s))\n", off, v, str+1);

			if (p) {
				int size = atoi(val+1);
				off = r_vm_get_math(vm, p+1);
				printf(" write size: %d\n", size);
				switch(size) {
				case 8: r_vm_mmu_write(vm, off, buf, 1);
					break;
				case 16: r_vm_mmu_write(vm, off, buf, 2);
					break;
				case 64: r_vm_mmu_write(vm, off, buf, 8);
					break;
				default:
					r_vm_mmu_write(vm, off, buf, 4);
				}
			} else {
				printf("   ; write %x @ 0x%08"PFMT64x"\n", v, off);
				r_vm_mmu_write(vm, off, (ut8*)&v, 4);
			}
		}
	} else {
		// USE REG
		// reg = [foo] , reg = 33
		if (*val=='[') {
			// use mmu
			ut64 off;
			ut32 _int32 = 0;
			p = strchr(val+1,':');
			if (p) {
				int size = atoi(val+1);
				off = r_vm_get_math(vm, p+1);
				switch(size) {
				case 8:
					r_vm_mmu_read(vm, off, (ut8*)&_int8, 1);
					r_vm_reg_set(vm, str, (ut64)_int8);
					break;
				case 16:
					r_vm_mmu_read(vm, off, (ut8*)&_int16, 2);
					r_vm_reg_set(vm, str, (ut64)_int16);
					break;
				case 64:
					r_vm_mmu_read(vm, off, (ut8*)&_int64, 8);
					r_vm_reg_set(vm, str, (ut64)_int64);
					break;
				default:
					r_vm_mmu_read(vm, off, (ut8*)&_int32, 4);
					r_vm_reg_set(vm, str, (ut64)_int32);
				}
			} else {
 				off = r_vm_get_math(vm, val+1);
				r_vm_mmu_read(vm, off, (ut8*)&_int32, 4);
				r_vm_reg_set(vm, str, (ut64)_int32);
			}
		} else r_vm_reg_set(vm, str, r_vm_get_math(vm, val));
	}
	return 0;
}

R_API int r_vm_eval_single(RVm *vm, const char *str) {
	char *ptr, *eq;
	char buf[128];
	int i, len;

//	if (log)
	fprintf(stderr,"   ; %s\n", str);
	for(;str&&str[0]==' ';str=str+1);
	len = strlen(str)+1;
	ptr = alloca(len);
	memcpy(ptr, str, len);
	
/* TODO: sync with r1 */
	eq = strchr(ptr, '=');
	if (eq) {
		eq[0]='\0';
		switch(eq[-1]) {
		case '+':
		case '-':
		case '*':
		case '/':
		case '&':
		case '^':
		case '%':
		case '|':
		case '<':
		case '>':
			snprintf(buf, 127, "%s%c%s", ptr, eq[-1], eq+1);
			r_vm_eval_eq(vm, ptr, buf);
			//printf("EQ(%s)(%s)\n", ptr, buf);
			break;
		case ' ':
			i=-1; do { eq[i--]='\0'; } while(eq[i]==' ');
		default:
			//printf("EQ(%s)(%s)\n", ptr, eq+1);
			r_vm_eval_eq(vm, ptr, eq+1);
		}
		eq[0]='=';
	} else {
		fprintf(stderr, "Unknown opcode\n");
		if (!memcmp(ptr, "if ", 3)) {
			if (r_vm_reg_get(vm, ptr+3)!=0)
				return -1;
		} else
		if (!memcmp(ptr, "ifnot ", 6)) {
			if (r_vm_reg_get(vm, ptr+6)==0)
				return -1;
		} else
		if (!memcmp(ptr, "cmp ", 4)) {
			r_vm_eval_cmp(vm, str+5);
		} else
		return 0;

		if (!memcmp(ptr, "syscall", 6)) {
			fprintf(stderr,"TODO: syscall interface not yet implemented\n");
		} else
		if((!memcmp(ptr, "call ", 4))
		|| (!memcmp(ptr, "jmp ", 4))){
			if (ptr[0]=='c')
				r_vm_stack_push(vm, r_vm_get_value(vm, vm->cpu.pc));
			printf("CALL(%s)\n", ptr+4);
			r_vm_reg_set(vm, vm->cpu.pc, r_vm_get_value(vm, ptr+4));
		} else
		if (!memcmp(ptr, "jz ", 3)){
			if (r_vm_reg_get(vm, ptr+3)==0)
				r_vm_reg_set(vm, vm->cpu.pc, r_vm_get_value(vm, ptr+3));
		} else
		if (!memcmp(ptr, "jnz ", 4)){
			if (r_vm_reg_get(vm, ptr+4)==0)
				r_vm_reg_set(vm, vm->cpu.pc, r_vm_get_value(vm, ptr+4));
		} else
		if (!memcmp(ptr, "push ", 5)) {
			r_vm_stack_push(vm, r_vm_get_value(vm, str+5));
		} else
		if (!memcmp(str, "pop ", 4)) {
			r_vm_stack_pop(vm, str+5);
		} else
		if (!memcmp(ptr, "ret", 3)) {
			r_vm_stack_pop(vm, vm->cpu.pc);
			printf("RET (%x)\n", (ut32)vm->cpu.pc);
		} else
			fprintf(stderr, "r_vm: Unknown opcode\n");
	}
	return 0;
}

R_API int r_vm_eval(RVm *vm, const char *str) {
	char *next, *ptr;
	int ret, len = strlen(str)+1;

	ptr = alloca (len);
	memcpy (ptr, str, len);

#if 0
	r_vm_mmu_real (vm, 0);
	r_vm_mmu_real(vm, config_get_i("vm.realio"));
	.int32 eax alias-get alias-set
	.alias eax get set
#endif
	do {
		next = strchr(ptr, ',');
		if (next) {
			next[0]='\0';
			ret = r_vm_eval_single(vm, ptr);
			if (ret == -1)
				return 0;
			next[0]=',';
			ptr = next +1;
		}
	} while (next);
	r_vm_eval_single (vm, ptr);

	return 1;
}

R_API int r_vm_eval_file(struct r_vm_t *vm, const char *str) {
	char buf[1024];
	FILE *fd = fopen(str, "r");
	if (fd) {
		while(!feof(fd)) {
			*buf='\0';
			fgets(buf, 1023, fd);
			if (*buf) {
				buf[strlen(buf)-1]='\0';
				//vm_eval(buf);
				r_vm_op_eval(vm, buf);
			}
		}
		fclose(fd);
		return 1;
	}
	return 0;
}

/* emulate n opcodes */
R_API int r_vm_emulate(struct r_vm_t *vm, int n) {
#if 0
	ut64 pc;
	char str[128];
	ut8 buf[128];
	int opsize;
	int op = config_get_i("asm.pseudo");
	struct aop_t aop;

	printf("Emulating %d opcodes\n", n);
	///vm_init(1);
	vm_mmu_real(config_get_i("vm.realio"));
	vm_import(0);
	config_set("asm.pseudo", "true");
	config_set("asm.syntax", "intel");
	config_set("asm.profile", "simple");
	while(n--) {
		pc = vm_reg_get(vm->cpu.pc);
	udis_init();
		udis_set_pc(pc);
		vm_mmu_read(pc, buf, 32);
//fprintf(stderr,"(%02x %02x)\n",  buf[0], buf[1]);
		radare_cmdf("pd 1 @ 0x%08"PFMT64x"", pc);
		pas_aop(config.arch, pc, buf, 32, &aop, str, 1);

		arch_aop(pc, buf, &aop);
		opsize = aop.length;
//fprintf(stderr,"%"PFMT64x" +  %d (%02x %02x)\n", pc, opsize, buf[0], buf[1]);
		//printf("=> 0x%08"PFMT64x" '%s' (%d)\n", vm_reg_get(vm->cpu.pc), str, opsize);
		vm_reg_set(vm->cpu.pc, vm_reg_get(vm->cpu.pc)+opsize);
		vm_op_eval(str);
	}
	config_set("asm.pseudo", op?"true":"false");
	
#if 0
	fprintf(stderr,"TODO: vm_emulate\n");
	vm_init(1);
	vm_print();
#endif
// TODO: perform asm-to-pas-eval
// TODO: evaluate string
	return n;
#endif
	return -1;
}
