/* radare - LGPL - Copyright 2008-2009 pancake<nopcode.org> */

#include "r_vm.h"

int r_vm_op_add(struct r_vm_t *vm, const char *op, const char *str)
{
	struct r_vm_op_t *o;
	o = MALLOC_STRUCT(struct r_vm_op_t);
	if (o == NULL)
		return -1;
	strncpy(o->opcode, op, sizeof(o->opcode));
	strncpy(o->code, str, sizeof(o->code));
	list_add_tail(&(o->list), &vm->ops);
	return 0;
}

int r_vm_op_eval(struct r_vm_t *vm, const char *str)
{
	struct list_head *pos;
	char *p, *s, *arg0;
	int j, k, len = strlen(str)+256;
	int nargs = 0;

	p = alloca(len);
	s = alloca(len);
	memcpy(p, str, len);
	memcpy(s, str, len);

	nargs = r_str_word_set0(s);
	arg0 = r_str_word_get0(s, 0);

	list_for_each(pos, &vm->ops) {
		struct r_vm_op_t *o = list_entry(pos, struct r_vm_op_t, list);
		if (!strcmp(arg0, o->opcode)) {
			str = o->code;
			p = alloca(strlen(o->code)+128);
			strcpy(p,str);
			for(j=k=0;str[j]!='\0';j++,k++) {
				if (str[j]=='$') {
					j++;
					if (str[j]=='\0') {
						fprintf(stderr, "invalid string\n");
						return 0;
					}
#if TODO
					if (str[j]=='$') {
						/* opcode size */
						if (str[j+1]=='$') {
							struct aop_t aop;
							char w[32];
							j++;
							arch_aop(config.seek, config.block,&aop);
							sprintf(w, "%d", aop.length);
							if (w[0]) {
								strcpy(p+k, w);
								k += strlen(w)-1;
							}
						} else {
							char w[32];
							sprintf(w, "0x%08llx", config.seek);
							if (w[0]) {
								strcpy(p+k, w);
								k += strlen(w)-1;
							}
						}
					}
#endif
					if (str[j]>='0' && str[j]<='9') {
						const char *w = r_str_word_get0(s, str[j]-'0');
						if (w != NULL) {
							strcpy(p+k, w);
							k += strlen(w)-1;
						}
					}
				} else p[k] = str[j];
			}
			p[k]='\0';
		}
	}
	return r_vm_eval(vm, p);
}

/* TODO : Allow to remove and so on */
int r_vm_op_cmd(struct r_vm_t *vm, const char *op)
{
	char *cmd, *ptr;
	int len = strlen(op)+1;
	if (*op==' ')
		op = op + 1;
	cmd = alloca(len);
	memcpy(cmd, op, len);
	ptr = strchr(cmd, ' ');
	if (ptr) {
		ptr[0]='\0';
		eprintf("vm: opcode '%s' added\n", cmd);
		r_vm_op_add(vm, cmd, ptr+1);
	} else r_vm_cmd_op_help();
	return 0;
}
