/* Copyright (C) 2007, 2008, 2009 - th0rpe <nopcode.org> */ 

#include "parser.h"

#if 0
extern struct regs_off roff[];
extern unsigned long get_reg(char *reg);
struct regs_off roff[] = {
	{"eax", R_EAX_OFF},
	{"ebx", R_EBX_OFF},
	{"ecx", R_ECX_OFF},
	{"edx", R_EDX_OFF},
	{"esi", R_ESI_OFF},
	{"edi", R_EDI_OFF},
	{"esp", R_ESP_OFF},
	{"ebp", R_EBP_OFF},
	{"eip", R_EIP_OFF},
	{"eflags", R_EFLAGS_OFF},

#if __WINDOWS__
	{"dr0", R_DR0_OFF},
	{"dr1", R_DR1_OFF},
	{"dr2", R_DR2_OFF},
	{"dr3", R_DR3_OFF},
	{"dr6", R_DR6_OFF},
	{"dr7", R_DR7_OFF},
#endif
	{0, 0}
};
#endif

#define ishexa(c) ((c >='0' && c <= '9') || \
		  (tolower(c) >='a' && tolower(c) <= 'f'))

/* skip \s\t and space characters */
char skip_chars(const char **c)
{
	for(;**c == ' ' || **c == '\t'; *c = *c + 1)
		;

	return **c;
}

int get_tok_op(const char **c, struct tok *t)
{
	t->op = -1;

	if(**c == '>') {
		if(*(*c  + 1) != '=') {
			t->op = _OP_GT;
			*c = *c + 1;
		} else {
			t->op = _OP_GE;
			*c = *c + 2;
		}

	} else if(**c == '=') {
		t->op = _OP_EQ;
		*c = *c + 1;

	} else if(**c == '<') {
		if(*(*c + 1) == '=') {
			t->op = _OP_LE;
			*c = *c + 1;
		} else if(*(*c + 1) == '>'){
			t->op = _OP_NE;
			*c = *c + 2;
		} else {
			t->op = _OP_LT;
			*c = *c + 2;
		}
	}

	if(t->type == MEM_TOK && t->op != _OP_EQ && t->op != _OP_NE)
		return -1;

	return t->op;
}

int get_tok_value(const char **c, struct tok *t)
{
	char aux[512];
	char *val = *c;
	int len;

	t->val = 0;

	/* hexadecimal value */
	if(**c == '0' && *(*c + 1) == 'x') {
		for(*c = *c + 2; ishexa(**c); *c = *c + 1) ;

		len = *c - val - 2;
		if( len <= 0 || (t->type == REG_TOK && 
		   (len >> 1) > sizeof(unsigned long)) ||
		   len + 2 >= sizeof(aux)) {
		  
			eprintf(":error  token value too large,"
					" near %s\n", val);
			return -1;
		}

		/* copy hexadecimal string */
		memcpy(aux, val, len + 2);
		aux[len + 2] = 0;

		if(t->type == REG_TOK) {
			t->val = malloc(sizeof(unsigned long));
			if(!t->val) {
				perror(":error malloc tok value");
				return -1;
			}

			*((unsigned long *)t->val) = get_math(aux);
			t->len = sizeof(unsigned long);
		} else {
			t-> val = malloc(len);
			if(!t->val) {
				perror(":error malloc tok value");
				return -1;
			}

			t->len = hexstr2binstr((const char *)aux + 2,
						(unsigned char *)(aux + 2));
			memcpy(t->val, aux + 2, t->len);
			/*
			for(i = 0; i < t->len; i++) {
				printf("\\x%.2x\n", (unsigned char)t->val[i]);
			}
			*/
			
		}

	/* decimal value */
	} else if(**c >= '0' && **c <= '9') {

		for(*c = *c + 1; **c >= '0' && **c <= '9'; *c = *c + 1)
			;

		len = *c - val;

		/* copy decimal string */
		memcpy(aux, val, len);
		aux[len] = 0;

                t->val = malloc(sizeof(unsigned long));
                if(!t->val) {
                        eprintf(":error malloc tok value");
                        return -1;
                }

		*((unsigned long *)t->val) = get_math(aux);
		t->len = sizeof(unsigned long);

	} else {
	/* TODO: get value from an external script */
		return -1;
	}

	return 0;
}

struct tok* get_tok(const char **c)
{
	struct tok *t = NULL;
	char aux[60];
	const char *val;
	int ret;

	skip_chars((const char**)c);

	/* register */
	if(**c == '%') {
		ret = get_reg(*c + 1);
		if(ret < 0) {
			eprintf(":error invalid register near ' %s '\n",
					*c);
			return NULL;
		}

		*c = *c + strlen(roff[ret].reg) + 1;

		t = (struct tok *)malloc(sizeof(*t));
		if(!t) {
			perror(":error malloc parse register");
			return NULL;
		}

		t->off = roff[ret].off;

		skip_chars((const char**)c);

		/* get operation */
		if(get_tok_op(c, t) == -1) {
			eprintf(":missing or invalid operation "
				"on register ' r%s '"
				"\n", roff[ret].reg);
			goto err_get_tok;
		}

		skip_chars((const char**)c);

		t->type = REG_TOK;

		/* get value */
		if(get_tok_value(c, t) == -1) {
			eprintf(":missing or invalid value "
				"on register ' r%s '"
				"\n", roff[ret].reg);
			goto err_get_tok;
		}

	/* memory */
	} if(**c == '[') {

		*c = *c + 1;

		skip_chars((const char **)c);

		val = *c;

		/* hexadecimal address */
		if(*val != '0' || *(val + 1) != 'x') {
			eprintf(":error invalid address near ' %s '\n",
					val);
			return NULL;
		}

		*c = *c + 2;

		for(; ishexa(**c) ; *c = *c + 1)
				;

		ret = *c - val - 2;	
		if((ret >> 1) > sizeof(unsigned long)) {
			eprintf(":error invalid address near ' %s '\n",
					val);

			return NULL;
		}

		skip_chars((const char **)c);

		if(**c != ']') {
			eprintf(":error invalid sintax near ' %s '\n",
					*c);
			return NULL;
		}

		memcpy(aux, val, ret + 2);
		aux[ret + 2] = 0;

		t = (struct tok *)malloc(sizeof(*t));
		if(!t) {
			perror(":error malloc parse memory");
			return NULL;
		}

		*c =  *c + 1;

		skip_chars((const char**)c);

		/* get operation */
		if(get_tok_op(c, t) == -1) {
			eprintf(":missing or invalid operation "
				"near ' %s '\n"
				, *c);
			goto err_get_tok;
		}

		skip_chars((const char**)c);

		t->off = get_math(aux);	
		t->type = MEM_TOK;

		/* get value */
		if(get_tok_value(c, t) == -1) {
			fprintf(stderr, ":missing or invalid value "
				"near ' %s '\n"
				, *c);
			goto err_get_tok;
		}
	} 

	return t;

err_get_tok:
	if(t)
		free(t);
		
	return NULL;
}

int get_log_op(const char **c, struct tok *t, int f)
{
	if(strncmp(*c, "and", 3) == 0) {
		if(!f)
			return -1;

		t->log_op = LOG_AND;

		*c = *c + 3;
	} else if(strncmp(*c, "or", 2) == 0) {
		if(!f)
			return -1;

		t->log_op = LOG_OR;

		*c = *c + 2;
	}

	return 0;
}

void free_cond(struct tok *group)
{
   	struct list_head *pos, *aux, *group_list;
	struct tok *t;

	assert(group->type == GROUP_TOK);

   	group_list = &group->list;
   	pos = group_list->next;

   	while(pos && pos != group_list)
    	{
        	t = (struct tok *)((char *)pos + \
                        sizeof(struct list_head) - \
                        sizeof(struct tok));

        	aux = pos->next;

		if(t->type == GROUP_TOK)
			free_cond(t);

        	list_del(&(t->next));

        	if(t->val)
                	free(t->val);

        	free(t);

        	pos = aux;
    	}

	free(group);
}

/* TODO: free list when error */
struct tok* process_cond(const char **c, int top)
{
	struct tok *t = NULL;
	struct tok *group;
	char *val;
	int f = 0;

	val = *c;

	/*printf("enter condition: %s\n", val); */
	

	group = (struct tok *)malloc(sizeof(*group));
	if(!group) {
		perror(":error malloc group token");
		return NULL;
	}

	/* initialize list group */
	INIT_LIST_HEAD(&group->list);
	group->type = GROUP_TOK;
	group->log_op = 0;

	for(;**c;) {

		skip_chars((const char **)c);

		if(get_log_op(c, t, f) < 0) {
			eprintf(":error missing token or "
			" operator not valid near ' %s '\n", val);
			goto err_cond;	
		}

		skip_chars((const char **)c);

		/* enter condition */
		if(**c == '(') {
			*c = *c + 1;
			t = process_cond(c, 0);
			if(!t)
				goto err_cond;

			list_add(&t->next, &group->list);

			if(**c != ')') {
				fprintf(stderr, ":error not closed condition "
						" near ' %s '\n",
						val);
				goto err_cond;
			}

			*c = *c + 1;
			f = 1;

		/* exit condition */
		} else if(**c == ')') {
			if(top !=  0) {
				fprintf(stderr, ":error not opened "
						"condition near ' %s '\n",
						val);
				goto err_cond;
			}	

			break;

		/* get token */
		} else {
			t = get_tok(c);
			if(!t)
				goto err_cond;

			t->log_op = 0;

			/* add token at group list */
			list_add(&t->next, &group->list);

			f = 2;
		}
	}

	/* printf("exit condition group\n"); */

	return group;

err_cond:

	free_cond(group);
	return NULL;
}

int eval_token_reg(struct tok *t)
{
	unsigned long reg_val;
	unsigned long val;
	int op, ret;

	if (!config.debug)
		return 0;

	op = t->op;
	reg_val = debug_get_regoff(&WS(regs), t->off);
	val = *(unsigned long *)(t->val);

	switch(op) {
		case _OP_LE:
			ret = (reg_val <= val);
			break;

		case _OP_LT:
			ret = (reg_val < val);
			break;

		case _OP_EQ:
			ret = (reg_val == val);
			break;

		case _OP_NE:
			ret = (reg_val != val);
			break;

		case _OP_GE:
			ret = (reg_val >= val);
			break;

		case _OP_GT:
		default:
			ret = (reg_val >= val);
			break;

	}

	return ret;
}

int eval_token_mem(struct tok *t)
{
	unsigned char rvalue[512];
	int op = t->op;
	int ret;

	if (!config.debug)
		return 0;

	/* printf("read_at: 0x%x %d\n", t->off, t->len); */
	if(debug_read_at(ps.tid, rvalue, t->len, t->off) <= 0)
		return 0;
/*
	printf("val: %x %x %x %x %x %x\n", rvalue[0], rvalue[1], rvalue[2],
		t->val[0], t->val[1], t->val[2]);
	printf("memcmp: %x\n", memcmp(t->val, rvalue, t->len));
*/

	switch(op) {
		case _OP_EQ:
			ret = (memcmp(t->val, rvalue, t->len) == 0);
			break;
		case _OP_NE:
		default:
			ret = (memcmp(t->val, rvalue, t->len) != 0);
	}

	return ret;
}

int eval_token(struct tok *t)
{
	int type = t->type;
	int ret;

	switch(type) {
		/* token register */
		case REG_TOK:
			ret = eval_token_reg(t);
			break;
		/* token memory */
		case MEM_TOK:
		default:
			ret = eval_token_mem(t);
			break;
	}	

	return ret;
}

int eval_cond(struct tok *group)
{
	struct list_head *pos;
	int log_op = 0, val_cond = 1;

	assert(group->type == GROUP_TOK);

	/* printf("EVAL enter group\n"); */

	list_for_each_prev(pos, &group->list) {

	        struct tok *t = (struct tok *)((char *)pos + \
                        sizeof(struct list_head) - \
                        sizeof(struct tok));

		/* not evalue next 'or' conditions 
		   when the condition is true yet or
		   the condition is false and exist next 'and'
		   conditions 
		*/

		if( (val_cond && log_op == LOG_OR) ||
		    (!val_cond && log_op == LOG_AND))
			continue;

		if(t->log_op)
			log_op = t->log_op;

		switch(t->type) {

			case GROUP_TOK:
				val_cond = eval_cond(t);
				break;
			default:
				val_cond = eval_token(t);
		}

	}

	/* printf("EVAL exit group\n"); */

	return val_cond;
}


void print_token(struct tok *t)
{
	char *op;
	char *log_op;

	switch(t->op) {
		case _OP_LE:
			op = "<=";
			break;

		case _OP_LT:
			op = "<";
			break;

		case _OP_EQ:
			op = "=";
			break;

		case _OP_NE:
			op = "<>";
			break;

		case _OP_GE:
			op = ">=";
			break;

		case _OP_GT:
			op = ">";
			break;
		default:
			op = "none";
	}

	if(t->log_op == LOG_OR)
		log_op = "or";
	else if(t->log_op == LOG_AND)
		log_op = "and";
	else
		log_op = "";

	if(t->type == REG_TOK) {
		printf( "register off %i\n"
			"logical op %s\n"
			"operator %s\n"
			"value    %x\n"
			,(unsigned int)t->off
			,log_op
			,op
			,(unsigned int)*((unsigned long *)t->val)
			);
	} else if(t->type == MEM_TOK) {
		printf( "memory %x\n"
			"logical op %s\n"
			"operator %s\n"
			"val    %x\n"
			"len    %d\n"
			,(unsigned int)t->off
			,log_op
			,op
			,(unsigned int)*((unsigned long *)t->val)
			,(unsigned int)t->len
			);
	} else {
	       printf(" operator group %s\n", log_op);
	}
}

void print_expr(struct tok *group)
{
	struct list_head *pos;

	assert(group->type == GROUP_TOK);

	printf("enter group\n");

	list_for_each_prev(pos, &group->list) {
	        struct tok *t = (struct tok *)((char *)pos + \
                        sizeof(struct list_head) - \
                        sizeof(struct tok));

		switch(t->type) {
			case GROUP_TOK:
				print_token(t);
				print_expr(t);
				break;

			default:
				print_token(t);
		}
	}

	printf("exit group\n");
}

struct tok* parse_cond(const char *cond)
{
	return process_cond(&cond, 1);
}
#if 0
void test_parser()
{
	struct tok *gr;
	char *v;
        char  *p = "reip >= 0x01020304 and rebx = 15 "
                   "and ([0x80456] = 10 or reip = 5) "
                   "and ([0xff456] = 1 and reip = 2) or "
                   "(reax <> 10 and recx = 4)"
                ;
	v = p;
	gr = process_cond(&p, 1);
	if(gr) {
		print_expr(gr);
		printf("cond: %s\n", v);
		printf("eval cond: %d\n", eval_cond(gr));
	}
}
#endif
