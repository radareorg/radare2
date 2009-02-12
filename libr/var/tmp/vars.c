/* Copyleft 2009 - pancake<AT>youterm.com */


#include "main.h"
#include "list.h"

int var_add(u64 addr, u64 eaddr, int delta, int type, const char *vartype, const char *name, int arraysize);
// this can be nested inside the function_t which is not defined..

#if 0
struct function_t {
	char name[128];
	int framesize;
	struct list_head ranges;
	struct list_head vars;
};
#endif

static struct list_head vars;

/* variable types */
enum {
	VAR_T_GLOBAL,
	VAR_T_LOCAL,
	VAR_T_ARG,
	VAR_T_ARGREG
};

struct var_xs_t {
	u64 addr;
	int set;
	struct list_head list;
};

struct var_t {
	int type;      /* global, local... */
	u64 addr;      /* address where it is used */
	u64 eaddr;      /* address where it is used */
	int delta;     /* */
	int arraysize; /* size of array var in bytes , 0 is no-array */
	char name[128];
	char vartype[128];
	struct list_head access; /* list of accesses for this var */
	struct list_head list;
};

int var_add(u64 addr, u64 eaddr, int delta, int type, const char *vartype, const char *name, int arraysize)
{
	struct var_t *var = (struct var_t *)malloc(sizeof(struct var_t));
	/* TODO: check of delta inside funframe */
	if (strchr(name, ' ') || strchr(vartype,' ')) {
		eprintf("Invalid name/type\n");
		return 0;
	}
	strncpy(var->name, name, sizeof(var->name));
	strncpy(var->vartype, vartype, sizeof(var->vartype));
	var->delta = delta;
	var->type = type;
	var->addr = addr;
	var->eaddr = eaddr;
	var->arraysize = arraysize;
	INIT_LIST_HEAD(&(var->access));
	list_add(&(var->list), &vars);
	return 1;
}

int var_add_access(u64 addr, int delta, int type, int set)
{
	struct list_head *pos;
	struct var_t *v;
	int reloop = 0;

	_reloop:
	list_for_each(pos, &vars) {
		v = (struct var_t *)list_entry(pos, struct var_t, list);
		if (addr >= v->addr) {
			//if (!strcmp(name, v->name)) {
			if (delta == v->delta && type == v->type) {
				struct var_xs_t *xs = (struct var_xs_t *)malloc(sizeof(struct var_xs_t));
				xs->addr = addr;
				xs->set = set;
//eprintf("==> %llx\n", addr);
				/* add var access here */
				list_add(&(xs->list), &(v->access));
				return 1;
			}
		}
	}
	/* automatic init */
	/* detect function in CF list */
	{
		u64 from = 0LL, to = 0LL;
		if ( data_get_fun_for(addr, &from, &to) ) {
			char varname[32];
			if (delta < 0) {
				delta = -delta;
				sprintf(varname, "arg_%d", delta);
			} else sprintf(varname, "var_%d", delta);
			//eprintf("0x%08llx: NEW LOCAL VAR %d\n", from, delta);
			var_add(from, to, delta, VAR_T_LOCAL, "int32", varname, 1);
			if (reloop) {
				#warning THIS IS BUGGY: SHOULD NEVER HAPPEN
				eprintf("LOOPING AT 0x%08llx NOT ADDING AN ACCESS\n", addr);
				return 0;
			}
			reloop=1;
			goto _reloop;
			return var_add_access(addr, delta, type, set);
		} else eprintf("Cannot find bounding function at 0x%08llx\n", addr);
	}
	return 0;
}

const char *var_type_str(int fd)
{
	switch(fd) {
	case VAR_T_GLOBAL: return "global";
	case VAR_T_LOCAL:  return "local";
	case VAR_T_ARG:    return "arg";
	case VAR_T_ARGREG: return "fastarg";
	}
	return "(?)";
}

u32 var_dbg_read(int delta)
{
	/* XXX: EBP ONLY FOR X86 */
	u32 ret;
	u64 foo = get_offset("ebp");
	foo-=delta;
	radare_read_at(foo, (u8*)&ret, 4);
	return ret;
}


void print_mem(u64 addr, const u8 *buf, u64 len, const char *fmt, int endian);

int var_print_value(struct var_t *v)
{
	struct var_type_t *t = data_var_type_get(v->vartype);
	if (t == NULL) {
		u32 value = var_dbg_read(v->delta);
		// TODO: use var type to 
		cons_printf("%x", value);
	} else {
		u8 buf[1024];
		int verbose = config.verbose;
		int size = v->arraysize * t->size;
		u64 foo = get_offset("ebp");
		foo -= v->delta;
		radare_read_at(foo, buf, size);
		//eprintf("PRINT_MEM(%llx,%d,%s)\n", foo, size, t->fmt);
		config.verbose = 0;
		print_mem(foo, buf, size, t->fmt, config.endian);
		config.verbose = verbose;
	}
	return 0;
}

/* CFV */
int var_list_show(u64 addr)
{
	char buf[256];
	struct list_head *pos, *pos2;
	struct var_t *v;
	struct var_xs_t *x;

	list_for_each(pos, &vars) {
		v = (struct var_t *)list_entry(pos, struct var_t, list);
		if (addr == 0 || (addr >= v->addr && addr <= v->eaddr)) {
			u32 value = var_dbg_read(v->delta);
			if (v->arraysize>1)
				cons_printf("%s %s %s[%d] = ", var_type_str(v->type), v->vartype, v->arraysize, v->name);
			else cons_printf("%s %s %s = ", var_type_str(v->type), v->vartype, v->name);
			var_print_value(v);
			/* TODO: detect pointer to strings and so on */
			if (string_flag_offset(buf, value, 0))
				cons_printf(" ; points to: %s\n", buf);
			else cons_newline();
		}
	}

	return 0;
}

/* 0,0 to list all */
int var_list(u64 addr, int delta)
{
	struct list_head *pos, *pos2;
	struct var_t *v;
	struct var_xs_t *x;

	list_for_each(pos, &vars) {
		v = (struct var_t *)list_entry(pos, struct var_t, list);
		if (addr == 0 || (addr >= v->addr && addr <= v->eaddr)) {
			cons_printf("0x%08llx - 0x%08llx type=%s type=%s name=%s delta=%d array=%d\n",
				v->addr, v->eaddr, var_type_str(v->type),
				v->vartype, v->name, v->delta, v->arraysize);
			list_for_each_prev(pos2, &v->access) {
				x = (struct var_xs_t *)list_entry(pos2, struct var_xs_t, list);
				cons_printf("  0x%08llx %s\n", x->addr, x->set?"set":"get");
			}
		}
	}

	return 0;
}

int var_init()
{
	INIT_LIST_HEAD(&vars);
	data_var_type_add("char", 1, "b");
	data_var_type_add("byte", 1, "b");
	data_var_type_add("int", 4, "d");
	data_var_type_add("int32", 4, "d");
	data_var_type_add("dword", 4, "x");
	data_var_type_add("float", 4, "f");
}

int var_help()
{
	eprintf("Try Cv?\n");
	eprintf(" Cv 12 int buffer[3]\n");
	eprintf(" Cv 12 byte buffer[1024]\n");
}

int var_cmd_help()
{
	eprintf("Try CF[aAv][gs] [delta]\n");
	eprintf(" CFag 0  = arg0 get\n");
	eprintf(" CFvs 12 = var12 set\n");
	eprintf("a = arg, A = fastarg, v = var\n");
}

int var_cmd(const char *str)
{
	char *p,*p2,*p3;
	int type, delta, len = strlen(str)+1;

	p = alloca(len);
	memcpy(p, str, len);
	str = p;

	switch(*str) {
	case 'V': // show vars in human readable format
		return var_list_show(config.seek);
	case 'v': // frame variable
	case 'a': // stack arg
	case 'A': // fastcall arg
		// XXX nested dup
		switch(*str) {
		case 'v': type = VAR_T_LOCAL; break;
		case 'a': type = VAR_T_ARG; break;
		case 'A': type = VAR_T_ARGREG; break;
		}
		/* Variable access CFvs = set fun var */
		switch(str[1]) {
		case '\0': return var_list(0, 0);
		case '.':  return var_list(config.seek, 0);
		case 's':  return var_add_access(config.seek, atoi(str+2), type, 1);
		case 'g':  return var_add_access(config.seek, atoi(str+2), type, 0);
		}
		str = str+1;
		if (str[0]==' ')str=str+1;
		delta = atoi(str);
		p = strchr(str, ' ');
		if (p==NULL)
			return var_cmd_help();
		p[0]='\0'; p=p+1;
		p2 = strchr(p, ' ');
		if (p2==NULL)
			return var_help();
		p2[0]='\0'; p2=p2+1;
		p3 = strchr(p2,'[');
		if (p3 != NULL) {
			p3[0]='\0';
			p3=p3+1;
		}
		var_add(config.seek, config.seek, delta, type, p, p2, p3?atoi(p3):0);
		break;
	default:
		var_help();
		break;
	}
	return 0;
}

#if 0
 -- function boundaries are used to limit variables life-cycle --
 // global vars are handled as flags??
 // "CV 0x8049200 x global_counter
 // local vars
 // types: glar: g=global, l=local, a=arg, r=argreg
  Cv l d i @ 0x8048200
   /* using code analysis we can identify local var accesses */

 f.ex:
 ; Set var0 
  0x4a13c014,  mov [ebp-0x34], eax

 ; set name for variable accessed.
 Cvn counter @ 0x4a13c014

 stack frame {
   var1 { offset, size, type, name }
   var2 { offset, size, type, name }
 }

// how to track a variable 

#endif
