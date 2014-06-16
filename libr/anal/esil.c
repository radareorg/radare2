#if 0
/* radare - LGPL - Copyright 2013-2014 - pancake */

#include <r_anal.h>
#include <r_types.h>

#define NARGS 64
typedef struct r_anal_esil_t {
	RAnal *anal;
	int rightside;
	int opsize;
	RList *stack;
	RList *opstack;
	int (*set)(struct r_anal_esil_t *c, const char *str, ut64 n);
	ut64 (*get)(struct r_anal_esil_t *c, const char *str);
	ut64 (*num)(struct r_anal_esil_t *c, const char *str);
	int (*iterate)(struct r_anal_esil_t *c, char *buf, int *tkns);
} RAnalEsil;

#if 0

mov ecx, 3      ecx=3
rep push ebx    esp-=4,[esp]=ebx,ecx--,@ecx
jb 0x804840     ?cf,eip=4[eip+1]
cmovc eax, 3    ?cf,eax=3
add eax, 44     cf=eax+44<eax,eax+=44
int 0x80        $0x80

#endif

static int token(char c) {
	switch (c) {
	case '(': // open scope
		return 5;
	case ')': // close scope
		return 6;
	case '$': // syscall
	case '@': // repeat if condition matches
	case '?': // conditional
	case '[': // store
	case ']': // store
	case '.':
		return 1;
	case ',':
		return 4;
	case '+':
	case '-':
	case '=':
	case '*':
	case '/':
	case '|':
	case '&':
	case '!':
	case '>':
	case '<':
		return 2;
	default:
		if ((c>='a' && c<='z')
			|| (c>='A' && c<='Z')
			|| (c>='0' && c<='9'))
			return 3;
	}
	return 0; // unknown
}

static int r_anal_esil (RAnalEsil *c, const char *str) {
	char buf[128];
	const char *chr = str;
	int t, bufi, tok, tknsi, tkns[128];
	bufi = tok = tknsi = 0;
	for (; *chr; chr++) {
		t = token (*chr);
		if (!t) {
			printf ("unknown!\n");
			return -1;
		}
		if (tok != t) {
			buf[bufi++] = 0;
			tkns[tknsi++] = t;
			tkns[tknsi++] = bufi;
			tok = t;
		}
		buf[bufi++] = *chr;
	}
	tkns[tknsi++] = 0;
	buf[bufi] = 0;
	return c->iterate (c, buf, tkns);
}

#if 0
static int iterate (RAnalEsil *c, char *buf, int *tkns) {
	char *str;
	int i, type;
	for (i=0; tkns[i]; i+=2) {
		type = tkns[i];
		str = buf+tkns[i+1];
		eprintf ("(%d) (%s)\n", type, str);
		if (type==1) {
			if (!strcmp (str, "?")) {
				printf ("   CONDITIONAL\n");
			}
		}
	}
	return 0;
}
#endif

#define TOKEN_IS(x,y,z) (x[i]==y && !strcmp (x[i+1]==z))
#define TOKEN_GET(x,y) x=tkns[i]; y=buf+tkns[i+1]
#define IS(x) (!strcmp(x,op))

static int esil_set (RAnalEsil *e, const char *s, ut64 n) {
	if (e->anal && e->anal->reg) {
		RRegItem *item;
		item = r_reg_get (e->anal->reg, s, 0); // GPR only wtf?
		eprintf ("SET (%p)\n", item);
		if (item) return r_reg_set_value (e->anal->reg, item, n);
	}
	return R_TRUE;
}

static ut64 esil_get (RAnalEsil *e, const char *s) {
	RRegItem *item;
	// check for register
	if (!s) return 0LL;
	item = r_reg_get (e->anal->reg, s, 0); // GPR only wtf?
	if (item) return r_reg_get_value (e->anal->reg, item);
	return r_num_get (NULL, s);
}

#define OPUSH(x) r_list_push (c->opstack,x)
#define PUSH(x) r_list_push (c->stack,(void*)x)
#define OPOP() r_list_pop (c->opstack)
#define POP() r_list_pop (c->stack)

static int esil_commit (RAnalEsil *c, const char *op) {
	const char *q = POP();
	const char *p = POP();
	//const char *o = op;
	int ss = c->opsize;
	if (ss) {
//		eprintf (";; GET %d[%s]\n", ss, q);
//		eprintf ("PSUH %s %s\n", p, q);
eprintf (";; -> this means that we have to resolve before accessing memory %d\n", c->opsize);
		c->opsize = 0;
		PUSH (p);
		PUSH (q);
		return 0;
	}
	if (!op) {
		eprintf ("COMMIT UNKNOWN OP.. THIs IS []\n");
		return 0;
	}
	//eprintf (";;; COMMIT ;;; (%s) %s (%s)\n", p, o, q);
	if (IS ("[=")) {
		eprintf ("EQUAL------SET\n");
	} else
	if (IS ("+")) {
		// push (get (p)+get (q));
		ut64 n = esil_get (c, p) + esil_get (c, q);
		char *ns = malloc (32); // XXX memleak
		sprintf (ns, "0x%"PFMT64x, n);
		PUSH (ns);
		eprintf (";;; %s %s\n", p, q);
		//eprintf (" (((0x%llx)))\n", esil_get (c, p));
		eprintf (";;; +EQUAL! (%s)\n", ns);
	} else
	if (IS ("-")) {
		// push (get (p)+get (q));
		ut64 n = esil_get (c, p) - esil_get (c, q);
		char *ns = malloc (32); // XXX memleak
		sprintf (ns, "0x%"PFMT64x, n);
		PUSH (ns);
		eprintf (";;; %s %s\n", p, q);
		eprintf (";;; -EQUAL! (%s)\n", ns);
	} else
	if (IS ("*")) {
		// push (get (p)+get (q));
		ut64 n = esil_get (c, p) * esil_get (c, q);
		char *ns = malloc (32); // XXX memleak
		sprintf (ns, "0x%"PFMT64x, n);
		PUSH (ns);
		eprintf (";;; %s %s\n", p, q);
		eprintf (";;; *EQUAL! (%s)\n", ns);
	}
	if (IS ("=")) {
		if (p == NULL || q == NULL) {
			eprintf ("Invalid construction\n");
			return -1;
		}
		// set (p, get (q))
		c->set (c, p, c->get (c, q));
		eprintf (";;; EQUAL! (%s=%s)\n", p, q);
	}
	return 0;
}

static int emulate (RAnalEsil *c, char *buf, int *tkns) {
	ut64 num = 0;
	char *op = NULL;
	char *str = NULL;
	int i, type;
	c->opstack = r_list_new ();
	c->stack = r_list_new ();
	c->opsize = 0;
	c->rightside = 0;
	for (i=0; tkns[i]; i+=2) {
		TOKEN_GET (type, str);
		eprintf ("(%d) (%s)\n", type, str);

		switch (type) {
		// case 0 handled in for conditional
		case 1: /* special command */
			if (!strcmp (str, "[")) {
				int curstack = r_list_length (c->stack);
eprintf ("STACK POINTER %d\n", curstack);
				c->opsize = (int)num;
				// TODO: test for size
				// read tokens until ']'
				// TOKEN_UNTIL (1, "]");
				for (i+=2; tkns[i]; i+=2) {
					TOKEN_GET (type, str);
					eprintf ("--- %d (%s)\n", tkns[i], buf+tkns[i+1]);
					switch (tkns[i]) {
					case 1:
						if (!strcmp (str, "]")) {
							if (!c->opsize) c->opsize = 
								c->anal->bits==64?8:4;
							//int j, len = r_list_length (c->stack) - curstack;
							char *a;
							OPUSH (op);
							while ((a = OPOP ())) {
								// eprintf ("---> op %s\n", op);
								esil_commit (c, a);
							}
							//op = NULL;
							printf ("   %s (size %d)\n", c->rightside?"GET":"SET", (int)num);
							goto dungeon;
							// set destination for write
							// expect '='
						}
						break;
					case 2:
						op = str;
						OPUSH (op);
						break;
					case 3:
						PUSH (str);
						break;
					}
				}
				if (!tkns[i]) {
					printf ("Unexpected eof\n");
					return 1;
				}
			} else
			if (!strcmp (str, "?")) {
				printf ("   CONDITIONAL\n");
				i += 2;
				TOKEN_GET (type, str);
				if (!type) {
					eprintf ("   UNEXPECTED EOF\n");
					return 1;
				}
				if (type!=3) {
					printf ("   UNEXPECTED TOKEN\n");
					return 1;
				}
				//while () { i += 2; }
			}
			break;
		case 2:
			if (op) {
				//eprintf (" XXX Redefine op %s\n", op);
				if (!strcmp (op, "*")) { // prio
					esil_commit (c, op);
				} else OPUSH (op);
			}
			op = str;
			if (IS ("=")) {
				c->rightside = 1;
			}
			break;
		case 3:
			num = c->num (c, str); // 
	//		eprintf ("; push %s\n" , str);
			PUSH (str);
			break;
		case 4:
			esil_commit (c, op);
			op = NULL;
			break;
		case 5:
// newcontext();
			//esil_push_scope (c);
			eprintf ("OPEN SCOPE\n");
			break;
		case 6:
			{
			//char *res = esil_pop_scope (c);
			// if scope > 0 : 
			//PUSH (res);
			esil_commit (c, op);
			// free (res);
			// commit()
			// closecontext()
			// push result
			eprintf ("CLOSE SCOPE\n");
			}
			break;
		}
		dungeon:
		{/*trick*/int/*label*/x/*parsing*/=/*fix*/0;x = !x;}
	}
	eprintf (";;; COMMIT (%s) (%s)\n", op, str);
	esil_commit (c, op);
	if (r_list_length (c->opstack)>0) {
		char *a;
		while ((a = OPOP ())) {
			esil_commit (c, a);
		}
	}
	op = NULL;
	return 0;
}

static ut64 num(struct r_anal_esil_t *c, const char *str) {
	return r_num_get (NULL, str);
}


#define C(x) r_anal_esil(&c,x)
#ifdef MAIN
int main() {
	RAnalEsil c = {
		.num = num,
		.iterate = emulate //iterate
	};
	//C ("esp=32,eax++");
	C ("4[eax+3]=123");
	//C ("?cf,esp=32+2,eax++");
	//C ("cf=eax+44<eax,eax+=44");
	//C ("esp-=4,[esp]=ebx,ecx--,@ecx");
	return 0;
}
#endif

R_API int r_anal_esil_eval(RAnal *anal, const char *str) {
	RAnalEsil c = {
		.anal = anal,
		.get = esil_get,
		.set = esil_set,
		.num = num,
		.iterate = emulate //iterate
	};
	C (str);
	return 0;
}
#endif
