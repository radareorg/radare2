/* radare - LGPL - Copyright 2010-2011 pancake<@nopcode.org> */

#include <r_egg.h>

#define isspace(x) IS_WHITESPACE(x)
#define IS_VAR(x) (x[0]=='.'||((x[0]=='*'||x[0]=='&')&&x[1]=='.'))

static void rcc_pushstr(REgg *egg, char *str, int filter);
static void rcc_context(REgg *egg, int delta);
static struct {
	char *name;
	char *body;
	//int fastcall; /* TODO: NOT YET USED */
} inlines[256];
static int ninlines = 0;

static struct {
	char *name;
	char *arg;
	//int sysnum; /* TODO: NOT YET USED */
} syscalls[256];

enum {
	NORMAL = 0,
	ALIAS,
	DATA,
	INLINE,
	SYSCALL,
	SYSCALLBODY,
	LAST
};
// XXX : globals are ugly
static int nsyscalls = 0;
static char *syscallbody = NULL;
static int commentmode = 0;
static int varsize = 'l';
static int varxs = 0;
static int lastctxdelta = 0;
static int nargs = 0;
static int docall = 1; /* do call or inline it ? */ // BOOL
static int nfunctions = 0;
static int nbrackets = 0;
static int slurpin = 0;
static int slurp = 0;
static int line = 1;
static char elem[1024];
int attsyntax = 0;
static int elem_n = 0;
static int context = 0;
static char *callname = NULL;
static char *endframe = NULL;
static char *ctxpush[32];
static char *file = "stdin";
static char *dstvar = NULL;
static char *dstval = NULL;
static int ndstval = 0;
static int skipline = 0; // BOOL
static int quoteline = 0;
static int quotelinevar = 0;
static int stackframe = 0;
static int stackfixed = 0;
static int oc = '\n';
static int mode = NORMAL;

static const char *skipspaces(const char *s) {
	for (;*s;s++)
		switch (*s) {
		case '\n':
		case '\r':
		case '\t':
		case ' ':
			break;
		default:
			return s;
		}
	return s;
}

static char *trim(char *s) {
	char *o;
	for (o=s; *s; s++)
		if (isspace (*s)) {
			*s = 0;
			break;
		}
	return o;
}

#define SYNTAX_ATT 0
#if SYNTAX_ATT
#define FRAME_FMT ".LC%d_%d_frame%d"
#define FRAME_END_FMT ".LC%d_%d_end_frame%d"
#else
#define FRAME_FMT "__%d_%d_frame%d"
#define FRAME_END_FMT "__%d_%d_end_frame%d"
#endif

static char *get_frame_label(int type) {
	static char label[128];
	int nf = nfunctions;
	int nb = nbrackets;
	int ct = context;
	/* TODO: this type hack to substruct nb and ctx looks weird */
#if 1
	if (type == 1) nb--; else
	if (type == 2) ct--;
#endif
	/* THIS IS GAS_ONLY */
	snprintf (label, sizeof (label), FRAME_FMT, nf, nb, ct);
	return label;
}

static char *get_end_frame_label(REgg *egg) {
	static char label[128];
	snprintf (label, sizeof (label)-1, FRAME_END_FMT,
		nfunctions, nbrackets, context-1);
	//snprintf (label, sizeof (label)-1, "frame_end_%d_%d", nfunctions, nbrackets);
	return label;
}

static void rcc_pusharg(REgg *egg, char *str) {
	REggEmit *e = egg->emit;
	char buf[64], *p = r_egg_mkvar (egg, buf, str, 0);
	ctxpush[context] = strdup (p); // INDEX IT WITH NARGS OR CONTEXT?!?
	nargs++;
	e->push_arg (egg, varxs, nargs, p);
	//ctxpush[context+nbrackets] = strdup(str); // use nargs??? (in callname)
}

static void rcc_element(REgg *egg, char *str) {
	REggEmit *e = egg->emit;
	char *p = strrchr (str, ',');
	int num, num2;

	if (context) {
		nargs = 0;
		while (p) {
			*p = '\0';
			p = (char *)skipspaces (p+1);
			rcc_pusharg (egg, p);
			p = strrchr (str, ',');
		}
		if (callname)
			rcc_pusharg (egg, str);
		else
		if (mode == NORMAL) {
			if (!atoi (str)) {
				if (dstvar == NULL) /* return string */
					dstvar = strdup (".fix0");
				rcc_pushstr (egg, str, 1);
			}
		}
	} else {
		switch (mode) {
		case ALIAS:
			e->equ (egg, dstvar, str);
			R_FREE (dstvar);
			mode = NORMAL;
			break;
		case SYSCALL:
			syscalls[nsyscalls].name = strdup (dstvar);
			syscalls[nsyscalls].arg = strdup (str);
			nsyscalls++;
			R_FREE (dstvar);
			break;
		default:
			p = strchr (str, ',');
			if (p) {
				*p='\0';
				num2 = atoi (p+1); 
			} else num2 = 0;
			num = atoi (str) + num2;
			stackframe = num;
			stackfixed = num2;
			e->frame (egg, stackframe+stackfixed);
		}
		elem[0] = 0;
		elem_n = 0;
	}
}

static void rcc_pushstr(REgg *egg, char *str, int filter) {
        int dotrim = 1;
        int i, j, len;
	REggEmit *e = egg->emit;

        e->comment (egg, "encode %s string (%s) (%s)",
                filter? "filtered": "unfiltered", str, callname);

        if (filter)
        for (i=0; str[i]; i++) {
                if (str[i]=='\\') {
                        switch (str[i+1]) {
                        case 't': str[i]='\t'; break;
                        case 'n': str[i]='\n'; break;
                        case 'e': str[i]='\x1b'; break;
                        default: dotrim = 0; break;
                        }
                        if (dotrim)
                                memmove (str+i+1, str+i+2, strlen (str+i+2));
                }
        }

        len = strlen (str);
        j = (len-len%e->size)+e->size;
        e->set_string (egg, dstvar, str, j);
        free (dstvar);
	dstvar = NULL;
}

R_API char *r_egg_mkvar(REgg *egg, char *out, const char *_str, int delta) {
	int i, idx, len, qi;
	char *str, foo[32], *q, *ret;

	delta += stackfixed; // XXX can be problematic
	if (_str == NULL)
		return NULL; /* fix segfault, but not badparsing */
	/* XXX memory leak */
 	ret = str = strdup (skipspaces (_str));
	//if (num || str[0]=='0') { sprintf(out, "$%d", num); ret = out; }
	if ( (q = strchr (str, ':')) ) {
		*q = '\0';
		qi = atoi (q+1);
		varsize = (qi==1)? 'b':'l';
	} else varsize='l';
	if (*str=='*'||*str=='&') {
		varxs = *str;
		str++;
	} else varxs = 0;
	if (str[0]=='.') {
		REggEmit *e = egg->emit;
		ret = out;
		idx = atoi (str+4) + delta + e->size;
		if (!memcmp (str+1, "fix", 3)) {
			e->get_var (egg, 0, out, idx-stackfixed);
			//sprintf(out, "%d(%%"R_BP")", -(atoi(str+4)+delta+R_SZ-stackfixed));
		} else
		if (!memcmp (str+1, "var", 3)) {
			e->get_var (egg, 0, out, idx);
		//sprintf(out, "%d(%%"R_BP")", -(atoi(str+4)+delta+R_SZ));
		} else
		if (!memcmp (str+1, "arg", 3)) {
			if (str[4]) {
				if (stackframe == 0)
					e->get_var (egg, 1, out, idx);
				else {
					/* XXX: must simplify */
					if (docall)
						e->get_var (egg, 0, out, 
							-(delta+e->size*2+(e->size*(atoi(str+4)))));
					else	e->get_var (egg, 1, out, 
							delta+(e->size*(atoi(str+4))));
				}
			} else {
				/* TODO: return size of syscall */
				if (callname==NULL) {
					eprintf ("NO CALLNAME'%s'\n", callname);
				} else {
					for (i=0; i<nsyscalls; i++)
						if (!strcmp (syscalls[i].name, callname))
							return syscalls[i].arg;
					eprintf ("Unknown arg for syscall '%s'\n", callname);
				}
			}
		} else
		if (!memcmp (str+1, "reg", 3)) {
			// XXX: can overflow if out is small
			if (attsyntax)
				snprintf (out, 32, "%%%s", e->regs (egg, atoi (str+4)));
			else snprintf (out, 32, "%s", e->regs (egg, atoi (str+4)));
		} else {
			ret = str; /* TODO: show error, invalid var name? */
			eprintf ("FUCKED UP\n");
		}
	} else if (*str=='"' || *str=='\'') {
		int mustfilter = *str=='"';
		if (!stackfixed)
			eprintf ("WARNING: No room in the static stackframe!\n");
		/* TODO: check for room in stackfixed area */
		str++;
		len = strlen (str)-1;
		str[len]='\0';
		snprintf (foo, sizeof (foo)-1, ".fix%d", nargs*16); /* XXX FIX DELTA !!!1 */
		dstvar = strdup (skipspaces (foo));
		rcc_pushstr (egg, str, mustfilter);
		ret = r_egg_mkvar (egg, out, foo, 0);
	}
	//free ((void *)_str);
	return ret;
}

static void rcc_fun(REgg *egg, const char *str) {
	char *ptr, *ptr2;
	str = skipspaces (str);
	if (context) {
		ptr = strchr (str, '=');
		if (ptr) {
			*ptr = '\0';
			free (dstvar);
			dstvar = strdup (skipspaces (str));
			ptr2 = (char *)skipspaces(ptr+1);
			if (*ptr2) {
				callname = trim (strdup (skipspaces (ptr+1)));
			}
		} else {
			str = skipspaces (str);
			free (callname);
			callname = trim (strdup (skipspaces (str)));
			egg->emit->comment (egg, "rcc_fun %d (%s)", context, callname);
		}
	} else {
		ptr = strchr (str, '@');
		if (ptr) {
			ptr[0]='\0';
			mode = NORMAL;
			if (strstr (ptr+1, "fastcall")) {
				/* TODO : not yet implemented */
			} else
			if (strstr (ptr+1, "syscall")) {
				if (str[0]) {
					mode = SYSCALL;
					dstvar = strdup (skipspaces (str));
				} else {
					mode = INLINE;
					free (syscallbody);
					syscallbody = malloc (4096); // XXX hardcoded size
					dstval = syscallbody;
					R_FREE (dstvar);
					ndstval = 0;
					*syscallbody = '\0';
				}
			} else
			if (strstr(ptr+1, "alias")) {
				mode = ALIAS;
				dstvar = strdup (skipspaces (str));
			} else
			if (strstr(ptr+1, "data")) {
				mode = DATA;
				ndstval = 0;
				dstvar = strdup (skipspaces (str));
				dstval = malloc (4096);
			} else
			if (strstr (ptr+1, "inline")) {
				mode = INLINE;
				free (dstvar);
				dstvar = strdup (skipspaces (str));
				dstval = malloc (4096);
				ndstval = 0;
			} else {
				egg->emit->init (egg);
				r_egg_printf (egg, "\n.%s %s\n%s:\n", ptr+1, str, str);
			}
		} else r_egg_printf (egg, "\n%s:\n", str);
	}
}

static void rcc_context(REgg *egg, int delta) {
	REggEmit *emit = egg->emit;
	char str[64];

	context += delta;
	lastctxdelta = delta;

	if (context == 0 && delta < 0) {
		emit->frame_end (egg, stackframe+stackfixed, nbrackets);
		if (mode == NORMAL) /* XXX : commenting this makes hello.r unhappy! TODO: find a cleaner alternative */
			stackframe = 0;
		mode = NORMAL;
	} else {
		if (callname) {
			/* TODO: this must be an array */
			char *b = NULL; /* below */
			char *g = NULL; /* greater */
			char *e = NULL; /* equal */
			char *n = NULL; /* negate */
			/* conditional block */
			emit->comment (egg, "cond frame %s (%s)", callname, elem);
			/* TODO: simplify with a single for */
			b = strchr (elem, '<');
			g = strchr (elem, '>');
			e = strchr (elem, '=');
			n = strchr (elem, '!');
			if (!strcmp (callname, "while")) {
				emit->get_while_end (egg, str, ctxpush[context-1], get_frame_label (2));
				free (endframe);
				endframe = strdup (str);
				free (callname);
				callname = strdup ("if");
			}
			if (!strcmp (callname, "if")) {
				emit->branch (egg, b, g, e, n, varsize, get_end_frame_label (egg));
				if (context>0) {
					/* XXX .. */
				} else eprintf ("FUCKING CASE\n");
				R_FREE (callname);
			} else eprintf ("Unknown statement (%s)(%s)\n", callname, elem);
		}
	}
}

static int parsedatachar(REgg *egg, char c) {
	static int inlinectr = 0;
	char *str;
	int i, j;

	/* skip until '{' */
	if (c == '{') { /* XXX: repeated code!! */
		rcc_context (egg, 1);
		if (++inlinectr==1)
			return (ndstval = 0);
	} else if (inlinectr == 0) {
		/* capture value between parenthesis foo@data(NNN) { ... } */
		if (c==')') {
			stackframe = atoi (dstval);
			ndstval = 0;
		} else dstval[ndstval++] = c;
		return 0;
	}
	/* capture body */
	if (c == '}') { /* XXX: repeated code!! */
		if (context < 2) {
			inlinectr = 0;
			rcc_context (egg, -1);
			slurp = 0;
			mode = NORMAL;
			/* register */
			if (dstval != NULL && dstvar != NULL) {
				dstval[ndstval]='\0';
				egg->emit->comment (egg, "data (%s)(%s)size=(%d)\n",
					dstvar, dstval, stackframe);
				r_egg_printf (egg, ".data\n");
				for (str=dstval; isspace (*str); str++);
				j = (stackframe)? stackframe: 1;
				/* emit label */
				r_egg_printf (egg, "%s:\n", dstvar);
				for (i=1; i<=j; i++) {
					if (*str=='"')
						r_egg_printf (egg, ".ascii %s%s\n", dstval, (i==j)?"\"\\x00\"":"");
					else r_egg_printf (egg, ".long %s\n", dstval);
				}
				r_egg_printf (egg, ".text\n");
				R_FREE (dstvar);
				R_FREE (dstval);
				ndstval = 0;
				context = 0;
				return 1;
			} else eprintf ("FUCK FUCK\n");
		}
	}
	dstval[ndstval++] = c;
	return 0;
}

static int parseinlinechar(REgg *egg, char c) {
	static int inlinectr = 0;

	/* skip until '{' */
	if (c == '{') { /* XXX: repeated code!! */
		rcc_context (egg, 1);
		inlinectr++;
		if (inlinectr==1)
			return 0;
	} else
	if (inlinectr == 0)
		return 0;

	/* capture body */
	if (c == '}') { /* XXX: repeated code!! */
		if (context < 2) {
			rcc_context (egg, -1);
			slurp = 0;
			mode = NORMAL;
			inlinectr = 0;
			if (dstvar == NULL && dstval == syscallbody) {
				dstval = NULL;
				return 1;
			} else
			/* register */
			if (dstval != NULL && dstvar != NULL) {
				dstval[ndstval]='\0';
				//printf(" /* END OF INLINE (%s)(%s) */\n", dstvar, dstval);
				inlines[ninlines].name = strdup (skipspaces (dstvar));
				inlines[ninlines].body = strdup (skipspaces (dstval));
				ninlines++;
				R_FREE (dstvar);
				R_FREE (dstval);
				return 1;
			} else eprintf ("FUCK FUCK\n");
		}
	}
	dstval[ndstval++] = c;
	dstval[ndstval]=0;
	return 0;
}

/* TODO: split this function into several ones..quite long fun */
static void rcc_next(REgg *egg) {
	const char *ocn;
	REggEmit *e = egg->emit;
	char *p, buf[64];
	int i;

	docall = 1;
	if (callname) {
		callname = trim (callname);
		char *str, *ptr = strchr (callname, '=');
		if (ptr) {
			*ptr = '\0';
			ocn = ptr+1;
		}
		ocn = skipspaces (callname);
		str = r_egg_mkvar (egg, buf, ocn, 0);
		if (*ocn=='.')
			e->call (egg, str, 1);
		else
		if (!strcmp (str, "while")) {
			if (lastctxdelta>=0)
				exit (eprintf ("ERROR: Unsupported while syntax\n"));
			e->while_end (egg, get_frame_label (1));
#if 0
			eprintf ("------------------------------------------ lastctx: %d\n", lastctxdelta);
			// TODO: the pushvar is required for the if(){}while(); constructions
			//char *pushvar = ctxpush[context+nbrackets-1];
			/* TODO: support to compare more than one expression (LOGICAL OR) */
			rcc_printf ("  pop %%eax\n");
			rcc_printf ("  cmp $0, %%eax\n"); // XXX MUST SUPPORT != 0 COMPARE HERE
			/* TODO : Simplify!! */
			//if (pushvar)
			//	printf("  push %s /* wihle push */\n", pushvar);
			if (lastctxdelta<0)
				rcc_printf ("  jnz %s\n", get_frame_label (1));
			else rcc_printf ("  jnz %s\n", get_frame_label (0));
			//if (pushvar)
			//	printf("  pop %%"R_AX" /* while pop */\n");
#endif
			nargs = 0;
		} else {
			for (i=0; i<nsyscalls; i++) {
				if (!strcmp (str, syscalls[i].name)) {
					p = syscallbody;
					e->comment (egg, "set syscall args");
					e->syscall_args (egg, nargs);
					docall = 0;
					e->comment (egg, "syscall");
					r_egg_lang_parsechar (egg, '\n'); /* FIX parsing issue */
					if (p) {
						for (; *p; p++)
							r_egg_lang_parsechar (egg, *p);
					} else {
						char *q, *s = e->syscall (egg, nargs);
						if (s) {
							for (q=s; *q; q++)
								r_egg_lang_parsechar (egg, *q);
							free (s);
						} else eprintf ("Cant get @syscall payload\n");
					}
					docall = 0;
					break;
				}
			}
			if (docall)
			for (i=0; i<ninlines; i++) {
				if (!strcmp (str, inlines[i].name)) {
					p = inlines[i].body;
					docall = 0;
					e->comment (egg, "inline");
					r_egg_lang_parsechar (egg, '\n'); /* FIX parsing issue */
					for (; *p; p++)
						r_egg_lang_parsechar (egg, *p);
					docall = 0;
					break;
				}
			}
			if (docall) {
				e->comment (egg, "call in mode %d", mode);
				e->call (egg, str, 0);
			}
		}
		if (nargs>0)
			e->restore_stack (egg, nargs*e->size);
		if (ocn) { // Used to call .var0()
			/* XXX: Probably buggy and wrong */
			*buf = 0;
			str = r_egg_mkvar (egg, buf, ocn, 0);
			if (*buf)
				e->get_result (egg, buf);
			//else { eprintf("external symbol %s\n", ocn); }
		}
		/* store result of call */
		if (dstvar) {
			*buf = 0;
			str = r_egg_mkvar (egg, buf, dstvar, 0);
			if (*buf == 0)
				eprintf ("Cannot resolve variable '%s'\n", dstvar);
			else e->get_result (egg, buf);
			R_FREE (dstvar);
		}
		R_FREE (callname);
		nargs = 0;
	} else {
		int vs = 'l';
		char type, *eq, *ptr = elem;
		elem[elem_n] = '\0';
		ptr = (char*)skipspaces (ptr);
		if (*ptr) {
			eq = strchr (ptr, '=');
			if (eq) {
				char str2[64], *p, ch = *(eq-1);
				*eq = '\0';
				eq = (char*) skipspaces (eq+1);
				p = r_egg_mkvar (egg, str2, ptr, 0);
				vs = varsize;
				if (IS_VAR (eq)) {
					eq = r_egg_mkvar (egg, buf, eq, 0);
					if (varxs=='*')
						e->load (egg, eq, varsize);
					else
					/* XXX this is a hack .. must be integrated with pusharg */
					if (varxs=='&')
						e->load_ptr (egg, eq);
					eq = NULL;
					type = ' ';
				} else type = '$';
				vs = 'l'; // XXX: add support for != 'l' size
				e->mathop (egg, ch, vs, type, eq, p);
			} else e->mathop (egg, '=', vs, '$', ptr, NULL);
		}
	}
}

R_API int r_egg_lang_parsechar(REgg *egg, char c) {
	REggEmit *e = egg->emit;
	char *ptr, str[64];
	if (c=='\n') {
		line++;
		elem_n = 0;
	}
	/* comments */
	if (skipline) {
		if (c != '\n')
			return 0;
		skipline = 0; 
	}
	if (mode == DATA)
		return parsedatachar (egg, c);
	if (mode == INLINE)
		return parseinlinechar (egg, c);
	/* quotes */
	if (quoteline) {
		if (c != quoteline) {
			if (quotelinevar == 1) {
				if (c == '`') {
					elem[elem_n] = 0;
					elem_n = 0;
					r_egg_printf (egg, "%s", r_egg_mkvar (egg, str, elem, 0));
					quotelinevar = 0;
				} else elem[elem_n++] = c;
			} else {
				if (c == '`') {
					elem_n = 0;
					quotelinevar = 1;
				} else r_egg_printf (egg, "%c", c);
			}
			return 0;
		} else {
			r_egg_printf (egg, "\n");
			quoteline = 0;
		}
	}

	if (commentmode) {
		if (c=='/' && oc == '*')
			commentmode = 0;
		return 0;
	} else if (c=='*' && oc == '/')
		commentmode = 1;
	if (slurp) {
		if (slurp != '"' && c == slurpin)
			exit (eprintf (
				"%s:%d Nesting of expressions not yet supported\n",
				file, line));
		if (c == slurp && oc != '\\') {
			slurp = 0;
			elem[elem_n] = '\0';
			if (elem_n > 0)
				rcc_element (egg, elem);
			else e->frame (egg, 0);
			elem_n = 0;
		} else elem[elem_n++] = c;
		elem[elem_n] = '\0';
	} else {
		switch (c) {
		case ';':
			rcc_next (egg);
			break;
		case '"':
			slurp = '"';
			break;
		case '(':
			slurpin = '(';
			slurp = ')';
			break;
		case '{':
			if (context>0)
				r_egg_printf (egg, " %s:\n", get_frame_label (0));
			rcc_context (egg, 1);
			break;
		case '}':
			if (endframe) {
				// XXX: use endframe[context]
				r_egg_printf (egg, "%s\n", endframe);
				R_FREE (endframe);
			}
			if (context>0) {
				r_egg_printf (egg, "  %s:\n", get_end_frame_label (egg));
				nbrackets++;
			}
			rcc_context (egg, -1);
			if (context == 0) {
				nbrackets = 0;
				nfunctions++;
			}
			break;
		case ':':
			if (oc == '\n' || oc == '}')
				quoteline = '\n';
			else elem[elem_n++] = c;
			break;
		case '#':
			if (oc == '\n')
				skipline = 1;
			break;
		case '/':
			if (oc == '/')
				skipline = 1;
			break;
		default:
			elem[elem_n++] = c;
		}
		if (slurp) {
			if (elem_n) {
				ptr = elem;
				elem[elem_n] = '\0';
				while (isspace (*ptr)) ptr++;
				rcc_fun (egg, ptr);
			}
			elem_n = 0;
		}
	}
	if (c!='\t' && c!=' ')
		oc = c;
	return 0;
}
