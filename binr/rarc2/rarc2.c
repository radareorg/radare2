/* GPLv3 -- Copyright 2009-2010 -- pancake /at/ nopcode.org */

#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include "rarc2.h"

static int parsechar(char c);

static struct {
	char *name;
	char *body;
	//int fastcall; /* TODO: NOT YET USED */
} inlines[MAX];
static int ninlines = 0;
static struct {
	char *name;
	char *arg;
	//int sysnum; /* TODO: NOT YET USED */
} syscalls[MAX];

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
static int showmain = 0;
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

extern struct emit_t emit_x86;
extern struct emit_t emit_x64;
extern struct emit_t emit_arm;
struct emit_t *emits[4] = {
	&emit_x86,
	&emit_x64,
	&emit_arm,
	NULL
};
#if __arm__
static struct emit_t *emit = &emit_arm;
#elif __i386__
static struct emit_t *emit = &emit_x86;
#else
static struct emit_t *emit = &emit_x64;
#endif

#if SYNTAX_ATT
#define FRAME_FMT ".LC%d_%d_frame%d"
#define FRAME_END_FMT ".LC%d_%d_end_frame%d"
#else
#define FRAME_FMT "__%d_%d_frame%d"
#define FRAME_END_FMT "__%d_%d_end_frame%d"
#endif

static char *get_end_frame_label() {
	static char label[128];
	/* THIS IS GAS_ONLY */
	snprintf (label, sizeof(label), FRAME_END_FMT,
		nfunctions, nbrackets, context-1);
	return label;
}

static char *get_frame_label(int type) {
	static char label[128];
	int nf = nfunctions;
	int nb = nbrackets;
	int ct = context;
	/* TODO: this type hack to substruct nb and ctx looks weird */
	if (type == 1) nb--; else
	if (type == 2) ct--;
	/* THIS IS GAS_ONLY */
	snprintf (label, sizeof (label), FRAME_FMT, nf, nb, ct);
	return label;
}

static void rcc_pushstr(char *str, int filter) {
	int dotrim = 1;
	int i, j, len;

	emit->comment ("encode %s string (%s) (%s)",
		filter?"filtered":"unfiltered", str, callname);

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
	j = (len-len%emit->size)+emit->size;
	emit->set_string (dstvar, str, j);
	FREE (dstvar);
}

char *mk_var(char *out, const char *_str, int delta) {
	int i, idx, len, qi;
	char *str, foo[32], *q, *ret;

	delta += stackfixed; // XXX can be problematic
	if (_str == NULL)
		return NULL; /* fix segfault, but not badparsing */
	/* XXX memory leak */
 	ret = str = strdup (_str);
	while (*str==' ') str++; /* skip spaces ...also tabs isspace()? */
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
		ret = out;
		idx = atoi (str+4) + delta + emit->size;
		if (!memcmp (str+1, "fix", 3)) {
			emit->get_var (0, out, idx-stackfixed);
			//sprintf(out, "%d(%%"R_BP")", -(atoi(str+4)+delta+R_SZ-stackfixed));
		} else
		if (!memcmp (str+1, "var", 3)) {
			emit->get_var (0, out, idx);
		//sprintf(out, "%d(%%"R_BP")", -(atoi(str+4)+delta+R_SZ));
		} else
		if (!memcmp(str+1, "arg", 3)) {
			if (str[4]) {
				if (stackframe == 0)
					emit->get_var (1, out, idx);
				else {
					/* XXX: must simplify */
					if (docall)
						emit->get_var (0, out, 
							-(delta+emit->size*2+(emit->size*(atoi(str+4)))));
					else	emit->get_var (1, out, 
							delta+(emit->size*(atoi(str+4))));
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
			snprintf (out, 32, "%%%s", emit->regs (atoi (str+4)));
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
		dstvar = strdup (foo);
		rcc_pushstr (str, mustfilter);
		ret = mk_var (out, foo, 0);
	}
	//free ((void *)_str);
	return ret;
}

static void rcc_fun(char *str) {
	char *ptr, *ptr2;
	if (context) {
		ptr = strchr(str, '=');
		if (ptr) {
			*ptr = '\0';
			free (dstvar);
			dstvar = strdup (str);
			for (ptr2=ptr+1; isspace (*ptr2); ptr2++);
			if (*ptr2)
				callname = strdup (ptr+1);
		} else {
			emit->comment ("rcc_fun %d (%s)", context, str);
			free (callname);
			callname = strdup (str);
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
					dstvar = strdup (str);
				} else {
					mode = INLINE;
					free (syscallbody);
					syscallbody = malloc (4096); // XXX hardcoded size
					dstval = syscallbody;
					FREE (dstvar);
					ndstval = 0;
					syscallbody[0] = '\0';
				}
			} else
			if (strstr(ptr+1, "alias")) {
				mode = ALIAS;
				dstvar = strdup (str);
			} else
			if (strstr(ptr+1, "data")) {
				mode = DATA;
				ndstval = 0;
				dstvar = strdup (str);
				dstval = malloc (4096);
			} else
			if (strstr (ptr+1, "inline")) {
				mode = INLINE;
				free (dstvar);
				dstvar = strdup (str);
				dstval = malloc (4096);
				ndstval = 0;
			} else rcc_printf ("\n.%s %s\n%s:\n", ptr+1, str, str);
		} else rcc_printf ("\n%s:\n", str);
	}
}

static void rcc_pusharg(char *str) {
	char buf[64], *p = mk_var (buf, str, 0);
	ctxpush[context] = strdup (p); // INDEX IT WITH NARGS OR CONTEXT?!?
	nargs++;
	emit->push_arg (varxs, nargs, p);
	//ctxpush[context+nbrackets] = strdup(str); // use nargs??? (in callname)
}

static void rcc_element(char *str) {
	int num, num2;
	char *p = strrchr (str, ',');

	if (context) {
		nargs = 0;
		while (p) {
			*p = '\0';
			for (p=p+1; *p==' '; p=p+1);
			rcc_pusharg (p);
			p = strrchr (str, ',');
		}
		if (callname)
			rcc_pusharg (str);
		else
		if (mode == NORMAL) {
			if (!atoi (str)) {
				if (dstvar == NULL) /* return string */
					dstvar = strdup (".fix0");
				rcc_pushstr (str, 1);
			}
		}
	} else {
		switch (mode) {
		case ALIAS:
			emit->equ (dstvar, str);
			FREE (dstvar);
			mode = NORMAL;
			break;
		case SYSCALL:
			syscalls[nsyscalls].name = strdup (dstvar);
			syscalls[nsyscalls].arg = strdup (str);
			nsyscalls++;
			FREE (dstvar);
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
			emit->frame (stackframe+stackfixed);
		}
		elem[0] = 0;
		elem_n = 0;
	}
}

/* TODO: split this function into several ones..quite long fun */
static void rcc_next() {
	int i;
	char *p, buf[64];

	docall = 1;
	if (callname) {
		char *str, *ocn, *ptr = strchr (callname, '=');
		if (ptr) {
			*ptr = '\0';
			ocn = ptr+1;
		}
		for (ocn=callname; *ocn==' '; ocn++);
		str = mk_var (buf, ocn, 0);
		if (ocn[0]=='.')
			emit->call (str, 1);
		else
		if (!strcmp (str, "while")) {
			if (lastctxdelta>=0)
				exit (eprintf ("ERROR: Unsupported while syntax\n"));
			emit->while_end (get_frame_label (1));
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
					emit->comment ("set syscall args");
					emit->syscall_args (nargs);
					docall = 0;
					emit->comment ("syscall");
					parsechar ('\n'); /* FIX parsing issue */
					for (; *p; p++) parsechar (*p);
					docall = 0;
					break;
				}
			}
			if (docall)
			for (i=0; i<ninlines; i++) {
				if (!strcmp (str, inlines[i].name)) {
					p = inlines[i].body;
					docall = 0;
					emit->comment ("inline");
					parsechar ('\n'); /* FIX parsing issue */
					for (; *p; p++) parsechar (*p);
					docall = 0;
					break;
				}
			}
			if (docall) {
				emit->comment ("call in mode %d", mode);
				emit->call (str, 0);
			}
		}
		if (nargs>0)
			emit->restore_stack (nargs*emit->size);
		if (ocn) { // Used to call .var0()
			/* XXX: Probably buggy and wrong */
			*buf = 0;
			str = mk_var (buf, ocn, 0);
			if (*buf)
				emit->get_result (buf);
			//else { eprintf("external symbol %s\n", ocn); }
		}
		/* store result of call */
		if (dstvar) {
			*buf = 0;
			str = mk_var (buf, dstvar, 0);
			if (*buf == 0)
				eprintf ("Cannot resolve variable '%s'\n", dstvar);
			else emit->get_result (buf);
			FREE (dstvar);
		}
		FREE (callname);
		nargs = 0;
	} else {
		int vs = 'l';
		char type, *eq, *ptr = elem;
		elem[elem_n] = '\0';
		while (isspace (ptr[0])) ptr=ptr+1; /* skip spaces */
		if (*ptr) {
			eq = strchr (ptr, '=');
			if (eq) {
				char str2[64], *p, ch = *(eq-1);
				*eq = '\0';
				for (eq=eq+1; *eq==' '; eq++);
				p = mk_var (str2, ptr, 0);
				vs = varsize;
				if (IS_VAR (eq)) {
					eq = mk_var (buf, eq, 0);
					if (varxs=='*')
						emit->load (eq, varsize);
					else
					/* XXX this is a hack .. must be integrated with pusharg */
					if (varxs=='&')
						emit->load_ptr (eq);
					eq = NULL;
					type = ' ';
				} else type = '$';
				vs = 'l'; // XXX: add support for != 'l' size
				emit->mathop (ch, vs, type, eq, p);
			} else emit->mathop ('=', vs, '$', ptr, NULL);
		}
	}
}

static void rcc_context(int delta) {
	char str[64];

	context += delta;
	lastctxdelta = delta;
	if (context == 0 && delta < 0) {
		emit->frame_end (stackframe+stackfixed, nbrackets);
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
			emit->comment ("cond frame %s (%s)", callname, elem);
			/* TODO: simplify with a single for */
			b = strchr (elem, '<');
			g = strchr (elem, '>');
			e = strchr (elem, '=');
			n = strchr (elem, '!');
			if (strstr (callname, "while")) {
				emit->get_while_end (str,
					ctxpush[context-1],
					get_frame_label (2));
				free (endframe);
				endframe = strdup (str);
				free (callname);
				callname = strdup ("if");
			}
			if (strstr (callname, "if")) {
				emit->branch (b, g, e, n, varsize, get_end_frame_label ());
				if (context>0) {
					/* XXX .. */
				} else eprintf ("FUCKING CASE\n");
				FREE (callname);
			} else eprintf ("Unknown statement (%s)(%s)\n", callname, elem);
		}
	}
}

static int parseinlinechar(char c) {
	static int inlinectr = 0;

	/* skip until '{' */
	if (c == '{') { /* XXX: repeated code!! */
		rcc_context (1);
		inlinectr++;
		if (inlinectr==1)
			return 0;
	} else
	if (inlinectr == 0)
		return 0;

	/* capture body */
	if (c == '}') { /* XXX: repeated code!! */
		if (context < 2) {
			rcc_context (-1);
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
				inlines[ninlines].name = strdup (dstvar);
				inlines[ninlines].body = strdup (dstval);
				ninlines++;
				FREE (dstvar);
				FREE (dstval);
				return 1;
			} else eprintf ("FUCK FUCK\n");
		}
	}
	dstval[ndstval++] = c;
	return 0;
}

static int parsedatachar(char c) {
	static int inlinectr = 0;
	char *str;
	int i,j;

	/* skip until '{' */
	if (c == '{') { /* XXX: repeated code!! */
		rcc_context (1);
		if (++inlinectr==1)
			return (ndstval = 0);
	} else if (inlinectr == 0) {
		/* capture value between parenthesis foo@data(NNN) { ... } */
		if (c==')') {
			stackframe = atoi (dstval);
			ndstval=0;
		} else dstval[ndstval++] = c;
		return 0;
	}
	/* capture body */
	if (c == '}') { /* XXX: repeated code!! */
		if (context < 2) {
			inlinectr = 0;
			rcc_context (-1);
			slurp = 0;
			mode = NORMAL;
			/* register */
			if (dstval == NULL || dstvar == NULL) {
				eprintf ("FUCK FUCK\n");
			} else {
				dstval[ndstval]='\0';
				emit->comment ("data (%s)(%s)size=(%d)\n",
					dstvar, dstval, stackframe);
				rcc_printf (".data\n");
				for (str=dstval; isspace (*str); str++);
				j = (stackframe)? stackframe:1;
				/* emit label */
				rcc_printf ("%s:\n", dstvar);
				for(i=1;i<=j;i++) {
					if (str[0]=='"')
						rcc_printf(".ascii %s%s\n", dstval, (i==j)?"\"\\x00\"":"");
					else rcc_printf (".long %s\n", dstval);
				}
				rcc_printf(".text\n");
				FREE (dstvar);
				FREE (dstval);
				ndstval = 0;
				context = 0;
				return 1;
			}
		}
	}
	dstval[ndstval++] = c;
	return 0;
}

static int parsechar(char c) {
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
		return parsedatachar (c);
	if (mode == INLINE)
		return parseinlinechar (c);
	/* quotes */
	if (quoteline) {
		if (c != quoteline) {
			if (quotelinevar == 1) {
				if (c == '`') {
					elem[elem_n] = 0;
					elem_n = 0;
					rcc_printf ("%s", mk_var (str, elem, 0));
					quotelinevar = 0;
				} else elem[elem_n++] = c;
			} else {
				if (c == '`') {
					elem_n = 0;
					quotelinevar = 1;
				} else rcc_printf ("%c", c);
			}
			return 0;
		} else {
			rcc_printf ("\n");
			quoteline = 0;
		}
	}

	if(commentmode) {
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
				rcc_element (elem);
			else emit->frame (0);
			elem_n = 0;
		} else elem[elem_n++] = c;
		elem[elem_n] = '\0';
	} else {
		switch (c) {
		case ';':
			rcc_next ();
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
				rcc_printf (" %s:\n", get_frame_label (0));
			rcc_context (1);
			break;
		case '}':
			if (endframe) {
				// XXX: use endframe[context]
				rcc_printf ("%s\n", endframe);
				FREE (endframe);
			}
			if (context>0) {
				rcc_printf ("  %s:\n", get_end_frame_label ());
				nbrackets++;
			}
			rcc_context (-1);
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
				rcc_fun (ptr);
			}
			elem_n = 0;
		}
	}
	if (c!='\t' && c!=' ')
		oc = c;
	return 0;
}

static void showhelp() {
	fprintf (stderr,
		"Usage: r2rc [-alh] [files] > file.S\n"
		"  -s      use at&t syntax instead of intel\n"
		"  -m      add 'call main prefix\n"
		"  -h      display this help\n"
		"  -A      show default architecture\n"
		"  -a      list all supported architectures\n"
		"  -ax86  use x86-32\n"
		"  -ax64  use x86-64\n"
		"  -aarm  use ARM\n");
}

static void parseflag(const char *arg) {
	int i;
	switch (*arg) {
	case 'a':
		if (arg[1]) {
			emit = NULL;
			for (i=0; emits[i]; i++)
				if (!strcmp (emits[i]->arch, arg+1)) {
					emit = emits[i];
					syscallbody = emit->syscall ();
					break;
				}
			if (emit == NULL) {
				eprintf ("Invalid architecture: '%s'\n", arg+1);
				exit (1);
			}
		} else {
			for (i=0; emits[i]; i++)
				printf ("%s\n", emits[i]->arch);
			exit (0);
		}
		break;
	case 'm':
		showmain = 1;
		break;
	case 's':
		attsyntax = 1;
		break;
	case 'A':
		printf ("%s\n", emit->arch);
		exit (0);
	case 'h':
		showhelp ();
		exit (0);
	default:
		eprintf ("Unknown flag '%c'\n", *arg);
	}
}

int main(int argc, char **argv) {
	int once=0, i, fd = 0;
	char ch;
	rcc_init ();
	for (i=1;i<argc;i++) {
		if (argv[i][0]=='-')
			parseflag (argv[i]+1);
		else break;
	}
	do {
		if (i!=argc)
			fd = open ((file=argv[i++]), O_RDONLY);
		if (fd == -1) {
			eprintf ("Cannot open '%s'.\n", file);
			return 1;
		}
		if (!once) {
			once++;
			if (!attsyntax && (emit==&emit_x86 || emit==&emit_x64))
				rcc_printf (".intel_syntax noprefix\n");
			if (showmain) {
				emit->call ("main", 0);
				emit->trap ();
			}
		}
		for (line=1; read (fd, &ch, 1)==1; )
			parsechar (ch);
		close (fd);
	} while (i<argc);
	if (commentmode) {
		eprintf("ERROR: non-closed /**/ comment\n");
		return 1;
	}
	rcc_flush ();
	return 0;
}
