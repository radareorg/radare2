/* radare - LGPL - Copyright 2013 - pancake */

#include <r_anal.h>
#include <r_types.h>

#define NARGS 64
typedef struct r_anal_code_t {
	ut64 (*num)(struct r_anal_code_t *c, const char *str);
	int (*iterate)(struct r_anal_code_t *c, char *buf, int *tkns);
} RAnalCode;

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

static int r_anal_code (RAnalCode *c, const char *str) {
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

int iterate (RAnalCode *c, char *buf, int *tkns) {
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

#define TOKEN_IS(x,y,z) (x[i]==y && !strcmp (x[i+1]==z))
#define TOKEN_GET(x,y) x=tkns[i]; y=buf+tkns[i+1]

int emulate (RAnalCode *c, char *buf, int *tkns) {
	ut64 num = 0;
	char *op = NULL;
	char *str;
	int i, type;
	for (i=0; tkns[i]; i+=2) {
		TOKEN_GET (type, str);
		eprintf ("(%d) (%s)\n", type, str);
		switch (type) {
		// case 0 handled in for conditional
		case 4:
			op = NULL;
eprintf (";;; COMMIT\n");
			break;
		case 1: /* special command */
			if (!strcmp (str, "[")) {
				// TODO: test for size
				printf  ("   SET (size %d)\n", (int)num);
				// read tokens until ']'
				// TOKEN_UNTIL (1, "]");
				for (i+=2; tkns[i]; i+=2) {
					TOKEN_GET (type, str);
					eprintf ("--- %d (%s)\n", tkns[i], buf+tkns[i+1]);
					if (tkns[i] == 1) {
						if (!strcmp (str, "]")) {
							printf ("  OP IS WRITE MEMORY\n");
							// set destination for write
break;
// expect '='
						}
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
			if (!strcmp (str, "=")) {
				eprintf ("EQUAL\n");
			}
			op = str;
			break;
		case 3:
			num = c->num (c, str); // 
			break;
		}
	}
	eprintf (";;; COMMIT\n");
	return 0;
}

ut64 num(struct r_anal_code_t *c, const char *str) {
	return r_num_get (NULL, str);
}

#define C(x) r_anal_code(&c,x)

#ifdef MAIN
int main() {
	RAnalCode c = {
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

R_API int r_anal_code_eval(RAnal *anal, const char *str) {
	RAnalCode c = {
		.num = num,
		.iterate = emulate //iterate
	};
	C (str);
	return 0;
}

