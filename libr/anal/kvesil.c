/* radare - LGPL - Copyright 2014 - pancake */
#include <r_anal.h>
#include <stdio.h>

static const char *chstr(int ch) {
	switch (ch) {
	case '!': return "not";
	case '[': return "mem";
	case '=': return "set";
	case '+': return "add";
	case '-': return "sub";
	case '*': return "mul";
	case '/': return "div";
	case '&': return "and";
	case '^': return "xor";
	case '|': return "orr";
	case '>': return "shr";
	case '<': return "shl";
	}
	return "?";
}

R_API char *r_anal_esil_to_sdb(char *str) {
// tokenize string 
#define TOK_NEW(x,y) (x<<24|(y+1))
#define TOK_OP(x) (x>>24)
#define TOK_ARG(x) str+(x&0xffffff)
	char *p = str;
	int tok[4096], i = 0, t = 0;
	tok[0] = 0;
	for (i=0; p[i]; i++) {
		char ch = p[i];
		switch (ch) {
		case '[': // TODO
		case ']': // TODO
		case '!':
		case ',':
		case ';':
		case '(':
		case ')':
		case '<':
		case '>':
		case '*':
		case '+':
		case '-':
		case '/':
		case '=':
			p[i] = 0;
			tok[t++] = TOK_NEW(ch, i);
			break;
		}
	}
// build sdb
	{
		char *a = str;
		char *b;
		int idx = 0;
		int top = 0;
		int level = 0;
		int stack[32];
		int store = 0;
		stack[0] = 0;
		for (i=0; i<t; i++) {
			char op = TOK_OP(tok[i]);
			b = TOK_ARG(tok[i]);
			switch (op) {
			case ',':
			case ';':
				idx = 0;
				stack[0] = 0;
				level = 0;
				a = TOK_ARG (tok[i]);
				continue;
			case '=':
				if (TOK_OP (tok[i+1])=='=') {
					printf ("TODO: cmp\n");
					return NULL;
				}
				break;
			case '(':
				level++;
				if (level>=(sizeof(stack)/sizeof(*stack))) {
					printf ("ERROR: too many open parenthesis\n");
					return NULL;
				}
				stack[level] = i;
				a = TOK_ARG(tok[i]);
				continue;
			case ')':
				level--;
				if (level<0) {
					printf ("ERROR: too many closing parenthesis\n");
					return NULL;
				}
				top = stack[level];
				continue;
			default:
				if ( TOK_OP(tok[i+1]) == '=') {
			//		printf ("TODO: %c= syntax sugar not yet supported\n", op);
					//printf ("[]%d=%s,%s,&%d\n", idx, "str", a, idx);
a="&0";
					store = 0;
					continue;
				}
			}
			if (store) {
				if (op=='=') {
eprintf ("SET\n");
					op='[';
				}
				store = 0;
			}
			//if (!a || (!*a) || *a==' ')
			//if (*a==' ') a ="8"; // for mem ref only
			if (*b) printf ("[]%d=%s,%s,%s\n", idx, chstr (op), a, b);
			else   printf ("[]%d=%s,%s,&%d\n", idx, chstr (op), a, idx+1);
			a = b;
			stack[level] = top = idx;
			if (i>0) {
				int sl = stack[level];
				if (sl>0) 
					printf ("[2]%d=&%d\n", sl-1, idx);
				stack[level] = top = idx;
			}
			idx++;
		}
	}
	return NULL;
}

#if 0
char *kvesil(char *str) {
	char *a, *b, *o, *p;
	char expect_arg = 0;
	int idx = 0, level = 0;
	b = 0;
eprintf ("(((%s)))\n", str);
	for (a=o=p=str;*p;p++) {
		char ch = *p;
printf ("= %c\n", ch);
		switch (ch) {
		case ';':
			a = NULL;
			b = NULL;
			expect_arg = 0;
			level = 0;
			break;
		case '(':
*p = 0;
			level++;
			break;
		case ')':
*p = 0;
			printf ("[]%d=%s,%s,$%d\n",
				idx, chstr (expect_arg), a, idx+1);
			level--;
			break;
		case '=':
			*p = 0;
			if (p[1]=='=') {
				// comparison
				printf ("TODO: cmp\n");
				break;
			}
		case '+':
		case '-':
		case '*':
		case '/':
			*p = 0;
			if (expect_arg) {
				printf ("[]%d=%s,%s,%s\n",
					idx, chstr (ch), a, b);
				idx++;
				a = p+1;
printf ("set\n");
				expect_arg = 0;
			} else {
printf ("zet\n");
/*
				printf ("[]%d=%s,%s,$%d\n",
					idx, chstr (ch), a, idx+1);
*/
				b = p+1;
				expect_arg = ch;
			}
				idx++;
			break;
		}
	}
	if (expect_arg) {
		if (!b || !*b) {
			printf ("Invalid expression\n");
			return NULL;
		} else {
			printf ("[]%d=%s,%s,%s\n",
				idx, chstr (expect_arg), a, b);
		}
	}
	return "";
}
#endif

#if USE_MAIN
int main(int argc, char **argv) {
	if (argc>1)
		esil_tokenize(argv[1]);
		//printf ("%s\n", kvesil (argv[1]));
	return 0;
}

#endif
