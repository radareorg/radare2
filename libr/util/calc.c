/* ported to C by pancake for r2 in 2012 */
// TODO: integrate floating point support
// TODO: do not use global variables
/*
   Reference Chapter 6:
   "The C++ Programming Language", Special Edition.
   Bjarne Stroustrup,Addison-Wesley Pub Co; 3 edition (February 15, 2000) 
    ISBN: 0201700735 
 */


#include <r_util.h>
#include <ctype.h>
#include <stdio.h>
#include <unistd.h>

/* TODO: move into libr/include */
#ifndef ut64
#define ut64 unsigned long long
#endif

typedef struct {
	double d;
	ut64 n;
} NumValue;

typedef enum {
	NAME, NUMBER, END, INC, DEC,
	PLUS='+', MINUS='-', MUL='*', DIV='/',
	//XOR='^', OR='|', AND='&',
	PRINT=';', ASSIGN='=', LEFTP='(', RIGHTP=')'
} RNumToken;

/* accessors */
static inline NumValue Nset(ut64 v) { NumValue n; n.d = (double)v; n.n = v; return n; }
static inline NumValue Nsetf(double v) { NumValue n; n.d = v; n.n = (ut64)v; return n; }
static inline NumValue Naddf(NumValue n, double v) { n.d += v; n.n += (ut64)v; return n; }
static inline NumValue Naddi(NumValue n, ut64 v) { n.d += (double)v; n.n += v; return n; }
static inline NumValue Nsubi(NumValue n, ut64 v) { n.d -= (double)v; n.n -= v; return n; }
static inline NumValue Nadd(NumValue n, NumValue v) { n.d += v.d; n.n += v.n; return n; }
static inline NumValue Nsub(NumValue n, NumValue v) { n.d -= v.d; n.n -= v.n; return n; }
static inline NumValue Nmul(NumValue n, NumValue v) { n.d *= v.d; n.n *= v.n; return n; }
static inline NumValue Ndiv(NumValue n, NumValue v) {
	if (v.d) n.d /= v.d; else n.d = 0;
	if (v.n) n.n /= v.n; else n.n = 0;
	return n;
}

static NumValue expr(int);
static NumValue term(int);
static void error(const char *);
static NumValue prim(int);
static RNumToken get_token();
static RNum *calc_num = NULL;

/* global shit */
#define STRSZ 128
static RNumToken curr_tok = PRINT;
static NumValue number_value = { 0 };
static char string_value[STRSZ];
static int errors = 0;
static char oc = 0;
static const char *calc_err = NULL;

static void error(const char *s) {
	errors++;
	calc_err = s;
	//fprintf (stderr, "error: %s\n", s);
}

static NumValue expr(int get) {
	NumValue left = term (get);
	for (;;) {
		if (curr_tok == PLUS)
			left = Nadd (left, term (1));
		else
		if (curr_tok == MINUS)
			left = Nsub (left, term (1));
		else return left;
	}
}

static NumValue term(int get) {
	NumValue left = prim (get);
	for (;;) {
		if (curr_tok == MUL) {
			left = Nmul (left, prim (1));
		} else
		if (curr_tok == DIV) {
			NumValue d = prim (1);
			if (!d.d) {
				error ("divide by 0");
				return d;
			}
			left = Ndiv (left, d);
		} else return left;
	}
}

static NumValue prim(int get) {
	NumValue v = {0};
	if (get) get_token ();
	switch (curr_tok) {
	case NUMBER:
		v = number_value;
		get_token ();
		return v;
	case NAME:
		//fprintf (stderr, "error: unknown keyword (%s)\n", string_value);
		//double& v = table[string_value];
		r_str_chop (string_value);
		v = Nset (r_num_get (calc_num, string_value));
		get_token ();
		if (curr_tok  == ASSIGN) 
			v = expr (1);
		if (curr_tok == INC) Naddi (v, 1);
		if (curr_tok == DEC) Nsubi (v, 1);
		return v;
	case INC: return Naddi (prim (1), 1);
	case DEC: return Naddi (prim (1), -1);
	case MINUS: return Nsub (v, prim (1));
	case LEFTP:
		v = expr (1);
		if (curr_tok == RIGHTP)
			get_token ();
		else error (" ')' expected");
	case END:
	case PLUS:
	case MUL:
	case DIV:
	case PRINT:
	case ASSIGN:
	case RIGHTP:
		return v;
	//default: error ("primary expected");
	}
	return v;
}

static void cin_putback (char c) {
	oc = c;
}

static int calc_i = 0;
static const char *calc_buf = NULL;

R_API const char *r_num_calc_index (const char *p) {
	if (p) {
		calc_buf = p;
		calc_i = 0;
	}
	return calc_buf +calc_i;
}

static int cin_get(char *c) {
	if (oc) {
		*c = oc;
		oc = 0;
	} else {
		if (!calc_buf)
			return 0;
		*c = calc_buf[calc_i];
		if (*c) calc_i++;
		else return 0;
	}
	return 1;
}

static int cin_get_num(NumValue *n) {
	double d;
	char str[128];
	int i = 0;
	char c;
	str[0] = 0;
	while (cin_get (&c)) {
		if (c!=':' && c!='.' && !isalnum (c)) {
			cin_putback (c);
			break;
		}
		if (i<STRSZ)
			str[i++] = c;
	}
	str[i] = 0;
	*n = Nset (r_num_get (calc_num, str));
	if (*str>='0' && *str<='9' && strchr (str, '.')) {
		if (sscanf (str, "%lf", &d)<1)
			return 0;
		*n = Nsetf (d);
	}
#if 0
// XXX: use r_num_get here
	if (str[0]=='0' && str[1]=='x') {
		ut64 x = 0;
		if (sscanf (str+2, "%llx", &x)<1)
			return 0;
		*n = Nset (x);
	} else
	if (strchr (str, '.')) {
		if (sscanf (str, "%lf", &d)<1)
			return 0;
		*n = Nsetf (d);
	} else {
		ut64 u;
		if (sscanf (str, "%"PFMT64d, &u)<1)
			return 0;
		*n = Nset (u);
	}
#endif
	return 1;
}

static RNumToken get_token() {
	char c, ch;

	do { if (!cin_get (&ch)) return curr_tok = END;
	} while (ch!='\n' && isspace (ch));

	switch (ch) {
	case 0:
	case ';':
	case '\n':
		return curr_tok = END;
	case '+':    // added for ++name and name++
		if (cin_get (&c) && c == '+')
			return curr_tok = INC;
		cin_putback (c);
		return curr_tok = (RNumToken) ch;
	case '-':
		if (cin_get (&c) && c == '-')
			return curr_tok = DEC;
		cin_putback (c);
		return curr_tok = (RNumToken) ch;
	case '*':
	case '/':
	case '(':
	case ')':
	case '=':
		return curr_tok = (RNumToken) ch;
	case '0':case '1': case '2': case '3': case '4':
	case '5': case '6': case '7': case '8': case '9':
	case '.':
		cin_putback (ch);
		if (!cin_get_num (&number_value)) {
			error ("invalid number conversion");
			return 1;
		}
		return curr_tok = NUMBER;
	default:
#define isvalidchar(x) \
	(isalnum(x) || x==':' || x=='$' || x=='.' || x=='_' || x=='?' || x=='\\' \
	|| x==' ' || x=='[' || x==']' || x=='}' || x=='{' || x=='/' || (x>='0'&&x<='9'))
{
			int i = 0;
			string_value[i++] = ch;
			if (ch == '[') {
				while (cin_get (&ch) && ch!=']') {
					if (i>=STRSZ) {
						error ("string too long");
						return 0;
					}
					string_value[i++] = ch;
				}
				string_value[i++] = ch;
			} else {
				while (cin_get (&ch) && isvalidchar (ch)) {
					if (i>=STRSZ) {
						error ("string too long");
						return 0;
					}
					string_value[i++] = ch;
				}
			}
			string_value[i] = 0;
			cin_putback (ch);

			return curr_tok = NAME;
}
		//}
		error ("bad token");
		return curr_tok = PRINT;
	}
}

static void load_token(const char *s) {
	calc_i = 0;
	calc_buf = s;
	calc_err = NULL;
}

R_API ut64 r_num_calc (RNum *num, const char *str, const char **err) {
	NumValue n;
	if (!*str)
		return 0LL;
	calc_num = num;
	load_token (str);
	get_token ();
	n = expr (0);
	if (err) *err = calc_err;
	//if (curr_tok == END) return 0LL; // XXX: Error
	//if (curr_tok == PRINT) //return 0LL; // XXX: the fuck
	//	n = expr (0);
	if (n.d != ((double)(ut64)n.d)) {
		if (num) num->fvalue = n.d;
	} else if (num) num->fvalue = (double)n.n;
	return n.n;
}

#ifdef TEST
int main(int argc, char* argv[]) {
	NumValue n;
	while (!feof (stdin)) {
		get_token ();
		if (curr_tok == END) break;
		if (curr_tok == PRINT) continue;
		n = expr (0);
		if (n.d == ((double)(int)n.d))
			printf ("%llx\n", n.n);
		else printf ("%lf\n", n.d);
	}
	return errors;
}
#endif
