/* ported to C by pancake for r2 in 2012-2017 */
// TODO: integrate floating point support
// TODO: do not use global variables
/*
   Reference Chapter 6:
   "The C++ Programming Language", Special Edition.
   Bjarne Stroustrup,Addison-Wesley Pub Co; 3 edition (February 15, 2000)
    ISBN: 0201700735
 */

#include <r_types.h>
#include <r_util.h>
#include <ctype.h>
#include <stdio.h>

/* accessors */
static inline RNumCalcValue Nset(ut64 v) { RNumCalcValue n; n.d = (double)v; n.n = v; return n; }
static inline RNumCalcValue Nsetf(double v) { RNumCalcValue n; n.d = v; n.n = (ut64)v; return n; }
//UNUSED static inline RNumCalcValue Naddf(RNumCalcValue n, double v) { n.d += v; n.n += (ut64)v; return n; }
static inline RNumCalcValue Naddi(RNumCalcValue n, ut64 v) { n.d += (double)v; n.n += v; return n; }
static inline RNumCalcValue Nsubi(RNumCalcValue n, ut64 v) { n.d -= (double)v; n.n -= v; return n; }
static inline RNumCalcValue Nneg(RNumCalcValue n) { n.n = ~n.n; return n; }
static inline RNumCalcValue Nor(RNumCalcValue n, RNumCalcValue v) { n.d = v.d; n.n |= v.n; return n; }
static inline RNumCalcValue Nxor(RNumCalcValue n, RNumCalcValue v) { n.d = v.d; n.n ^= v.n; return n; }
static inline RNumCalcValue Nand(RNumCalcValue n, RNumCalcValue v) { n.d = v.d; n.n &= v.n; return n; }
static inline RNumCalcValue Nadd(RNumCalcValue n, RNumCalcValue v) { n.d += v.d; n.n += v.n; return n; }
static inline RNumCalcValue Nsub(RNumCalcValue n, RNumCalcValue v) { n.d -= v.d; n.n -= v.n; return n; }
static inline RNumCalcValue Nmul(RNumCalcValue n, RNumCalcValue v) {
	n.d *= v.d;
	n.n *= v.n;
	return n;
}

static inline RNumCalcValue Nshl(RNumCalcValue n, RNumCalcValue v) { n.d += v.d; n.n <<= v.n; return n; }
static inline RNumCalcValue Nshr(RNumCalcValue n, RNumCalcValue v) { n.d += v.d; n.n >>= v.n; return n; }
static inline RNumCalcValue Nrol(RNumCalcValue n, RNumCalcValue v) {
	n.d += v.d;
	n.n = (n.n << v.n) | (n.n >> (sizeof(n.n) * 8 - v.n));
	return n;
}
static inline RNumCalcValue Nror(RNumCalcValue n, RNumCalcValue v) {
	n.d += v.d;
	n.n = (n.n >> v.n) | (n.n << (sizeof(n.n) * 8 - v.n));
	return n;
}
static inline RNumCalcValue Nmod(RNumCalcValue n, RNumCalcValue v) {
	if (v.d) {
		n.d = (n.d - (n.d / v.d));
	} else {
		n.d = 0;
	}
	if (v.n) {
		n.n %= v.n;
	} else {
		n.n = 0;
	}
	return n;
}

static inline RNumCalcValue Ndiv(RNumCalcValue n, RNumCalcValue v) {
	if (v.d) {
		n.d /= v.d;
	} else {
		n.d = 0;
	}
	if (v.n) {
		n.n /= v.n;
	} else {
		n.n = 0;
	}
	return n;
}

static RNumCalcValue expr(RNum*, RNumCalc*, int);
static RNumCalcValue term(RNum*, RNumCalc*, int);
static void error(RNum*, RNumCalc*, const char *);
static RNumCalcValue prim(RNum*, RNumCalc*, int);
static RNumCalcToken get_token(RNum*, RNumCalc*);

static void error(RNum *num, RNumCalc *nc, const char *s) {
	nc->errors++;
	nc->calc_err = s;
	//fprintf (stderr, "error: %s\n", s);
}

static RNumCalcValue expr(RNum *num, RNumCalc *nc, int get) {
	RNumCalcValue left = term (num, nc, get);
	for (;;) {
		switch (nc->curr_tok) {
		case RNCSHL: left = Nshl (left, term (num, nc, 1)); break;
		case RNCSHR: left = Nshr (left, term (num, nc, 1)); break;
		case RNCROL: left = Nrol (left, term (num, nc, 1)); break;
		case RNCROR: left = Nror (left, term (num, nc, 1)); break;
		case RNCPLUS: left = Nadd (left, term (num, nc, 1)); break;
		case RNCMINUS: left = Nsub (left, term (num, nc, 1)); break;
		case RNCXOR: left = Nxor (left, term (num, nc, 1)); break;
		case RNCOR: left = Nor (left, term (num, nc, 1)); break;
		case RNCAND: left = Nand (left, term (num, nc, 1)); break;
		default:
			return left;
		}
	}
	return left;
}

static RNumCalcValue term(RNum *num, RNumCalc *nc, int get) {
	RNumCalcValue left = prim (num, nc, get);
	for (;;) {
		if (nc->curr_tok == RNCMUL) {
			left = Nmul (left, prim (num, nc, 1));
		} else if (nc->curr_tok == RNCMOD) {
			RNumCalcValue d = prim (num, nc, 1);
			if (!d.d) {
				//error (num, nc, "divide by 0");
				return d;
			}
			left = Nmod (left, d);
		} else if (nc->curr_tok == RNCDIV) {
			RNumCalcValue d = prim (num, nc, 1);
			if (num != NULL && (!d.d || !d.n)) {
				num->dbz = 1;
				return d;
			}
			left = Ndiv (left, d);
		} else {
			return left;
		}
	}
}

static RNumCalcValue prim(RNum *num, RNumCalc *nc, int get) {
	RNumCalcValue v = {0};
	if (get) {
		get_token (num, nc);
	}
	switch (nc->curr_tok) {
	case RNCNUMBER:
		v = nc->number_value;
		get_token (num, nc);
		return v;
	case RNCNAME:
		//fprintf (stderr, "error: unknown keyword (%s)\n", nc->string_value);
		//double& v = table[nc->string_value];
		r_str_trim (nc->string_value);
		v = Nset (r_num_get (num, nc->string_value));
		get_token (num, nc);
		if (nc->curr_tok  == RNCASSIGN) {
			v = expr (num, nc, 1);
		}
		if (nc->curr_tok == RNCINC) {
			Naddi (v, 1);
		}
		if (nc->curr_tok == RNCDEC) {
			Nsubi (v, 1);
		}
		return v;
	case RNCNEG:
		get_token (num, nc);
		return Nneg (nc->number_value); //prim (num, nc, 1), 1);
	case RNCINC:
		return Naddi (prim (num, nc, 1), 1);
	case RNCDEC:
		return Naddi (prim (num, nc, 1), -1);
	case RNCOR:
		return Nor (v, prim (num, nc, 1));
	case RNCMINUS:
		return Nsub (v, prim (num, nc, 1));
	case RNCLEFTP:
		v = expr (num, nc, 1);
		if (nc->curr_tok == RNCRIGHTP) {
			get_token (num, nc);
		} else {
			error (num, nc, " ')' expected");
		}
	case RNCEND:
	case RNCXOR:
	case RNCAND:
	case RNCPLUS:
	case RNCMOD:
	case RNCMUL:
	case RNCDIV:
	case RNCPRINT:
	case RNCASSIGN:
	case RNCRIGHTP:
	case RNCSHL:
	case RNCSHR:
	case RNCROL:
	case RNCROR:
		return v;
	//default: error (num, nc, "primary expected");
	}
	return v;
}

static void cin_putback (RNum *num, RNumCalc *nc, char c) {
	nc->oc = c;
}

R_API const char *r_num_calc_index(RNum *num, const char *p) {
	if (!num) {
		return NULL;
	}
	if (p) {
		num->nc.calc_buf = p;
		num->nc.calc_len = strlen (p);
		num->nc.calc_i = 0;
	}
	return num->nc.calc_buf + num->nc.calc_i;
}

static int cin_get(RNum *num, RNumCalc *nc, char *c) {
	if (nc->oc) {
		*c = nc->oc;
		nc->oc = 0;
	} else {
		if (!nc->calc_buf || !*nc->calc_buf) {
			return 0;
		}
		*c = nc->calc_buf[nc->calc_i];
		if (*c) {
			nc->calc_i++;
		} else {
			return 0;
		}
	}
	return 1;
}

static int cin_get_num(RNum *num, RNumCalc *nc, RNumCalcValue *n) {
	double d;
	char str[R_NUMCALC_STRSZ + 1]; // TODO: move into the heap?
	int i = 0;
	char c;
	str[0] = 0;
	while (cin_get (num, nc, &c)) {
		if (c != '_' && c != ':' && c != '.' && !isalnum ((ut8)c)) {
			cin_putback (num, nc, c);
			break;
		}
		if (i < R_NUMCALC_STRSZ) {
			str[i++] = c;
		}
	}
	str[i] = 0;
	*n = Nset (r_num_get (num, str));
	if (IS_DIGIT (*str) && strchr (str, '.')) {
		if (sscanf (str, "%lf", &d) < 1) {
			return 0;
		}
		if (n->n < d) {
			*n = Nsetf (d);
		}
		n->d = d;
	}
	return 1;
}

static RNumCalcToken get_token(RNum *num, RNumCalc *nc) {
	char ch = 0, c = 0;

	do {
		if (!cin_get (num, nc, &ch)) {
			return nc->curr_tok = RNCEND;
		}
	} while (ch != '\n' && isspace ((ut8)ch));

	switch (ch) {
	case 0:
	case ';':
	case '\n':
		return nc->curr_tok = RNCEND;
	case '+':    // added for ++name and name++
		if (cin_get (num, nc, &c) && c == '+') {
			return nc->curr_tok = RNCINC;
		}
		cin_putback (num, nc, c);
		return nc->curr_tok = (RNumCalcToken) ch;
	// negate hack
	case '~':
		if (cin_get (num, nc, &c) && c == '-') {
			return nc->curr_tok = RNCNEG;
		}
		cin_putback (num, nc, c);
		return nc->curr_tok = (RNumCalcToken) ch;
	// negative number
	case '-':
		if (cin_get (num, nc, &c) && c == '-') {
			return nc->curr_tok = RNCDEC;
		}
		cin_putback (num, nc, c);
		return nc->curr_tok = (RNumCalcToken) ch;
	case '<':
		if (cin_get (num, nc, &c) && c == '<') {
			if (cin_get (num, nc, &c) && c == '<') {
				return nc->curr_tok = RNCROL;
			}
			cin_putback (num, nc, c);
			return nc->curr_tok = RNCSHL;
		}
		cin_putback (num, nc, c);
		return nc->curr_tok = RNCEND;
	case '>':
		if (cin_get (num, nc, &c) && c == '>') {
			if (cin_get (num, nc, &c) && c == '>') {
				return nc->curr_tok = RNCROR;
			}
			cin_putback (num, nc, c);
			return nc->curr_tok = RNCSHR;
		}
		cin_putback (num, nc, c);
		return nc->curr_tok = RNCEND;
	case '^':
	case '&':
	case '|':
	case '*':
	case '%':
	case '/':
	case '(':
	case ')':
	case '=':
		return nc->curr_tok = (RNumCalcToken) ch;
	case '0': case '1': case '2': case '3': case '4':
	case '5': case '6': case '7': case '8': case '9':
	case '.':
		cin_putback (num, nc, ch);
		if (!cin_get_num (num, nc, &nc->number_value)) {
			error (num, nc, "invalid number conversion");
			return 1;
		}
		return nc->curr_tok = RNCNUMBER;

#define isvalidchar(x) \
	(isalnum(x) || (x)==':' || (x)=='$' || (x)=='.' || (x)=='_' || (x)=='?' || (x)=='\\' \
	|| (x)==' ' || (x)=='[' || (x)==']' || (x)=='}' || (x)=='{' || ((x)>='0'&&(x)<='9'))

	default:
		{
			int i = 0;
#define stringValueAppend(x) { \
	const size_t max = sizeof (nc->string_value) - 1; \
	if (i < max) nc->string_value[i++] = x; \
	else nc->string_value[max] = 0; \
}
			stringValueAppend(ch);
			if (ch == '[') {
				while (cin_get (num, nc, &ch) && ch!=']') {
					if (i > R_NUMCALC_STRSZ - 1) {
						error (num, nc, "string too long");
						return 0;
					}
					stringValueAppend(ch);
				}
				stringValueAppend(ch);
			} else {
				while (cin_get (num, nc, &ch) && isvalidchar ((unsigned char)ch)) {
					if (i >= R_NUMCALC_STRSZ) {
						error (num, nc, "string too long");
						return 0;
					}
					stringValueAppend(ch);
				}
			}
			stringValueAppend(0);
			if (ch!='\'') {
				cin_putback (num, nc, ch);
			}
			return nc->curr_tok = RNCNAME;
		}
	}
}

static void load_token(RNum *num, RNumCalc *nc, const char *s) {
	nc->calc_i = 0;
	nc->calc_len = strlen (s);
	nc->calc_buf = s;
	nc->calc_err = NULL;
}

R_API ut64 r_num_calc(RNum *num, const char *str, const char **err) {
	RNumCalcValue n;
	RNumCalc *nc, nc_local;
	if (!str || !*str) {
		return 0LL;
	}
	if (num) {
		nc = &num->nc;
		num->dbz = 0;
	} else {
		nc = &nc_local;
	}
	/* init */
	nc->curr_tok = RNCPRINT;
	nc->number_value.d = 0.0;
	nc->number_value.n = 0LL;
	nc->errors = 0;
	nc->oc = 0;
	nc->calc_err = NULL;
	nc->calc_i = 0;
	nc->calc_len = 0;
	nc->calc_buf = NULL;
	nc->under_calc = true;

	load_token (num, nc, str);
	get_token (num, nc);
	n = expr (num, nc, 0);
	if (err) {
		*err = nc->calc_err;
	}
	if (num) {
		num->fvalue = n.d;
	}
	nc->under_calc = false;
	return n.n;
}

#ifdef TEST
int main(int argc, char* argv[]) {
	RNumCalcValue n;
	RNumCalc nc;
	while (!feof (stdin)) {
		get_token (nc);
		if (nc.curr_tok == RNCEND) {
			break;
		}
		if (nc.curr_tok == RNCPRINT) {
			continue;
		}
		n = expr (num, nc, 0);
		if (n.d == ((double)(int)n.d)) {
			printf ("%llx\n", n.n);
		} else {
			printf ("%lf\n", n.d);
		}
	}
	return nc->errors;
}
#endif
