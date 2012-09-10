/* exptree.c: Copyright (C) 2011 by Brian Raiter <breadbox@muppetlabs.com>
 * License GPLv2+: GNU GPL version 2 or later.
 * This is free software; you are free to change and redistribute it.
 * There is NO WARRANTY, to the extent permitted by law.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "gen.h"
#include "error.h"
#include "symset.h"
#include "pplex.h"
#include "exptree.h"

/* The different types of expressions.
 */
enum exp
{
    expNone = 0,
    expConstant,		/* a literal constant */
    expMacro,			/* a simple macro identifier */
    expParamMacro,		/* a function-like macro */
    expDefined,			/* a defined operator with an identifier */
    expOperator			/* a C operator with 1-3 subexpressions */
};

/* The different operators available in the C preprocessor. Unary
 * prefix operators are listed first, after which are listed the infix
 * operators.
 */
enum op
{
    opNone = 0,
    opLogNot, opBitNot, opPositive, opNegative,
    opPrefixCount,
    opLeftShift = opPrefixCount, opRightShift, opEqual, opInequal,
    opLogAnd, opLogOr, opMultiply, opDivide, opModulo,
    opGreater, opLesser, opGreaterEqual, opLesserEqual,
    opAdd, opSubtract, opBitAnd, opBitXor, opBitOr,
    opConditional, opComma,
    opCount
};

/* The representation of a parsed expresssion tree.
 */
struct exptree {
    char const	   *begin;	/* start of the expression in the source */
    char const     *end;	/* end of the expression */
    int		    valued;	/* true if it has a definite value */
    long	    value;	/* the expression's value, if it has one */
    enum exp	    exp;	/* the type of expression */
    enum op	    op;		/* the operator for this expression, if any */
    char const	   *identifier;	/* the identifer, for the defined operator */
    int		    childcount;	/* how many subexpressions are present */
    struct exptree *child[4];	/* pointers to the subexpressions */
};

/*
 * The tables of operator precedence and associativity.
 */

struct opinfo {
    enum op	    op;		/* the operator */
    char const     *symbol;	/* the operator's representation */
    int		    size;	/* length of the representation string */
    int		    prec;	/* the precedence, from 1 to 14 inclusive */
    int		    l2r;	/* true if associativity is left-to-right */
};

static struct opinfo const prefixops[] = {
    { opLogNot,       "!",  1, 14, FALSE },
    { opBitNot,       "~",  1, 14, FALSE },
    { opPositive,     "+",  1, 14, FALSE },
    { opNegative,     "-",  1, 14, FALSE }
};

static struct opinfo const infixops[] = {
    { opLeftShift,    "<<", 2, 11, TRUE  },
    { opRightShift,   ">>", 2, 11, TRUE  },
    { opEqual,        "==", 2,  9, TRUE  },
    { opInequal,      "!=", 2,  9, TRUE  },
    { opLesserEqual,  "<=", 2, 10, TRUE  },
    { opGreaterEqual, ">=", 2, 10, TRUE  },
    { opLogAnd,       "&&", 2,  5, TRUE  },
    { opLogOr,        "||", 2,  4, TRUE  },
    { opMultiply,      "*", 1, 13, TRUE  },
    { opDivide,        "/", 1, 13, TRUE  },
    { opModulo,        "%", 1, 13, TRUE  },
    { opGreater,       "<", 1, 10, TRUE  },
    { opLesser,        ">", 1, 10, TRUE  },
    { opAdd,	       "+", 1, 12, TRUE  },
    { opSubtract,      "-", 1, 12, TRUE  },
    { opBitAnd,        "&", 1,  8, TRUE  },
    { opBitOr,	       "|", 1,  6, TRUE  },
    { opBitXor,        "^", 1,  7, TRUE  },
    { opConditional,   "?", 1,  3, FALSE },
    { opComma,	       ",", 1,  1, TRUE  }
};

/* Allocates an expression tree.
 */
struct exptree *initexptree(void)
{
    struct exptree *t;

    t = allocate(sizeof *t);
    t->childcount = 0;
    t->exp = expNone;
    t->valued = FALSE;
    t->begin = NULL;
    t->end = NULL;
    return t;
}

/* Deallocates the expression tree.
 */
void freeexptree(struct exptree *t)
{
    int n;

    if (t) {
	for (n = 0 ; n < t->childcount ; ++n)
	    freeexptree(t->child[n]);
	deallocate(t);
    }
}

/* Resets an expression tree to be empty.
 */
void clearexptree(struct exptree *t)
{
    t->childcount = 0;
    t->exp = expNone;
    t->valued = FALSE;
    t->begin = NULL;
    t->end = NULL;
}

/* Returns the length of the C source representing the expression.
 */
int getexplength(struct exptree const *t)
{
    return t->exp == expNone ? 0 : (int)(t->end - t->begin);
}

/* Inserts a subtree into the given expression tree, with pos being
 * the index of where to add the child branch.
 */
static int addchild(struct exptree *t, struct exptree *sub, int pos)
{
    int n;

    if (t->childcount == sizearray(t->child) || !sub)
	return FALSE;
    if (pos < -1 || pos > t->childcount)
	return FALSE;

    if (pos == -1 || pos == t->childcount) {
	t->child[t->childcount] = sub;
    } else {
	for (n = t->childcount ; n > pos ; --n)
	    t->child[n] = t->child[n - 1];
	t->child[pos] = sub;
    }
    ++t->childcount;
    return TRUE;
}

/* Creates and returns a new subtree, with pos being the index of
 * which child branch to insert the new subtree at.
 */
static struct exptree *addnewchild(struct exptree *t, int pos)
{
    struct exptree *child;

    child = initexptree();
    if (!addchild(t, child, pos)) {
	deallocate(child);
	return NULL;
    }
    return child;
}

/* Returns the value of the character literal pointed to by input.
 * This function does not check for invalid character constants, as
 * the lexer already takes care of that.
 */
static int getcharconstant(char const *input)
{
    int value, n;

    if (*input != '\\')
	return *input;

    ++input;
    if (*input >= '0' && *input <= '7') {
	value = 0;
	for (n = 0 ; n < 3 ; ++n) {
	    if (input[n] < '0' || input[n] > '7')
		break;
	    value = value * 8 + input[n] - '0';
	}
	return value;
    }

    if (*input == 'x') {
	value = 0;
	for (n = 1 ; n < 3 ; ++n) {
	    if (!isxdigit(input[n]))
		break;
	    value = value * 16 + (isdigit(input[n]) ? input[n] - '0' :
						tolower(input[n]) - 'a' + 10);
	}
	return value;
    }

    switch (*input) {
      case 'a':    return '\a';
      case 'b':    return '\b';
      case 'f':    return '\f';
      case 'n':    return '\n';
      case 'r':    return '\r';
      case 't':    return '\t';
      case 'v':    return '\v';
      default:     return *input;
    }
}

/* Reads a constant from the C source at input via the given lexer,
 * and uses it to initialize the expression tree. Literal numbers,
 * strings, characters, macro identifiers and function-like macro
 * invocations, and uses of the defined operator are all considered
 * constants by this function. The return value is the text following
 * the constant.
 */
static char const *parseconstant(struct exptree *t, struct pplex *cl,
				 char const *input)
{
    char *p;
    int size, paren, mark;

    mark = geterrormark();
    t->begin = input;
    if (charquotep(cl)) {
	t->exp = expConstant;
	t->valued = TRUE;
	t->value = getcharconstant(input + 1);
	while (!endoflinep(cl) && charquotep(cl))
	    input = nextchar(cl, input);
	t->end = input;
	input = skipwhite(cl, input);
    } else if (!memcmp(input, "defined", 7)) {
	t->exp = expDefined;
	input = skipwhite(cl, nextchars(cl, input, 7));
	paren = *input == '(';
	if (paren)
	    input = skipwhite(cl, nextchar(cl, input));
	size = getidentifierlength(input);
	if (!size) {
	    error(errDefinedSyntax);
	    goto failure;
	}
	t->identifier = input;
	input = nextchars(cl, input, size);
	if (paren) {
	    input = skipwhite(cl, input);
	    if (*input != ')') {
		error(errDefinedSyntax);
		goto failure;
	    }
	    input = nextchar(cl, input);
	}
	t->valued = FALSE;
	t->end = input;
	input = skipwhite(cl, input);
    } else if (isdigit(*input)) {
	t->exp = expConstant;
	if (*input == '0') {
	    input = nextchar(cl, input);
	    if (tolower(*input) == 'x') {
		do
		    input = nextchar(cl, input);
		while (isxdigit(*input));
	    } else {
		while (*input >= '0' && *input <= '7')
		    input = nextchar(cl, input);
	    }
	} else {
	    do
		input = nextchar(cl, input);
	    while (isdigit(*input));
	}
	t->value = strtol(t->begin, &p, 0);
	t->valued = p == input;
	if (toupper(*input) == 'L') {
	    input = nextchar(cl, input);
	    if (toupper(*input) == 'L')
		input = nextchar(cl, input);
	    if (toupper(*input) == 'U')
		input = nextchar(cl, input);
	} else if (toupper(*input) == 'U') {
	    input = nextchar(cl, input);
	    if (toupper(*input) == 'L') {
		input = nextchar(cl, input);
		if (toupper(*input) == 'L')
		    input = nextchar(cl, input);
	    }
	}
	t->end = input;
	input = skipwhite(cl, input);
    } else if (_issym(*input)) {
	do
	    input = nextchar(cl, input);
	while (_issym(*input));
	t->end = input;
	input = skipwhite(cl, input);
	if (*input == '(') {
	    t->exp = expParamMacro;
	    paren = getparenlevel(cl);
	    do {
		input = nextchar(cl, input);
		if (endoflinep(cl)) {
		    error(errOpenParenthesis);
		    goto failure;
		}
	    } while (getparenlevel(cl) >= paren);
	    t->valued = FALSE;
	    t->end = input;
	    input = skipwhite(cl, input);
	} else {
	    t->exp = expMacro;
	}
    } else {
	error(errSyntax);
	goto failure;
    }

    if (!errorsincemark(mark))
	return input;

  failure:
    t->exp = expNone;
    t->end = input;
    return input;
}

/* Parses a C preprocessor expression from the C source code pointed
 * to by input, via the given lexer, and creates a expression tree
 * representing it. prec gives the precedence of the operator this
 * expression is attached to, or zero if there is no such operator.
 * The return value points to the source immediately following the
 * parsed expression.
 */
static char const *parseexp(struct exptree *t, struct pplex *cl,
			    char const *input, int prec)
{
    struct exptree *x;
    char const *tmp;
    int found, n;

    if (t->exp != expNone)
	return input;

    if (*input == '(') {
	tmp = input;
	input = skipwhite(cl, nextchar(cl, input));
	input = parseexp(t, cl, input, 0);
	if (t->exp == expNone) {
	    error(errSyntax);
	    goto failure;
	} else if (*input != ')') {
	    error(errOpenParenthesis);
	    goto failure;
	}
	t->begin = tmp;
	input = nextchar(cl, input);
	t->end = input;
	input = skipwhite(cl, input);
    } else {
	found = FALSE;
	for (n = 0 ; n < sizearray(prefixops) ; ++n) {
	    if (!memcmp(input, prefixops[n].symbol, prefixops[n].size)) {
		found = TRUE;
		break;
	    }
	}
	if (found) {
	    if (prefixops[n].prec < prec) {
		error(errMissingOperand);
		goto failure;
	    }
	    t->exp = expOperator;
	    t->op = prefixops[n].op;
	    t->begin = input;
	    input = nextchars(cl, input, prefixops[n].size);
	    input = skipwhite(cl, input);
	    x = addnewchild(t, -1);
	    input = parseexp(x, cl, input, prefixops[n].prec);
	    if (x->exp == expNone) {
		error(errSyntax);
		goto failure;
	    }
	    t->end = x->end;
	} else {
	    input = parseconstant(t, cl, input);
	    if (t->exp == expNone) {
		error(errSyntax);
		goto failure;
	    }
	}
    }

    for (;;) {
	found = FALSE;
	for (n = 0 ; n < sizearray(infixops) ; ++n) {
	    if (!memcmp(input, infixops[n].symbol, infixops[n].size)) {
		found = TRUE;
		break;
	    }
	}
	if (!found || infixops[n].prec < prec
		   || (infixops[n].prec == prec && infixops[n].l2r))
	    break;
	input = nextchars(cl, input, infixops[n].size);
	input = skipwhite(cl, input);
	x = initexptree();
	tmp = t->begin;
	*x = *t;
	clearexptree(t);
	t->exp = expOperator;
	t->op = infixops[n].op;
	t->begin = tmp;
	addchild(t, x, -1);
	x = addnewchild(t, -1);
	if (t->op == opConditional) {
	    input = parseexp(x, cl, input, infixops[n].prec);
	    if (x->exp == expNone) {
		error(errSyntax);
		goto failure;
	    }
	    if (*input != ':') {
		error(errSyntax);
		goto failure;
	    }
	    input = skipwhite(cl, nextchar(cl, input));
	    x = addnewchild(t, -1);
	}
	input = parseexp(x, cl, input, infixops[n].prec);
	if (x->exp == expNone) {
	    error(errSyntax);
	    goto failure;
	}
	t->end = x->end;
    }
    return input;

  failure:
    t->exp = expNone;
    return input;
}

/* Parses a C preprocessor expression.
 */
char const *parseexptree(struct exptree *t, struct pplex *cl,
			 char const *input)
{
    return parseexp(t, cl, input, 0);
}

/* Recursively examines an expression tree and sets the definition
 * state of any identifiers within that appear in the given symset.
 * The third parameter indicates whether the identifiers are to be
 * treated as defined or as undefined.
 */
int markdefined(struct exptree *t, struct symset *set, int defined)
{
    long value;
    int count, n;

    count = 0;
    for (n = 0 ; n < t->childcount ; ++n)
	count += markdefined(t->child[n], set, defined);
    if (!t->valued) {
	if (t->exp == expDefined) {
	    if (findsymbolinset(set, t->identifier, NULL)) {
		t->valued = TRUE;
		t->value = defined ? 1 : 0;
		++count;
	    }
	} else if (t->exp == expMacro) {
	    if (findsymbolinset(set, t->begin, &value)) {
		t->valued = TRUE;
		t->value = defined ? value : 0;
		++count;
	    }
	}
    }
    return count;
}

/* Calculates the value of the parsed C preprocessor expression stored
 * in the given expression tree. defined receives true or false,
 * indicating whether or not the expression has a definite value. If
 * defined receives true, the actual value is returned.
 */
long evaltree(struct exptree *t, int *defined)
{
    long val1, val2;
    int valued;

    if (t->exp == expNone) {
	if (defined)
	    *defined = FALSE;
	return 0;
    }
    if (t->exp != expOperator) {
	if (defined)
	    *defined = t->valued;
	return t->valued ? t->value : 0;
    }

    if (t->op < opPrefixCount) {
	val1 = evaltree(t->child[0], &valued);
	if (valued) {
	    switch (t->op) {
	      case opLogNot:	val1 = !val1;	break;
	      case opBitNot:	val1 = ~val1;	break;
	      case opPositive:	val1 = +val1;	break;
	      case opNegative:	val1 = -val1;	break;
	      default:				break;
	    }
	}
	goto done;
    }
    val1 = evaltree(t->child[0], &valued);
    if (t->op == opComma) {
	val1 = evaltree(t->child[1], &valued);
	goto done;
    } else if (t->op == opConditional) {
	if (valued)
	    val1 = evaltree(t->child[val1 ? 1 : 2], &valued);
	goto done;
    } else if (t->op == opLogAnd) {
	if (valued) {
	    if (val1)
		val1 = evaltree(t->child[1], &valued);
	} else {
	    val1 = evaltree(t->child[1], &valued);
	    if (valued && val1)
		valued = FALSE;
	}
	goto done;
    } else if (t->op == opLogOr) {
	if (valued) {
	    if (!val1)
		val1 = evaltree(t->child[1], &valued);
	} else {
	    val1 = evaltree(t->child[1], &valued);
	    if (valued && !val1)
		valued = FALSE;
	}
	goto done;
    }
    if (!valued)
	goto done;

    val2 = evaltree(t->child[1], &valued);
    if (valued) {
	if (val2 == 0 && (t->op == opDivide || t->op == opModulo)) {
	    error(errZeroDiv);
	    valued = FALSE;
	    goto done;
	}
	switch (t->op) {
	  case opLeftShift:	val1 = val1 << (int)val2;	break;
	  case opRightShift:	val1 = val1 >> (int)val2;	break;
	  case opLesserEqual:	val1 = val1 <= val2;		break;
	  case opGreaterEqual:	val1 = val1 >= val2;		break;
	  case opEqual:		val1 = val1 == val2;		break;
	  case opInequal:	val1 = val1 != val2;		break;
	  case opMultiply:	val1 = val1 * val2;		break;
	  case opDivide:	val1 = val1 / val2;		break;
	  case opModulo:	val1 = val1 % val2;		break;
	  case opGreater:	val1 = val1 > val2;		break;
	  case opLesser:	val1 = val1 < val2;		break;
	  case opAdd:		val1 = val1 + val2;		break;
	  case opSubtract:	val1 = val1 - val2;		break;
	  case opBitAnd:	val1 = val1 & val2;		break;
	  case opBitXor:	val1 = val1 ^ val2;		break;
	  case opBitOr:		val1 = val1 | val2;		break;
	  default:						break;
	}
    }

  done:
    t->valued = valued;
    if (valued)
	t->value = val1;
    if (defined)
	*defined = valued;
    return defined ? val1 : 0;
}

/* Extracts from the expression tree those parts that do not have a
 * defined value, and "unparses" that back into a C preprocessor
 * expression, storing the resulting source code in buffer.
 */
int unparseevaluated(struct exptree const *t, char *buffer)
{
    char const *src;
    char *buf;
    size_t size;
    int n;

    if (t->exp == expNone)
	return 0;
    if (t->exp != expOperator) {
	if (t->valued) {
	    size = sprintf(buffer, "%ld", t->value);
	} else {
	    size = getexplength(t);
	    memcpy(buffer, t->begin, size);
	}
	return (int)size;
    }
    if (t->op == opConditional) {
	if (t->child[0]->valued)
	    return unparseevaluated(t->child[t->child[0]->value ? 1 : 2],
				    buffer);
    } else if (t->op == opLogAnd || t->op == opLogOr) {
	if (t->child[0]->valued)
	    return unparseevaluated(t->child[1], buffer);
	else if (t->child[1]->valued)
	    return unparseevaluated(t->child[0], buffer);
    }

    buf = buffer;
    src = t->begin;
    for (n = 0 ; n < t->childcount ; ++n) {
	size = t->child[n]->begin - src;
	if (size) {
	    memcpy(buf, src, size);
	    buf += size;
	}
	buf += unparseevaluated(t->child[n], buf);
	src = t->child[n]->end;
    }
    size = t->end - src;
    if (size) {
	memcpy(buf, src, size);
	buf += size;
    }
    return (int)(buf - buffer);
}
