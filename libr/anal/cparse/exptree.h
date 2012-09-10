/* exptree.h: Copyright (C) 2011 by Brian Raiter <breadbox@muppetlabs.com>
 * License GPLv2+: GNU GPL version 2 or later.
 * This is free software; you are free to change and redistribute it.
 * There is NO WARRANTY, to the extent permitted by law.
 */
#ifndef	_exptree_h_
#define	_exptree_h_

/*
 * An expression tree parses and, where possible, evaluates C
 * preprocessor expressions. A parsed expression can then be evaluated
 * and to a limited degree edited.
 */

struct exptree;
struct symset;
struct pplex;

/* Allocates an expression tree.
 */
extern struct exptree *initexptree(void);

/* Deallocates the expression tree.
 */
extern void freeexptree(struct exptree *t);

/* Resets an exptree back to its initial state.
 */
extern void clearexptree(struct exptree *t);

/* Returns the length of the expression inside the string.
 */
extern int getexplength(struct exptree const *t);

/* Parses a C expression into an expression tree. exp points to the
 * expression to parse, potentially embedded inside of a larger
 * string, and cl provides a lexer initialized to exp's position. The
 * return value points to the bytes following the parsed expression.
 */
extern char const *parseexptree(struct exptree *t, struct pplex *cl,
				char const *input);

/* Runs through the parsed expression and marks all of the identifiers
 * that appear in set as having a specific definition state, either
 * defined or undefined according to the third argument.
 * (Sub-expressions consisting entirely of definite symbols are
 * themselves considered definite.) The return value is true if any
 * identifiers in set were found in the expression tree.
 */
extern int markdefined(struct exptree *t, struct symset *set, int defined);

/* Attempts to evaluate the parsed expression's value. If the
 * expression has a definite value, it is returned and defined
 * receives a true value. If some or all of the expression lacks a
 * definition state, defined receives a false value.
 */
extern long evaltree(struct exptree *t, int *defined);

/* Copy into buffer the part of the parsed expression that lacks a
 * definition state. Any sub-expressions that have a definite value
 * are applied and do not form part of the output. The return value is
 * the length of the string written to buffer. This string is
 * guaranteed not to be longer than the original parsed expression.
 */
extern int unparseevaluated(struct exptree const *t, char *buffer);

#endif
