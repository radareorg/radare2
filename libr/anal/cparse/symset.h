/* symset.h: Copyright (C) 2011 by Brian Raiter <breadbox@muppetlabs.com>
 * License GPLv2+: GNU GPL version 2 or later.
 * This is free software; you are free to change and redistribute it.
 * There is NO WARRANTY, to the extent permitted by law.
 */
#ifndef _symset_h_
#define _symset_h_

/*
 * A symset is an unordered set of symbols, which in turn are id/value
 * pairs, the ids being macro names. The strings representing the ids
 * are not copied by the symset objects; the caller retains ownership.
 */

struct symset;

/* Creates an empty set of symbols.
 */
extern struct symset *initsymset(void);

/* Deallocates the set of symbols.
 */
extern void freesymset(struct symset *set);

/* Adds a symbol to the set.
 */
extern void addsymboltoset(struct symset *set, char const *id, long value);

/* Finds a symbol in a set. id points to an identifier, typically not
 * NUL-delimited but embedded within a larger string. The return value
 * is true if a symbol with that name is a member of the set. If value
 * is not NULL, it receives the found symbol's value.
 */
extern int findsymbolinset(struct symset const *set,
			   char const *id, long *value);

#endif
