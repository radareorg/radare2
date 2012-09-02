/* symset.c: Copyright (C) 2011 by Brian Raiter <breadbox@muppetlabs.com>
 * License GPLv2+: GNU GPL version 2 or later.
 * This is free software; you are free to change and redistribute it.
 * There is NO WARRANTY, to the extent permitted by law.
 */
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "gen.h"
#include "symset.h"

/*
 * The obvious data structure for an unordered collection of
 * preprocessor symbols is a hash table. However, given that the vast
 * majority of symbol sets will have a size of zero or one, and will
 * almost never exceed three, and that symbol lookups are not inside
 * the program's inner loops, even hash tables are overkill here.
 */

/* A preprocessor symbol.
 */
struct sym {
    char const *id;		/* the symbol's name */
    long	value;		/* the symbol's value */
};

/* An unordered collection of symbols.
 */
struct symset {
    struct sym *syms;		/* an array of symbols */
    int		allocated;	/* how many entries are allocated */
    int		size;		/* how many entries are currently stored */
};

/* Allocate a new symset.
 */
struct symset *initsymset(void)
{
    struct symset *set;

    set = allocate(sizeof *set);
    set->syms = allocate(sizeof *set->syms);
    set->allocated = 1;
    set->size = 0;
    return set;
}

/* Deallocate an symset.
 */
void freesymset(struct symset *set)
{
    if (set) {
	deallocate(set->syms);
	deallocate(set);
    }
}

/* Append a symbol to a set.
 */
void addsymboltoset(struct symset *set, char const *id, long value)
{
    if (set->size == set->allocated) {
	set->allocated *= 2;
	set->syms = reallocate(set->syms,
			       set->allocated * sizeof *set->syms);
    }
    set->syms[set->size].id = id;
    set->syms[set->size].value = value;
    ++set->size;
}

/* A string comparison function that treats any non-identifier
 * character as a delimiter.
 */
static int idcmp(char const *a, char const *b)
{
    int i;

    i = 0;
    for (;;) {
	if (!_issym(a[i]))
	    return _issym(b[i]) ? -1 : 0;
	else if (!_issym(b[i]))
	    return +1;
	else if (a[i] != b[i])
	    return a[i] - b[i];
	++i;
    }
}

/* Retrieve the value of a symbol.
 */
int findsymbolinset(struct symset const *set, char const *id, long *value)
{
    int i;

    for (i = 0 ; i < set->size ; ++i) {
	if (!idcmp(set->syms[i].id, id)) {
	    if (value)
		*value = set->syms[i].value;
	    return TRUE;
	}
    }
    return FALSE;
}
