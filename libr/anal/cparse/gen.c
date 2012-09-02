/* gen.c: Copyright (C) 2011 by Brian Raiter <breadbox@muppetlabs.com>
 * License GPLv2+: GNU GPL version 2 or later.
 * This is free software; you are free to change and redistribute it.
 * There is NO WARRANTY, to the extent permitted by law.
 */
#include <stdio.h>
#include <stdlib.h>
#include "gen.h"

/* Wrapper for malloc().
 */
void *allocate(size_t size)
{
    void *p;

    p = malloc(size);
    if (!p) {
	fputs("Out of memory.\n", stderr);
	exit(EXIT_FAILURE);
    }
    return p;
}

/* Wrapper for realloc().
 */
void *reallocate(void *p, size_t size)
{
    p = realloc(p, size);
    if (!p) {
	fputs("Out of memory.\n", stderr);
	exit(EXIT_FAILURE);
    }
    return p;
}

/* Wrapper for free().
 */
void deallocate(void *p)
{
    free(p);
}
