/* gen.h: Copyright (C) 2011 by Brian Raiter <breadbox@muppetlabs.com>
 * License GPLv2+: GNU GPL version 2 or later.
 * This is free software; you are free to change and redistribute it.
 * There is NO WARRANTY, to the extent permitted by law.
 */
#ifndef	_gen_h_
#define	_gen_h_

/*
 * General definitions and functionality not specific to any module.
 */

#include <stddef.h>

#ifndef TRUE
#define	TRUE  1
#define	FALSE 0
#endif

/* Returns the number of elements in an array.
 */
#define sizearray(a) ((int)(sizeof (a) / sizeof *(a)))

/* Returns true if ch is a valid C identifier character.
 */
#define _issym(ch) (isalnum(ch) || (ch) == '_')

/* Memory allocation functions. These functions either succeed or exit
 * the program.
 */
extern void *allocate(size_t size);
extern void *reallocate(void *ptr, size_t size);
extern void deallocate(void *ptr);

#endif
