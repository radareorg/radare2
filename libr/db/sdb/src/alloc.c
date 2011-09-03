#include <stdlib.h>
#include "alloc.h"

#define ALIGNMENT 16 /* XXX: assuming that this alignment is enough */
#define SPACE 4096 /* must be multiple of ALIGNMENT */

typedef union { char irrelevant[ALIGNMENT]; double d; } aligned;
static aligned realspace[SPACE / ALIGNMENT];
#define space ((char *) realspace)
static unsigned int avail = SPACE; /* multiple of ALIGNMENT; 0<=avail<=SPACE */

char *alloc(unsigned int n) {
	n = ALIGNMENT + n - (n & (ALIGNMENT - 1)); /* XXX: could overflow */
	if (n <= avail) { avail -= n; return space + avail; }
	return (char*)malloc (n);
}

void alloc_free(char *x) {
	if (x >= space)
		if (x < space + SPACE)
			return; /* XXX: assuming that pointers are flat */
	free (x);
}
