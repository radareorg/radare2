#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if 0
/* XXX buggy gnu code */

// FROM bash::stringlib
#define RESIZE_MALLOCED_BUFFER(str,cind,room,csize,sincr) \
	if ((cind) + (room) >= csize) { \
		while ((cind) + (room) >= csize) \
		csize += (sincr); \
		str = realloc (str, csize); \
	}

/* Replace occurrences of PAT with REP in STRING.  If GLOBAL is non-zero,
   replace all occurrences, otherwise replace only the first.
   This returns a new string; the caller should free it. */

static int strsub_memcmp (char *string, char *pat, int len)
{
	int res = 0;
	while(len--) {
		if (*pat!='?')
			res += *string - *pat;
		string = string+1;
		pat = pat+1;
	}
	return res;
}

const char *strsub (char *string, char *pat, char *rep, int global)
{
	int patlen, templen, tempsize, repl, i;
	char *temp, *r;

	patlen = strlen (pat);
	for (temp = (char *)NULL, i = templen = tempsize = 0, repl = 1; string[i]; )
	{
//		if (repl && !memcmp(string + i, pat, patlen)) {
		if (repl && !strsub_memcmp(string + i, pat, patlen)) {
			RESIZE_MALLOCED_BUFFER (temp, templen, patlen, tempsize, 4096); //UGLY HACK (patlen * 2));
			if (temp == NULL)
				return NULL;
			for (r = rep; *r; )
				temp[templen++] = *r++;

			i += patlen;
			repl = global != 0;
		} else {
			RESIZE_MALLOCED_BUFFER (temp, templen, 1, tempsize, 4096); // UGLY HACK 16);
			temp[templen++] = string[i++];
		}
	}
	if (temp != NULL)
		temp[templen] = 0;
	return (temp);
}
#endif
