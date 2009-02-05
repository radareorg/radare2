/* radare - LGPL - Copyright 2007-2009 pancake<nopcode.org> */

#include <r_util.h>
#include <sys/types.h>
#include <regex.h>

/* XXX: This code uses POSIX 2001 . can be nonportable */
#define NUM_MATCHES 16

/* returns 1 if 'str' matches 'reg' regexp */
int r_str_re_match(const char *str, const char *reg)
{
	regex_t preg;
	regmatch_t pmatch[NUM_MATCHES];
	if (regcomp(&preg, reg, REG_EXTENDED))
		return -1;
	return (regexec (&preg, str, NUM_MATCHES, pmatch, 0))?1:0;
}

int r_str_re_replace(const char *str, const char *reg, const char *sub)
{
	/* TODO: not yet implemented */
	return -1;
}
