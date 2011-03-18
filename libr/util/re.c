/* radare - LGPL - Copyright 2007-2010 pancake<nopcode.org> */

#include <r_util.h>

#if HAVE_REGEXP
#include <regex.h>
/* XXX: This code uses POSIX 2001 . can be nonportable */
#define NUM_MATCHES 16
#endif

/* returns 1 if 'str' matches 'reg' regexp */
R_API int r_str_re_match(const char *str, const char *reg) {
#if HAVE_REGEXP
	regex_t preg;
	regmatch_t pmatch[NUM_MATCHES];
	if (regcomp(&preg, reg, REG_EXTENDED))
		return -1;
	return (regexec (&preg, str, NUM_MATCHES, pmatch, 0))?1:0;
#else
	return -1;
#endif
}

R_API int r_str_re_replace(const char *str, const char *reg, const char *sub) {
	/* TODO: not yet implemented */
	return -1;
}

/* Added glob stuff here */
