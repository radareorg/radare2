#ifndef R2_UEFI_VC4_REGEX_H
#define R2_UEFI_VC4_REGEX_H

#include <r_regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef RRegex regex_t;
typedef RRegexMatch regmatch_t;

#define REG_NOSUB R_REGEX_NOSUB
#define REG_NOMATCH R_REGEX_NOMATCH
#define regexec r_regex_exec
#define regfree r_regex_fini

static inline int regcomp(regex_t *regex, const char *pattern, int flags) {
	memset (regex, 0, sizeof (*regex));
	return r_regex_init (regex, pattern, flags);
}

static inline size_t regerror(int code, regex_t *regex, char *buffer, size_t size) {
	char *message = r_regex_error (regex, code);
	const char *error = message? message: "Regex error";
	size_t length = strlen (error) + 1;
	if (size > 0) {
		snprintf (buffer, size, "%s", error);
	}
	free (message);
	return length;
}

#endif
