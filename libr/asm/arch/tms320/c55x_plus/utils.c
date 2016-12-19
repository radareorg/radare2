/* c55plus - LGPL - Copyright 2013 - th0rpe */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "utils.h"

static char hex_str[] = "01234567890abcdef";

// TODO: Add in a Coverity modelling file
char *strcat_dup(char *s1, char *s2, st32 n_free) {
	char *res;
	ut32 len_s1 = s1? strlen (s1) : 0;
	ut32 len_s2 = s2? strlen (s2) : 0;

	if (!(res = (char *)malloc (len_s1 + len_s2 + 1))) {
		return NULL;
	}
	if (len_s1 > 0) {
		memcpy (res, s1, len_s1);
	}
	if (len_s2 > 0) {
		memcpy (res + len_s1, s2, len_s2);
	}
	res[len_s1 + len_s2] = '\0';
	if (n_free == 1) {
		R_FREE (s1);
	} else if (n_free == 2) {
		R_FREE (s2);
	} else if (n_free == 3) {
		R_FREE (s1);
		R_FREE (s2);
	}
	return res;
}

char *get_hex_str(ut32 hex_num) {
    char aux[3];

    aux[2] = '\0';
    aux[1] = hex_str[hex_num & 0xF];
    aux[0] = hex_str[(hex_num >> 4) & 0xF];

    return strdup(aux);
}
