/* c55plus - LGPL - Copyright 2013 - th0rpe */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "utils.h"

static char hex_str[] = "01234567890abcdef";

st8 *strcat_dup(st8 *s1, st8 *s2, st32 n_free)
{
	st8 *res;
	ut32 len_s1, len_s2;


	if(s1 != NULL)
		len_s1 = strlen(s1);
	else
		len_s1 = 0;

	if(s2 != NULL)
		len_s2 = strlen(s2);
	else
		len_s2 = 0;

	res = (char *)malloc(len_s1 + len_s2 + 1);
	if(!res)
		return NULL;

	if(len_s1 > 0)
		memcpy(res, s1, len_s1);

	if(len_s2 > 0)
		memcpy(res + len_s1, s2, len_s2);

	res[len_s1 + len_s2] = '\0';

	if(n_free == 1) {
		if(s1 != NULL)
			free(s1);

	} else if(n_free == 2) {
		if(s2 != NULL)
			free(s2);

	} else if(n_free == 3) {
		if(s1 != NULL)
			free(s1);

		if(s2 != NULL)
			free(s2);
	}

	return res;
}

st8 *get_hex_str(ut32 hex_num)
{
    st8 aux[3];

    aux[2] = '\0';
    aux[1] = hex_str[hex_num & 0xF];
    aux[0] = hex_str[(hex_num >> 4) & 0xF];

    return strdup(aux);
}
