/* radare - LGPL - Copyright 2013 - pancake */

#include <iconv.h>
#include <stdio.h>
#include <string.h>

char *r_str_iconv (const char *str, int *len) {
	iconv_t cd;
	char *inbuf = (char*)str; // XXX dangerous cast
	size_t inbytesleft = strlen (str);
	char data[1024];
	char *outbuf = (char*)&data;
	size_t rest, outbytesleft = 1024;
	rest = outbytesleft;
	//cd = iconv_open ("ISO8859-15", "UTF-8");
	cd = iconv_open ("UTF-8", "UTF-8");
	if (cd == (iconv_t)-1) {	
		perror ("iconv_open");
		return NULL;
	}
	size_t s = iconv (cd, &inbuf, &inbytesleft, &outbuf, &outbytesleft);
               iconv (cd, NULL, NULL, &outbuf, &outbytesleft);
	rest -= outbytesleft;
	data[rest] = 0;
	printf ("S = %d (%s)\n", (int)rest, data);
	iconv_close (cd);
	if (len) *len = rest;
	return strdup (data);
}

int main() {
	char *str = r_str_iconv ("hellç", NULL);
	printf ("(((%s)))\n", str);
	free (str);
}
