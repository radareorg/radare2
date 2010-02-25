/* pancake // nopcode.org -- 2010 -- output module for rcc */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>

static char *output = NULL;
static int output_len;
static int output_size;

void rcc_init() {
	output_size = 1024;
	output_len = 0;
	output = malloc (output_size);
}

void rcc_puts(const char *str) {
	int len = strlen (str);
	if (len+output_len >= output_size) {
		output_size += 1024 + len;
		output = realloc (output, output_size);
	}
	memcpy (output+output_len, str, len);
	output_len += len;
}

void rcc_printf(const char *fmt, ...) {
	va_list ap;
	char buf[1024];
	va_start (ap, fmt);
	vsnprintf (buf, sizeof (buf), fmt, ap);
	rcc_puts (buf);
	va_end (ap);
}

void rcc_reset () {
	output_len = 0;
}

char *rcc_get () {
	char *buf = malloc (output_len);
	if (buf) memcpy (buf, output, output_len);
	return buf;
}

void rcc_flush () {
	write (1, output, output_len);
	rcc_reset ();
}

#if MAIN
void main () {
	rcc_out_init ();
	rcc_printf ("((%d))\n", 23);
	rcc_puts ("Hello World\n");
	rcc_puts ("((hehe))\n");
	rcc_flush ();
}
#endif
