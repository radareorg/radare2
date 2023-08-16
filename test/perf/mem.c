#define _GNU_SOURCE

#include <dlfcn.h>
#include <unistd.h>
#include <fcntl.h>

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

extern void* malloc(size_t);
extern void* calloc(size_t, size_t);
extern void free(void*);

static int mem_fd = 1;

static void init(void) __attribute__((constructor));
static void init(void) {
	write(1,"pop\n", 4);
//	mem_fd = open ("mem.log", O_RDWR);
	if (mem_fd == -1) mem_fd = 1;
}
static void fini(void) __attribute__((destructor));
static void fini(void) {
	write(1,"end\n",4);
	if (mem_fd != 1) close (mem_fd);
	mem_fd = 1;
}

enum flag_itoa {
	FILL_ZERO = 1,
	PUT_PLUS = 2,
	PUT_MINUS = 4,
	BASE_2 = 8,
	BASE_10 = 16,
};

static char * my_itoa(unsigned int num, char *buf, int width, int flags) {
	unsigned int base;
	if (flags & BASE_2)
		base = 2;
	else if (flags & BASE_10)
		base = 10;
	else
		base = 16;

	char tmp[32] = {0};
	char *p = tmp;
	do {
		int rem = num % base;
		*p++ = (rem <= 9) ? (rem + '0') : (rem + 'a' - 0xA);
	} while ((num /= base));
	width -= p - tmp;
	char fill = (flags & FILL_ZERO)? '0' : ' ';
	while (0 <= --width) {
		*(buf++) = fill;
	}
	if (flags & PUT_MINUS)
		*(buf++) = '-';
	else if (flags & PUT_PLUS)
		*(buf++) = '+';
	do
		*(buf++) = *(--p);
	while (tmp < p);
	*buf = 0;
	return buf;
}

int my_printf(char const *fmt, ...) {
	int int_temp;
	char char_temp;
	char *string_temp;
	double double_temp;

	char ch;
	int length = 0;

	char buffer[512];
	va_list arg;
	va_start (arg, fmt);

	while ((ch = *fmt++)) {
		if ('%' != ch) {
			write(1, &ch,1);
			length++;
			continue;
		}
		switch (ch = *fmt++) {
		/* %% - print out a single %    */
		case '%':
			write(1, "%", 1);
			length++;
			break;

			/* %c: print out a character    */
		case 'c':
			char_temp = va_arg (arg, int);
			write(1, &char_temp, 1);
			length++;
			break;

			/* %s: print out a string       */
		case 's':
			string_temp = va_arg (arg, char *);
			write(1, string_temp, strlen(string_temp));
			length += strlen(string_temp);
			break;

			/* %d: print out an int         */
		case 'd':
			{
			int_temp = va_arg (arg, int);
			my_itoa(int_temp, buffer, 10, 0);
			char *p = buffer;
			while (*p == ' ') p++;
			write(1, p, strlen (p));
			length += strlen(p);
			}
			break;
		case 'p':
			{
			int_temp = va_arg (arg, size_t);
			my_itoa(int_temp, buffer, 16, 0);
			write(1, "0x", 2);
			char *p = buffer;
			length += 2;
			while (*p == ' ') p++;
			write(1, p, strlen (p));
			length += strlen(p);
			}
			break;
			/* %x: print out an int in hex  */
		case 'x':
			{
			int_temp = va_arg (arg, int);
			my_itoa(int_temp, buffer, 16, 0);
			char *p = buffer;
			while (*p == ' ') p++;
			write(1,p, strlen(buffer));
			length += strlen(p);
			}
			break;
		}
	}
	va_end (arg);
	return length;
}

/////////////////////////////////

static void *(*o_malloc)(size_t s) = NULL;
static void *(*o_realloc)(void *p, size_t s) = NULL;
static void (*o_free)(void *p) = NULL;

void *malloc(size_t s) {
	if (o_malloc == NULL) {
		o_malloc = dlsym(RTLD_NEXT, "malloc");
	}
	void *m = o_malloc (s);
	my_printf ("mem::malloc %d = %p\n", (int)s, m);
	return m;
}

void *realloc(void *p, size_t s) {
	if (o_realloc == NULL) {
		o_realloc = dlsym(RTLD_NEXT, "realloc");
	}
	void *m = o_realloc (p, s);
	my_printf ("mem::realloc %p %d = %p\n", p, (int)s, m);
	return m;
}

void free(void *p) {
	if (o_free == NULL) {
		o_free = dlsym(RTLD_NEXT, "free");
	}
	o_free (p);
	my_printf ("mem::free %p\n", p);
}
