// snprintf implementation for radare2 (safe+custom extensions)

// %b for boolean (true|false)
// %n is forbidden
// modifier for padding
// %P -> pad with zeroes
// always null terminate

#include <r_util.h>

enum flag_itoa {
	FILL_ZERO = 1,
	PUT_PLUS = 2,
	PUT_MINUS = 4,
	BASE_2 = 8,
	BASE_10 = 16,
};

static char *sitoa(char * buf, char *buf_end, unsigned int num, int width, enum flag_itoa flags) {
	unsigned int base;
	if (flags & BASE_2) {
		base = 2;
	} else if (flags & BASE_10) {
		base = 10;
	} else {
		base = 16;
	}
	char tmp[32];
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
	if (flags & PUT_MINUS) {
		*(buf++) = '-';
	} else if (flags & PUT_PLUS) {
		*(buf++) = '+';
	}
	do {
		*(buf++) = *(--p);
	} while (tmp < p);
	return buf;
}

static int my_vsnprintf(char * buf, size_t buf_size, const char *fmt, va_list va) {
	char c;
	const char *save = buf;
	char *buf_end = buf + buf_size;
	while ((c  = *fmt++)) {
		int width = 0;
		enum flag_itoa flags = 0;
		if (c != '%') {
			*(buf++) = c;
			continue;
		}
redo_spec:
		c  = *fmt++;
		switch (c) {
		case '%':
			*(buf++) = c;
			break;
		case 'c':
			 *(buf++) = va_arg (va, int);
			 break;
		case 'd':
			 {
			 int num = va_arg (va, int);
			 if (num < 0) {
				 num = -num;
				 flags |= PUT_MINUS;
			 }
			 buf = sitoa (buf, buf_end, num, width, flags | BASE_10);
			 }
			 break;
		case 'u':
			 buf = sitoa (buf, buf_end, va_arg (va, unsigned int), width, flags | BASE_10);
			 break;
		case 'x':
			 buf = sitoa (buf, buf_end, va_arg (va, unsigned int), width, flags);
			 break;
		case 'b':
			 buf = sitoa (buf, buf_end, va_arg (va, unsigned int), width, flags | BASE_2);
			 break;
		case 's':;
			 const char *p  = va_arg (va, const char *);
			 if (p) {
				 while (*p)
					 *(buf++) = *(p++);
			 }
			 break;
		case 'm':;
			 const uint8_t *m  = va_arg (va, const uint8_t *);
			 width = R_MIN (width, 64); // buffer limited to 256!
			 if (m)
				 for (;;) {
					 buf = sitoa (buf, buf_end, *(m++), 2, FILL_ZERO);
					 if (--width <= 0)
						 break;
					 *(buf++) = ':';
				 }
			 break;
		case '0':
			 if (!width) {
				 flags |= FILL_ZERO;
			 }
			 // fall through
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
			 width = width * 10 + c - '0';
			 goto redo_spec;
		case '*':
			 width = va_arg (va, unsigned int);
			 goto redo_spec;
		case '+':
			 flags |= PUT_PLUS;
			 goto redo_spec;
		case '\0':
		default:
			 *(buf++) = '?';
		}
		width = 0;
	}
	*buf = '\0';
	return buf - save;
}

R_API int r_str_printf(char * R_NONNULL buf, size_t buf_size, const char * R_NONNULL fmt, ...) {
	va_list va;
	va_start (va,fmt);
	int ret = my_vsnprintf (buf, buf_size, fmt, va);
	va_end (va);
	return ret;
}
