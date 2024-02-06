// MIT licensed code inspired by https://github.com/tusharjois/bscanf

#define R_LOG_ORIGIN "r_str_scanf"

#include <r_util.h>

#define _BSCANF_CONSUME_WSPACE() while (isspace(*buf_ptr)) {buf_ptr++;}
#define _BSCANF_CHECK(x) if (!(x)) goto exit;
#define _BSCANF_MATCH() _BSCANF_CHECK(*buf_ptr == *fmt_ptr);
#define _BSCANF_CHECK_NULL(ptr) _BSCANF_CHECK(NULL != ptr);
#define _BSCANF_CHECK_STRING() _BSCANF_CHECK(0 != max_width);
#define _BSCANF_CHECK_BUFFER() _BSCANF_CHECK('\0' != *buffer);
#define _BSCANF_CHECK_STRTONUM() _BSCANF_CHECK(buf_ptr != end_ptr);

R_API int r_str_scanf(const char *buffer, const char *format, ...) {
	/* Our return value. On a conversion error, we return this immediately. */
	int num_args_set = 0;

	/* We use these to index into our buffer and format string. */
	const char *buf_ptr = buffer;
	const char *fmt_ptr = format;

	/* Variadic arguments -- pointers in which we put our conversion results. */
	va_list args;
	long *long_ptr;
	int *int_ptr;
	short *short_ptr;
	ut64 *ut64_ptr;
	unsigned long *ulong_ptr;
	unsigned short *ushort_ptr;
	unsigned int *uint_ptr;
	double *double_ptr;
	float*float_ptr;
	char *char_ptr;
	wchar_t *wchar_ptr;

	/* These are useful variables when doing string to number conversion. */
	char* end_ptr;
	int base;

	/* These are flags that are used by different conversion specifiers. */
	bool is_suppressed = false;
	size_t max_width = 0;
	char length_mod = '\0';

	/* Return a special value when one of the arguments is NULL. */
	if (NULL == buffer || NULL == format) {
		return -1;
	}

	va_start(args, format);

	while ('\0' != *fmt_ptr) {
		/* We ignore spaces before specifiers. */
		if (isspace(*fmt_ptr)) {
			/* Any whitespace in the format consumes all of the whitespace in the
			   buffer. */
			_BSCANF_CONSUME_WSPACE();
			fmt_ptr++;
			continue;
		}

		if ('%' == *fmt_ptr) {
			/* Handle conversion specifier. */
			fmt_ptr++;

			/* Check for assignment-suppressing character. */
			if ('*' == *fmt_ptr) {
				is_suppressed = true;
				fmt_ptr++;
			} else {
				is_suppressed = false;
			}

			/* Check for maximum field width. */
			if (*fmt_ptr == '.') {
				// R2SCANF extension. '.' works like %*s in printf
				max_width = va_arg (args, size_t) - 1;
				fmt_ptr++;
			} else if (isdigit(*fmt_ptr)) {
				max_width = strtoul(fmt_ptr, &end_ptr, 0);
				/* Check if the sequence is a number > 0. */
				_BSCANF_CHECK(fmt_ptr != end_ptr);
				_BSCANF_CHECK(max_width > 0);

				fmt_ptr = end_ptr;
			}

			/* Check for a length modifier. */
			if ('h' == *fmt_ptr || 'l' == *fmt_ptr || 'L' == *fmt_ptr) {
				length_mod = *fmt_ptr;
				fmt_ptr++;
			} else {
				length_mod = '\0';
			}

			/* Handle the conversion format specifier. */
			if ('n' == *fmt_ptr) {
				/* 'n': number of characters read so far. */
				/* 'n' conversion specifiers DO NOT consume whitespace. */
				/* Technically undefined, but just stop here for safety. */
				_BSCANF_CHECK(!is_suppressed);
				if ('l' == length_mod) {
					long_ptr = va_arg(args, long*);
					_BSCANF_CHECK_NULL(long_ptr);
					*long_ptr = (long) (buf_ptr - buffer);
				} else if ('h' == length_mod) {
					short_ptr = va_arg(args, short*);
					_BSCANF_CHECK_NULL(short_ptr);
					*short_ptr = (short) (buf_ptr - buffer);
				} else {
					int_ptr = va_arg(args, int*);
					_BSCANF_CHECK_NULL(int_ptr);
					*int_ptr = (int) (buf_ptr - buffer);
				}
				fmt_ptr++;
				num_args_set++;
				continue;
			}

			/* All other specifiers move the buffer pointer, so check that it's not NUL. */
			_BSCANF_CHECK_BUFFER();

			if ('%' == *fmt_ptr) {
				/* '%': match literal %. */
				_BSCANF_CONSUME_WSPACE();
				_BSCANF_MATCH();
				buf_ptr++;
			} else if ('c' == *fmt_ptr || 's' == *fmt_ptr) {
				/* 'c'/'s': match a character sequence/string. */
				/* String conversion requires a width. */
				// _BSCANF_CHECK_STRING(); -- we want to actually *str=0 instead of early fail

				/* 'c' conversion specifiers DO NOT consume whitespace. */
				if ('c' != *fmt_ptr) {
					_BSCANF_CONSUME_WSPACE();
				}

				if (is_suppressed) {
					/* Consume the character (string) and ignore it in this case. */
					for (; max_width > 0; max_width--) {
						buf_ptr++;
						if (*buf_ptr == '\0' || (isspace(*buf_ptr) && 's' == *fmt_ptr)) {
							break;
						}
					}
					fmt_ptr++;
					continue;

				} else if ('l' == length_mod) {
					wchar_ptr = va_arg(args, wchar_t*);
					wchar_t *wbuf_ptr = (wchar_t *) buf_ptr;
					_BSCANF_CHECK_NULL(wchar_ptr);
					// ckl_BSCANF_CHECK(0);
					*wchar_ptr = 0; // null byte the first char before failing
					if (max_width < 1) {
						R_LOG_DEBUG ("Missing length specifier for string");
					} else {
						for (; max_width > 0; max_width--) {
							*wchar_ptr = *wbuf_ptr;
							if (*wbuf_ptr == '\0' || (isspace (*wbuf_ptr) && 's' == *fmt_ptr)) {
								break;
							}
							wchar_ptr++;
							wbuf_ptr++;
						}
						if (max_width == 0 && *fmt_ptr == 's') {
							R_LOG_DEBUG ("Truncated string in scanf");
							while (*wbuf_ptr) {
								if (isspace (*wbuf_ptr)) {
									break;
								}
								wbuf_ptr++;
							}
						}
						/* Strings are null-terminated. */
						if ('s' == *fmt_ptr) {
							*wchar_ptr = '\0';
						}
						buf_ptr = (char *)wbuf_ptr;
						num_args_set++;
					}
					// reset max width value
					max_width = 0;
				} else {
					char_ptr = va_arg(args, char*);
					_BSCANF_CHECK_NULL(char_ptr);
					*char_ptr = 0; // null byte the first char before failing
					if (max_width < 1) {
						num_args_set--;
						R_LOG_DEBUG ("Missing length specifier for string");
					} else {
						for (; max_width > 0; max_width--) {
							*char_ptr = *buf_ptr;
							if (*buf_ptr == '\0' || (isspace (*buf_ptr) && 's' == *fmt_ptr)) {
								break;
							}
							char_ptr++;
							buf_ptr++;
						}
						if (max_width == 0 && *fmt_ptr == 's') {
							R_LOG_DEBUG ("Truncated string in scanf");
							while (*buf_ptr) {
								if (isspace (*buf_ptr)) {
									break;
								}
								buf_ptr++;
							}
						}
						/* Strings are null-terminated. */
						if ('s' == *fmt_ptr) {
							*char_ptr = '\0';
						}
						num_args_set++;
					}
					// reset max width value
					max_width = 0;
				}

			} else if ('[' == *fmt_ptr) {
				/* TODO: '[': match a non-empty sequence of characters from a set. */
				_BSCANF_CHECK(0);

				/* String conversion requires a width. */
				_BSCANF_CHECK_STRING();
				/* '[' conversion specifiers DO NOT consume whitespace. */

			} else if ('i' == *fmt_ptr || 'd' == *fmt_ptr) {
				/* 'i'/'d': match a integer/decimal integer. */

				_BSCANF_CONSUME_WSPACE();
				base = ('d' == *fmt_ptr) * 10;

				if (is_suppressed) {
					/* Consume the integer and ignore it in this case. */
					strtol(buf_ptr, &end_ptr, base);
				} else if ('l' == length_mod) {
					long_ptr = va_arg(args, long*);
					_BSCANF_CHECK_NULL(long_ptr);
					*long_ptr = (long) strtol(buf_ptr, &end_ptr, base);
				} else if ('L' == length_mod) {
					ut64_ptr = va_arg(args, ut64*);
					_BSCANF_CHECK_NULL(long_ptr);
					*long_ptr = (ut64) strtoll(buf_ptr, &end_ptr, base);
				} else if ('h' == length_mod) {
					short_ptr = va_arg(args, short*);
					_BSCANF_CHECK_NULL(short_ptr);
					*short_ptr = (short) (strtol(buf_ptr, &end_ptr, base));
				} else {
					int_ptr = va_arg(args, int*);
					_BSCANF_CHECK_NULL(int_ptr);
					*int_ptr = (int) (strtol(buf_ptr, &end_ptr, base));
				}

				_BSCANF_CHECK_STRTONUM();
				buf_ptr = end_ptr;
				num_args_set++;

			} else if ('g' == *fmt_ptr || 'e' == *fmt_ptr || 'f' == *fmt_ptr ||
					'G' == *fmt_ptr || 'E' == *fmt_ptr || 'F' == *fmt_ptr) {
				/* 'g'/'e'/'f': match a float in strtod form. */
				/* TODO: 'a': match a float in C99 binary floating-point form. */

				_BSCANF_CONSUME_WSPACE();

				if (is_suppressed) {
					/* Consume the float and ignore it in this case. */
					strtod(buf_ptr, &end_ptr);
				} else if ('l' == length_mod) {
					double_ptr = va_arg(args, double*);
					_BSCANF_CHECK_NULL(double_ptr);
					*double_ptr = (double) (strtod(buf_ptr, &end_ptr));
				} else {
					float_ptr = va_arg(args, float*);
					_BSCANF_CHECK_NULL(float_ptr);
					*float_ptr = (float) (strtod(buf_ptr, &end_ptr));
				}

				_BSCANF_CHECK_STRTONUM();
				buf_ptr = end_ptr;
				num_args_set++;

			} else if ('u' == *fmt_ptr || 'o' == *fmt_ptr || 'x' == *fmt_ptr || 'X' == *fmt_ptr) {
				/* 'u'/'o'/'x': match a unsigned decimal/octal/hexadecimal integer */

				_BSCANF_CONSUME_WSPACE();
				base = ('u' == *fmt_ptr) * 10 + ('o' == *fmt_ptr) * 8 +
					('x' == *fmt_ptr || 'X' == *fmt_ptr) * 16;

				if (is_suppressed) {
					/* Consume the unsigned integer and ignore it in this case. */
					strtoul(buf_ptr, &end_ptr, base);
				} else if ('l' == length_mod) {
					ulong_ptr = va_arg(args, unsigned long*);
					_BSCANF_CHECK_NULL(ulong_ptr);
					*ulong_ptr = (unsigned long) strtoul(buf_ptr, &end_ptr, base);
				} else if ('L' == length_mod) {
					ut64_ptr = va_arg(args, ut64*);
					_BSCANF_CHECK_NULL(ut64_ptr);
					*ut64_ptr = (ut64) strtoull(buf_ptr, &end_ptr, base);
				} else if ('h' == length_mod) {
					ushort_ptr = va_arg(args, unsigned short*);
					_BSCANF_CHECK_NULL(ushort_ptr);
					*ushort_ptr = (unsigned short) (strtoul(buf_ptr, &end_ptr, base));
				} else {
					uint_ptr = va_arg(args, unsigned int*);
					_BSCANF_CHECK_NULL(uint_ptr);
					*uint_ptr = (unsigned int) (strtoul(buf_ptr, &end_ptr, base));
				}

				_BSCANF_CHECK_STRTONUM();
				buf_ptr = end_ptr;
				num_args_set++;

			} else {
				/* Unknown conversion specifier. */
				_BSCANF_CHECK(0);
			}

			/* TODO: 'p': match a (implementation-defined) pointer. */

		} else {
			/* Match character with that in buffer. */
			_BSCANF_MATCH();
			buf_ptr++;
		}

		/* Get the next format specifier. */
		fmt_ptr++;
	}

exit:
	va_end(args);
	return num_args_set;
}
