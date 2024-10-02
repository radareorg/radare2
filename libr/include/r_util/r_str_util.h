#ifndef R_STR_UTIL_H
#define R_STR_UTIL_H

#ifdef __cplusplus
extern "C" {
#endif

#define IS_NULLSTR(x) (!(x) || !*(x))
#define IS_WHITECHAR(x) ((x) == ' ' || (x) == '\t' || (x) == '\n' || (x) == '\r')
#define IS_SEPARATOR(x) ((x) == ' ' || (x) == '\t' || (x) == '\n' || (x) == '\r' || (x) == ' '|| \
		(x) == ',' || (x) == ';' || (x) == ':' || (x) == '[' || (x) == ']' || \
		(x) == '(' || (x) == ')' || (x) == '{' || (x) == '}')
#define IS_HEXCHAR(x) (((x) >= '0' && (x) <= '9') || ((x) >= 'a' && (x) <= 'f') || ((x) >= 'A' && (x) <= 'F'))
#define IS_PRINTABLE(x) ((x) >=' ' && (x) <= '~')
// R2_600 - deprecate
#define IS_DIGIT(x) isdigit((x))
#define IS_OCTAL(x) ((x) >= '0' && (x) <= '7')
#define IS_WHITESPACE(x) ((x) == ' ' || (x) == '\t')
#define IS_UPPER(c) isupper((c))
#define IS_LOWER(c) islower((c))

#ifdef __cplusplus
}
#endif

#endif //  R_STR_UTIL_H
