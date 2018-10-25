#ifndef R_STR_UTIL_H
#define R_STR_UTIL_H
 
#define IS_NULLSTR(x) (!(x) || !*(x))
#define IS_WHITECHAR(x) ((x) == ' ' || (x)=='\t' || (x) == '\n' || (x) == '\r')
#define IS_SEPARATOR(x) ((x) == ' ' || (x)=='\t' || (x) == '\n' || (x) == '\r' || (x) == ' '|| \
		(x) == ',' || (x) == ';' || (x) == ':' || (x) == '[' || (x) == ']' || \
		(x) == '(' || (x) == ')' || (x) == '{' || (x) == '}')
#define IS_HEXCHAR(x) (((x) >= '0' && (x) <= '9') || ((x) >= 'a' && (x) <= 'f') || ((x) >= 'A' && (x) <= 'F'))
#define IS_PRINTABLE(x) ((x) >=' ' && (x) <= '~')
#define IS_DIGIT(x) ((x) >= '0' && (x) <= '9')
#define IS_OCTAL(x) ((x) >= '0' && (x) <= '7')
#define IS_WHITESPACE(x) ((x) == ' ' || (x) == '\t')
#define IS_UPPER(c) ((c) >= 'A' && (c) <= 'Z')
#define IS_LOWER(c) ((c) >= 'a' && (c) <= 'z')

#endif //  R_STR_UTIL_H
