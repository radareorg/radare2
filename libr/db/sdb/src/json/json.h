#ifndef _INCLUDE_JSON_H_
#define _INCLUDE_JSON_H_

#include "rangstr.h"

int js0n(const unsigned char *js, unsigned int len, unsigned short *out);
Rangstr json_get (const char *s, const char *path);

/* string based api */
char *api_json_get (const char *s, const char *p);
char *api_json_set (const char *s, const char *k, const char *v);
int api_json_geti (const char *s, const char *p);
char *api_json_seti (const char *s, const char *k, int a);
char *api_json_unindent(const char *s);
char *api_json_indent(const char *s);

#endif
