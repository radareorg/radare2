#ifndef _INCLUDE_JSON_H_
#define _INCLUDE_JSON_H_

#include "rangstr.h"

#if 0
SDB_IPI int js0n(const unsigned char *js, RangstrType len, RangstrType *out);
SDB_IPI Rangstr json_get (const char *s, const char *path);

/* string based api */
SDB_IPI char *api_json_get (const char *s, const char *p);
SDB_IPI char *api_json_set (const char *s, const char *k, const char *v);
SDB_IPI int api_json_geti (const char *s, const char *p);
SDB_IPI char *api_json_seti (const char *s, const char *k, int a);
SDB_IPI char *api_json_unindent(const char *s);
SDB_IPI char *api_json_indent(const char *s);
#endif

#endif
