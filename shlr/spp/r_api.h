#ifndef S_STRBUF_H
#define S_STRBUF_H

#ifdef _MSC_VER
void out_printf(Output *out, char *str, ...);
#else
void out_printf(Output *out, char *str, ...) __attribute__ ((format (printf, 2, 3)));
#endif

int r_sys_setenv(const char *key, const char *value);

#endif
