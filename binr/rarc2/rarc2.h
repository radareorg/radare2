#ifndef _INCLUDE_RCC_H_
#define _INCLUDE_RCC_H_

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>

#include "config.h"

enum {
	NORMAL = 0,
	ALIAS,
	DATA,
	INLINE,
	SYSCALL,
	SYSCALLBODY,
	LAST
};

#define eprintf(x,y...) (fprintf(stderr,"\x1b[31m"x"\x1b[0m",##y),1)
#define FREE(x) free(x); x=NULL
#define IS_VAR(x) (x[0]=='.'||((x[0]=='*'||x[0]=='&')&&x[1]=='.'))
#define MAX 255

extern void rcc_puts(const char *str);
extern void rcc_printf(const char *fmt, ...);
extern void rcc_flush();
extern void rcc_init();
extern char *mk_var(char *out, const char *str, int delta);

/* emit */
typedef unsigned long long ut64;

struct emit_t {
	const char *arch;
	int size; /* in bytes.. 32bit arch is 4, 64bit is 8 .. */
	const char *syscall_body;
	const char* (*regs)(int idx);
	void (*call)(const char *addr, int ptr);
	//void (*sc)(int num);
	void (*frame)(int sz);
	void (*trap)();
	void (*frame_end)(int sz, int ctx);
	void (*comment)(const char *fmt, ...);
	void (*push_arg)(int xs, int num, const char *str);
	void (*set_string)(const char *dstvar, const char *str, int j);
	void (*equ)(const char *key, const char *value);
	void (*get_result)(const char *ocn);
	void (*restore_stack)(int size);
	void (*syscall_args)(int nargs);
	void (*get_var)(int type, char *out, int idx);
	void (*while_end)(const char *label);
	void (*load)(const char *str, int sz);
	void (*load_ptr)(const char *str);
	void (*branch)(char *b, char *g, char *e, char *n, int sz, const char *dst);
	void (*mathop)(int ch, int sz, int type, const char *eq, const char *p);
	void (*get_while_end)(char *out, const char *ctxpush, const char *label);
};

#endif
