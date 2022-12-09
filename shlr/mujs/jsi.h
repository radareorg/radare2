#ifndef jsi_h
#define jsi_h

#include "mujs.h"

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdarg.h>
#include <string.h>
#include <setjmp.h>
#include <math.h>
#include <float.h>
#include <limits.h>

/* NOTE: https://gcc.gnu.org/bugzilla/show_bug.cgi?id=103052 */
#ifdef __GNUC__
#if (__GNUC__ >= 6)
#pragma GCC optimize ("no-ipa-pure-const")
#endif
#endif

/* Microsoft Visual C */
#ifdef _MSC_VER
#pragma warning(disable:4996) /* _CRT_SECURE_NO_WARNINGS */
#pragma warning(disable:4244) /* implicit conversion from double to int */
#pragma warning(disable:4267) /* implicit conversion of int to smaller int */
#pragma warning(disable:4090) /* broken const warnings */
#define inline __inline
#if _MSC_VER < 1900 /* MSVC 2015 */
#define snprintf jsW_snprintf
#define vsnprintf jsW_vsnprintf
static int jsW_vsnprintf(char *str, size_t size, const char *fmt, va_list ap)
{
	int n;
	n = _vsnprintf(str, size, fmt, ap);
	str[size-1] = 0;
	return n;
}
static int jsW_snprintf(char *str, size_t size, const char *fmt, ...)
{
	int n;
	va_list ap;
	va_start(ap, fmt);
	n = jsW_vsnprintf(str, size, fmt, ap);
	va_end(ap);
	return n;
}
#endif
#if _MSC_VER <= 1700 /* <= MSVC 2012 */
#define isnan(x) _isnan(x)
#define isinf(x) (!_finite(x))
#define isfinite(x) _finite(x)
static __inline int signbit(double x) { __int64 i; memcpy(&i, &x, 8); return i>>63; }
#define INFINITY (DBL_MAX+DBL_MAX)
#define NAN (INFINITY-INFINITY)
#endif
#endif

#define soffsetof(x,y) ((int)offsetof(x,y))
#define nelem(a) (int)(sizeof (a) / sizeof (a)[0])

void *js_malloc(js_State *J, int size);
void *js_realloc(js_State *J, void *ptr, int size);
void js_free(js_State *J, void *ptr);

typedef struct js_Regexp js_Regexp;
typedef struct js_Value js_Value;
typedef struct js_Object js_Object;
typedef struct js_String js_String;
typedef struct js_Ast js_Ast;
typedef struct js_Function js_Function;
typedef struct js_Environment js_Environment;
typedef struct js_StringNode js_StringNode;
typedef struct js_Jumpbuf js_Jumpbuf;
typedef struct js_StackTrace js_StackTrace;

/* Limits */

#ifndef JS_STACKSIZE
#define JS_STACKSIZE 256	/* value stack size */
#endif
#ifndef JS_ENVLIMIT
#define JS_ENVLIMIT 128		/* environment stack size */
#endif
#ifndef JS_TRYLIMIT
#define JS_TRYLIMIT 64		/* exception stack size */
#endif
#ifndef JS_ARRAYLIMIT
#define JS_ARRAYLIMIT (1<<26)	/* limit arrays to 64M entries (1G of flat array data) */
#endif
#ifndef JS_GCFACTOR
/*
 * GC will try to trigger when memory usage is this value times the minimum
 * needed memory. E.g. if there are 100 remaining objects after GC and this
 * value is 5.0, then the next GC will trigger when the overall number is 500.
 * I.e. a value of 5.0 aims at 80% garbage, 20% remain-used on each GC.
 * The bigger the value the less impact GC has on overall performance, but more
 * memory is used and individual GC pauses are longer (but fewer).
 */
#define JS_GCFACTOR 5.0		/* memory overhead factor >= 1.0 */
#endif
#ifndef JS_ASTLIMIT
#define JS_ASTLIMIT 100		/* max nested expressions */
#endif
#ifndef JS_STRLIMIT
#define JS_STRLIMIT (1<<28)	/* max string length */
#endif

/* instruction size -- change to int if you get integer overflow syntax errors */

#ifdef JS_INSTRUCTION
typedef JS_INSTRUCTION js_Instruction;
#else
typedef unsigned short js_Instruction;
#endif

/* String interning */

char *js_strdup(js_State *J, const char *s);
const char *js_intern(js_State *J, const char *s);
void jsS_dumpstrings(js_State *J);
void jsS_freestrings(js_State *J);

/* Portable strtod and printf float formatting */

void js_fmtexp(char *p, int e);
int js_grisu2(double v, char *buffer, int *K);
double js_strtod(const char *as, char **aas);

double js_strtol(const char *s, char **ep, int radix);

/* Private stack functions */

void js_newarguments(js_State *J);
void js_newfunction(js_State *J, js_Function *function, js_Environment *scope);
void js_newscript(js_State *J, js_Function *function, js_Environment *scope);
void js_loadeval(js_State *J, const char *filename, const char *source);

js_Regexp *js_toregexp(js_State *J, int idx);
int js_isarrayindex(js_State *J, const char *str, int *idx);
int js_runeat(js_State *J, const char *s, int i);
int js_utfptrtoidx(const char *s, const char *p);
const char *js_utfidxtoptr(const char *s, int i);

void js_dup(js_State *J);
void js_dup2(js_State *J);
void js_rot2(js_State *J);
void js_rot3(js_State *J);
void js_rot4(js_State *J);
void js_rot2pop1(js_State *J);
void js_rot3pop2(js_State *J);
void js_dup1rot3(js_State *J);
void js_dup1rot4(js_State *J);

void js_RegExp_prototype_exec(js_State *J, js_Regexp *re, const char *text);

void js_trap(js_State *J, int pc); /* dump stack and environment to stdout */

struct js_StackTrace
{
	const char *name;
	const char *file;
	int line;
};

/* Exception handling */

struct js_Jumpbuf
{
	jmp_buf buf;
	js_Environment *E;
	int envtop;
	int tracetop;
	int top, bot;
	int strict;
	js_Instruction *pc;
};

void *js_savetrypc(js_State *J, js_Instruction *pc);

#define js_trypc(J, PC) \
	setjmp(js_savetrypc(J, PC))

/* String buffer */

typedef struct js_Buffer { int n, m; char s[64]; } js_Buffer;

void js_putc(js_State *J, js_Buffer **sbp, int c);
void js_puts(js_State *J, js_Buffer **sb, const char *s);
void js_putm(js_State *J, js_Buffer **sb, const char *s, const char *e);

/* State struct */

struct js_State
{
	void *actx;
	void *uctx;
	js_Alloc alloc;
	js_Report report;
	js_Panic panic;

	js_StringNode *strings;

	int default_strict;
	int strict;

	/* parser input source */
	const char *filename;
	const char *source;
	int line;

	/* lexer state */
	struct { char *text; int len, cap; } lexbuf;
	int lexline;
	int lexchar;
	int lasttoken;
	int newline;

	/* parser state */
	int astdepth;
	int lookahead;
	const char *text;
	double number;
	js_Ast *gcast; /* list of allocated nodes to free after parsing */

	/* runtime environment */
	js_Object *Object_prototype;
	js_Object *Array_prototype;
	js_Object *Function_prototype;
	js_Object *Boolean_prototype;
	js_Object *Number_prototype;
	js_Object *String_prototype;
	js_Object *RegExp_prototype;
	js_Object *Date_prototype;

	js_Object *Error_prototype;
	js_Object *EvalError_prototype;
	js_Object *RangeError_prototype;
	js_Object *ReferenceError_prototype;
	js_Object *SyntaxError_prototype;
	js_Object *TypeError_prototype;
	js_Object *URIError_prototype;

	unsigned int seed; /* Math.random seed */

	char scratch[12]; /* scratch buffer for iterating over array indices */

	int nextref; /* for js_ref use */
	js_Object *R; /* registry of hidden values */
	js_Object *G; /* the global object */
	js_Environment *E; /* current environment scope */
	js_Environment *GE; /* global environment scope (at the root) */

	/* execution stack */
	int top, bot;
	js_Value *stack;

	/* garbage collector list */
	int gcpause;
	int gcmark;
	unsigned int gccounter, gcthresh;
	js_Environment *gcenv;
	js_Function *gcfun;
	js_Object *gcobj;
	js_String *gcstr;

	js_Object *gcroot; /* gc scan list */

	/* environments on the call stack but currently not in scope */
	int envtop;
	js_Environment *envstack[JS_ENVLIMIT];

	/* debug info stack trace */
	int tracetop;
	js_StackTrace trace[JS_ENVLIMIT];

	/* exception stack */
	int trytop;
	js_Jumpbuf trybuf[JS_TRYLIMIT];
};

#endif
