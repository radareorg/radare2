#ifndef _INCLUDE_SPP_H_
#define _INCLUDE_SPP_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdbool.h>
#include <errno.h>

#ifdef S_API
#undef S_API
#endif
#if R_SWIG
  #define S_API export
#elif R_INLINE
  #define S_API inline
#else
  #if defined(__GNUC__) && __GNUC__ >= 4
    #define S_API __attribute__((visibility("default")))
  #elif defined(_MSC_VER)
    #define S_API __declspec(dllexport)
  #else
    #define S_API
  #endif
#endif

#if defined(EMSCRIPTEN) || defined(__linux__) || defined(__APPLE__) || defined(__GNU__) || defined(__ANDROID__) || defined(__QNX__)
  #define __BSD__ 0
  #define __UNIX__ 1
#endif
#if __KFBSD__ || defined(__NetBSD__) || defined(__OpenBSD__)
  #define __BSD__ 1
  #define __UNIX__ 1
#endif
#if __WIN32__ || __CYGWIN__ || MINGW32
  #define __addr_t_defined
  #include <windows.h>
#endif
#if __WIN32__ || MINGW32 && !__CYGWIN__ || _MSC_VER
  #ifndef _MSC_VER
    #include <winsock.h>
  #endif
  typedef int socklen_t;
  #undef USE_SOCKETS
  #define __WINDOWS__ 1
  #undef __UNIX__
  #undef __BSD__
#endif

#ifdef __WINDOWS__
#include <io.h>
#define popen    _popen
#define pclose   _pclose
#define srandom  srand
#define snprintf _snprintf
#endif

#define VERSION "1.0"

#define MAXIFL 128

#ifndef HAVE_FORK
#define HAVE_FORK 1
#endif

#ifndef HAVE_FORK
#define HAVE_FORK 1
#endif

#ifndef DLL_LOCAL
#ifdef _MSC_VER
#define DLL_LOCAL
#else
#define DLL_LOCAL  __attribute__ ((visibility ("hidden")))
#endif
#endif

#define GET_ARG(x,y,i) if (y[i][2]) x = y[i] + 2; else x = y[++i]

#define DEFAULT_PROC(x) \
struct Tag *tags = (struct Tag *)&x##_tags; \
struct Arg *args = (struct Arg *)&x##_args; \
struct Proc *proc = &x##_proc;

#if USE_R2
#include <r_util.h>
#define SStrBuf RStrBuf
#else
typedef struct s_strbuf_t {
	int len;
	char *ptr;
	int ptrlen;
	char buf[64];
} SStrBuf;
#endif

typedef struct {
	SStrBuf *cout;
	FILE *fout;
	int size;
} Output;

typedef struct SppState {
	int lineno;
	int echo[MAXIFL];
	int ifl;
} SppState;

typedef struct SppBuf {
    char *lbuf;
    int lbuf_s;
    int lbuf_n;
} SppBuf;

#define ARG_CALLBACK(x) int x (char *arg)
/* XXX swap arguments ?? */
#define TAG_CALLBACK(x) int x (SppState *state, Output *out, char *buf)
#define PUT_CALLBACK(x) int x (Output *out, char *buf)
#define IS_SPACE(x) ((x==' ')||(x=='\t')||(x=='\r')||(x=='\n'))

struct Tag {
	const char *name;
	TAG_CALLBACK((*callback));
};

struct Arg {
	const char *flag;
	const char *desc;
	int has_arg;
	ARG_CALLBACK((*callback));
};

struct Proc {
	const char *name;
	struct Tag **tags;
	struct Arg **args;
	TAG_CALLBACK ((*eof));
	PUT_CALLBACK ((*fputs));
	char *tag_pre;
	char *tag_post;
	char *token;
	char *multiline;
	int chop;
	int tag_begin;
	int default_echo;
	SppState state;
	SppBuf buf;
};

S_API int spp_file(const char *file, Output *out);
S_API int spp_run(char *buf, Output *out);
S_API void spp_eval(char *buf, Output *out);
S_API void spp_io(FILE *in, Output *out);
S_API void spp_proc_list(void);
S_API void spp_proc_list_kw(void);
S_API void spp_proc_set(struct Proc *p, char *arg, int fail);

#if DEBUG
#define D if (1)
#else
#define D if (0)
#endif

#endif
