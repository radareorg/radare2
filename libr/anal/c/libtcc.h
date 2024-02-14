#ifndef LIBTCC_H
#define LIBTCC_H

#ifdef __cplusplus
extern "C" {
#endif

struct TCCState;

typedef struct TCCState TCCState;

/* create a new TCC compilation context */
R_API TCCState *tcc_new(const char* arch, int bits, const char *os);

/* free a TCC compilation context */
R_API void tcc_delete(TCCState *s);

/* set CONFIG_TCCDIR at runtime */
R_API void tcc_set_lib_path(TCCState *s, const char *path);

/* set error/warning display callback */
typedef void (*TccErrorCallback)(void *opaque, const char *msg);
R_API void tcc_set_error_func(TCCState *s, void *error_opaque, TccErrorCallback error_func);

/* set options as from command line (multiple supported) */
R_API int tcc_set_options(TCCState *s, const char *str);

/*****************************/
/* preprocessor */

/* add include path */
R_API int tcc_add_include_path(TCCState *s, const char *pathname);

/* add in system include path */
R_API int tcc_add_sysinclude_path(TCCState *s, const char *pathname);

/* define preprocessor symbol 'sym'. Can put optional value */
R_API void tcc_define_symbol(TCCState *s, const char *sym, const char *value);

/* undefine preprocess symbol 'sym' */
R_API void tcc_undefine_symbol(TCCState *s, const char *sym);

/*****************************/
/* compiling */

/* add a file (C file, dll, object, library, ld script). Return -1 if error. */
R_API int tcc_add_file(TCCState *s, const char *filename, const char *dir);

/* compile a string containing a C source. Return -1 if error. */
R_API int tcc_compile_string(TCCState *s, const char *buf);

/*****************************/
/* linking commands */

/* set output type. MUST BE CALLED before any compilation */
R_API int tcc_set_output_type(TCCState *s, int output_type);
#define TCC_OUTPUT_MEMORY   0 /* output will be run in memory (default) */
#define TCC_OUTPUT_EXE      1 /* executable file */
#define TCC_OUTPUT_DLL      2 /* dynamic library */
#define TCC_OUTPUT_OBJ      3 /* object file */
#define TCC_OUTPUT_PREPROCESS 4 /* only preprocess (used internally) */

/* equivalent to -Lpath option */
R_API int tcc_add_library_path(TCCState *s, const char *pathname);

/* the library name is the same as the argument of the '-l' option */
R_API int tcc_add_library(TCCState *s, const char *libraryname);

/* add a symbol to the compiled program */
R_API int tcc_add_symbol(TCCState *s, const char *name, const void *val);

/* output an executable, library or object file. DO NOT call
   tcc_relocate() before. */
R_API int tcc_output_file(TCCState *s, const char *filename);

/* link and run main() function and return its value. DO NOT call
   tcc_relocate() before. */
R_API int tcc_run(TCCState *s, int argc, char **argv);

/* do all relocations (needed before using tcc_get_symbol()) */
R_API int tcc_relocate(TCCState *s1, void *ptr);
/* possible values for 'ptr':
   - TCC_RELOCATE_AUTO : Allocate and manage memory internally
   - NULL              : return required memory size for the step below
   - memory address    : copy code to memory passed by the caller
   returns -1 if error. */
#define TCC_RELOCATE_AUTO (void*)1

/* return symbol value or NULL if not found */
R_API void *tcc_get_symbol(TCCState *s, const char *name);

typedef void (*TccCallback)(const char *, char **);

R_API void tcc_set_callback(TCCState *s, TccCallback cb, char **p);

#ifdef __cplusplus
}
#endif

#endif
