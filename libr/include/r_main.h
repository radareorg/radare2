/* radare - LGPL - Copyright 2008-2026 - pancake */

#ifndef R2_MAIN_H
#define R2_MAIN_H

#include <r_types.h>
#include <r_getopt.h>
#include <r_cons.h>

#ifdef __cplusplus
extern "C" {
#endif


R_LIB_VERSION_HEADER(r_main);

typedef int (*RMainCallback)(RCons *cons, int argc, const char **argv);

typedef struct r_main_t {
	const char *name;
	RMainCallback main;
} RMain;

R_API RMain *r_main_new(const char *name);
R_API void r_main_free(RMain *m);
R_API int r_main_run(RMain *m, RCons *cons, int argc, const char **argv);

R_API int r_main_version_print(RCons *cons, const char *program, int rad);
R_API int r_main_ravc2(RCons *cons, int argc, const char **argv);
R_API int r_main_rax2(RCons *cons, int argc, const char **argv);
R_API int r_main_rarun2(RCons *cons, int argc, const char **argv);
R_API int r_main_rahash2(RCons *cons, int argc, const char **argv);
R_API int r_main_rabin2(RCons *cons, int argc, const char **argv);
R_API int r_main_radare2(RCons *cons, int argc, const char **argv);
R_API int r_main_rasm2(RCons *cons, int argc, const char **argv);
R_API int r_main_r2agent(RCons *cons, int argc, const char **argv);
R_API int r_main_rafind2(RCons *cons, int argc, const char **argv);
R_API int r_main_radiff2(RCons *cons, int argc, const char **argv);
R_API int r_main_ragg2(RCons *cons, int argc, const char **argv);
R_API int r_main_rasign2(RCons *cons, int argc, const char **argv);
R_API int r_main_r2pm(RCons *cons, int argc, const char **argv);
R_API int r_main_rapatch2(RCons *cons, int argc, const char **argv);
R_API int r_main_rafs2(RCons *cons, int argc, const char **argv);
R_API bool r_main_buildflags(char **out_cflags, char **out_ldflags, char **out_libs);

#ifdef __cplusplus
}
#endif

#endif
