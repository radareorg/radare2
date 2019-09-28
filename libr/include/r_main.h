/* radare - LGPL - Copyright 2008-2019 - pancake */

#ifndef R2_MAIN_H
#define R2_MAIN_H

#include <r_types.h>

R_LIB_VERSION_HEADER(r_main);

typedef struct r_main_t {
	char *name;
	int (*main)(int argc, char **argv);
	// stdin/stdout
} RMain;

typedef int (*RMainCallback)(int argc, char **argv);

R_API RMain *r_main_new(const char *name);
R_API void r_main_free(RMain *m);
R_API int r_main_run(RMain *m, int argc, char **argv);

R_API int r_main_version_print(const char *program);
R_API int r_main_rax2(int argc, char **argv);
R_API int r_main_rarun2(int argc, char **argv);
R_API int r_main_rahash2(int argc, char **argv);
R_API int r_main_rabin2(int argc, char **argv);
R_API int r_main_radare2(int argc, char **argv);
R_API int r_main_rasm2(int argc, char **argv);
R_API int r_main_r2agent(int argc, char **argv);
R_API int r_main_rafind2(int argc, char **argv);
R_API int r_main_radiff2(int argc, char **argv);
R_API int r_main_ragg2(int argc, char **argv);

#endif
