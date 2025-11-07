#ifndef R_GETOPT_H
#define R_GETOPT_H 1

#ifdef __cplusplus
extern "C" {
#endif

#include <r_util.h>

typedef struct r_getopt_t {
	bool err;
	int ind;
	int opt;
	const char *arg;
	// ...
	int argc;
	const char **argv;
	const char *ostr;
} RGetopt;

R_API void r_getopt_init(RGetopt *go, int argc, const char **argv, const char *ostr);
R_API int r_getopt_next(RGetopt *opt);

#ifdef __cplusplus
}
#endif

#endif
