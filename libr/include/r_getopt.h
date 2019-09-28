#include <r_util.h>

/*

At some point we should have a working and reliable implementation
of getopt to work on any operating system independently of the libc

Duplicated code in here:

* libr/util/getopt.c

*/

#if __WINDOWS__

#ifndef GETOPT_C
__declspec(dllimport) int r_optind;
__declspec(dllimport) char *r_optarg;
#endif
R_API int r_getopt(int nargc, char * const *nargv, const char *ostr);

#else

#include <getopt.h>
#define r_getopt getopt
#define r_optind optind
#define r_optarg optarg

#endif
