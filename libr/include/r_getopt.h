#include <r_util.h>

/*

At some point we should have a working and reliable implementation
of getopt to work on any operating system independently of the libc

Duplicated code in here:

* libr/util/getopt.c
* libr/include/msvc/getopt.h

*/

#if __WINDOWS__

extern R_API int r_optind;
extern R_API char *r_optarg;
R_API int r_getopt(int nargc, char * const *nargv, const char *ostr);

#else

#include <getopt.h>
#define r_getopt getopt
#define r_optind optind
#define r_optarg optarg

#endif
