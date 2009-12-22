%module r_util
%{
#include "../libr/include/r_util.h"
%}
/* stabilized */
#define R_SWIG 1
%include "../libr/include/r_util.h"

#if 0
%typemap(in) ut64 * {
//#ifdef SWIG<PYTHON>
#define HAVE_LONG_LONG 1
#if HAVE_LONG_LONG
        $result = ($type) PyLong_AsUnsignedLongLong ($1);
#else
#warning python without long long support??
#endif

// .. support for perl, ruby ..
//#endif
}
#endif

%extend Num {
        Num () {
                return r_num_new (NULL, NULL);
        }
        unsigned long long get (char *foo) {
                return r_num_get (self, foo);
        }
        unsigned long long math (char *foo) {
                return r_num_math (self, foo);
        }
/*
        static void minmap_swap (int *OUTPUT, int *OUTPUT) {
                r_num_minmap_swap_i ( ... )
        }
*/
};
