%module r_util
%{
#include "../libr/include/r_util.h"
%}
/* stabilized */
#define R_SWIG 1
%include "../libr/include/r_util.h"
