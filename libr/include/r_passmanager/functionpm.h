#ifndef _FUNCTION_PM_H
#define _FUNCTION_PM_H

#include <r_anal.h>

#undef TYPE_NAME
#undef TYPE
#undef PMFN_

#define TYPE_NAME Function
#define TYPE RAnalFunction
#define PMFN_(name) fpm_##name

#include "pm_inc.h"

#endif
