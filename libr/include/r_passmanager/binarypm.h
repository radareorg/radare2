#ifndef _BINARY_PM_H
#define _BINARY_PM_H

#include <r_anal.h>

#undef TYPE_NAME
#undef TYPE
#undef PMFN_

#define TYPE_NAME RBin
#define TYPE RBin
#define PMFN_(name) bpm_##name

#include "pm_inc.h"

#endif
