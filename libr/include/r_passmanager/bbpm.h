#ifndef _BASIC_BLOCK_PM_H
#define _BASIC_BLOCK_PM_H

#include <r_anal.h>

#undef TYPE_NAME
#undef TYPE
#undef PMFN_

#define TYPE_NAME BasicBlock
#define TYPE RAnalBlock
#define PMFN_(name) bbpm_##name

#include "pm_inc.h"

#endif
