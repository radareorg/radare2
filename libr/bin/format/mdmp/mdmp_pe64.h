/* radare2 - LGPL - Copyright 2016 - Davis, Alex Kornitzer */

#ifndef MDMP_PE64_H
#define MDMP_PE64_H

#define R_BIN_PE64 1

#ifdef MDMP_PE_H
#undef MDMP_PE_H
#include "mdmp_pe.h"
#else
#include "mdmp_pe.h"
#undef MDMP_PE_H
#endif

#endif /* MDMP_PE64_H */
