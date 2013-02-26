#ifndef _INCLUDE_SYSDEP_H_
#define _INCLUDE_SYSDEP_H_

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <stdlib.h>
typedef unsigned int uint32_t;
typedef unsigned long long uint64_t;
#include "mybfd.h"
#if 0
#define bfd_boolean int
#define bfd_vma unsigned long long
#endif
#define TRUE 1
#define FALSE 0
#include "aarch64.h"

#endif
