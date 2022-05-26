#ifndef HAVE_FORK
#define HAVE_FORK 1
#endif

#if HAVE_FORK
# if TARGET_OS_IPHONE || APPLE_SDK_IPHONEOS || APPLE_SDK_IPHONESIMULATOR
#  define SPP_HAVE_SYSTEM 0
# else
#  define SPP_HAVE_SYSTEM 1
# endif
#else
# define SPP_HAVE_SYSTEM 0
#endif

#if SPP_HAVE_SYSTEM
#include "p/sh.h"
#endif

#include "p/spp.h"
#include "p/acr.h"
#include "p/pod.h"
#include "p/cpp.h"

struct Proc *procs[] = {
	&spp_proc,
	&cpp_proc,
	&pod_proc,
	&acr_proc,
#if SPP_HAVE_SYSTEM
	&sh_proc,
#endif
	NULL
};

DEFAULT_PROC(spp)

#define DEBUG 0
