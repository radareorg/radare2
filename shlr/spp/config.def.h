#include "p/sh.h"
#include "p/spp.h"
#include "p/acr.h"
#include "p/pod.h"
#include "p/cpp.h"

#ifdef HAVE_FORK
#define HAVE_FORK 1
#endif

struct Proc *procs[] = {
	&spp_proc,
	&cpp_proc,
	&pod_proc,
	&acr_proc,
	&sh_proc,
	NULL
};

DEFAULT_PROC(spp)

#define DEBUG 0
