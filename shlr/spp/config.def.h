#include "p/sh.h"
#include "p/spp.h"
#include "p/acr.h"
#include "p/pod.h"
#include "p/cpp.h"
#include "p/asm.h"

struct Proc *procs[] = {
	&spp_proc,
	&cpp_proc,
	&pod_proc,
	&acr_proc,
	&sh_proc,
	&asm_proc,
	NULL
};

DEFAULT_PROC(spp)

#define DEBUG 0
