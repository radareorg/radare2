/* radare - LGPL - Copyright 2021-2026 - pancake */

#include <r_syscall.h>

#if HAVE_GPERF
extern SdbGperf gperf_darwin_arm_32;
extern SdbGperf gperf_darwin_arm_64;
extern SdbGperf gperf_darwin_x86_32;
extern SdbGperf gperf_darwin_x86_64;
extern SdbGperf gperf_dos_x86_16;
extern SdbGperf gperf_freebsd_x86_32;
extern SdbGperf gperf_ios_arm_32;
extern SdbGperf gperf_ios_arm_64;
extern SdbGperf gperf_ios_x86_32;
extern SdbGperf gperf_linux_arm_32;
extern SdbGperf gperf_linux_arm_64;
extern SdbGperf gperf_linux_mips_32;
extern SdbGperf gperf_linux_sparc_32;
extern SdbGperf gperf_linux_x86_32;
extern SdbGperf gperf_linux_x86_64;
extern SdbGperf gperf_netbsd_x86_32;
extern SdbGperf gperf_openbsd_x86_32;
extern SdbGperf gperf_openbsd_x86_64;
extern SdbGperf gperf_s110_arm_16;
extern SdbGperf gperf_windows_x86_32;
extern SdbGperf gperf_windows_x86_64;

static const SdbGperf *gperfs[] = {
	&gperf_darwin_arm_32,
	&gperf_darwin_arm_64,
	&gperf_darwin_x86_32,
	&gperf_darwin_x86_64,
	&gperf_dos_x86_16,
	&gperf_freebsd_x86_32,
	&gperf_ios_arm_32,
	&gperf_ios_arm_64,
	&gperf_ios_x86_32,
	&gperf_linux_arm_32,
	&gperf_linux_arm_64,
	&gperf_linux_mips_32,
	&gperf_linux_sparc_32,
	&gperf_linux_x86_32,
	&gperf_linux_x86_64,
	&gperf_netbsd_x86_32,
	&gperf_openbsd_x86_32,
	&gperf_openbsd_x86_64,
	&gperf_s110_arm_16,
	&gperf_windows_x86_32,
	&gperf_windows_x86_64,
	NULL
};

R_API SdbGperf *r_syscall_get_gperf(const char *k) {
	SdbGperf **gp = (SdbGperf**)gperfs;
	while (*gp) {
		SdbGperf *g = *gp;
		if (!strcmp (k, g->name)) {
			return *gp;
		}
		gp++;
	}
	return NULL;
}
#else
R_API SdbGperf *r_syscall_get_gperf(const char *k) {
	return NULL;
}
#endif
