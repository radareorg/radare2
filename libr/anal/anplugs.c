/* radare - LGPL - Copyright 2021-2022 - pancake */

#include <r_util.h>
#include <r_asm.h>

#if HAVE_GPERF
extern SdbGperf gperf_cc_arm_16;
extern SdbGperf gperf_cc_arm_32;
extern SdbGperf gperf_cc_arm_64;
extern SdbGperf gperf_cc_avr_8;
// extern SdbGperf gperf_cc_hexagon_32;
extern SdbGperf gperf_cc_m68k_32;
extern SdbGperf gperf_cc_mips_32;
extern SdbGperf gperf_cc_mips_64;
extern SdbGperf gperf_cc_ppc_32;
extern SdbGperf gperf_cc_ppc_64;
extern SdbGperf gperf_cc_riscv_64;
extern SdbGperf gperf_cc_s390_64;
extern SdbGperf gperf_cc_sparc_32;
extern SdbGperf gperf_cc_v850_32;
extern SdbGperf gperf_cc_x86_16;
extern SdbGperf gperf_cc_x86_32;
extern SdbGperf gperf_cc_x86_64;
//extern SdbGperf gperf_cc_xtensa_32;
extern SdbGperf gperf_spec;
extern SdbGperf gperf_types_16;
extern SdbGperf gperf_types_32;
extern SdbGperf gperf_types_64;
extern SdbGperf gperf_types_android;
extern SdbGperf gperf_types_arm_ios_16;
extern SdbGperf gperf_types_arm_ios_32;
extern SdbGperf gperf_types_arm_ios_64;
extern SdbGperf gperf_types_darwin;
extern SdbGperf gperf_types_linux;
extern SdbGperf gperf_types_x86_macos_64;
extern SdbGperf gperf_types;
// #OBJS+=d/types_windows.o
// #OBJS+=d/types_x86_windows_32.o
// #OBJS+=d/types_x86_windows_64.o

static const SdbGperf *gperfs_cc[] = {
	&gperf_cc_arm_16,
	&gperf_cc_arm_32,
	&gperf_cc_arm_64,
	&gperf_cc_avr_8,
	// &gperf_cc_hexagon_32,
	&gperf_cc_m68k_32,
	&gperf_cc_mips_32,
	&gperf_cc_mips_64,
	&gperf_cc_ppc_32,
	&gperf_cc_ppc_64,
	&gperf_cc_riscv_64,
	&gperf_cc_s390_64,
	&gperf_cc_sparc_32,
	&gperf_cc_v850_32,
	&gperf_cc_x86_16,
	&gperf_cc_x86_32,
	&gperf_cc_x86_64,
	// &gperf_cc_xtensa_32,
	NULL
};
static const SdbGperf *gperfs_types[] = {
	&gperf_spec,
	&gperf_types_16,
	&gperf_types_32,
	&gperf_types_64,
	&gperf_types_android,
	&gperf_types_arm_ios_16,
	&gperf_types_arm_ios_32,
	&gperf_types_arm_ios_64,
	&gperf_types_darwin,
	&gperf_types_linux,
	&gperf_types_x86_macos_64,
	&gperf_types,
	NULL
};

R_API SdbGperf *r_anal_get_gperf_cc(const char *k) {
	R_RETURN_VAL_IF_FAIL (k, NULL);
	SdbGperf **gp = (SdbGperf**)gperfs_cc;
	char *kk = strdup (k);
	r_str_replace_char (kk, '_', '-');
	while (*gp) {
		SdbGperf *g = *gp;
		if (!strcmp (kk, g->name)) {
			free (kk);
			return *gp;
		}
		gp++;
	}
	free (kk);
	return NULL;
}

R_API SdbGperf *r_anal_get_gperf_types(const char *k) {
	R_RETURN_VAL_IF_FAIL (k, NULL);
	SdbGperf **gp = (SdbGperf**)gperfs_types;
	char *s = strdup (k);
	r_str_replace_char (s, '-', '_');
	while (*gp) {
		SdbGperf *g = *gp;
		if (!strcmp (s, g->name)) {
			free (s);
			return *gp;
		}
		gp++;
	}
	free (s);
	return NULL;
}
#else
R_API SdbGperf *r_anal_get_gperf_cc(const char * R_NULLABLE k) {
	return NULL;
}

R_API SdbGperf *r_anal_get_gperf_types(const char * R_NULLABLE k) {
	return NULL;
}
#endif

