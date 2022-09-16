/* radare2 - LGPL - Copyright 2022 - pancake */

#include <r_arch.h>

static void my_ac_free(RArchConfig *cfg) {
	if (cfg) {
		free (cfg->arch);
		free (cfg->cpu);
		free (cfg->os);
		free (cfg);
	}
}

R_API void r_arch_use(RArchConfig *config, R_NULLABLE const char *arch) {
	r_return_if_fail (config);
	// R_LOG_DEBUG ("RArch.USE (%s)", arch);
	if (arch && !strcmp (arch, "null")) {
		return;
	}
	free (config->arch);
	config->arch = R_STR_ISNOTEMPTY (arch) ? strdup (arch) : NULL;
}

R_API void r_arch_set_cpu(RArchConfig *config, R_NULLABLE const char *cpu) {
	r_return_if_fail (config);
	// R_LOG_DEBUG ("RArch.CPU (%s)", cpu);
	free (config->cpu);
	config->cpu = R_STR_ISNOTEMPTY (cpu) ? strdup (cpu) : NULL;
}

R_API void r_arch_set_bits(RArchConfig *config, int bits) {
	r_return_if_fail (config);
	config->bits = bits;
	// callback
	// r_signal_now (config->events, "bits"
	// r_signal_on (config->events, "bits", &cb_bitschange);
}

R_API RArchConfig *r_arch_config_new(void) {
	RArchConfig *ac = R_NEW0 (RArchConfig);
	if (!ac) {
		return NULL;
	}
	ac->arch = strdup (R_SYS_ARCH);
	ac->bits = R_SYS_BITS;
	ac->bitshift = 0;
	ac->syntax = R_ARCH_SYNTAX_INTEL;
	ac->free = (void (*)(void*))my_ac_free;
	ac->big_endian = false;
	return r_ref (ac);
}
