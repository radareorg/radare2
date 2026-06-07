/* radare2 - LGPL - Copyright 2022-2024 - pancake */

#include <r_arch.h>

static void _ac_free(RArchConfig *cfg) {
	if (cfg) {
		free (cfg->decoder);
//		free (cfg->arch);
		free (cfg->abi);
		free (cfg->cpu);
		free (cfg->os);
		free (cfg);
	}
}

R_API void r_arch_config_free(RArchConfig *r) {
	if (r) {
		r_unref (r);
	}
}

R_API void r_arch_config_use(RArchConfig *config, const char * R_NULLABLE arch) {
	R_RETURN_IF_FAIL (config);
	if (arch && !strcmp (arch, "null")) {
		return;
	}
	if (arch) {
		r_str_ncpy (config->arch, arch, sizeof (config->arch));
	}
}

R_API bool r_arch_config_iseq(RArchConfig *a, RArchConfig *b) {
	R_RETURN_VAL_IF_FAIL (a && b, false);
	return false;
}

R_API void r_arch_config_set_cpu(RArchConfig *config, const char * R_NULLABLE cpu) {
	R_RETURN_IF_FAIL (config);
	// R_LOG_DEBUG ("RArch.CPU (%s)", cpu);
	free (config->cpu);
	config->cpu = R_STR_ISNOTEMPTY (cpu) ? strdup (cpu) : NULL;
}

R_API RList *r_arch_plugin_cpus(RArchPlugin *plugin) {
	R_RETURN_VAL_IF_FAIL (plugin, NULL);
	return plugin->cpus
		? r_str_split_duplist (plugin->cpus, ",", true)
		: r_list_newf (free);
}

// Returns the canonical (plugin-cased) spelling of `cpu` for `plugin`, or NULL
// if `cpu` is not a valid CPU. The empty string is valid (the default cpu), the
// arch/plugin name is always accepted, and a plugin that exposes no cpu list
// accepts any value, preserving old behavior.
R_API char *r_arch_plugin_cpu_canonical(RArchPlugin *plugin, const char *cpu) {
	R_RETURN_VAL_IF_FAIL (plugin, NULL);
	if (R_STR_ISEMPTY (cpu)) {
		return strdup ("");
	}
	if (plugin->meta.name && !r_str_casecmp (plugin->meta.name, cpu)) {
		return strdup (plugin->meta.name);
	}
	if (plugin->arch && !r_str_casecmp (plugin->arch, cpu)) {
		return strdup (plugin->arch);
	}
	if (R_STR_ISEMPTY (plugin->cpus)) {
		return strdup (cpu);
	}
	char *res = NULL, *word;
	RListIter *iter;
	RList *cpus = r_arch_plugin_cpus (plugin);
	r_list_foreach (cpus, iter, word) {
		if (!r_str_casecmp (word, cpu)) {
			res = strdup (word);
			break;
		}
	}
	r_list_free (cpus);
	return res;
}

R_API bool r_arch_config_set_bits(RArchConfig *config, int bits) {
	R_RETURN_VAL_IF_FAIL (config, false);
	// if the config is tied to a session, there must be a callback to notify the plugin
	// that the config has chnaged and act accordingly. this is,
	bool is_valid = true;
#if 0
	if (config->setbits) {
		is_valid = config->setbits (config, bits);
	}
#endif
	if (is_valid) {
		config->bits = bits;
	}
	return is_valid;
}

R_API bool r_arch_config_set_syntax(RArchConfig *config, int syntax) {
	switch (syntax) {
	case R_ARCH_SYNTAX_REGNUM:
	case R_ARCH_SYNTAX_INTEL:
	case R_ARCH_SYNTAX_MASM:
	case R_ARCH_SYNTAX_ATT:
	case R_ARCH_SYNTAX_JZ:
	case R_ARCH_SYNTAX_CAMEL:
		config->syntax = syntax;
		return true;
	default:
		return false;
	}
}

R_API RArchConfig *r_arch_config_clone(RArchConfig *c) {
	R_RETURN_VAL_IF_FAIL (c, NULL);
	RArchConfig *ac = R_NEW0 (RArchConfig);
	r_str_ncpy (ac->arch, c->arch, sizeof (c->arch));
	ac->abi = c->abi? strdup (c->abi): NULL;
	ac->cpu = c->cpu? strdup (c->cpu): NULL;
	ac->os = c->os? strdup (c->os): NULL;
	ac->decoder = c->decoder? strdup (c->decoder): NULL;
	ac->bits = c->bits;
	ac->endian = c->endian;
	ac->syntax = c->syntax;
	ac->codealign = c->codealign;
	ac->dataalign = c->dataalign;
	ac->addrbytes = c->addrbytes;
	ac->segbas = c->segbas;
	ac->seggrn = c->seggrn;
	ac->invhex = c->invhex;
	ac->bitshift = c->bitshift;
	ac->gp = c->gp;
	ac->cfloat_profile = c->cfloat_profile;
	r_ref_init (ac, &_ac_free);
	return ac;
}

R_API RArchConfig *r_arch_config_new(void) {
	RArchConfig *ac = R_NEW0 (RArchConfig);
	if (!ac) {
		return NULL;
	}
	r_str_ncpy (ac->arch, R_SYS_ARCH, sizeof (ac->arch));
	ac->bits = R_SYS_BITS_CHECK (R_SYS_BITS, 64)? 64: 32;
	ac->bitshift = 0;
	ac->syntax = R_ARCH_SYNTAX_INTEL;
	r_ref_init (ac, &_ac_free);
	ac->endian = R_SYS_ENDIAN_NONE;
	ac->cfloat_profile = R_CFLOAT_PROFILE_BINARY64; // default
	return (RArchConfig *)ac;
}
