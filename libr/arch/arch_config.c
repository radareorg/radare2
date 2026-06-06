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

static void set_cpu_canonical(char **canonical, const char *cpu) {
	if (canonical) {
		*canonical = strdup (cpu);
	}
}

static void set_cpu_canonical_n(char **canonical, const char *cpu, size_t len) {
	if (canonical) {
		*canonical = r_str_ndup (cpu, len);
	}
}

static RArchCpuMatch match_cpu_name(const char *name, const char *cpu, char **canonical) {
	R_RETURN_VAL_IF_FAIL (name && cpu, R_ARCH_CPU_MATCH_INVALID);
	if (!strcmp (name, cpu)) {
		set_cpu_canonical (canonical, name);
		return R_ARCH_CPU_MATCH_VALID;
	}
	if (!r_str_casecmp (name, cpu)) {
		set_cpu_canonical (canonical, name);
		return R_ARCH_CPU_MATCH_CANONICALIZED;
	}
	return R_ARCH_CPU_MATCH_INVALID;
}

static RArchCpuMatch match_cpu_aliases(const char **aliases, const char *cpu, char **canonical, const char *name) {
	R_RETURN_VAL_IF_FAIL (name && cpu, R_ARCH_CPU_MATCH_INVALID);
	if (!aliases) {
		return R_ARCH_CPU_MATCH_INVALID;
	}
	int i;
	for (i = 0; aliases[i]; i++) {
		RArchCpuMatch match = match_cpu_name (aliases[i], cpu, NULL);
		if (match != R_ARCH_CPU_MATCH_INVALID) {
			set_cpu_canonical (canonical, name);
			return R_ARCH_CPU_MATCH_CANONICALIZED;
		}
	}
	return R_ARCH_CPU_MATCH_INVALID;
}

static RArchCpuMatch match_cpu_csv(const char *cpus, const char *cpu, char **canonical) {
	R_RETURN_VAL_IF_FAIL (cpu, R_ARCH_CPU_MATCH_INVALID);
	if (R_STR_ISEMPTY (cpus)) {
		return R_ARCH_CPU_MATCH_UNKNOWN_DOMAIN;
	}
	const size_t cpu_len = strlen (cpu);
	const char *p = cpus;
	while (*p) {
		const char *q = strchr (p, ',');
		size_t len = q? q - p: strlen (p);
		if (len && cpu_len == len && !r_str_ncasecmp (p, cpu, len)) {
			set_cpu_canonical_n (canonical, p, len);
			return !strncmp (p, cpu, len)? R_ARCH_CPU_MATCH_VALID: R_ARCH_CPU_MATCH_CANONICALIZED;
		}
		p = q? q + 1: p + len;
	}
	return R_ARCH_CPU_MATCH_INVALID;
}

R_API RList *r_arch_plugin_cpus(RArchPlugin *plugin) {
	R_RETURN_VAL_IF_FAIL (plugin, NULL);
	RList *list = r_list_newf (free);
	if (!list) {
		return NULL;
	}
	if (plugin->cpu_models && plugin->cpu_models_count > 0) {
		size_t i;
		for (i = 0; i < plugin->cpu_models_count; i++) {
			const char *name = plugin->cpu_models[i].name;
			if (R_STR_ISNOTEMPTY (name)) {
				r_list_append (list, strdup (name));
			}
		}
	} else if (plugin->cpus) {
		char *c = strdup (plugin->cpus);
		int i, n = r_str_split (c, ',');
		for (i = 0; i < n; i++) {
			const char *word = r_str_word_get0 (c, i);
			if (R_STR_ISNOTEMPTY (word)) {
				r_list_append (list, strdup (word));
			}
		}
		free (c);
	}
	return list;
}

R_API RArchCpuMatch r_arch_plugin_match_cpu(RArchPlugin *plugin, const char *cpu, char **canonical) {
	R_RETURN_VAL_IF_FAIL (plugin, R_ARCH_CPU_MATCH_INVALID);
	if (canonical) {
		*canonical = NULL;
	}
	if (R_STR_ISEMPTY (cpu)) {
		if (canonical) {
			*canonical = strdup ("");
		}
		return R_ARCH_CPU_MATCH_VALID;
	}
	RArchCpuMatch match = R_ARCH_CPU_MATCH_INVALID;
	if (plugin->meta.name) {
		match = match_cpu_name (plugin->meta.name, cpu, canonical);
		if (match != R_ARCH_CPU_MATCH_INVALID) {
			return match;
		}
	}
	if (plugin->arch) {
		match = match_cpu_name (plugin->arch, cpu, canonical);
		if (match != R_ARCH_CPU_MATCH_INVALID) {
			return match;
		}
	}
	if (plugin->cpu_models && plugin->cpu_models_count > 0) {
		size_t i;
		for (i = 0; i < plugin->cpu_models_count; i++) {
			const RArchCpu *model = &plugin->cpu_models[i];
			if (model->name) {
				match = match_cpu_name (model->name, cpu, canonical);
				if (match != R_ARCH_CPU_MATCH_INVALID) {
					return match;
				}
				match = match_cpu_aliases (model->aliases, cpu, canonical, model->name);
				if (match != R_ARCH_CPU_MATCH_INVALID) {
					return match;
				}
			}
		}
		return R_ARCH_CPU_MATCH_INVALID;
	}
	return match_cpu_csv (plugin->cpus, cpu, canonical);
}

R_API char *r_arch_plugin_cpu_match(RArchPlugin *plugin, const char *cpu) {
	char *canonical = NULL;
	RArchCpuMatch match = r_arch_plugin_match_cpu (plugin, cpu, &canonical);
	if (match == R_ARCH_CPU_MATCH_INVALID) {
		free (canonical);
		return NULL;
	}
	if (match == R_ARCH_CPU_MATCH_UNKNOWN_DOMAIN && !canonical) {
		return strdup (r_str_get (cpu));
	}
	return canonical;
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
