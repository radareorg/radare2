/* radare - LGPL - Copyright 2022 - pancake, condret */

#include <r_arch.h>
#include <config.h>

static const RArchPlugin * const arch_static_plugins[] = { R_ARCH_STATIC_PLUGINS };

static void plugin_free(void *p) {
}

static void _decoder_free_cb(HtPPKv *kv) {
	free (kv->key);
	RArchDecoder *decoder = (RArchDecoder *)kv->value;
	if (decoder->p->fini) {
		decoder->p->fini (decoder->user);
	}
	free (decoder);
}

R_API RArch *r_arch_new(void) {
	RArch *a = R_NEW0 (RArch);
	if (!a) {
		return NULL;
	}
	a->plugins = r_list_newf ((RListFree)plugin_free);
	if (!a->plugins) {
		free (a);
		return NULL;
	}
	a->decoders = ht_pp_new (NULL, _decoder_free_cb, NULL);
	if (!a->decoders) {
		r_list_free (a->plugins);
		free (a);
		return NULL;
	}
	ut32 i = 0;
	while (arch_static_plugins[i]) {
		r_arch_add (a, (RArchPlugin*)arch_static_plugins[i++]);
	}
	return a;
}

static ut32 _rate_compat(RArchPlugin *p, RArchConfig *cfg, const char *name) {
	ut32 bits;
	switch (cfg->bits) {
	case 64:
		bits = R_SYS_BITS_64;
		break;
	case 32:
		bits = R_SYS_BITS_32;
		break;
	case 27:
		bits = R_SYS_BITS_27;
		break;
	case 16:
		bits = R_SYS_BITS_16;
		break;
	case 12:
		bits = R_SYS_BITS_12;
		break;
	case 8:
		bits = R_SYS_BITS_8;
		break;
	case 4:
		bits = R_SYS_BITS_4;
		break;
	default:
		bits = UT32_MAX;
		break;
	}
	ut32 score = 0;
	if (name && !strcmp (p->name, name)) {
		score += 50;
	}
	if (!strcmp (p->arch, cfg->arch)) {
		score += 50;
	}
	if (p->bits & bits) {
		score += (!!score) * 30;
	}
	if (p->endian & cfg->endian) {
		score += (!!score) * 20;
	}
	return score;
}

static char *_find_bestmatch(RList *plugins, RArchConfig *cfg, const char *name) {
	ut8 best_score = 0;
	char *rname = NULL;
	RListIter *iter;
	RArchPlugin *p;
	r_list_foreach (plugins, iter, p) {
		const ut32 score = _rate_compat (p, cfg, name);
		if (score > best_score) {
			best_score = score;
			rname = p->name;
		}
		if (score == 100) {
			break;
		}
	}
	return rname;
}

// use config as new arch config and use matching decoder as current
// must return arch->current, and remove that field. and use refcounting
R_API bool r_arch_use(RArch *arch, RArchConfig *config, const char *name) {
	r_return_val_if_fail (arch, false);
	if (!config) {
		config = arch->cfg;
	}
	if (config && arch->cfg == config) {
		return true;
	}
	if (!config) {
	//	arch->decoder = NULL;
		return false;
	}
	const char *dname = config->decoder ? config->decoder: _find_bestmatch (arch->plugins, config, name);
	if (!dname) {
		return false;
	}
	RArchConfig *oconfig = arch->cfg;
	r_unref (arch->cfg);
	arch->cfg = config;
	r_ref (arch->cfg);
	if (!r_arch_use_decoder (arch, dname)) {
		r_unref (arch->cfg);
		arch->cfg = oconfig;
		r_ref (oconfig);
		r_unref (config);
		arch->current = NULL;
		return false;
	}
	r_unref (oconfig);
	return true;
}

// set bits and update config
// This api conflicts with r_arch_config_set_bits
R_API bool r_arch_set_bits(RArch *arch, ut32 bits) {
	r_return_val_if_fail (arch && bits, false);
	if (!arch->cfg) {
		RArchConfig *cfg = r_arch_config_new ();
		if (!cfg) {
			return false;
		}
		// r_arch_config_set_bits (arch->cfg, bits);
		cfg->bits = bits;
		if (!r_arch_use (arch, cfg, NULL)) {
			r_unref (cfg);
			arch->cfg = NULL;
			return false;
		}
		return true;
	}
	if (arch->autoselect) {
		if (arch->current) {
			const ut32 score = _rate_compat (arch->current->p, arch->cfg, NULL);
			arch->cfg->bits = bits;
			if (!score || score > _rate_compat (arch->current->p, arch->cfg, NULL)) {
				R_FREE (arch->cfg->decoder);
				return r_arch_use (arch, arch->cfg, NULL);
			}
			return true;
		}
		R_FREE (arch->cfg->decoder);
		arch->cfg->bits = bits;
		return r_arch_use (arch, arch->cfg, NULL);
	}
	arch->cfg->bits = bits;
	return true;
}

R_API bool r_arch_set_endian(RArch *arch, ut32 endian) {
	r_return_val_if_fail (arch, false);
	if (!arch->cfg) {
		RArchConfig *cfg = r_arch_config_new ();
		if (!cfg) {
			return false;
		}
		cfg->endian = endian;
		if (!r_arch_use (arch, cfg, NULL)) {
			r_unref (cfg);
			arch->cfg = NULL;
			return false;
		}
		return true;
	}
	if (arch->autoselect) {
		if (arch->current) {
			const ut32 score = _rate_compat (arch->current->p, arch->cfg, NULL);
			arch->cfg->endian = endian;
			if (!score || score > _rate_compat (arch->current->p, arch->cfg, NULL)) {
				R_FREE (arch->cfg->decoder);
				return r_arch_use (arch, arch->cfg, NULL);
			}
			return true;
		}
		R_FREE (arch->cfg->decoder);
		arch->cfg->endian = endian;
		return r_arch_use (arch, arch->cfg, NULL);
	}
	arch->cfg->endian = endian;
	return true;
}

R_API bool r_arch_set_arch(RArch *arch, char *archname) {
	r_return_val_if_fail (arch && archname, false);
	char *_arch = strdup (archname);
	if (!_arch) {
		return false;
	}
	if (!arch->cfg) {
		RArchConfig *cfg = r_arch_config_new ();
		if (!cfg) {
			free (_arch);
			return false;
		}
		free (cfg->arch);
		cfg->arch =_arch;
		if (!r_arch_use (arch, cfg, archname)) {
			r_unref (cfg);
			return false;
		}
		return true;
	}
	if (arch->autoselect) {
		if (arch->current) {
			const ut32 score = _rate_compat (arch->current->p, arch->cfg, archname);
			free (arch->cfg->arch);
			arch->cfg->arch = _arch;
			if (!score || score > _rate_compat (arch->current->p, arch->cfg, archname)) {
				R_FREE (arch->cfg->decoder);
				return r_arch_use (arch, arch->cfg, archname);
			}
			return true;
		}
		R_FREE (arch->cfg->decoder);
		free (arch->cfg->arch);
		arch->cfg->arch = _arch;
		return r_arch_use (arch, arch->cfg, archname);
	}
	free (arch->cfg->arch);
	arch->cfg->arch = _arch;
	return true;
}

R_API bool r_arch_add(RArch *a, RArchPlugin *ap) {
	r_return_val_if_fail (a && ap->name && ap->arch, false);
	return !!r_list_append (a->plugins, ap);
}

static bool _pick_any_decoder_as_current (void *user, const char *dname, const void *dec) {
	RArch *arch = (RArch *)user;
	arch->current = (RArchDecoder *)dec;
	return false;
}

R_API bool r_arch_del(RArch *arch, const char *name) {
	r_return_val_if_fail (arch && arch->plugins && name, false);
	if (arch->current && !strcmp (arch->current->p->name, name)) {
		arch->current = NULL;
	}
	if (arch->decoders) {
		ht_pp_delete (arch->decoders, name);
	}
	RListIter *iter;
	RArchPlugin *p;
	r_list_foreach (arch->plugins, iter, p) {
		if (!strcmp (name, p->name)) {
			r_list_delete (arch->plugins, iter);
			if (!arch->current) {
				ht_pp_foreach (arch->decoders, (HtPPForeachCallback)_pick_any_decoder_as_current, arch);
				if (arch->cfg && arch->cfg->decoder) {
					free (arch->cfg->decoder);
					if (arch->current) {
						arch->cfg->decoder = strdup (arch->current->p->name);
						//also update arch here?
					} else {
						arch->cfg->decoder = NULL;
					}
				}
			}
			return true;
		}
	}
	return false;
}

R_API void r_arch_free(RArch *arch) {
	r_return_if_fail (arch);
	ht_pp_free (arch->decoders);
	r_list_free (arch->plugins);
	r_unref (arch->cfg);
	free (arch);
}

#if 0
R_API int r_arch_info(RArch *a, int query) {
	r_return_val_if_fail (a, -1);
	switch (query) {
	case R_ANAL_ARCHINFO_MIN_OP_SIZE:
	case R_ANAL_ARCHINFO_MAX_OP_SIZE:
	case R_ANAL_ARCHINFO_INV_OP_SIZE:
	case R_ANAL_ARCHINFO_ALIGN:
		if (arch->current && anal->arch->current->archinfo) {
			return arch->current->archinfo (arch, query);
		}
		break;
	}
	return -1;
}
#endif
