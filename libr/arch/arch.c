/* radare - LGPL - Copyright 2022-2023 - pancake, condret */

#include <r_arch.h>
#include <config.h>

static const RArchPlugin * const arch_static_plugins[] = { R_ARCH_STATIC_PLUGINS };

static void plugin_free(void *p) {
	// XXX
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
	a->num = r_num_new (NULL, NULL, NULL);
	a->cfg = r_arch_config_new ();
	ut32 i = 0;
	while (arch_static_plugins[i]) {
		r_arch_plugin_add (a, (RArchPlugin*)arch_static_plugins[i++]);
	}
	return a;
}

static ut32 _rate_compat(RArchPlugin *p, RArchConfig *cfg, const char *name) {
	ut32 bits = cfg->bits;
	ut32 score = 0;
	if (name && !strcmp (p->meta.name, name)) {
		score += 100;
	}
	//eprintf ("compare %s %s\n", p->arch, cfg->arch);
	if (cfg->arch && !strcmp (p->arch, cfg->arch)) {
		score += 50;
	}
	if (score > 0) {
		if (strstr (p->meta.name, ".nz")) {
			score += 50;
		}
		if (R_SYS_BITS_CHECK (p->bits, bits)) {
			score += (!!score) * 30;
		}
		if (p->endian & cfg->endian) {
			score += (!!score) * 20;
		}
	}
	return score;
}

static RArchPlugin *find_bestmatch(RArch *arch, RArchConfig *cfg, const char *name, bool enc) {
	ut8 best_score = 0;
	RArchPlugin *ap = NULL;
	RListIter *iter;
	RArchPlugin *p;
	r_list_foreach (arch->plugins, iter, p) {
#if 1
		if (enc) {
			if (!p->encode) {
				continue;
			}
		} else {
			if (!p->decode) {
				continue;
			}
		}
#else
		if (enc && !p->encode) {
			continue;
		}
#endif
		const ut32 score = _rate_compat (p, cfg, name);
		if (score > 0 && score > best_score) {
			best_score = score;
			ap = p;
		}
	}
	// fallback: retry accepting only encoders just in case
	if (!ap) {
		RListIter *iter;
		RArchPlugin *p;
		r_list_foreach (arch->plugins, iter, p) {
			if (enc && !p->encode) {
				continue;
			}
			const ut32 score = _rate_compat (p, cfg, name);
			if (score > 0 && score > best_score) {
				best_score = score;
				ap = p;
			}
		}
	}
	return ap;
}

// use config as new arch config and use matching decoder as current
// must return arch->current, and remove that field. and use refcounting
R_API bool r_arch_use(RArch *arch, RArchConfig *config, const char *name) {
	r_return_val_if_fail (arch, false);
	if (!config) {
		config = arch->cfg;
	}
#if 0
	if (arch->session && !strcmp (name, arch->session->plugin->name)) {
		R_LOG_WARN ("already set%c", 10);
		arch->cfg = config;
		return true;
	}
	if (config && arch->cfg == config) {
		return true;
	}
#endif
	RArchPlugin *ap = find_bestmatch (arch, config, name, false);
	if (!ap) {
		r_unref (arch->session);
		arch->session = NULL;
		return false;
	}
	r_unref (arch->session);
	arch->session = r_arch_session (arch, config, ap);
	if (arch->session && !arch->session->encoder) {
		RArchPluginEncodeCallback encode = arch->session->plugin->encode;
		if (encode) {
			arch->session->encoder = arch->session;
		} else {
			free (config->arch);
			config->arch = strdup (arch->session->plugin->arch);
			RArchPlugin *ap = find_bestmatch (arch, config, name, true);
			if (ap) {
				RArchSession *es = r_arch_session (arch, config, ap);
				if (es && es->plugin == arch->session->plugin) {
					r_unref (es);
				} else if (es) {
					arch->session->encoder = es;
				}
			}
		}
	}
#if 0
	RArchConfig *oconfig = arch->cfg;
	r_unref (arch->cfg);
	arch->cfg = config;
	r_ref (arch->cfg);
	r_unref (oconfig);
#endif
	return true;
}

R_API bool r_arch_use_decoder(RArch *arch, const char *dname) {
	RArchConfig *cfg = r_arch_config_clone (arch->cfg);
	bool r = r_arch_use (arch, cfg, dname);
	if (!r) {
		r_unref (cfg);
	}
	return r;
}

R_API bool r_arch_use_encoder(RArch *arch, const char *dname) {
	/// XXX this should be storing the plugin in a separate pointer
	return r_arch_use (arch, arch->cfg, dname);
}

// set bits and update config
// This api conflicts with r_arch_config_set_bits
R_API bool r_arch_set_bits(RArch *arch, ut32 bits) {
	// XXX unused??
	r_return_val_if_fail (arch && bits, false);
	if (!arch->cfg) {
		RArchConfig *cfg = r_arch_config_new ();
		if (!cfg) {
			return false;
		}
		// TODO: check if archplugin supports those bits?
		// r_arch_config_set_bits (arch->cfg, bits);
		cfg->bits = bits;
		if (!r_arch_use (arch, cfg, NULL)) {
			r_unref (cfg);
			arch->cfg = NULL;
			return false;
		}
		return true;
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
	arch->cfg->endian = endian;
	return true;
}

R_API bool r_arch_set_arch(RArch *arch, char *archname) {
	// Rename to _use_arch instead ?
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
	free (arch->cfg->arch);
	arch->cfg->arch = _arch;
	return true;
}

R_API bool r_arch_plugin_add(RArch *a, RArchPlugin *ap) {
	r_return_val_if_fail (a && ap, false);
	if (!ap->meta.name || !ap->arch) {
		return false;
	}
	return r_list_append (a->plugins, ap) != NULL;
}

R_API bool r_arch_plugin_remove(RArch *arch, RArchPlugin *ap) {
	// R2_590 TODO
	return true;
}

R_API bool r_arch_del(RArch *arch, const char *name) {
	r_return_val_if_fail (arch && arch->plugins && name, false);
	RArchPlugin *ap = find_bestmatch (arch, NULL, name, false);
#if 0
	if (arch->current && !strcmp (arch->current->p->name, name)) {
		arch->current = NULL;
	}
#endif
	r_list_delete_data (arch->plugins, ap);
	return false;
}

R_API void r_arch_free(RArch *arch) {
	if (arch) {
		r_list_free (arch->plugins);
		r_unref (arch->cfg);
		free (arch);
	}
}

// query must be ut32!
R_API int r_arch_info(RArch *a, int query) {
	// XXX should be unused, because its not tied to a session
	RArchSession *session = R_UNWRAP2 (a, session);
	RArchPluginInfoCallback info = R_UNWRAP4 (a, session, plugin, info);
	return info? info (session, query): -1;
}

R_API bool r_arch_encode(RArch *a, RAnalOp *op, RArchEncodeMask mask) {
	RArchSession *session = a->session;
	RArchPluginEncodeCallback encode = R_UNWRAP3 (session, plugin, encode);
	if (!encode && session->encoder) {
		session = session->encoder;
		encode = R_UNWRAP3 (session, plugin, encode);
	}
	return encode? encode (session, op, mask): false;
}

R_API bool r_arch_decode(RArch *a, RAnalOp *op, RArchDecodeMask mask) {
	// XXX should be unused
	RArchPluginEncodeCallback decode = R_UNWRAP4 (a, session, plugin, decode);
	bool res = false;
	if (decode) {
		res = decode (a->session, op, mask);
		if (!res) {
			int align = r_arch_info (a, R_ARCH_INFO_ALIGN);
			if (align < 1) {
				align = 1;
			}
			int minop = r_arch_info (a, R_ARCH_INFO_INV_OP_SIZE);
			// adjust mininstr and align
			int remai = (op->addr + minop) % align;
			if (align > 1 && remai) {
				op->size = remai;
			} else {
				op->size = minop;
			}
			if (mask & R_ARCH_OP_MASK_DISASM) {
				if (!op->mnemonic) {
					op->mnemonic = strdup ("invalid");
				}
			}
		}
	}
	return res;
}
