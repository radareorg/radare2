/* radare - LGPL - Copyright 2022 - pancake, condret */

#include <r_arch.h>
#include <config.h>

static const RArchPlugin * const arch_static_plugins[] = { R_ARCH_STATIC_PLUGINS };

static void plugin_free (void *p) {
}

static void _decoder_free_cb (HtPPKv *kv) {
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

R_API bool r_arch_use(RArch *a, RArchConfig *config) {
	r_return_val_if_fail (a && config && config->arch, false);
	ut32 bits_bits;
	switch (config->bits) {
	case 64:
		bits_bits = R_SYS_BITS_64;
		break;
	case 32:
		bits_bits = R_SYS_BITS_32;
		break;
	case 27:
		bits_bits = R_SYS_BITS_27;
		break;
	case 16:
		bits_bits = R_SYS_BITS_16;
		break;
	case 8:
		bits_bits = R_SYS_BITS_8;
		break;
	default:
		return false;
	}
	char *dname = NULL;
	RArchPlugin *p = NULL;
	RListIter *iter;
	r_list_foreach (a->plugins, iter, p) {
		if (!strcmp (p->arch, config->arch)) {
			//TODO: add more checks here
			if (p->bits & bits_bits) {
				dname = p->name;
			}
		}
	}
	if (!dname) {
		return false;
	}
	r_ref (config);
	if (a->cfg) {
		r_unref (a->cfg);
	}
	r_arch_use_decoder (a, dname);	//use load here?
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

R_API bool r_arch_del(RArch *a, const char *name) {
	r_return_val_if_fail (a && a->plugins && name, false);
	if (a->current && !strcmp (a->current->p->name, name)) {
		a->current = NULL;
	}
	if (a->decoders) {
		ht_pp_delete (a->decoders, name);
	}
	RListIter *iter;
	RArchPlugin *p;
	r_list_foreach (a->plugins, iter, p) {
		if (!strcmp (name, p->name)) {
			r_list_delete (a->plugins, iter);
			if (!a->current) {
				ht_pp_foreach (a->decoders, (HtPPForeachCallback)_pick_any_decoder_as_current, a);
			}
			return true;
		}
	}
	return false;
}

R_API void r_arch_free(RArch *a) {
	r_return_if_fail (a);
	ht_pp_free (a->decoders);
	r_list_free (a->plugins);
	free (a);
}
