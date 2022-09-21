/* radare - LGPL - Copyright 2022 - pancake */

#include <r_arch.h>
#include <config.h>

static const RArchPlugin * const arch_static_plugins[] = { R_ARCH_STATIC_PLUGINS };

static void plugin_free (void *p) {
}

R_API RArch *r_arch_new(void) {
	int i;
	RArch *a = R_NEW0 (RArch);
	if (!a) {
		return NULL;
	}
	a->plugins = r_list_newf ((RListFree)plugin_free);
	if (!a->plugins) {
		free (a);
		return NULL;
	}
	for (i = 0; arch_static_plugins[i]; i++) {
		r_arch_add (a, (RArchPlugin*)arch_static_plugins[i]);
	}
	return NULL;
}

R_API int r_arch_del(RArch *a, const char *name) {
	/* TODO: r_arch_del not implemented */
	return false;
}

R_API bool r_arch_add(RArch *a, RArchPlugin *foo) {
	if (!foo->name) {
		return false;
	}
	// TODO: do more checks
	r_list_append (a->plugins, foo);
	return true;
}

R_API void r_arch_free(RArch *a) {
	free (a);
}

R_API RArchDecoder *r_arch_use(RArch *a, RArchConfig *ac, const char *name) {
	RListIter *iter;
	RArchPlugin *ap = NULL;
	RArchPlugin *p = NULL;
	r_list_foreach (a->plugins, iter, p) {
		if (!strcmp (name, p->name)) {
			ap = p;
			break;
		}
	}
	if (ap) {
		RArchDecoder *ad = R_NEW0 (RArchDecoder);
		ad->data = ap->init ((void *)a, ac);
		ad->p = ap;
		ad->ac = ac; // XXX copy instead of reference?
		return ad;
	}
	return NULL;
}

#if 0
R_API RArchOp *r_arch_decode(RArchDecoder *ad, const ut8 *buf, size_t len) {
	ad->p->decode (ad, buf, len);
	return NULL;
}
#endif
