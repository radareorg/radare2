/* radare - LGPL - Copyright 2020 - pancake */

#include <r_arch.h>
#include <r_asm.h>
#include "../config.h"

static RArchPlugin *arch_static_plugins[] = { R_ARCH_STATIC_PLUGINS };

static void plugin_free(RArchPlugin *p) {
	if (p && p->fini) {
		p->fini (NULL);
	}
}

static bool is_valid(RArch *a, const char *name) {
        RArchPlugin *h;
        RListIter *iter;
        if (!name || !*name) {
                return false;
        }
        r_list_foreach (a->plugins, iter, h) {
                if (!strcmp (h->name, name)) {
                        return true;
                }
        }
        return false;
}

R_API RArch *r_arch_new() {
	RArch *a = R_NEW0 (RArch);
	a->setup.bits = R_SYS_BITS;
	a->setup.endian = R_SYS_ENDIAN_LITTLE;
        a->plugins = r_list_newf ((RListFree)plugin_free);
        if (!a->plugins) {
                free (a);
                return NULL;
        }
	size_t i;
        for (i = 0; arch_static_plugins[i]; i++) {
                r_arch_add (a, arch_static_plugins[i]);
        }
	return a;
}

R_API void r_arch_free(RArch *arch) {
	free (arch);
}

// attributes

static bool has_bits(RArchPlugin *h, RArchBits bits) {
        return (h && h->bits && (bits & h->bits));
}

R_API bool r_arch_set_cpu(RArch *a, const char *cpu) {
	// TODO: check if cpu is valid for the selected plugin
	if (a) {
		free (a->setup.cpu);
		a->setup.cpu = cpu? strdup (cpu): NULL;
	}
	return true;
}

R_API bool r_arch_setup(RArch *a, const char *arch, RArchBits bits, RArchEndian endian) {
	r_return_val_if_fail (a && arch, false);
	bool ret = !r_arch_use (a, arch);
	r_arch_set_endian (a, endian);
	return ret | !r_arch_set_bits (a, bits);
}

R_API bool r_arch_set_syntax(RArch *a, int syntax) {
	r_return_val_if_fail (a, false);
	switch (syntax) {
	case R_ASM_SYNTAX_REGNUM:
	case R_ASM_SYNTAX_INTEL:
	case R_ASM_SYNTAX_MASM:
	case R_ASM_SYNTAX_ATT:
	case R_ASM_SYNTAX_JZ:
		a->setup.syntax = syntax;
		return true;
	default:
		return false;
	}
}

R_API bool r_arch_set_endian(RArch *a, RArchEndian endian) {
	r_return_val_if_fail (a, false);
	switch (endian) {
	case R_SYS_ENDIAN_LITTLE:
	case R_SYS_ENDIAN_BIG:
	case R_SYS_ENDIAN_NONE:
	case R_SYS_ENDIAN_BI:
		a->setup.endian = endian;
		return true;
	}
	return false;
}

R_API bool r_arch_set_bits(RArch *a, int bits) {
	r_return_val_if_fail (a, false);
	if (has_bits (a->cur, bits)) {
		a->setup.bits = bits;
		return true;
	}
	return false;
}

// plugins

R_API bool r_arch_use(RArch *a, const char *name) {
	r_return_val_if_fail (a && a->plugins, false);

	if (!name || !*name) {
		a->cur = NULL;
		return true;
	}
        RArchPlugin *h;
        RListIter *iter;
        r_list_foreach (a->plugins, iter, h) {
                if (!strcmp (h->name, name) && h->arch) {
                        a->cur = h;
                        return true;
                }
        }
        return false;
}

R_API bool r_arch_encode(RArch *a, RArchInstruction *ins, RArchOptions opt) {
	r_return_val_if_fail (a, false);
	if (a->cur && a->cur->encode) {
		return a->cur->encode (a, ins, opt);
	}
	return false;
}

R_API bool r_arch_decode(RArch *a, RArchInstruction *ins, RArchOptions opt) {
	r_return_val_if_fail (a, false);
	if (a->cur && a->cur->decode) {
		return a->cur->decode (a, ins, opt);
	}
	return false;
}

R_API bool r_arch_add(RArch *a, RArchPlugin *foo) {
	r_return_val_if_fail (a && foo, false);
        if (foo->init) {
                foo->init (a);
        }
	if (!is_valid (a, foo->name)) {
		r_list_append (a->plugins, foo);
		return true;
	}
	return false;
}

R_API bool r_arch_del(RArch *a, const char *name) {
	r_return_val_if_fail (a, false);
	/* TODO: Implement r_arch_del */
	return false;
}

