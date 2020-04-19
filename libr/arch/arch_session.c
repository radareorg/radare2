/* radare - LGPL - Copyright 2020 - pancake */

#include <r_arch.h>
#include <r_asm.h>
#include "../config.h"


static bool r_arch_session_set_cpu(RArchSession *ai, const char *cpu) {
	r_return_val_if_fail (ai, false);
	// TODO: check if cpu is valid for the selected plugin
	if (ai) {
		free (ai->setup.cpu);
		ai->setup.cpu = cpu? strdup (cpu): NULL;
		return true;
	}
	return false;
}

static bool r_arch_session_set_syntax(RArchSession *ai, RArchSyntax syntax) {
	r_return_val_if_fail (ai, false);
	switch (syntax) {
	case R_ASM_SYNTAX_REGNUM:
	case R_ASM_SYNTAX_INTEL:
	case R_ASM_SYNTAX_MASM:
	case R_ASM_SYNTAX_ATT:
	case R_ASM_SYNTAX_JZ:
		ai->setup.syntax = syntax;
		return true;
	default:
		return false;
	}
}

static bool r_arch_session_set_endian(RArchSession *ai, RArchEndian endian) {
	r_return_val_if_fail (ai && ai->cur, false);
	if (!(ai->setup.endian & endian)) {
		return false;
	}
	switch (endian) {
	case R_SYS_ENDIAN_LITTLE:
	case R_SYS_ENDIAN_BIG:
	case R_SYS_ENDIAN_NONE:
	case R_SYS_ENDIAN_BI:
		ai->setup.endian = endian;
		return true;
	}
	return false;
}

static bool has_bits(RArchPlugin *h, RArchBits bits) {
        return (h && h->bits && (bits & h->bits));
}

R_API bool r_arch_session_set_bits(RArchSession *ai, RArchBits bits) {
	r_return_val_if_fail (ai && ai->cur, false);
	if (has_bits (ai->cur, bits)) {
		ai->setup.bits = bits;
		return true;
	}
	return false;
}

R_API bool r_arch_session_can_decode(RArchSession *ai) {
	r_return_val_if_fail (ai && ai->cur, false);
	return ai->cur->decode;
}

R_API bool r_arch_session_can_encode(RArchSession *ai) {
	r_return_val_if_fail (ai && ai->cur, false);
	return ai->cur->encode;
}

R_API bool r_arch_session_encode(RArchSession *ai, RArchInstruction *ins, RArchOptions opt) {
	r_return_val_if_fail (ai && ai->cur, false);
	if (ai->cur->encode) {
		return ai->cur->encode (ai, ins, opt);
	}
	return false;
}

R_API bool r_arch_session_decode(RArchSession *ai, RArchInstruction *ins, RArchOptions opt) {
	r_return_val_if_fail (ai && ai->cur, false);
	if (ai->cur->decode) {
		return ai->cur->decode (ai, ins, opt);
	}
	return false;
}

R_API void r_arch_session_free(RArchSession *as) {
	// somethng more
	free (as);
}

//RArchPlugin *ap = r_arch_get_plugin (a, name);
R_API RArchSession *r_arch_session_new(RArch *a, RArchPlugin *ap, RArchSetup *setup) {
	r_return_val_if_fail (a && ap, NULL);
	RArchSession *ai = R_NEW0 (RArchSession);
	if (ai) {
		ai->cur = ap;
		if (!setup) {
			RArchSetup _setup = {
				.endian = R_SYS_ENDIAN,
				.bits = R_SYS_BITS
			};
			memcpy (&ai->setup, &_setup, sizeof (RArchSetup));
			setup = &ai->setup;
		} else {
			memcpy (&ai->setup, setup, sizeof (RArchSetup));
		}
		if (ap && ap->init) {
			ap->init_session (ai);
		}
		r_arch_session_set_syntax (ai, setup->syntax);
		r_arch_session_set_bits (ai, setup->bits);
		r_arch_session_set_endian (ai, setup->endian);
		r_arch_session_set_cpu (ai, setup->cpu);
		return ai;
	}
	return NULL;
}
