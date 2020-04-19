/* radare - LGPL - Copyright 2020 - pancake */

#include <r_arch.h>
#include <r_asm.h>
#include "../config.h"

static bool is_valid_endian (RArchEndian endian, RArchPlugin *ap) {
	return endian & ap->endian;
}

static bool is_valid_bits (RArchBits bits, RArchPlugin *ap) {
	return bits & ap->bits;
}

static bool is_valid_cpu (const char *cpu, RArchPlugin *ap) {
	return (!cpu && ap->cpus) || (cpu && ap->cpus && strstr (ap->cpus, cpu));
}

static bool is_valid_setup (RArchSetup *setup, RArchPlugin *ap) {
	return is_valid_endian (setup->endian, ap) && is_valid_bits (setup->bits, ap) &&
		is_valid_cpu (setup->cpu, ap);
}

R_API bool r_arch_session_can_xxcode(RArchSession *ai, RArchInputOptions inopt, RArchOutputOptions outopt) {
	r_return_val_if_fail (ai && ai->cur, false);
	return (inopt & ai->cur->inopts) && (outopt & ai->cur->outopts);
}

R_API bool r_arch_session_xxcode(RArchSession *ai, RArchInstruction *ins, RArchInputOptions inopt, RArchOutputOptions outopt) {
	r_return_val_if_fail (ai && ai->cur, false);
	if (r_arch_session_can_xxcode (ai, inopt, outopt)) {
		return ai->cur->xxcode (ai, ins, inopt, outopt);
	}
	return false;
}

R_API void r_arch_session_free(RArchSession *as) {
	// somethng more
	free (as);
}

R_API RArchSession *r_arch_session_new(RArch *a, RArchPlugin *ap, RArchSetup *setup) {
	r_return_val_if_fail (a && ap, NULL);
	RArchSession *ai = R_NEW0 (RArchSession);
	if (!ai) {
		return NULL;
	}
	ai->cur = ap;
	if (!setup) {
		ap->default_setup (&ai->setup);
	} else {
		memcpy (&ai->setup, setup, sizeof (RArchSetup));
	}
	if (!is_valid_setup (&ai->setup, ap)) {
		r_arch_session_free (ai);
		return NULL;
	}
	if (ap->init) {
		ap->init_session (ai);
	}
	r_arch_session_ref (ai);
	return ai;
}
