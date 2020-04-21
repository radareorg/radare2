/* radare - LGPL - Copyright 2020 - pancake */

#include <r_arch.h>
#include <r_asm.h>
#include "../config.h"


static bool r_arch_session_set_cpu(RArchSession *ai, const char *cpu) {
	r_return_val_if_fail (ai && cpu, false);
	if (ai && *cpu) {
		// TODO: improve the check with r_str_split_list()
		if (R_STR_ISEMPTY (ai->cur->cpus) || strstr (ai->cur->cpus, cpu)) {
			free (ai->setup.cpu);
			ai->setup.cpu = cpu? strdup (cpu): NULL;
		}
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
		if (ai->cur->syntax & syntax) {
			ai->setup.syntax = syntax;
			return true;
		}
		break;
	default:
		return false;
	}
	return false;
}

static bool r_arch_session_set_endian(RArchSession *ai, RArchEndian endian) {
	r_return_val_if_fail (ai && ai->cur, false);
	switch (endian) {
	case R_SYS_ENDIAN_LITTLE:
	case R_SYS_ENDIAN_BIG:
	case R_SYS_ENDIAN_NONE:
	case R_SYS_ENDIAN_BI:
		if (ai->cur->endian & endian) {
			ai->setup.endian = endian;
			return true;
		}
		break;
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
	// something more
	free (as);
}

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
		if (ap && ap->init_session) {
			ap->init_session (ai);
		}
		ai->cbs = &a->cbs; // use ref maybe
		r_arch_session_set_syntax (ai, setup->syntax);
		r_arch_session_set_bits (ai, setup->bits);
		r_arch_session_set_endian (ai, setup->endian);
		r_arch_session_set_cpu (ai, setup->cpu);
		return ai;
	}
	return NULL;
}

// user frendly apis

R_API bool r_arch_session_encode_instruction (RArchSession *as, RArchInstruction *ins, ut64 addr, const char *opstr) {
	r_return_val_if_fail (as && ins && opstr, false);
	r_strbuf_set (&ins->code, opstr);
	return r_arch_session_encode (as, ins, R_ARCH_OPTION_CODE);
}

R_API bool r_arch_session_decode_bytes (RArchSession *as, RArchInstruction *ins, ut64 addr, const ut8 *buf, size_t len) {
	r_return_val_if_fail (as && ins, false);
	if (buf) {
		r_strbuf_setbin (&ins->data, (const ut8*)buf, len);
	}
	return r_arch_session_decode (as, ins, R_ARCH_OPTION_CODE);
}

R_API bool r_arch_session_decode_esil (RArchSession *as, RArchInstruction *ins, ut64 addr, const ut8 *buf, size_t len) {
	r_return_val_if_fail (as && ins, false);
	if (buf) {
		r_strbuf_setbin (&ins->data, (const ut8*)buf, len);
	}
	return r_arch_session_decode (as, ins, R_ARCH_OPTION_CODE|R_ARCH_OPTION_ESIL|R_ARCH_OPTION_ANAL);
}

