/* radare2 - LGPL - Copyright 2022-2026 - pancake */

#include <r_arch.h>

static void _arch_session_free(RArchSession *s) {
	if (s) {
		free (s->name);
		r_unref (s->config);
		r_unref (s->encoder);
		RArchPluginFiniCallback fini = R_UNWRAP3 (s, plugin, fini);
		if (fini) {
			fini (s);
		}
		free (s);
	}
}

R_API RArchSession *r_arch_session(RArch *arch, RArchConfig *cfg, RArchPlugin *ap) {
	R_RETURN_VAL_IF_FAIL (arch && cfg && ap, false);
	RArchSession *ai = R_NEW0 (RArchSession);
	r_ref_init (ai, _arch_session_free);
	ai->arch = arch;
	ai->config = r_ref (cfg);
	ai->plugin = ap;
	ai->user = arch->user;
	RArchPluginInitCallback init = R_UNWRAP3 (ai, plugin, init);
	if (init) {
		bool res = init (ai); // must fill ai->data
		if (!res) {
			// On init failure, drop our refcounted session to release owned refs
			r_unref (ai);
			ai = NULL;
		}
	}
	return ai;
}

R_API bool r_arch_session_decode(RArchSession *ai, RAnalOp *op, RArchDecodeMask mask) {
	R_RETURN_VAL_IF_FAIL (ai && op, false);
	RArchPluginDecodeCallback decode = R_UNWRAP3 (ai, plugin, decode);
	if (!(mask & R_ARCH_OP_MASK_DISASM)) {
		return decode && decode (ai, op, mask);
	}
	const RArchConfig *config = ai->config;
	ut8 bytes[8];
	const int len = op->bytes? R_MIN (op->size, (int)sizeof (bytes)): 0;
	if (config->invhex && len > 0) {
		memcpy (bytes, op->bytes, len);
	}
	bool ret = decode && decode (ai, op, mask);
	if (op->size < 1 || !op->mnemonic || !strcmp (op->mnemonic, "invalid")) {
		const int bits = config->bits;
		const char *directive = bits == 8? "byte": bits == 16? "word": bits == 64? "qword": "dword";
		const int width = bits == 8 || bits == 16 || bits == 64? bits: 32;
		char *text = config->invhex && len >= width / 8
			? r_str_newf (".%s 0x%0*"PFMT64x, directive, width / 4,
				r_read_ble (bytes, R_ARCH_CONFIG_IS_BIG_ENDIAN (config), width))
			: strdup ("invalid");
		free (op->mnemonic);
		op->mnemonic = text;
	}
	return ret;
}

// NULL session or missing callback is a no-op, so callers can reset unconditionally
R_API bool r_arch_session_reset(RArchSession *ai) {
	R_RETURN_VAL_IF_FAIL (ai, false);
	RArchPluginResetCallback reset = R_UNWRAP3 (ai, plugin, reset);
	if (reset != NULL) {
		return reset (ai);
	}
	return false;
}

// encoders replace op->bytes with their own buffer, never let them free the inline one
static bool session_encode(RArchSession *ai, RArchPluginEncodeCallback encode, RAnalOp *op, RArchEncodeMask mask) {
	if (!encode) {
		return false;
	}
	if (op->weakbytes) {
		op->bytes = NULL;
		op->weakbytes = false;
	}
	return encode (ai, op, mask);
}

R_API bool r_arch_session_patch(RArchSession *ai, RAnalOp *op, RArchEncodeMask mask) {
	R_RETURN_VAL_IF_FAIL (ai && op, false);
	return session_encode (ai, R_UNWRAP3 (ai, plugin, encode), op, mask);
}

R_API bool r_arch_session_encode(RArchSession *ai, RAnalOp *op, RArchEncodeMask mask) {
	R_RETURN_VAL_IF_FAIL (ai && op, false);
	RArchPluginEncodeCallback encode = R_UNWRAP3 (ai, plugin, encode);
	if (!encode && ai->encoder) {
		ai = ai->encoder;
		encode = R_UNWRAP3 (ai, plugin, encode);
	}
	return session_encode (ai, encode, op, mask);
}

R_API RList *r_arch_session_preludes(RArchSession *s) {
	R_RETURN_VAL_IF_FAIL (s, false);
	RArchPluginPreludesCallback preludes = R_UNWRAP3 (s, plugin, preludes);
	if (preludes != NULL) {
		return preludes (s);
	}
	return NULL;
}

R_API int r_arch_session_info(RArchSession *s, int query) {
	R_RETURN_VAL_IF_FAIL (s, -1);
	RArchPluginInfoCallback info = R_UNWRAP3 (s, plugin, info);
	if (info != NULL) {
		return info (s, query);
	}
	return -1;
}
