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
	if (decode != NULL) {
		return decode (ai, op, mask);
	}
	return false;
}

R_API bool r_arch_session_patch(RArchSession *ai, RAnalOp *op, RArchEncodeMask mask) {
	R_RETURN_VAL_IF_FAIL (ai && op, false);
	RArchPluginEncodeCallback encode = R_UNWRAP3 (ai, plugin, encode);
	if (encode != NULL) {
		return encode (ai, op, mask);
	}
	return false;
}

R_API bool r_arch_session_encode(RArchSession *ai, RAnalOp *op, RArchEncodeMask mask) {
	R_RETURN_VAL_IF_FAIL (ai && op, false);
	// TODO R2_590 use the encoder if found in the current session ai->encoder->..
	RArchPluginEncodeCallback encode = R_UNWRAP3 (ai, plugin, encode);
	if (encode != NULL) {
		return encode (ai, op, mask);
	}
	return false;
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
