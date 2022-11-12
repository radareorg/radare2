/* radare2 - LGPL - Copyright 2022 - pancake */

#include <r_arch.h>
#include <r_util.h>

#if 0
// pseudocode
var a = arch.session("x86", {bits: 64});
var op = new RArchOp ();
op.setBytes("\x90");
if (!a.decode(op)) {
	println("cannot decode");
}
printfln (a.mnemonic);
#endif

R_API RArchSession *r_arch_session(RArch *arch, RArchConfig *cfg, RArchPlugin *ap) {
	RArchSession *ai = R_NEW0 (RArchSession);
	if (!ai) {
		return NULL;
	}
	if (ai) {
		ai->arch = arch;
		ai->config = cfg;
		ai->plugin = ap;
		ai->user = NULL;
		RArchPluginInitCallback init = R_UNWRAP3 (ai, plugin, init);
		if (init) {
			bool res = init (ai); // must fill ai->data
			if (!res) {
				R_FREE (ai);
			}
		}
	}
	// resolve and instantiate plugin by name (
	return ai;
}

R_API bool r_arch_session_decode(RArchSession *ai, RAnalOp *op, RArchDecodeMask mask) {
	RArchPluginDecodeCallback decode = R_UNWRAP3 (ai, plugin, decode);
	if (decode != NULL) {
		return decode (ai, op, mask);
	}
	return false;
}

R_API bool r_arch_session_encode(RArchSession *ai, RAnalOp *op, RArchEncodeMask mask) {
	RArchPluginEncodeCallback encode = R_UNWRAP3 (ai, plugin, encode);
	if (encode != NULL) {
		return encode (ai, op, mask);
	}
	return false;
}

R_API int r_arch_session_info(RArchSession *s, int query) {
	if (!s) {
		return -1;
	}
	RArchPluginInfoCallback info = R_UNWRAP3 (s, plugin, info);
	if (info != NULL) {
		return info (s, query);
	}
	return -1;
}
