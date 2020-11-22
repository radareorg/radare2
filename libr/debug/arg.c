/* radare - LGPL - Copyright 2010-2020 pancake */

#include <r_debug.h>

R_API ut64 r_debug_arg_get(RDebug *dbg, int cctype, int num) {
	r_return_val_if_fail (dbg, UT64_MAX);
	ut32 n32;
	ut64 n64, sp;
	char reg[32];
	if (dbg->anal) {
		const char *cc = r_anal_syscc_default (dbg->anal);
		if (!R_STR_ISEMPTY (cc)) {
			if (!strcmp (cc, "stdcall") || !strcmp (cc, "pascal")) {
				sp = r_debug_reg_get (dbg, "SP");
				if (dbg->bits == 64) {
					sp += 8; // skip return address, assume we are inside the call
					sp += 8 * num;
					dbg->iob.read_at (dbg->iob.io, sp, (ut8*)&n64, sizeof(ut64));
					// TODO: honor endianness of platform
					return (ut64)n64;
				} else {
					sp += 4; // skip return address, assume we are inside the call
					sp += 4 * num;
					dbg->iob.read_at (dbg->iob.io, sp, (ut8*)&n32, sizeof(ut32));
					// TODO: honor endianness of platform
					return (ut64)n32;
				}
			}
			const char *rn = r_anal_cc_arg (dbg->anal, cc, num);
			if (rn) {
				return r_debug_reg_get (dbg, rn);
			}
		}
	}
	snprintf (reg, sizeof (reg) - 1, "A%d", num);
	return r_debug_reg_get (dbg, reg);
}

R_API bool r_debug_arg_set(RDebug *dbg, int cctype, int num, ut64 val) {
	r_return_val_if_fail (dbg, false);
	const char *cc = r_anal_syscc_default (dbg->anal);
	if (!R_STR_ISEMPTY (cc)) {
		cc = "reg";
	}
	const char *rn = r_anal_cc_arg (dbg->anal, cc, num);
	if (rn) {
		r_debug_reg_set (dbg, rn, val);
		return true;
	}
	char reg[32];
	snprintf (reg, sizeof (reg) - 1, "A%d", num);
	r_debug_reg_set (dbg, reg, val);
	return true;
}
