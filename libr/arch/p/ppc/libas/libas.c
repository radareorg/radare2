/* radare - LGPL - PowerPC-AS tagged-memory instruction decoder.
 *
 * Implements the AS instruction set used by the IBM i LIC, matching the
 * patched QEMU target/ppc/translate.c dispatch (always-valid tag model):
 *
 *   op31 XO228  TXER    - set cr7 from XER[43] (TAG)
 *   op31 XO499  SETTAG  - XER[43] <- 1
 *   op31 XO676  ASNOP   - unknown AS op, no-op on POWER9 hardware
 *   op57  XO=1  LTPTR  - load tagged pointer (DQ-form: RT, RA, DQ*4, EPT)
 *   op30 minor>=24 SELxx - rD = XER[32+imm] ? op1 : op2
 *                         24/25 selii 26/27 selir 28/29 selri 30/31 selrr
 *                         (odd minor = Rc); op1_reg = minor>=28,
 *                         op2_reg = minor in {26,27,30,31}
 *   op58 XO=3   ld-as  - AS DS-form load (stock XO=3 is reserved)
 *   op62 XO=3   std-as - AS DS-form store (stock XO=3 is reserved)
 *
 * XER tag bits (IBM numbering): [41]=T02 [42]=T07 [43]=TAG  -> imm 9/10/11
 *
 * Field extraction follows QEMU (execution authority): for SELxx,
 *   op1 = (w>>21)&0x1f  op2 = (w>>11)&0x1f  rD = (w>>16)&0x1f  imm = (w>>7)&0xf
 */
#include "libas.h"
#include <stdio.h>

static const char *xer_tag_name (int imm) {
	/* imm is the 4-bit XER selector; XER[32+imm] (IBM numbering) */
	switch (imm) {
	case 9: return "T02";   /* XER[41] */
	case 10: return "T07";  /* XER[42] */
	case 11: return "TAG";  /* XER[43] */
	default: return NULL;
	}
}

static int decode_sel (ut32 w, char *out, int outsz) {
	int minor = w & 0x1f;
	if (minor < 24) {
		return 0;
	}
	const char *base;
	switch (minor & ~1) {
	case 24: base = "selii"; break;
	case 26: base = "selir"; break;
	case 28: base = "selri"; break;
	case 30: base = "selrr"; break;
	default: return 0;
	}
	int op1 = (w >> 21) & 0x1f;
	int op2 = (w >> 11) & 0x1f;
	int rD = (w >> 16) & 0x1f;
	int imm = (w >> 7) & 0xf;
	bool op1_reg = (minor >= 28);           /* selri / selrr */
	bool op2_reg = (minor == 26 || minor == 27 || minor == 30 || minor == 31);

	const char *xb = xer_tag_name (imm);
	char xbuf[24];
	if (!xb) {
		snprintf (xbuf, sizeof xbuf, "xer[%d]", 32 + imm);
		xb = xbuf;
	}
	char o1[16], o2[16];
	snprintf (o1, sizeof o1, op1_reg ? "r%d" : "%d", op1);
	snprintf (o2, sizeof o2, op2_reg ? "r%d" : "%d", op2);
	snprintf (out, outsz, "%s%s r%d, %s, %s, %s",
		base, (minor & 1) ? "." : "", rD, o1, o2, xb);
	return 1;
}

static int decode_lqtag (ut32 w, char *out, int outsz) {
	/* AS tagged-quad load (op56 under TA): single-register load of [RA + DQ*4]. */
	int rt = (w >> 21) & 0x1f;
	int ra = (w >> 16) & 0x1f;
	int dq = (w >> 4) & 0xfff;
	int32_t off = (int32_t)dq * 4;
	snprintf (out, outsz, "lqtag r%d, %d(r%d)", rt, off, ra);
	return 1;
}

static int decode_ds (ut32 w, char *out, int outsz, bool is_store) {
	/* AS DS-form load (op58 XO=3) / store (op62 XO=3) */
	int rt = (w >> 21) & 0x1f;
	int ra = (w >> 16) & 0x1f;
	/* DS(14b) || 0b00, sign-extended as a 16-bit field (QEMU: (int16_t)ds) */
	const int32_t ds = (int32_t)(int16_t)(w & ~3u);
	snprintf (out, outsz, "%s r%d, %d(r%d)", is_store ? "std" : "ld", rt, ds, ra);
	return 1;
}

bool libas_decode (ut32 w, char *out, int outsz) {
	if (outsz <= 0) {
		return false;
	}
	int op = (w >> 26) & 0x3f;
	switch (op) {
	case 31: {
		int xo = (w >> 1) & 0x3ff;
		int rc = w & 1;
		if (xo == 228) {
			snprintf (out, outsz, "txer%s", rc ? "." : "");
			return true;
		}
		if (xo == 499) {
			snprintf (out, outsz, "settag%s", rc ? "." : "");
			return true;
		}
		if (xo == 676) {
			snprintf (out, outsz, "asnop%s", rc ? "." : "");
			return true;
		}
		return false;
	}
	case 16: {  /* BCA: BO=14 (always) BI=29 (cr7.GT) LK=1 -> trace vector 0x8000.
	             * Modelled as a no-op in the AS private-op set (QEMU: ok=true). */
		if (((w >> 21) & 0x1f) != 14 || ((w >> 16) & 0x1f) != 29 || !(w & 1)) {
			return false;
		}
		int32_t off = (int32_t)(int16_t)(w & 0xfffc);
		snprintf (out, outsz, "bca 0x%x", (unsigned)off);
		return true;
	}
	case 57: {  /* LTPTR (XO=1) */
		if ((w & 3) != 1) {
			return false;
		}
		int rt = (w >> 21) & 0x1f;
		int ra = (w >> 16) & 0x1f;
		int dq = (w >> 4) & 0xfff;       /* 12-bit, offset = DQ*4 */
		int ept = (w >> 2) & 0x3;
		int32_t off = (int32_t)dq * 4;
		snprintf (out, outsz, "ltptr r%d, %d(r%d), ept=%d", rt, off, ra, ept);
		return true;
	}
	case 56:  /* AS tagged-quad load (op56 under TA) */
		return decode_lqtag (w, out, outsz) != 0;
	case 30:  /* SELxx (minor>=24) */
		return decode_sel (w, out, outsz) != 0;
	case 58:  /* AS ld (XO=3) */
		if ((w & 3) != 3) {
			return false;
		}
		return decode_ds (w, out, outsz, false) != 0;
	case 62:  /* AS std (XO=3) */
		if ((w & 3) != 3) {
			return false;
		}
		return decode_ds (w, out, outsz, true) != 0;
	default:
		return false;
	}
}
