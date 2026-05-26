/* radare - LGPL - Copyright 2026 - radare2 contributors */
/* PowerPC handmade assembler. 32-bit instructions; endianness from RArchSession config. */

#include <r_util.h>

/* ---------- Operand parsing ---------- */

static void skip_ws(const char **sp) {
	while (**sp == ' ' || **sp == '\t') {
		(*sp)++;
	}
}

static bool eat_char(const char **sp, char c) {
	skip_ws (sp);
	if (**sp != c) {
		return false;
	}
	(*sp)++;
	return true;
}

static bool eat_comma(const char **sp) {
	return eat_char (sp, ',');
}

/* Parse a GPR: "r0".."r31" or bare "0".."31". Returns register number or -1. */
static int parse_reg(const char **sp) {
	skip_ws (sp);
	const char *s = *sp;
	if (*s == 'r' || *s == 'R') {
		s++;
	}
	if (!isdigit ((unsigned char)*s)) {
		return -1;
	}
	int n = 0;
	while (isdigit ((unsigned char)*s)) {
		n = n * 10 + (*s - '0');
		if (n > 31) {
			return -1;
		}
		s++;
	}
	*sp = s;
	return n;
}

/* Parse a signed immediate: decimal, "0x..." hex, optional leading "-". */
static bool parse_imm(const char **sp, st64 *out) {
	skip_ws (sp);
	const char *s = *sp;
	if (!*s) {
		return false;
	}
	char *end = NULL;
	st64 v = strtoll (s, &end, 0);
	if (!end || end == s) {
		return false;
	}
	*out = v;
	*sp = end;
	return true;
}

/* Parse a D(rA) displacement form. Sets *disp_out and *ra_out. */
static bool parse_disp(const char **sp, st64 *disp_out, int *ra_out) {
	st64 d;
	if (!parse_imm (sp, &d) || !eat_char (sp, '(')) {
		return false;
	}
	int ra = parse_reg (sp);
	if (ra < 0 || !eat_char (sp, ')')) {
		return false;
	}
	*disp_out = d;
	*ra_out = ra;
	return true;
}

/* ---------- Instruction-form encoders ---------- */

/* D-form: |opcd 6|RT 5|RA 5|D 16|
 * SIMM/UIMM is the low 16 bits. Caller masks if needed. */
static ut32 enc_d(int op, int rt, int ra, int simm) {
	return ((op & 0x3f) << 26) |
		((rt & 0x1f) << 21) |
		((ra & 0x1f) << 16) |
		(simm & 0xffff);
}

/* DS-form: |opcd 6|RT 5|RA 5|DS 14|XO 2|
 * DS field is the upper 14 bits of a 16-bit displacement; low 2 bits must
 * be zero. xo selects the variant (0=ld/std, 1=ldu/stdu, 2=lwa). */
static ut32 enc_ds(int op, int rt, int ra, int ds, int xo) {
	return ((op & 0x3f) << 26) |
		((rt & 0x1f) << 21) |
		((ra & 0x1f) << 16) |
		((ds & 0xfffc)) |
		(xo & 3);
}

/* X-form: |opcd 6|RT 5|RA 5|RB 5|XO 10|Rc 1| */
static ut32 enc_x(int op, int rt, int ra, int rb, int xo, int rc) {
	return ((op & 0x3f) << 26) |
		((rt & 0x1f) << 21) |
		((ra & 0x1f) << 16) |
		((rb & 0x1f) << 11) |
		((xo & 0x3ff) << 1) |
		(rc & 1);
}

/* XO-form: |opcd 6|RT 5|RA 5|RB 5|OE 1|XO 9|Rc 1| */
static ut32 enc_xo(int op, int rt, int ra, int rb, int oe, int xo, int rc) {
	return ((op & 0x3f) << 26) |
		((rt & 0x1f) << 21) |
		((ra & 0x1f) << 16) |
		((rb & 0x1f) << 11) |
		((oe & 1) << 10) |
		((xo & 0x1ff) << 1) |
		(rc & 1);
}

/* B-form: |opcd 6|BO 5|BI 5|BD 14|AA 1|LK 1|
 * BD is signed 14-bit byte displacement (low 2 bits zero, range +/- 32 KiB). */
static ut32 enc_b(int op, int bo, int bi, int bd, int aa, int lk) {
	return ((op & 0x3f) << 26) |
		((bo & 0x1f) << 21) |
		((bi & 0x1f) << 16) |
		(bd & 0xfffc) |
		((aa & 1) << 1) |
		(lk & 1);
}

/* I-form: |opcd 6|LI 24|AA 1|LK 1|
 * LI is signed 24-bit byte displacement (low 2 bits zero, range +/- 32 MiB). */
static ut32 enc_i(int op, int li, int aa, int lk) {
	return ((op & 0x3f) << 26) |
		(li & 0x3fffffc) |
		((aa & 1) << 1) |
		(lk & 1);
}

/* XL-form: |opcd 6|BO 5|BI 5|---5|XO 10|LK 1|
 * Used for blr, bctr, bctrl. */
static ut32 enc_xl(int op, int bo, int bi, int xo, int lk) {
	return ((op & 0x3f) << 26) |
		((bo & 0x1f) << 21) |
		((bi & 0x1f) << 16) |
		((xo & 0x3ff) << 1) |
		(lk & 1);
}

/* XFX-form for mtspr/mfspr: |opcd 6|RT 5|spr 10|XO 10|Rc 1|
 * The SPR field is split: bits 11-15 hold the low 5 bits of SPR,
 * bits 16-20 hold the high 5 bits. */
static ut32 enc_xfx(int op, int rt, int spr, int xo) {
	int spr_lo = spr & 0x1f;
	int spr_hi = (spr >> 5) & 0x1f;
	int spr_field = (spr_lo << 5) | spr_hi;
	return ((op & 0x3f) << 26) |
		((rt & 0x1f) << 21) |
		((spr_field & 0x3ff) << 11) |
		((xo & 0x3ff) << 1);
}

/* ---------- Output emission ---------- */

static int emit_word(RArchSession *s, RAnalOp *op, ut32 word) {
	ut8 *buf = malloc (4);
	if (!buf) {
		return -1;
	}
	if (R_ARCH_CONFIG_IS_BIG_ENDIAN (s->config)) {
		r_write_be32 (buf, word);
	} else {
		r_write_le32 (buf, word);
	}
	free (op->bytes);
	op->bytes = buf;
	return 4;
}

/* ---------- Branch displacement helpers ---------- */

/* Compute a signed branch displacement from absolute target to op->addr,
 * verify it fits in `bits` and is 4-byte aligned. Returns true on success. */
static bool branch_disp(RAnalOp *op, st64 target, int bits, st64 *out) {
	st64 disp = target - (st64)op->addr;
	if (disp & 3) {
		return false;
	}
	st64 lim = 1LL << (bits - 1);
	if (disp >= lim || disp < -lim) {
		return false;
	}
	*out = disp;
	return true;
}

// ---------- Per-mnemonic handlers ----------
// Each handler receives a session, an op, and the argument-string suffix
// (just past the mnemonic + whitespace). Returns 4 on success, <=0 on error.

typedef int (*ppc_handler)(RArchSession *s, RAnalOp *op, const char *args);

#define REQ_REG(name) \
	int name = parse_reg (&p); \
	if (name < 0) { return -1; }

#define REQ_COMMA() \
	if (!eat_comma (&p)) { return -1; }

#define REQ_IMM(name) \
	st64 name; \
	if (!parse_imm (&p, &name)) { return -1; }

#define REQ_DISP(d_name, ra_name) \
	st64 d_name; int ra_name; \
	if (!parse_disp (&p, &d_name, &ra_name)) { return -1; }

/* Parse "rX, rY, rZ" into three register numbers. */
static bool parse_3reg(const char **p, int *r1, int *r2, int *r3) {
	*r1 = parse_reg (p);
	if (*r1 < 0 || !eat_comma (p)) {
		return false;
	}
	*r2 = parse_reg (p);
	if (*r2 < 0 || !eat_comma (p)) {
		return false;
	}
	*r3 = parse_reg (p);
	return *r3 >= 0;
}

/* Shared D-form load/store body. SIMM is signed-16 (-0x8000..0x7fff). */
static int dform_ls(RArchSession *s, RAnalOp *op, const char *args, int opcd) {
	const char *p = args;
	REQ_REG (rt);
	REQ_COMMA ();
	REQ_DISP (d, ra);
	if (d < -0x8000 || d > 0x7fff) {
		return -1;
	}
	return emit_word (s, op, enc_d (opcd, rt, ra, (int)d));
}

/* Shared DS-form load/store body. 64-bit only; displacement must be 4-aligned. */
static int dsform_ls(RArchSession *s, RAnalOp *op, const char *args, int opcd, int xo) {
	if (s->config->bits != 64) {
		return -1;
	}
	const char *p = args;
	REQ_REG (rt);
	REQ_COMMA ();
	REQ_DISP (d, ra);
	if ((d & 3) || d < -0x8000 || d > 0x7fff) {
		return -1;
	}
	return emit_word (s, op, enc_ds (opcd, rt, ra, (int)d, xo));
}

/* Fixed-encoding instructions. */
static int h_nop(RArchSession *s, RAnalOp *op, const char *args)  { return emit_word (s, op, 0x60000000); }
static int h_sc(RArchSession *s, RAnalOp *op, const char *args)   { return emit_word (s, op, 0x44000002); }
static int h_trap(RArchSession *s, RAnalOp *op, const char *args) { return emit_word (s, op, 0x7fe00008); }

/* SIMM is signed-16; range -0x8000..0x7fff. */
static int h_li(RArchSession *s, RAnalOp *op, const char *args) {
	const char *p = args;
	REQ_REG (rt);
	REQ_COMMA ();
	REQ_IMM (simm);
	if (simm < -0x8000 || simm > 0x7fff) {
		return -1;
	}
	return emit_word (s, op, enc_d (14, rt, 0, (int)simm));
}

/* lis rT, SIMM -> addis rT, 0, SIMM. ISA defines SIMM as signed-16, but
 * the conventional idiom `lis rT, 0xFF00` uses the unsigned range; accept
 * 0..0xffff in addition to the signed range. */
static int h_lis(RArchSession *s, RAnalOp *op, const char *args) {
	const char *p = args;
	REQ_REG (rt);
	REQ_COMMA ();
	REQ_IMM (simm);
	if (simm < -0x8000 || simm > 0xffff) {
		return -1;
	}
	return emit_word (s, op, enc_d (15, rt, 0, (int)simm));
}

/* SIMM is signed-16; range -0x8000..0x7fff. */
static int h_addi(RArchSession *s, RAnalOp *op, const char *args) {
	const char *p = args;
	REQ_REG (rt);
	REQ_COMMA ();
	REQ_REG (ra);
	REQ_COMMA ();
	REQ_IMM (simm);
	if (simm < -0x8000 || simm > 0x7fff) {
		return -1;
	}
	return emit_word (s, op, enc_d (14, rt, ra, (int)simm));
}

/* addis rT, rA, SIMM. Accepts the wider 0..0xffff range for the same
 * convention reason as h_lis. */
static int h_addis(RArchSession *s, RAnalOp *op, const char *args) {
	const char *p = args;
	REQ_REG (rt);
	REQ_COMMA ();
	REQ_REG (ra);
	REQ_COMMA ();
	REQ_IMM (simm);
	if (simm < -0x8000 || simm > 0xffff) {
		return -1;
	}
	return emit_word (s, op, enc_d (15, rt, ra, (int)simm));
}

/* ori dest is the first operand but lands in the RA slot, not RT. */
static int h_ori(RArchSession *s, RAnalOp *op, const char *args) {
	const char *p = args;
	REQ_REG (ra);
	REQ_COMMA ();
	REQ_REG (rs);
	REQ_COMMA ();
	REQ_IMM (uimm);
	if (uimm < 0 || uimm > 0xffff) {
		return -1;
	}
	return emit_word (s, op, enc_d (24, rs, ra, (int)uimm));
}

static int h_lwz(RArchSession *s, RAnalOp *op, const char *args)  { return dform_ls (s, op, args, 32); }
static int h_stw(RArchSession *s, RAnalOp *op, const char *args)  { return dform_ls (s, op, args, 36); }
static int h_stwu(RArchSession *s, RAnalOp *op, const char *args) { return dform_ls (s, op, args, 37); }
static int h_lbz(RArchSession *s, RAnalOp *op, const char *args)  { return dform_ls (s, op, args, 34); }
static int h_stb(RArchSession *s, RAnalOp *op, const char *args)  { return dform_ls (s, op, args, 38); }

/* DS-form loads/stores are 64-bit only and require a 4-aligned displacement. */
static int h_ld(RArchSession *s, RAnalOp *op, const char *args)   { return dsform_ls (s, op, args, 58, 0); }
static int h_std(RArchSession *s, RAnalOp *op, const char *args)  { return dsform_ls (s, op, args, 62, 0); }
static int h_stdu(RArchSession *s, RAnalOp *op, const char *args) { return dsform_ls (s, op, args, 62, 1); }
static int h_ldu(RArchSession *s, RAnalOp *op, const char *args)  { return dsform_ls (s, op, args, 58, 1); }

// cmpw / cmpd: register-register compare. L=0 → 32-bit (cmpw), L=1 → 64-bit
// (cmpd). The L bit is the low bit of the 5-bit RT slot. Accepts the 3-op
// `crf, rA, rB` form and the 2-op `rA, rB` form (implicit crf=0).
static int cmp_x(RArchSession *s, RAnalOp *op, const char *args, int l) {
	const char *p = args;
	int first = parse_reg (&p);
	if (first < 0 || !eat_comma (&p)) {
		return -1;
	}
	int second = parse_reg (&p);
	if (second < 0) {
		return -1;
	}
	const char *probe = p;
	if (eat_comma (&probe)) {
		int third = parse_reg (&probe);
		if (third < 0 || first > 7) {
			return -1;
		}
		return emit_word (s, op, enc_x (31, first * 4 + l, second, third, 0, 0));
	}
	return emit_word (s, op, enc_x (31, l, first, second, 0, 0));
}

/* cmpwi / cmpdi: register-immediate compare. Same L-bit and crf semantics as cmp_x. */
static int cmp_i(RArchSession *s, RAnalOp *op, const char *args, int l) {
	const char *p = args;
	int first = parse_reg (&p);
	if (first < 0) {
		return -1;
	}
	const char *save = p;
	if (!eat_comma (&p)) {
		return -1;
	}
	int maybe_ra = parse_reg (&p);
	if (maybe_ra >= 0) {
		const char *probe = p;
		if (eat_comma (&probe)) {
			if (first > 7) {
				return -1;
			}
			p = probe;
			REQ_IMM (simm);
			if (simm < -0x8000 || simm > 0x7fff) {
				return -1;
			}
			return emit_word (s, op, enc_d (11, first * 4 + l, maybe_ra, (int)simm));
		}
	}
	p = save;
	if (!eat_comma (&p)) {
		return -1;
	}
	REQ_IMM (simm);
	if (simm < -0x8000 || simm > 0x7fff) {
		return -1;
	}
	return emit_word (s, op, enc_d (11, l, first, (int)simm));
}

static int h_cmpw(RArchSession *s, RAnalOp *op, const char *args)  { return cmp_x (s, op, args, 0); }
static int h_cmpd(RArchSession *s, RAnalOp *op, const char *args)  { return cmp_x (s, op, args, 1); }
static int h_cmpwi(RArchSession *s, RAnalOp *op, const char *args) { return cmp_i (s, op, args, 0); }
static int h_cmpdi(RArchSession *s, RAnalOp *op, const char *args) { return cmp_i (s, op, args, 1); }

/* PPC bitwise ops: destination is first operand but encodes into RA slot (not RT). */
static int x_logical(RArchSession *s, RAnalOp *op, const char *args, int xo) {
	const char *p = args;
	int ra, rs, rb;
	if (!parse_3reg (&p, &ra, &rs, &rb)) {
		return -1;
	}
	return emit_word (s, op, enc_x (31, rs, ra, rb, xo, 0));
}

static int h_and(RArchSession *s, RAnalOp *op, const char *args) { return x_logical (s, op, args, 28); }
static int h_or(RArchSession *s, RAnalOp *op, const char *args)  { return x_logical (s, op, args, 444); }
static int h_xor(RArchSession *s, RAnalOp *op, const char *args) { return x_logical (s, op, args, 316); }

/* `mr rA, rS` is the conventional alias for `or rA, rS, rS`. */
static int h_mr(RArchSession *s, RAnalOp *op, const char *args) {
	const char *p = args;
	REQ_REG (ra);
	REQ_COMMA ();
	REQ_REG (rs);
	return emit_word (s, op, enc_x (31, rs, ra, rs, 444, 0));
}

/* Shared XO-form arithmetic body: `op rT, rA, rB`. */
static int xo_3reg(RArchSession *s, RAnalOp *op, const char *args, int xo) {
	const char *p = args;
	int rt, ra, rb;
	if (!parse_3reg (&p, &rt, &ra, &rb)) {
		return -1;
	}
	return emit_word (s, op, enc_xo (31, rt, ra, rb, 0, xo, 0));
}

static int h_add(RArchSession *s, RAnalOp *op, const char *args)   { return xo_3reg (s, op, args, 266); }
/* subf computes rB - rA, not rA - rB. */
static int h_subf(RArchSession *s, RAnalOp *op, const char *args)  { return xo_3reg (s, op, args, 40); }
static int h_mullw(RArchSession *s, RAnalOp *op, const char *args) { return xo_3reg (s, op, args, 235); }
static int h_divw(RArchSession *s, RAnalOp *op, const char *args)  { return xo_3reg (s, op, args, 491); }
/* mulld / divd are the 64-bit variants of mullw / divw. */
static int h_mulld(RArchSession *s, RAnalOp *op, const char *args) { return xo_3reg (s, op, args, 233); }
static int h_divd(RArchSession *s, RAnalOp *op, const char *args)  { return xo_3reg (s, op, args, 489); }

/* `sub rT, rA, rB` is the alias for `subf rT, rB, rA` (operands swapped
 * so the more conventional reading rT = rA - rB holds). */
static int h_sub(RArchSession *s, RAnalOp *op, const char *args) {
	const char *p = args;
	int rt, ra, rb;
	if (!parse_3reg (&p, &rt, &ra, &rb)) {
		return -1;
	}
	return emit_word (s, op, enc_xo (31, rt, rb, ra, 0, 40, 0));
}

static int h_neg(RArchSession *s, RAnalOp *op, const char *args) {
	const char *p = args;
	REQ_REG (rt);
	REQ_COMMA ();
	REQ_REG (ra);
	return emit_word (s, op, enc_xo (31, rt, ra, 0, 0, 104, 0));
}

/* Branch helpers — compute relative displacement from op->addr to target. */
static int do_b_form(RArchSession *s, RAnalOp *op, int bo, int bi, st64 target) {
	st64 disp;
	if (!branch_disp (op, target, 16, &disp)) {
		return -1;
	}
	return emit_word (s, op, enc_b (16, bo, bi, (int)disp, 0, 0));
}

static int do_i_form(RArchSession *s, RAnalOp *op, st64 target, int lk) {
	st64 disp;
	if (!branch_disp (op, target, 26, &disp)) {
		return -1;
	}
	return emit_word (s, op, enc_i (18, (int)disp, 0, lk));
}

/* Conditional branches. BI selects which cr0 bit; BO selects taken/not. */
#define BO_TRUE 12
#define BO_FALSE 4
#define BI_LT 0
#define BI_GT 1
#define BI_EQ 2

static int do_cbranch(RArchSession *s, RAnalOp *op, const char *args, int bo, int bi) {
	const char *p = args;
	REQ_IMM (tgt);
	return do_b_form (s, op, bo, bi, tgt);
}

static int h_beq(RArchSession *s, RAnalOp *op, const char *args) { return do_cbranch (s, op, args, BO_TRUE,  BI_EQ); }
static int h_bne(RArchSession *s, RAnalOp *op, const char *args) { return do_cbranch (s, op, args, BO_FALSE, BI_EQ); }
static int h_bgt(RArchSession *s, RAnalOp *op, const char *args) { return do_cbranch (s, op, args, BO_TRUE,  BI_GT); }
static int h_blt(RArchSession *s, RAnalOp *op, const char *args) { return do_cbranch (s, op, args, BO_TRUE,  BI_LT); }
static int h_bge(RArchSession *s, RAnalOp *op, const char *args) { return do_cbranch (s, op, args, BO_FALSE, BI_LT); }
static int h_ble(RArchSession *s, RAnalOp *op, const char *args) { return do_cbranch (s, op, args, BO_FALSE, BI_GT); }

// Unconditional branches. lk=0 → b, lk=1 → bl
static int h_ubranch(RArchSession *s, RAnalOp *op, const char *args, int lk) {
	const char *p = args;
	REQ_IMM (tgt);
	return do_i_form (s, op, tgt, lk);
}

static int h_b(RArchSession *s, RAnalOp *op, const char *args)  { return h_ubranch (s, op, args, 0); }
static int h_bl(RArchSession *s, RAnalOp *op, const char *args) { return h_ubranch (s, op, args, 1); }

/* XL-form (LR/CTR-relative) branches. */
static int h_blr(RArchSession *s, RAnalOp *op, const char *args)   { return emit_word (s, op, enc_xl (19, 20, 0, 16, 0)); }
static int h_bctr(RArchSession *s, RAnalOp *op, const char *args)  { return emit_word (s, op, enc_xl (19, 20, 0, 528, 0)); }
static int h_bctrl(RArchSession *s, RAnalOp *op, const char *args) { return emit_word (s, op, enc_xl (19, 20, 0, 528, 1)); }

/* SPR moves. spr=8 is LR, spr=9 is CTR. xo=467 → mtspr, xo=339 → mfspr. */
static int spr_move(RArchSession *s, RAnalOp *op, const char *args, int spr, int xo) {
	const char *p = args;
	REQ_REG (r);
	return emit_word (s, op, enc_xfx (31, r, spr, xo));
}

static int h_mtctr(RArchSession *s, RAnalOp *op, const char *args) { return spr_move (s, op, args, 9, 467); }
static int h_mtlr(RArchSession *s, RAnalOp *op, const char *args)  { return spr_move (s, op, args, 8, 467); }
static int h_mfctr(RArchSession *s, RAnalOp *op, const char *args) { return spr_move (s, op, args, 9, 339); }
static int h_mflr(RArchSession *s, RAnalOp *op, const char *args)  { return spr_move (s, op, args, 8, 339); }

/* ---------- Mnemonic dispatch ---------- */

static const struct {
	const char *name;
	ppc_handler fn;
} mnemonic_table[] = {
	{ "nop",   h_nop },
	{ "sc",    h_sc },
	{ "trap",  h_trap },
	{ "li",    h_li },
	{ "lis",   h_lis },
	{ "addi",  h_addi },
	{ "addis", h_addis },
	{ "ori",   h_ori },
	{ "lwz",   h_lwz },
	{ "stw",   h_stw },
	{ "stwu",  h_stwu },
	{ "lbz",   h_lbz },
	{ "stb",   h_stb },
	{ "ld",    h_ld },
	{ "std",   h_std },
	{ "stdu",  h_stdu },
	{ "ldu",   h_ldu },
	{ "cmpwi", h_cmpwi },
	{ "cmpw",  h_cmpw },
	{ "cmpdi", h_cmpdi },
	{ "cmpd",  h_cmpd },
	{ "and",   h_and },
	{ "or",    h_or },
	{ "xor",   h_xor },
	{ "mr",    h_mr },
	{ "add",   h_add },
	{ "subf",  h_subf },
	{ "sub",   h_sub },
	{ "mullw", h_mullw },
	{ "divw",  h_divw },
	{ "mulld", h_mulld },
	{ "divd",  h_divd },
	{ "neg",   h_neg },
	{ "beq",   h_beq },
	{ "bne",   h_bne },
	{ "bgt",   h_bgt },
	{ "blt",   h_blt },
	{ "bge",   h_bge },
	{ "ble",   h_ble },
	{ "b",     h_b },
	{ "bl",    h_bl },
	{ "blr",   h_blr },
	{ "bctr",  h_bctr },
	{ "bctrl", h_bctrl },
	{ "mtctr", h_mtctr },
	{ "mtlr",  h_mtlr },
	{ "mfctr", h_mfctr },
	{ "mflr",  h_mflr },
	{ NULL,    NULL }
};

R_API int ppc_nz_assemble(RArchSession *s, RAnalOp *op, const char *str) {
	R_RETURN_VAL_IF_FAIL (s && s->config && op && str, -1);
	const char *p = str;
	skip_ws (&p);
	if (!*p) {
		return -1;
	}
	/* Read mnemonic (up to first whitespace or end of string). */
	const char *m_start = p;
	while (*p && !isspace ((unsigned char)*p)) {
		p++;
	}
	size_t m_len = p - m_start;
	if (m_len == 0 || m_len > 15) {
		return -1;
	}
	char mnem[16];
	memcpy (mnem, m_start, m_len);
	mnem[m_len] = '\0';
	int i;
	for (i = 0; mnemonic_table[i].name; i++) {
		if (!r_str_casecmp (mnemonic_table[i].name, mnem)) {
			return mnemonic_table[i].fn (s, op, p);
		}
	}
	return -1;
}
