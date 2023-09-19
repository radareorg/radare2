/* radare - LGPL - Copyright 2021 - pancake */

typedef struct {
	RCore *core;
	RStrBuf *sb;
} EsilC;

static char *esil2c(RCore *core, REsil *esil, const char *expr) {
	EsilC *user = esil->user;
	RStrBuf *sb = r_strbuf_new ("");
	user->sb = sb;
	if (!r_esil_parse (esil, expr)) {
		R_LOG_ERROR ("Invalid ESIL expression");
	}
	user->sb = NULL;
	return r_strbuf_drain (sb);
}

static bool esil2c_eq(REsil *esil) {
	EsilC *user = esil->user;
	char *dst = r_esil_pop (esil);
	char *src = r_esil_pop (esil);

	if (!src || !dst) {
		free (dst);
		free (src);
		return false;
	}
	const char *pcreg = "rip";
	if (!strcmp (dst, pcreg)) {
		r_strbuf_appendf (user->sb, "  goto addr_0x%08"PFMT64x"_0;\n", r_num_get (NULL, src));
	} else {
		r_strbuf_appendf (user->sb, "  %s = %s;\n", dst, src);
	}
	free (dst);
	free (src);
	return true;
}

static bool esil2c_peek8(REsil *esil) {
	EsilC *user = esil->user;
	char *src = r_esil_pop (esil);

	if (!src) {
		return false;
	}
	r_strbuf_appendf (user->sb, "  tmp = mem_qword[%s];\n", src);
	r_esil_push (esil, "tmp");
	free (src);
	return true;
}

static bool esil2c_poke8(REsil *esil) {
	EsilC *user = esil->user;
	char *dst = r_esil_pop (esil);
	char *src = r_esil_pop (esil);

	if (!src || !dst) {
		free (dst);
		free (src);
		return false;
	}
	r_strbuf_appendf (user->sb, "  mem_qword[%s] = %s;\n", dst, src);
	free (dst);
	free (src);
	return true;
}

static bool esil2c_addeq(REsil *esil) {
	EsilC *user = esil->user;
	char *dst = r_esil_pop (esil);
	char *src = r_esil_pop (esil);

	if (!src || !dst) {
		free (dst);
		free (src);
		return false;
	}
	r_strbuf_appendf (user->sb, "  %s += %s;\n", dst, src);
	free (dst);
	free (src);
	return true;
}

static bool esil2c_add(REsil *esil) {
	EsilC *user = esil->user;
	char *dst = r_esil_pop (esil);
	char *src = r_esil_pop (esil);

	if (!src || !dst) {
		free (dst);
		free (src);
		return false;
	}
	r_strbuf_appendf (user->sb, "  tmp = %s + %s;\n", dst, src);
	free (dst);
	free (src);
	return true;
}

static bool esil2c_subeq(REsil *esil) {
	EsilC *user = esil->user;
	char *dst = r_esil_pop (esil);
	char *src = r_esil_pop (esil);

	if (!src || !dst) {
		free (dst);
		free (src);
		return false;
	}
	r_strbuf_appendf (user->sb, "  %s -= %s;\n", dst, src);
	free (dst);
	free (src);
	return true;
}

static bool esil2c_xor(REsil *esil) {
	EsilC *user = esil->user;
	char *dst = r_esil_pop (esil);
	char *src = r_esil_pop (esil);

	if (!src || !dst) {
		free (dst);
		free (src);
		return false;
	}
	char *var = r_str_newf ("tmp%d", esil->stackptr);
	r_strbuf_appendf (user->sb, "  %s = %s ^ %s;\n", var, dst, src);
	r_esil_push (esil, var);
	free (dst);
	free (src);
	free (var);
	return true;
}

static bool esil2c_sub(REsil *esil) {
	EsilC *user = esil->user;
	char *dst = r_esil_pop (esil);
	char *src = r_esil_pop (esil);
	const bool lgtm = (src && dst);
	if (lgtm) {
		r_strbuf_appendf (user->sb, "  tmp = %s - %s;\n", dst, src);
		r_esil_push (esil, "tmp");
	}
	free (dst);
	free (src);
	return lgtm;
}

static bool esil2c_dec(REsil *esil) {
	EsilC *user = esil->user;
	char *src = r_esil_pop (esil);
	if (!src) {
		return false;
	}
	r_strbuf_appendf (user->sb, "  %s--;\n", src);
	free (src);
	return true;
}

static bool esil2c_inc(REsil *esil) {
	EsilC *user = esil->user;
	char *src = r_esil_pop (esil);
	if (!src) {
		return false;
	}
	r_strbuf_appendf (user->sb, "  %s++;\n", src);
	free (src);
	return true;
}

static bool esil2c_neg(REsil *esil) {
	EsilC *user = esil->user;
	char *src = r_esil_pop (esil);
	if (!src) {
		return false;
	}
	char *var = r_str_newf ("tmp%d", esil->stackptr);
	r_strbuf_appendf (user->sb, "  %s = !%s;\n", var, src);
	r_esil_push (esil, var);
	free (src);
	free (var);
	return true;
}

static bool esil2c_goto(REsil *esil) {
	EsilC *user = esil->user;
	char *src = r_esil_pop (esil);
	if (!src) {
		return false;
	}
	r_strbuf_appendf (user->sb, "  goto addr_%08"PFMT64x"_%s;\n", esil->addr, src);
	free (src);
	return true;
}

static void esil2c_free(EsilC *user) {
	free (user);
}

static bool esil2c_mw(REsil *esil, ut64 addr, const ut8 *buf, int len) {
	R_LOG_TODO ("poke%d 0x%08"PFMT64x" %d", len, addr, *buf);
	return true;
}

static bool esil2c_mr(REsil *esil, ut64 addr, ut8 *buf, int len) {
	R_LOG_TODO ("peek%d 0x%08"PFMT64x, len, addr);
	return true;
}

static void esil2c_setup(RCore *core, REsil *esil) {
	EsilC *user = R_NEW (EsilC);
	esil->user = user;
	esil->anal = core->anal;
	esil->verbose = true; // r_config_get_b (core->config, "esil.verbose");
	esil->cb.mem_read = esil2c_mr;
	esil->cb.mem_write = esil2c_mw;
	r_esil_set_op (esil, "=", esil2c_eq, 0, 2, R_ESIL_OP_TYPE_REG_WRITE);
	r_esil_set_op (esil, ":=", esil2c_eq, 0, 2, R_ESIL_OP_TYPE_REG_WRITE);
	r_esil_set_op (esil, "-", esil2c_sub, 1, 2, R_ESIL_OP_TYPE_REG_WRITE);
	r_esil_set_op (esil, "^", esil2c_xor, 1, 2, R_ESIL_OP_TYPE_REG_WRITE);
	r_esil_set_op (esil, "++", esil2c_inc, 1, 1, R_ESIL_OP_TYPE_REG_WRITE);
	r_esil_set_op (esil, "--", esil2c_dec, 1, 1, R_ESIL_OP_TYPE_REG_WRITE);
	r_esil_set_op (esil, "+", esil2c_add, 1, 2, R_ESIL_OP_TYPE_REG_WRITE);
	r_esil_set_op (esil, "+=", esil2c_addeq, 0, 2, R_ESIL_OP_TYPE_REG_WRITE);
	r_esil_set_op (esil, "!", esil2c_neg, 1, 1, R_ESIL_OP_TYPE_REG_WRITE);
	r_esil_set_op (esil, "-=", esil2c_subeq, 0, 2, R_ESIL_OP_TYPE_REG_WRITE);
	r_esil_set_op (esil, "=[8]", esil2c_poke8, 0, 2, R_ESIL_OP_TYPE_REG_WRITE);
	r_esil_set_op (esil, "=[]", esil2c_poke8, 0, 2, R_ESIL_OP_TYPE_REG_WRITE);
	r_esil_set_op (esil, "[8]", esil2c_peek8, 1, 1, R_ESIL_OP_TYPE_REG_WRITE);
	r_esil_set_op (esil, "[]", esil2c_peek8, 1, 1, R_ESIL_OP_TYPE_REG_WRITE);
	r_esil_set_op (esil, "GOTO", esil2c_goto, 0, 2, R_ESIL_OP_TYPE_REG_WRITE);
	// r_esil_set_op (esil, "+=", esil2c_set, 0, 2, R_ESIL_OP_TYPE_REG_WRITE);
}

