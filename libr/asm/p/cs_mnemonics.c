static char *mnemonics(RAsm *a, int id, bool json) {
	int i;
	a->cur->disassemble (a, NULL, NULL, -1);
	if (id != -1) {
		const char *name = cs_insn_name (cd, id);
		if (json) {
			return name? r_str_newf ("[\"%s\"]\n", name): NULL;
		}
		return name? strdup (name): NULL;
	}
	PJ *pj = NULL;
	RStrBuf *buf = NULL;
	if (json) {
		pj = pj_new ();
		pj_a (pj);
	} else {
		r_strbuf_new ("");
	}
	for (i = 1; ; i++) {
		const char *op = cs_insn_name (cd, i);
		if (!op) {
			break;
		}
		if (pj) {
			pj_s (pj, op);
		} else {
			r_strbuf_append (buf, op);
			r_strbuf_append (buf, "\n");
		}
	}
	if (pj) {
		pj_end (pj);
	}
	return pj? pj_drain (pj): r_strbuf_drain (buf);
}
