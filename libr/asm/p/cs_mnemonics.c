static char *mnemonics(RAsm *a, int id, bool json) {
	int i;
	a->cur->disassemble (a, NULL, NULL, -1);
	if (id != -1) {
		const char *name = cs_insn_name (cd, id);
		if (json) {
			return name? r_str_newf ("[\"%s\"]\n", name): NULL;
		}
		return name? r_str_newf ("%s", name): NULL;
	}
	RStrBuf *buf = r_strbuf_new ("");
	if (json) {
			r_strbuf_append (buf, "[");
	}
	for (i = 1; ; i++) {
		const char *op = cs_insn_name (cd, i);
		if (!op) {
			break;
		}
		if (json) {
			r_strbuf_append (buf, "\"");
		}
		r_strbuf_append (buf, op);
		if (json) {
			if (cs_insn_name (cd, i + 1)) {
				r_strbuf_append (buf, "\",");
			} else {
				r_strbuf_append (buf, "\"]\n");
			}
		} else {
			r_strbuf_append (buf, "\n");
		}
	}
	return r_strbuf_drain (buf);
}
