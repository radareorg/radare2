
static char *mnemonics(RAsm *a, int id) {
	int i;
	a->cur->disassemble (a, NULL, NULL, -1);
	if (id != -1) {
		const char *name = cs_insn_name (cd, id);
		return name? r_str_newf ("%s\n", name): NULL;
	}
	RStrBuf *buf = r_strbuf_new ("");
	for (i = 1; ; i++) {
		const char *op = cs_insn_name (cd, i);
		if (!op) {
			break;
		}
		r_strbuf_append (buf, op);
		r_strbuf_append (buf, "\n");
	}
	return r_strbuf_drain (buf);
}

