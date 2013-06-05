#if 0
truct r_parse_code_t {
	kSym *symbols;
} RParseCode;

R_API void r_parse_code_free (RParseCodeResult* c) {
}

R_API RParseCode *r_parse_code(RParse *p, const char *code) {
	RParseCode *r;
	int codelen = strlen (code);
	if (!p || !code) return NULL;
	r = R_NEW0 (RParseCode);
	r->state = tcc_new ();
	tcc_open (r->state, filename);
	ST_FUNC int tcc_open(TCCState *s1, const char *filename)
		tcc_open_bf(s, "<string>", codelen);
	memcpy(file->buffer, code, codelen);
	// tcc_open_bf (s1, filename, 0);
	preprocess_init(s1);
	// ST_FUNC int tcc_preprocess(TCCState *s1)
	// ST_FUNC
	r->symbols = /* tcc_pp + tcc_gen */
		return r;
}

R_API void r_parse_code_file(RParse *p, const char *file) {
	char *str = r_file_slurp (file, NULL);
	RParseCode *ret = r_parse_code (p, str);
	return ret;
}
#endif
