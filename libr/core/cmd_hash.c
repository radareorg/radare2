/* radare - LGPL - Copyright 2009-2013 - pancake, nibble */

static void algolist(int mode) {
	const char *name;
	ut64 bits;
	int i;
	for (i=0; ; i++) {
		bits = 1<<i;
		name = r_hash_name (bits);
		if (!name||!*name) break;
		if (mode) {
			r_cons_printf ("%s\n", name);
		} else {
			r_cons_printf (" #%s", name);
			if (!((i+1)%10)) r_cons_newline ();
		}
	}
	if (!mode) r_cons_printf ("\n");
}

static int cmd_hash(void *data, const char *input) {
	char *p, algo[32];
	RCore *core = (RCore *)data;
	ut32 i, osize, len = core->blocksize;
	const char *ptr;

	if (input[0]==' ') return 0;
	if (input[0]=='#' && !input[1]) {
		algolist (1);
		return R_TRUE;
	}
	if (input[0]=='!') {
		const char *lang = input+1;
		if (*lang=='/') {
			char *ptr = lang+1;
			while (*lang) {
				if (*lang=='/')
					ptr = lang+1;
				lang++;
			}
			RLangPlugin *p = r_lang_get_by_extension (core->lang, ptr);
			if (p && p->name) lang = p->name;
		}
		if (*lang==' ') {
			RLangPlugin *p = r_lang_get_by_extension (core->lang, input+2);
			if (p && p->name) lang = p->name;
		} else if (input[1]=='?' || input[1]=='*' || input[1]=='\0') {
			r_lang_list (core->lang);
			return R_TRUE;
		}
		p = strchr (input, ' ');
		if (p) *p=0;
		// TODO: set argv here
		if (r_lang_use (core->lang, lang)) {
			r_lang_setup (core->lang);
			if (p) r_lang_run_file (core->lang, p+1);
			else r_lang_prompt (core->lang);
		} else
		if (!p || *p)
			eprintf ("Invalid hashbang. See '#!' for help.\n");
		return R_TRUE;
	}

	ptr = strchr (input, ' ');
	sscanf (input, "%31s", algo);
	if (ptr != NULL) {
		int nlen = r_num_math (core->num, ptr+1);
		if (nlen>0) len = nlen;
		osize = core->blocksize;
		if (nlen>core->blocksize) {
			r_core_block_size (core, nlen);
		}
	} else osize =0;
	/* TODO: Simplify this spaguetti monster */
	if (!r_str_ccmp (input, "md4", ' ')) {
		RHash *ctx = r_hash_new (R_TRUE, R_HASH_MD4);
		const ut8 *c = r_hash_do_md4 (ctx, core->block, len);
		for (i=0; i<R_HASH_SIZE_MD4; i++) r_cons_printf ("%02x", c[i]);
		r_cons_newline ();
		r_hash_free (ctx);
	} else
	if (!r_str_ccmp (input, "adler32", ' ')) {
		ut32 hn = r_hash_adler32 (core->block, len);
		ut8 *b = (ut8*)&hn;
		r_cons_printf ("%02x%02x%02x%02x\n", b[0], b[1], b[2], b[3]);
	} else
	if (!r_str_ccmp (input, "md5", ' ')) {
		RHash *ctx = r_hash_new (R_TRUE, R_HASH_MD5);
		const ut8 *c = r_hash_do_md5 (ctx, core->block, len);
		for (i=0; i<R_HASH_SIZE_MD5; i++) r_cons_printf ("%02x", c[i]);
		r_cons_newline ();
		r_hash_free (ctx);
	} else
	if (!r_str_ccmp (input, "sha1", ' ')) {
		RHash *ctx = r_hash_new (R_TRUE, R_HASH_SHA1);
		const ut8 *c = r_hash_do_sha1 (ctx, core->block, len);
		for (i=0; i<R_HASH_SIZE_SHA1; i++) r_cons_printf ("%02x", c[i]);
		r_cons_newline ();
		r_hash_free (ctx);
	} else
	if (!r_str_ccmp (input, "sha256", ' ')) {
		RHash *ctx = r_hash_new (R_TRUE, R_HASH_SHA256);
		const ut8 *c = r_hash_do_sha256 (ctx, core->block, len);
		for (i=0; i<R_HASH_SIZE_SHA256; i++) r_cons_printf ("%02x", c[i]);
		r_cons_newline ();
		r_hash_free (ctx);
	} else
	if (!r_str_ccmp (input, "sha512", ' ')) {
		RHash *ctx = r_hash_new (R_TRUE, R_HASH_SHA512);
		const ut8 *c = r_hash_do_sha512 (ctx, core->block, len);
		for (i=0; i<R_HASH_SIZE_SHA512; i++) r_cons_printf ("%02x", c[i]);
		r_cons_newline ();
		r_hash_free (ctx);
	} else
	if (!r_str_ccmp (input, "entropy", ' ')) {
		r_cons_printf ("%lf\n", r_hash_entropy (core->block, len));
	} else
	if (!r_str_ccmp (input, "hamdist", ' ')) {
		r_cons_printf ("%d\n", r_hash_hamdist (core->block, len));
	} else
	if (!r_str_ccmp (input, "pcprint", ' ')) {
		r_cons_printf ("%d\n", r_hash_pcprint (core->block, len));
	} else
	if (!r_str_ccmp (input, "crc32", ' ')) {
		r_cons_printf ("%04x\n", r_hash_crc32 (core->block, len));
	} else
	if (!r_str_ccmp (input, "xor", ' ')) {
		r_cons_printf ("%02x\n", r_hash_xor (core->block, len));
	} else
	if (!r_str_ccmp (input, "crc16", ' ')) {
		r_cons_printf ("%02x\n", r_hash_crc16 (0, core->block, len));
	} else
	if (input[0]=='?') {
		r_cons_printf (
		"Usage: #algo <size> @ addr\n"
		" # this is a comment   note the space after the sharp sign\n"
		" ##                    List hash/checksum algorithms.\n"
		" #sha256 10K @ 33      calculate sha256 of 10K at 33\n"
		"Hashes:\n");
		algolist (0);
		r_cons_printf (
		"Usage #!interpreter [<args>] [<file] [<<eof]\n"
		" #!                    list all available interpreters\n"
		" #!python              run python commandline\n"
		" #!python foo.py       run foo.py python script (same as '. foo.py')\n"
		//" #!python <<EOF        get python code until 'EOF' mark\n"
		" #!python arg0 a1 <<q  set arg0 and arg1 and read until 'q'\n");
	}
	if (osize)
		r_core_block_size (core, osize);
	return 0;
}
