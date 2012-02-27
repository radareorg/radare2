/* radare - LGPL - Copyright 2009-2012 // nibble<.ds@gmail.com>, pancake<nopcode.org> */

static int cmd_hash(void *data, const char *input) {
	char *p, algo[32];
	RCore *core = (RCore *)data;
	ut32 i, len = core->blocksize;
	const char *ptr;

	if (input[0]==' ') return 0;
	if (input[0]=='!') {
#if 0
	TODO: Honor OOBI
		#!lua < file
		#!lua <<EOF
		#!lua
		#!lua foo bar
                        //r_lang_run (core->lang, p+1, strlen (p+1));
                                //core->oobi, core->oobi_len);
#endif
		if (input[1]=='?' || input[1]=='*' || input[1]=='\0') {
			r_lang_list (core->lang);
			return R_TRUE;
		}
		p = strchr (input+1, ' ');
		if (p) *p=0;
		// TODO: set argv here
		if (r_lang_use (core->lang, input+1)) {
			r_lang_setup (core->lang);
			if (p) r_lang_run_file (core->lang, p+1);
			else r_lang_prompt (core->lang);
		} else eprintf ("Invalid hashbang plugin name. Try '#!'\n");
		return R_TRUE;
	}

	ptr = strchr (input, ' ');
	sscanf (input, "%31s", algo);
	if (ptr != NULL)
		len = r_num_math (core->num, ptr+1);
	/* TODO: Simplify this spaguetti monster */
	if (!r_str_ccmp (input, "md4", ' ')) {
		RHash *ctx = r_hash_new (R_TRUE, R_HASH_MD4);
		const ut8 *c = r_hash_do_md4 (ctx, core->block, len);
		for (i=0; i<R_HASH_SIZE_MD4; i++) r_cons_printf ("%02x", c[i]);
		r_cons_newline ();
		r_hash_free (ctx);
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
		" #xor                 ; calculate xor of all bytes in current block\n"
		" #crc32               ; calculate crc32 of current block\n"
		" #crc32 < /etc/fstab  ; calculate crc32 of this file\n"
		" #pcprint             ; count printable chars in current block\n"
		" #hamdist             ; calculate hamming distance in current block\n"
		" #entropy             ; calculate entropy of current block\n"
		" #md4                 ; calculate md4\n"
		" #md5 128K @ edi      ; calculate md5 of 128K from 'edi'\n"
		" #sha1                ; calculate SHA-1\n"
		" #sha256              ; calculate SHA-256\n"
		" #sha512              ; calculate SHA-512\n"
		"Usage #!interpreter [<args>] [<file] [<<eof]\n"
		" #!                   ; list all available interpreters\n"
		" #!python             ; run python commandline\n"
		" #!python < foo.py    ; run foo.py python script\n"
		" #!python <<EOF       ; get python code until 'EOF' mark\n"
		" #!python arg0 a1 <<q ; set arg0 and arg1 and read until 'q'\n"
		"Comments:\n"
		" # this is a comment  ; note the space after the sharp sign\n");
	}
	return 0;
}

