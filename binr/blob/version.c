static int blob_version(const char *program) {
	printf ("%s "R2_VERSION" @ "R_SYS_OS"-"R_SYS_ENDIAN"-"
			R_SYS_ARCH"-%d git.%s\n",
			program, R_SYS_BITS&8?64:32,
			*R2_GITTAP? R2_GITTAP: "");
	if (*R2_GITTIP) {
		printf ("commit: "R2_GITTIP" build: "R2_BIRTH"\n");
	}
	return 0;
}

static int verify_version(int show) {
	int i, ret;
	typedef const char* (*vc)();
	const char *base = GIT_TAP;
	struct vcs_t {
		const char *name;
		vc callback;
	} vcs[] = {
		{ "r_anal", &r_anal_version },
		{ "r_bin", &r_bin_version },
		{ "r_cons", &r_cons_version },
		{ "r_core", &r_core_version },
		{ "r_util", &r_util_version },
		{ "r_debug", &r_debug_version },
		{ "r_io", &r_io_version },
		{ "r_fs", &r_fs_version },
		{ "r_crypto", &r_crypto_version },
		{ "r_asm", &r_asm_version },
		{ "r_parse", &r_parse_version },
		{ "r_reg", &r_reg_version },
		/* ... */
		{NULL,NULL}
	};

	if (show)
	printf ("%s  r2\n", base);
	for (i=ret=0; vcs[i].name; i++) {
		struct vcs_t *v = &vcs[i];
		const char *name = v->callback ();
		if (!ret && strcmp (base, name))
			ret = 1;
		if (show) printf ("%s  %s\n", name, v->name);
	}
	if (ret) eprintf ("Warning: r2 library versions missmatch!\n");
	return ret;
}
