/* CPP */

static char *pkgname = NULL;
static char *version = NULL;
static char **slurp_ptr = NULL;

static int slurp_args(char *buf) {
	if (slurp_ptr) {
		*slurp_ptr = strdup (buf);
		slurp_ptr = NULL;
		return 1;
	}
	return 0;
}

static TAG_CALLBACK(acr_default) {
	//printf("acr keyword(%s)\n", buf);
	if (slurp_args (buf)) {
		return 0;
	}
	if (!strcmp (buf, "PKGNAME")) {
		slurp_ptr = &pkgname;
	} else if (!strcmp (buf, "VERSION")) {
		slurp_ptr = &version;
	}
	return 0;
}

static TAG_CALLBACK(acr_eof) {
	printf ("Report:\n pkgname: %s\n version: %s\n", pkgname, version);
	return 0;
}

DLL_LOCAL struct Tag acr_tags[] = {
	{ NULL, acr_default },
	{ NULL }
};

DLL_LOCAL struct Arg acr_args[] = {
	{ NULL }
};

DLL_LOCAL struct Proc acr_proc = {
	.name = "acr",
	.tags = (struct Tag **)acr_tags,
	.args = (struct Arg **)acr_args,
	.token = " ",
	.eof = &acr_eof,
	.tag_pre = NULL,
	.tag_post = NULL,
	.multiline = NULL,
	.default_echo = 1,
	.chop = 0,
	.tag_begin = 0,
};
